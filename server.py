
import os, re, json, asyncio
from typing import List, Dict, Any
import httpx, tldextract
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY","").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY","").strip()

app = FastAPI(title="PhishGuard Local", version="0.2.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+|www\.[^\s<>\"]+", re.I)
URGENT = ["urgent","immediately","action required","verify","password","unusual activity","suspend","limited","reset","confirm","failed delivery","past due","overdue"]
SHORTEN = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","cutt.ly","rb.gy"}
SUSP_TLDS = {"zip","mov","tk","gq","ml","ga","ru","top","icu","cn"}
BRANDS = {"google","microsoft","apple","amazon","paypal","netflix","sbi","icici","paytm","facebook","instagram","flipkart"}

def html_to_text(html: str) -> str:
    try:
        return BeautifulSoup(html, "html.parser").get_text(" ")
    except Exception:
        return html

def get_domain(u: str) -> str:
    try:
        if not re.match(r"^\w+://", u): u = "http://" + u
        from urllib.parse import urlparse
        h = (urlparse(u).hostname or "").lower()
        return h
    except Exception:
        return ""

def tld_of(h: str) -> str:
    ext = tldextract.extract(h)
    return ext.suffix.split(".")[-1] if ext.suffix else ""

def levenshtein(a: str, b: str) -> int:
    if a==b: return 0
    m,n=len(a),len(b)
    dp=[[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0]=i
    for j in range(n+1): dp[0][j]=j
    for i in range(1,m+1):
        for j in range(1,n+1):
            dp[i][j]=min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(a[i-1]!=b[j-1]))
    return dp[m][n]

def extract_urls(text: str):
    return list({m.group(0) for m in URL_RE.finditer(text or "")})

def extract_features(email_raw: str) -> Dict[str, Any]:
    text = html_to_text(email_raw)
    urls = extract_urls(email_raw) or extract_urls(text)
    hosts = [get_domain(u) for u in urls if u]
    hosts = [h for h in hosts if h]

    risky_attachments = sum(1 for u in urls if any(u.lower().endswith(ext) for ext in [".html",".htm",".exe",".scr",".js",".jar",".bat",".zip",".7z",".rar"]))
    has_non_ascii = any(any(ord(ch)>127 for ch in (h or "")) for h in hosts)
    susp_tld_links = sum(1 for h in hosts if tld_of(h) in SUSP_TLDS)
    shortener_links = sum(1 for h in hosts if h in SHORTEN)
    anchor_mismatch = 0
    lower = text.lower()
    for b in BRANDS:
        if b in lower:
            dists = [levenshtein(h.split(".")[0], b) for h in hosts] or [3]
            if min(dists) >= 2: anchor_mismatch += 1
    best = min([levenshtein(h.split(".")[0], b) for h in hosts for b in BRANDS] or [3])
    brand_distance = min(best, 6)
    urgent_hits = sum(1 for w in URGENT if w in lower)

    features = {
        "links": len(urls),
        "suspicious_tld_links": susp_tld_links,
        "shortener_links": shortener_links,
        "anchor_mismatch": anchor_mismatch,
        "idn_in_links": int(has_non_ascii),
        "urgency_hits": urgent_hits,
        "risky_attachment_links": risky_attachments,
        "brand_distance": brand_distance,
        "long_body": int(len(text) > 5000),
    }
    weights = {"links":0.10,"suspicious_tld_links":0.25,"shortener_links":0.20,"anchor_mismatch":0.15,"idn_in_links":0.10,"urgency_hits":0.18,"risky_attachment_links":0.18,"brand_distance":0.08,"long_body":0.05}
    s = sum(features[k]*w for k,w in weights.items())
    base_prob = max(0.0, min(1.0, 1 - pow(2.71828, -0.45 * s)))
    return {"text": text, "urls": urls, "hosts": hosts, "features": features, "base_prob": base_prob}

async def vt_analyze_urls(urls, api_key):
    if not api_key: return None
    headers = {"x-apikey": api_key, "content-type": "application/x-www-form-urlencoded"}
    out = []
    async with httpx.AsyncClient(timeout=20) as client:
        for u in urls[:8]:
            try:
                r = await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": u})
                jid = r.json().get("data",{}).get("id") if r.status_code<300 else None
                if not jid: 
                    out.append({"url":u,"err":"submit"}); 
                    continue
                rep=None
                for i in range(5):
                    a = await client.get(f"https://www.virustotal.com/api/v3/analyses/{jid}", headers={"x-apikey": api_key})
                    if a.status_code>=300: break
                    j = a.json()
                    if j.get("data",{}).get("attributes",{}).get("status")=="completed":
                        rep=j; break
                    await asyncio.sleep(1+i*0.4)
                if not rep: out.append({"url":u,"err":"timeout"}); continue
                st = rep["data"]["attributes"].get("stats",{})
                out.append({"url":u,"mal":int(st.get("malicious",0)),"sus":int(st.get("suspicious",0))})
            except Exception:
                out.append({"url":u,"err":"net"})
    flagged = sum(1 for r in out if (r.get("mal",0)+r.get("sus",0))>0)
    return {"flagged": flagged, "total": len(out)}

async def gemini_classify(payload, api_key):
    if not api_key: return None
    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    req = {
        "contents":[{"role":"user","parts":[
            {"text": 'Return strict JSON: {"label":"phishing|legit|uncertain","confidence":0..1,"reasons":["..."]}.'},
            {"text": "Signals: "+json.dumps({"features":payload.get("features"),"hosts":payload.get("hosts")})},
            {"text": "Body: "+(payload.get("bodyText","")[:6000])}
        ]}],
        "generationConfig":{"temperature":0.2,"responseMimeType":"application/json"}
    }
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.post(f"{endpoint}?key={api_key}", json=req)
            j = r.json() if r.status_code<300 else {}
            txt = (j.get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text","")) or ""
            try:
                return json.loads(txt)
            except Exception:
                return None
    except Exception:
        return None

def build_feedback(features: dict) -> list[str]:
    fb = []
    f = features
    if f["suspicious_tld_links"] > 0: fb.append("Links use high‑risk TLDs")
    if f["shortener_links"] > 0: fb.append("Links use URL shorteners")
    if f["anchor_mismatch"] > 0: fb.append("Brand names do not match link hosts")
    if f["idn_in_links"]: fb.append("Links include non‑ASCII domains")
    if f["urgency_hits"] > 0: fb.append("Urgent or coercive language detected")
    if f["risky_attachment_links"] > 0: fb.append("Links to risky attachment types")
    if f["brand_distance"] >= 2: fb.append("Sender/links resemble brands but do not match")
    if f["long_body"]: fb.append("Unusually long body content")
    if not fb: fb.append("No strong phishing indicators in content")
    return fb

class AnalyzeIn(BaseModel):
    email: str
    share_body: bool = False

class AnalyzeOut(BaseModel):
    score: float
    verdict: str
    feedback: list[str]
    details: Dict[str, Any]

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(open("static/index.html","r",encoding="utf-8").read())

@app.post("/analyze", response_model=AnalyzeOut)
async def analyze(inp: AnalyzeIn):
    if not inp.email or len(inp.email) < 5:
        raise HTTPException(400, "email required")
    feats = extract_features(inp.email)
    public_urls = [u for u in feats["urls"] if re.match(r"^https?://", u, re.I)]

    # External intelligence used internally only
    p = feats["base_prob"]
    if VT_API_KEY and public_urls:
        vt = await vt_analyze_urls(public_urls, VT_API_KEY)
        if vt and vt.get("flagged",0) > 0:
            p = min(1.0, p + 0.35)
    if GEMINI_API_KEY:
        body = feats["text"] if inp.share_body else ""
        g = await gemini_classify({"features":feats["features"],"hosts":feats["hosts"],"bodyText":body}, GEMINI_API_KEY)
        if isinstance(g, dict):
            if g.get("label")=="phishing":
                p = min(1.0, max(p, 0.85*max(p, g.get("confidence",0.8)) + 0.15))
            elif g.get("label")=="legit":
                p = max(0.0, p - 0.2*(g.get("confidence",0.7)))

    verdict = "low"
    if p >= 0.75: verdict = "high"
    elif p >= 0.45: verdict = "medium"

    feedback = build_feedback(feats["features"])

    return AnalyzeOut(
        score=float(p),
        verdict=verdict,
        feedback=feedback,
        details={"features":feats["features"], "urls": public_urls, "hosts": feats["hosts"]}
    )
