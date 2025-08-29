const $ = (s)=>document.querySelector(s);

function verdictClass(p){
  if (p >= 0.75) return "high";
  if (p >= 0.45) return "medium";
  return "low";
}

$("#analyze").addEventListener("click", async () => {
  const email = $("#email").value.trim();
  if (!email) { alert("Paste an email"); return; }
  $("#analyze").disabled = true;
  $("#status").textContent = "Analyzing...";
  $("#result").classList.add("hidden");

  try {
    const r = await fetch("/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, share_body: $("#shareBody").checked })
    });
    if (!r.ok) throw new Error("HTTP "+r.status);
    const j = await r.json();
    $("#result").classList.remove("hidden");
    const risk = document.querySelector(".risk");
    risk.classList.remove("low","medium","high");
    const p = Number(j.score || 0);
    risk.classList.add(verdictClass(p));
    $("#verdict").textContent = j.verdict.toUpperCase();
    $("#score").textContent = "Score: " + Math.round(p*100) + "%";

    // Feedback
    const ul = document.getElementById("feedback");
    ul.innerHTML = "";
    (j.feedback || []).forEach(item => {
      const li = document.createElement("li");
      li.textContent = item;
      ul.appendChild(li);
    });

    // Signals
    $("#signals").textContent = JSON.stringify(j.details, null, 2);
  } catch(e){
    alert("Error: "+e.message);
  } finally {
    $("#analyze").disabled = false;
    $("#status").textContent = "";
  }
});
