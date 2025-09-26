import os
import tempfile
import uuid
import asyncio
import json
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from app import run_file

app = FastAPI()
JOBS = {}

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head>
      <title>Email Validation Tool</title>
      <style>
        body { font-family: Arial, sans-serif; background:#f6f8fa; padding:20px; }
        .form-box { background:white; padding:20px; border-radius:10px; box-shadow:0 3px 10px rgba(0,0,0,0.1); margin-bottom:20px; }
        .card { background:white; border-radius:10px; padding:20px; margin:20px 0; box-shadow:0 2px 8px rgba(0,0,0,0.1); }
        .header { display:flex; justify-content:space-between; align-items:center; }
        .email { font-size:18px; font-weight:600; }
        .badge { padding:5px 10px; border-radius:6px; font-weight:600; }
        .badge.ok { background:#e6ffed; color:#087f23; }
        .badge.risky { background:#fff3cd; color:#856404; }
        .badge.bad { background:#f8d7da; color:#842029; }
        .scorebar { height:12px; background:#e9ecef; border-radius:8px; margin:8px 0; }
        .scorefill { height:100%; border-radius:8px; }
        .grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:15px; }
        .box { background:#fafafa; padding:12px; border-radius:6px; }
        table { width:100%; }
        td { padding:4px; }
        dt { font-weight:bold; }
      </style>
      <script>
        async function submitForm(event) {
            event.preventDefault();
            const form = document.getElementById("validateForm");
            const formData = new FormData(form);
            document.getElementById("results").innerHTML = "<p>Processing...</p>";
            const res = await fetch("/validate-file", { method:"POST", body: formData });
            const data = await res.json();
            let html = "";
            if(data.results && data.results.results){
                data.results.results.forEach(r=>{
                    let badgeClass = r.final_status=="valid" ? "ok" : (r.catch_all ? "risky" : "bad");
                    let badgeText = r.final_status=="valid" ? "Deliverable" : (r.catch_all ? "Catch-all / Risky" : "Undeliverable");
                    let score = r.score || 0;
                    html += `
                    <div class="card">
                      <div class="header">
                        <div class="email">${r.email}</div>
                        <div class="badge ${badgeClass}">${badgeText}</div>
                      </div>
                      <p style="color:#555;">${badgeText=="Deliverable" ? "This address accepts email" : "This address may not accept email"}</p>
                      <div><b>Email quality score:</b> ${score}/100
                        <div class="scorebar"><div class="scorefill" style="width:${score}%; background:${score>80?'#28a745':score>50?'#ffc107':'#dc3545'}"></div></div>
                      </div>
                      <div class="grid">
                        <div class="box">
                          <h4>Quality Check</h4>
                          <table>
                            <tr><td>Valid format</td><td>${r.syntax_ok?"Yes":"No"}</td></tr>
                            <tr><td>Valid domain</td><td>${r.mx_ok?"Yes":"No"}</td></tr>
                            <tr><td>Can receive email</td><td>${r.smtp_ok?"Yes":"No"}</td></tr>
                            <tr><td>Not a catch-all</td><td>${r.catch_all?"No":"Yes"}</td></tr>
                            <tr><td>Not generic</td><td>${r.role_based?"No":"Yes"}</td></tr>
                            <tr><td>Disposable</td><td>${r.disposable?"Yes":"No"}</td></tr>
                          </table>
                        </div>
                        <div class="box">
                          <h4>Attributes</h4>
                          <dl>
                            <dt>Username</dt><dd>${r.local_part||""}</dd>
                            <dt>Domain</dt><dd>${r.domain||""}</dd>
                            <dt>Is free</dt><dd>${r.free_provider?"Yes":"No"}</dd>
                            <dt>Provider</dt><dd>${r.domain||""}</dd>
                            <dt>MX record</dt><dd>${(r.mx_hosts||[]).join(", ")}</dd>
                          </dl>
                        </div>
                      </div>
                    </div>`;
                });
            } else {
                html = "<p>No results.</p>";
            }
            html += `<p><a href="${data.files.results_csv}" target="_blank">Download CSV</a> | 
                     <a href="${data.files.results_json}" target="_blank">Download JSON</a></p>`;
            document.getElementById("results").innerHTML = html;
        }
      </script>
    </head>
    <body>
      <div class="form-box">
        <h2>Email Validation Tool</h2>
        <form id="validateForm" onsubmit="submitForm(event)">
          <label>Upload CSV:</label> <input type="file" name="file" required><br><br>
          <label>SMTP:</label> 
          <select name="smtp"><option value="true">true</option><option value="false" selected>false</option></select><br><br>
          <label>SMTP From:</label> <input type="text" name="smtp_from" value="hello@sagarjobanputra.com"><br><br>
          <label>Workers:</label> <input type="number" name="workers" value="8"><br><br>
          <button type="submit">Validate</button>
        </form>
      </div>
      <div id="results"></div>
    </body>
    </html>
    """

@app.post("/validate-file")
async def validate_file(file: UploadFile = File(...), smtp: bool = Form(False), smtp_from: str = Form("noreply@example.com"), workers: int = Form(8)):
    jobid = uuid.uuid4().hex
    tmp_input = os.path.join(tempfile.gettempdir(), f"{jobid}.csv")
    with open(tmp_input, "wb") as f: f.write(file.file.read())
    outdir = os.path.join(tempfile.gettempdir(), f"results_{jobid}")
    os.makedirs(outdir, exist_ok=True)
    db_path = os.path.join(outdir, "cache.db")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, run_file, tmp_input, outdir, smtp, smtp_from, db_path, workers)
    json_path = os.path.join(outdir, "results.json")
    with open(json_path, "r", encoding="utf-8") as f: results = json.load(f)
    JOBS[jobid] = outdir
    return {
        "jobid": jobid,
        "results": results,
        "files": {
            "results_json": f"/download/{jobid}/results.json",
            "results_csv": f"/download/{jobid}/results.csv",
        }
    }

@app.get("/download/{jobid}/{name}")
def download_result(jobid: str, name: str):
    outdir = JOBS.get(jobid)
    if not outdir: return HTMLResponse("Job not found", status_code=404)
    path = os.path.join(outdir, name)
    if not os.path.exists(path): return HTMLResponse("File not found", status_code=404)
    return FileResponse(path, filename=name)
