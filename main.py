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
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>Email Verifier — Modern UI</title>
      <!-- Tailwind CDN for quick responsive design (replace with your own build if you prefer) -->
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        /* small inline tweaks */
        .score-fill { height: 12px; border-radius: 8px; }
        .card-scroll { max-height: 60vh; overflow:auto; }
      </style>
    </head>
    <body class="bg-slate-50 min-h-screen p-6">
      <div class="max-w-5xl mx-auto">
        <header class="mb-6">
          <h1 class="text-2xl font-semibold">Email Verification</h1>
          <p class="text-slate-600">Upload a CSV or verify a single address. Results keep the exact verifier output (CSV/JSON).</p>
        </header>

        <section class="bg-white rounded-lg shadow p-6 mb-6">
          <form id="validateForm" class="grid md:grid-cols-2 gap-6" onsubmit="submitFile(event)" enctype="multipart/form-data">
            <div>
              <label class="block font-medium mb-2">Upload CSV (single column or header 'email')</label>
              <div id="dropzone" class="border-2 border-dashed border-slate-200 rounded p-4 text-center cursor-pointer"
                   onclick="document.getElementById('fileInput').click()">
                <input id="fileInput" name="file" type="file" accept=".csv,text/csv" class="hidden" onchange="handleFile(this.files)">
                <p id="dropText" class="text-slate-500">Drag & drop CSV here, or click to choose file</p>
                <p id="filename" class="text-slate-700 mt-2"></p>
                <!-- Preview removed as requested -->
              </div>
            </div>

            <div>
              <label class="block font-medium mb-2">Single email verification</label>
              <div class="flex gap-2 mb-3">
                <input id="singleEmail" type="email" placeholder="me@example.com" class="flex-1 border rounded px-3 py-2" />
                <button type="button" onclick="checkSingle()" class="px-4 py-2 bg-indigo-600 text-white rounded">Verify</button>
              </div>

              <label class="block font-medium mb-2">Options</label>
              <div class="grid grid-cols-2 gap-2 mb-3">
                <div>
                  <label class="block text-sm">SMTP probing</label>
                  <select id="smtpSelect" name="smtp" class="w-full border rounded px-2 py-1">
                    <option value="true">true</option><option value="false" selected>false</option>
                  </select>
                </div>
                <div>
                  <label class="block text-sm">Workers</label>
                  <input id="workers" name="workers" type="number" min="1" value="8" class="w-full border rounded px-2 py-1" />
                </div>
              </div>

              <label class="block text-sm mb-2">SMTP From</label>
              <input id="smtpFrom" name="smtp_from" value="noreply@example.com" class="w-full border rounded px-3 py-2" />

              <div class="mt-4 flex gap-2">
                <button type="submit" class="px-4 py-2 bg-green-600 text-white rounded">Validate CSV</button>
                <button type="button" onclick="clearResults()" class="px-4 py-2 border rounded">Clear</button>
              </div>
            </div>
          </form>
        </section>

        <!-- Status area (now contains download links at the top once results come back) -->
        <section id="statusSection" class="mb-6"></section>

        <section id="results" class="card-scroll space-y-4"></section>
      </div>

      <script>
        let selectedFile = null;

        function handleFile(files){
          if(!files || !files.length) return;
          selectedFile = files[0];
          document.getElementById('filename').innerText = selectedFile.name + " (" + Math.round(selectedFile.size/1024) + " KB)";
          // Preview intentionally removed per user request.
        }

        function escapeHtml(s){ return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

        async function submitFile(event){
          event.preventDefault();
          if(!selectedFile){
            alert('Please choose a CSV file first.');
            return;
          }
          const form = document.getElementById('validateForm');
          const fd = new FormData();
          fd.append('file', selectedFile);
          fd.append('smtp', document.getElementById('smtpSelect').value);
          fd.append('smtp_from', document.getElementById('smtpFrom').value || 'noreply@example.com');
          fd.append('workers', document.getElementById('workers').value || '8');

          document.getElementById('statusSection').innerHTML = '<div class="p-4 bg-yellow-50 rounded">Processing... this can take some time when SMTP probing is ON.</div>';
          document.getElementById('results').innerHTML = '';

          try {
            const res = await fetch('/validate-file', { method: 'POST', body: fd });
            if(!res.ok) throw new Error('Server error');
            const data = await res.json();
            renderResults(data);
          } catch(e) {
            document.getElementById('statusSection').innerHTML = '<div class="p-4 bg-red-50 rounded">Error running verifier: ' + e + '</div>';
          }
        }

        function clearResults(){
          document.getElementById('results').innerHTML = '';
          document.getElementById('statusSection').innerHTML = '';
          document.getElementById('filename').innerText = '';
          selectedFile = null;
          document.getElementById('fileInput').value = '';
        }

        function prettyBadge(status, catch_all){
          if(status==='valid') return '<span class="px-2 py-1 bg-green-100 text-green-800 rounded">Deliverable</span>';
          if(status==='risky' || catch_all) return '<span class="px-2 py-1 bg-yellow-100 text-yellow-800 rounded">Risky</span>';
          return '<span class="px-2 py-1 bg-red-100 text-red-800 rounded">Undeliverable</span>';
        }

        function renderResults(data){
          // Put downloads (if available) at top of status section
          let statusHtml = '<div class="p-3 bg-green-50 rounded">Done — results ready.</div>';
          if(data.files && data.files.results_csv && data.files.results_csv !== '#'){
            statusHtml += '<div class="mt-2 p-3 bg-slate-50 rounded"><b>Downloads</b>: ' +
                          `<a class="text-indigo-600" href="${data.files.results_csv}" target="_blank">CSV</a> | ` +
                          `<a class="text-indigo-600" href="${data.files.results_json}" target="_blank">JSON</a></div>`;
          }
          document.getElementById('statusSection').innerHTML = statusHtml;

          const outDiv = document.getElementById('results');
          outDiv.innerHTML = '';

          if(!data.results || !data.results.results) {
            outDiv.innerHTML = '<div class="p-3 bg-slate-50 rounded">No results</div>';
            return;
          }
          data.results.results.forEach(r=>{
            const score = r.score || 0;
            const card = document.createElement('div');
            card.className = 'bg-white p-4 rounded shadow';

            card.innerHTML = `
              <div class="flex justify-between items-start">
                <div>
                  <div class="text-lg font-medium">${r.email}</div>
                  <div class="text-sm text-slate-500">${r.smtp_reason || (r.notes ? r.notes.join(' ; ') : '')}</div>
                </div>
                <div class="text-right space-y-1">
                  ${prettyBadge(r.final_status, r.catch_all)}
                  <div class="text-xs mt-2">Score: ${score}/100</div>
                  <div class="w-40 mt-1 bg-slate-200 rounded overflow-hidden"><div class="score-fill" style="width:${score}%; background:${score>80? '#16a34a' : score>50 ? '#f59e0b' : '#dc2626'}"></div></div>
                </div>
              </div>
              <div class="grid md:grid-cols-2 gap-4 mt-3">
                <div class="text-sm">
                  <b>Checks</b>
                  <ul class="mt-2 list-disc ml-5 text-slate-600">
                    <li>Format: ${r.syntax_ok ? 'Yes' : 'No'}</li>
                    <li>MX: ${r.mx_ok ? 'Yes' : 'No'}</li>
                    <li>SMTP Accepts: ${r.smtp_ok === true ? 'Yes' : (r.smtp_ok === false ? 'No' : 'Unknown')}</li>
                    <li>Catch-all: ${r.catch_all ? 'Yes' : 'No'}</li>
                    <li>Disposable: ${r.disposable ? 'Yes' : 'No'}</li>
                  </ul>
                </div>
                <div class="text-sm">
                  <b>Attributes</b>
                  <div class="mt-2 text-slate-600">
                    <div><b>Local:</b> ${r.local_part || ''}</div>
                    <div><b>Domain:</b> ${r.domain || ''}</div>
                    <div><b>MX Hosts:</b> ${(r.mx_hosts || []).join(', ')}</div>
                  </div>
                </div>
              </div>
            `;
            outDiv.appendChild(card);
          });
        }

        // Single-email check (calls new /validate-email)
        async function checkSingle(){
          const email = document.getElementById('singleEmail').value.trim();
          if(!email){ alert('Enter an email to check'); return; }
          document.getElementById('statusSection').innerHTML = '<div class="p-3 bg-yellow-50 rounded">Checking...</div>';
          try {
            const form = new FormData();
            form.append('email', email);
            form.append('smtp', document.getElementById('smtpSelect').value);
            form.append('smtp_from', document.getElementById('smtpFrom').value || 'noreply@example.com');
            const res = await fetch('/validate-email', { method: 'POST', body: form });
            const json = await res.json();
            // emulate same data shape as batch endpoint; single checks have no downloadable CSV so files are '#'
            renderResults({ results: { results: [json.result] }, files: { results_csv: '#', results_json: '#' } });
          } catch(err) {
            document.getElementById('statusSection').innerHTML = '<div class="p-3 bg-red-50 rounded">Error: '+ err +'</div>';
          }
        }
      </script>
    </body>
    </html>
    """
# at top, add imports
from app import validate_single, connect_db, init_db

@app.post("/validate-email")
async def validate_email(email: str = Form(...), smtp: bool = Form(False), smtp_from: str = Form("noreply@example.com")):
    # create a tiny per-request DB in tmpdir to reuse same caching functions
    jobid = uuid.uuid4().hex
    outdir = os.path.join(tempfile.gettempdir(), f"email_job_{jobid}")
    os.makedirs(outdir, exist_ok=True)
    db_path = os.path.join(outdir, "cache.db")
    db_conn = connect_db(db_path)
    init_db(db_conn)
    # call validate_single (synchronous CPU/IO, but light). We can run in executor if desired.
    res = validate_single(email, smtp_from, db_conn, smtp_probe_flag=(str(smtp).lower() == "true" or smtp is True))
    return {"result": res}

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
