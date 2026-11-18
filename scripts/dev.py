import subprocess, sys, os, time, socket, shutil, signal, urllib.request, hashlib, webbrowser
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); WIN = os.name == "nt"; procs = []
def stop(*_):
    for p in procs:
        try:
            if WIN: subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            else: p.terminate()
        except Exception: pass
def die(m): print("\nERROR: " + m); stop(); sys.exit(1)
def busy(port):
    s = socket.socket(); r = s.connect_ex(("127.0.0.1", port)) == 0; s.close(); return r
signal.signal(signal.SIGINT, lambda *a: (stop(), sys.exit(0)))
if sys.version_info < (3, 9): die("Python 3.9 or newer is required. Install it from python.org")
npm = shutil.which("npm") or shutil.which("npm.cmd")
if not npm: die("Node.js is not installed. Install the LTS version from nodejs.org, then restart VS Code")
for port in (8000, 5173):
    if busy(port): die(f"Port {port} is already in use. Close other terminals/apps using it (or restart your PC) and try again")
py = sys.executable; vdir = os.path.join(R, ".venv")
if not os.path.isdir(vdir):
    print("Creating Python environment (first run)...")
    if subprocess.run([sys.executable, "-m", "venv", vdir]).returncode != 0: print("Could not create .venv, using system Python")
vpy = os.path.join(vdir, "Scripts" if WIN else "bin", "python.exe" if WIN else "python")
if os.path.exists(vpy): py = vpy
req = os.path.join(R, "backend", "requirements.txt"); stamp = os.path.join(R, ".deps_ok"); h = hashlib.md5(open(req, "rb").read()).hexdigest()
if not (os.path.exists(stamp) and open(stamp).read() == h):
    print("Installing Python packages (first run, 1-3 minutes)...")
    cmd = [py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", req]
    if subprocess.run(cmd).returncode != 0 and subprocess.run(cmd + ["--break-system-packages"]).returncode != 0: die("Python package install failed. Check your internet connection and retry")
    open(stamp, "w").write(h)
if not os.path.isdir(os.path.join(R, "frontend", "node_modules")):
    print("Installing website packages (first run, 1-3 minutes)...")
    if subprocess.run([npm, "install", "--no-audit", "--no-fund"], cwd=os.path.join(R, "frontend"), shell=WIN).returncode != 0: die("npm install failed. Check your internet connection and retry")
print("Starting SmartKYC...")
be = subprocess.Popen([py, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"], cwd=os.path.join(R, "backend")); procs.append(be)
procs.append(subprocess.Popen([npm, "run", "dev"], cwd=os.path.join(R, "frontend"), shell=WIN, stdout=subprocess.DEVNULL))
for _ in range(120):
    if be.poll() is not None: die("Backend crashed. Read the error printed above")
    try:
        if b"connected" in urllib.request.urlopen("http://127.0.0.1:5173/api/health", timeout=2).read(): break
    except Exception: time.sleep(1)
else: die("Services did not start in time")
url = "http://localhost:5173"
print(f"\n==========================================\nSMARTKYC STARTED SUCCESSFULLY\nOpen this link:\n{url}\n\nFrontend: Running\nBackend API: Connected\nDatabase: Connected\n==========================================\nPress Ctrl+C to stop.", flush=True)
try:
    if not webbrowser.open(url):
        print("Could not open a browser automatically. Copy the link above into your browser.", flush=True)
except (OSError, webbrowser.Error) as e:
    print(f"Could not open a browser automatically: {e}\nCopy the link above into your browser.", flush=True)
try:
    while True:
        if be.poll() is not None: die("Backend stopped unexpectedly")
        time.sleep(2)
except KeyboardInterrupt: stop()
