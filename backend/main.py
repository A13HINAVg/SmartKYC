import os, re, json, hashlib, secrets, difflib, io, datetime as dt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
import jwt
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "storage"); os.makedirs(STORE, exist_ok=True)
SECRET = os.getenv("JWT_SECRET", "smartkyc-dev-secret-change-me-in-production-0123456789")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT}/smartkyc.db")
engine_options = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **engine_options)
Session = sessionmaker(bind=engine); Base = declarative_base()
now = lambda: dt.datetime.utcnow()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); email = Column(String, unique=True); name = Column(String); pw = Column(String); role = Column(String, default="customer")
class App(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True); ref = Column(String, unique=True); user_id = Column(Integer)
    status = Column(String, default="draft"); reason = Column(Text, default=""); created = Column(DateTime, default=now)
class Doc(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True); app_id = Column(Integer); type = Column(String); path = Column(String)
    sha = Column(String); quality = Column(Text, default="{}"); ocr = Column(Text, default="{}"); fields = Column(Text, default="{}")
class Audit(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True); app_id = Column(Integer); actor = Column(String); action = Column(String); ts = Column(DateTime, default=now)
Base.metadata.create_all(engine)

def hpw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100000).hex()
def chk(p, h):
    try:
        salt, digest = h.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100000).hex()
        return secrets.compare_digest(candidate, digest)
    except (AttributeError, ValueError):
        return False
def log(s, aid, actor, action): s.add(Audit(app_id=aid, actor=actor, action=action)); s.commit()

def seed():  # synthetic demo data only
    with Session() as s:
        if s.query(User).count(): return
        s.add(User(email="admin@smartkyc.demo", name="Demo Admin", pw=hpw("Admin@123"), role="admin")); s.commit()
        data = [("demo@smartkyc.demo", "Demo Customer", "Demo@1234", [
                    ("approved", [("Aadhaar", "Rahul Sharma", "14/03/1995", "123456789012"), ("PAN", "Rahul Sharma", "14/03/1995", "ABCDE1234F")], "All details consistent; verified manually"),
                    ("manual_review", [("Aadhaar", "Priya Deshmukh", "02/11/1998", "234567890123"), ("PAN", "Priya Desai", "02/11/1999", "BCDEF2345G")], "")]),
                ("sneha@smartkyc.demo", "Sneha Patil", "Demo@1234", [
                    ("ready_for_review", [("Passport", "Sneha Patil", "21/07/2000", "P1234567"), ("PAN", "Sneha Patil", "21/07/2000", "CDEFG3456H")], ""),
                    ("rejected", [("Driving Licence", "Amit Kulkarni", "09/01/1990", "MH1220200001234"), ("Aadhaar", "Amit Joshi", "09/01/1985", "345678901234")], "Identity mismatch not resolved after resubmission request")])]
        for em, nm, pw, apps in data:
            u = User(email=em, name=nm, pw=hpw(pw)); s.add(u); s.commit()
            for st, docs, why in apps:
                a = App(ref="KYC-" + secrets.token_hex(4).upper(), user_id=u.id, status=st, reason=why); s.add(a); s.commit()
                log(s, a.id, em, "Application created (synthetic demo)")
                for t, n, d, num in docs:
                    s.add(Doc(app_id=a.id, type=t, sha=secrets.token_hex(16), quality=json.dumps({"issues": [], "screening": {"flags": [], "note": "Synthetic demo record"}}),
                              ocr=json.dumps({"engine": "synthetic", "note": "Synthetic demo record", "fields": {}}), fields=json.dumps({"name": n, "dob": d, "number": num})))
                s.commit()
seed()

app = FastAPI(title="SmartKYC"); bearer = HTTPBearer()
def db():
    s = Session()
    try: yield s
    finally: s.close()
def me(c=Depends(bearer), s=Depends(db)):
    try: u = s.get(User, int(jwt.decode(c.credentials, SECRET, algorithms=["HS256"])["sub"]))
    except Exception: raise HTTPException(401, "Session expired. Please log in again")
    if not u: raise HTTPException(401, "User not found")
    return u
def get_app(s, u, aid):
    a = s.get(App, aid)
    if not a or (u.role != "admin" and a.user_id != u.id): raise HTTPException(404, "Application not found")
    return a

class Reg(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"); name: str = Field(min_length=2); password: str = Field(min_length=8); consent: bool
class Login(BaseModel): email: str; password: str
class Fields(BaseModel): name: str = ""; dob: str = ""; number: str = ""
class Decision(BaseModel): action: str; reason: str = Field(min_length=5)

@app.get("/api/health")
def health(s=Depends(db)): s.query(User).count(); return {"status": "ok", "database": "connected"}
@app.post("/api/auth/register")
def register(r: Reg, s=Depends(db)):
    if not r.consent: raise HTTPException(400, "Consent is required to register")
    email = r.email.strip().lower()
    name = r.name.strip()
    if s.query(User).filter_by(email=email).first(): raise HTTPException(409, "Email already registered")
    s.add(User(email=email, name=name, pw=hpw(r.password))); s.commit(); return {"ok": True}
@app.post("/api/auth/login")
def login(r: Login, s=Depends(db)):
    u = s.query(User).filter_by(email=r.email.lower().strip()).first()
    if not u or not chk(r.password, u.pw): raise HTTPException(401, "Wrong email or password")
    return {"token": jwt.encode({"sub": str(u.id), "exp": now() + dt.timedelta(hours=8)}, SECRET), "role": u.role, "name": u.name}

def nname(x): return " ".join(sorted(re.sub(r"[^a-z ]", "", x.lower()).split()))
def ndob(x):
    m = re.search(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})", x)
    return f"{int(m[1]):02d}/{int(m[2]):02d}/{m[3]}" if m else x.strip()
def analyze(docs):
    fm = {k: {} for k in ["name", "dob", "number"]}; mism, warn, miss, ok, bad = [], [], [], [], set()
    for d in docs:
        f = json.loads(d.fields)
        for k in fm:
            if f.get(k, "").strip(): fm[k][d.type] = f[k].strip()
        for k in ["name", "dob"]:
            if not f.get(k, "").strip(): miss.append(f"{'Name' if k == 'name' else 'Date of birth'} not confirmed on {d.type}")
    names = list(fm["name"].items()); n0 = len(mism) + len(warn)
    for t, v in names[1:]:
        a, b = nname(names[0][1]), nname(v)
        if a == b: continue
        if set(a.split()) <= set(b.split()) or set(b.split()) <= set(a.split()): warn.append(f"Name on {t} has extra or missing words ('{v}' vs '{names[0][1]}')")
        elif difflib.SequenceMatcher(None, a, b).ratio() >= .85: warn.append(f"Name spelling differs slightly between {names[0][0]} and {t}")
        else: mism.append(f"Name differs: {names[0][0]} '{names[0][1]}' vs {t} '{v}'"); bad.add("name")
    if len(names) > 1 and len(mism) + len(warn) == n0: ok.append("Name is consistent across documents")
    dobs = {t: ndob(v) for t, v in fm["dob"].items()}
    if len(set(dobs.values())) > 1: mism.append("Date of birth differs: " + ", ".join(f"{t} {v}" for t, v in dobs.items())); bad.add("dob")
    elif len(dobs) > 1: ok.append("Date of birth is consistent across documents")
    qi, fl = [], []
    for d in docs:
        q = json.loads(d.quality); qi += [f"{d.type}: {i}" for i in q.get("issues", [])]; fl += [f"{d.type}: {i}" for i in q.get("screening", {}).get("flags", [])]
    reasons = mism + fl + warn
    return {"fieldmap": fm, "bad": sorted(bad), "mismatches": mism, "warnings": warn, "missing": miss, "passed": ok, "quality_issues": qi, "flags": fl,
            "reasons": reasons, "face_verification": "Not run: face matching is not part of this build"}
def readiness(docs, an):
    it = [("Upload at least 2 documents", len(docs) >= 2, 25, "Add a second ID, e.g. PAN + Aadhaar"),
          ("Name & date of birth confirmed on every document", bool(docs) and not an["missing"], 20, "Review and confirm the extracted fields"),
          ("Identity data is consistent", len(docs) >= 2 and not an["mismatches"], 25, "Fix the mismatching name/DOB or upload the right document"),
          ("Images are clear and readable", bool(docs) and not an["quality_issues"], 15, "Re-upload sharper, well-lit photos"),
          ("No tamper indicators found", bool(docs) and not an["flags"], 15, "Upload the original, unedited file")]
    return {"score": sum(w for _, o, w, _ in it if o), "items": [{"label": l, "ok": o, "hint": h} for l, o, w, h in it]}
def mask(v): return v if len(v) < 5 else "*" * (len(v) - 4) + v[-4:]
def ser(a, s):
    docs = s.query(Doc).filter_by(app_id=a.id).all(); an = analyze(docs); ow = s.get(User, a.user_id)
    return {"id": a.id, "ref": a.ref, "status": a.status, "reason": a.reason, "owner": ow.name if ow else "", "analysis": an, "readiness": readiness(docs, an),
            "docs": [{"id": d.id, "type": d.type, "has_file": bool(d.path), "quality": json.loads(d.quality), "ocr": json.loads(d.ocr), "fields": json.loads(d.fields), "masked": mask(json.loads(d.fields).get("number", ""))} for d in docs],
            "audit": [{"actor": x.actor, "action": x.action, "ts": str(x.ts)} for x in s.query(Audit).filter_by(app_id=a.id)]}

@app.post("/api/apps")
def create(u=Depends(me), s=Depends(db)):
    a = App(ref="KYC-" + secrets.token_hex(4).upper(), user_id=u.id); s.add(a); s.commit(); log(s, a.id, u.email, "Application created"); return ser(a, s)
@app.get("/api/apps")
def lst(q: str = "", status: str = "", u=Depends(me), s=Depends(db)):
    qs = s.query(App)
    if u.role != "admin": qs = qs.filter_by(user_id=u.id)
    if status: qs = qs.filter_by(status=status)
    if q: qs = qs.filter(App.ref.contains(q.upper()))
    return [{"id": a.id, "ref": a.ref, "status": a.status, "owner": (s.get(User, a.user_id).name if s.get(User, a.user_id) else ""), "created": str(a.created)[:10]} for a in qs.order_by(App.id.desc())]
@app.get("/api/apps/{aid}")
def one(aid: int, u=Depends(me), s=Depends(db)): return ser(get_app(s, u, aid), s)
@app.get("/api/admin/stats")
def stats(u=Depends(me), s=Depends(db)):
    if u.role != "admin": raise HTTPException(403, "Admin only")
    return {"total": s.query(App).count(), **{k: s.query(App).filter_by(status=k).count() for k in ["approved", "rejected", "manual_review", "ready_for_review", "resubmission_requested", "draft"]}}

def quality(data, ext):
    if ext == "pdf": return {"note": "PDF accepted; image checks apply to JPG/PNG only", "issues": []}
    import numpy as np
    from PIL import Image
    try: im = Image.open(io.BytesIO(data)).convert("L")
    except Exception: raise HTTPException(400, "File is not a readable image")
    w, h = im.size; g = np.asarray(im, dtype=float)
    lap = g[1:-1, 1:-1] * 4 - g[:-2, 1:-1] - g[2:, 1:-1] - g[1:-1, :-2] - g[1:-1, 2:]
    blur, br = float(lap.var()), float(g.mean()); tips = []
    if blur < 100: tips.append("Blurry: hold the camera steady and refocus")
    if br < 60: tips.append("Too dark: use better lighting")
    if br > 210: tips.append("Overexposed: avoid glare")
    if min(w, h) < 500: tips.append("Low resolution: use a higher quality scan")
    if h > w * 1.3: tips.append("Portrait orientation: check the document rotation")
    return {"blur_score": round(blur, 1), "brightness": round(br, 1), "size": [w, h], "issues": tips}
def screen(data, ext):
    note = "Preliminary screening only, not proof of fraud"
    if ext == "pdf": return {"flags": [], "note": note}
    import numpy as np
    from PIL import Image
    im = Image.open(io.BytesIO(data)); fl = []
    try: sw = str(im.getexif().get(305, "") or "")
    except Exception: sw = ""
    if any(k in sw.lower() for k in ["photoshop", "gimp", "canva", "pixlr"]): fl.append(f"Image metadata shows editing software ({sw})")
    rgb = im.convert("RGB"); b = io.BytesIO(); rgb.save(b, "JPEG", quality=90); b.seek(0)
    d = np.abs(np.asarray(rgb, float) - np.asarray(Image.open(b).convert("RGB"), float)).mean(axis=2); bs = 32
    bl = [d[y:y + bs, x:x + bs].mean() for y in range(0, d.shape[0] - bs, bs) for x in range(0, d.shape[1] - bs, bs)]
    if len(bl) > 8 and float(np.std(bl)) > 3 * max(float(np.mean(bl)), 1.0): fl.append("Uneven compression regions (possible local edit, ELA)")
    return {"flags": fl, "ela_mean": round(float(d.mean()), 2), "software": sw or None, "note": note}
def ocr(data, ext, dtype):
    if ext == "pdf": return {"engine": "none", "note": "PDF OCR not available; enter fields manually", "fields": {}}
    try:
        import pytesseract; from PIL import Image
        t = pytesseract.image_to_string(Image.open(io.BytesIO(data)))
    except Exception: return {"engine": "unavailable", "note": "Tesseract OCR not installed. Nothing was extracted; please type the fields.", "fields": {}}
    f = {}; m = re.search(r"\b[A-Z]{5}\d{4}[A-Z]\b", t) if dtype == "PAN" else re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b", t)
    if m: f["number"] = m.group(0)
    m = re.search(r"\b\d{2}[/-]\d{2}[/-]\d{4}\b", t)
    if m: f["dob"] = m.group(0).replace("-", "/")
    return {"engine": "tesseract", "note": "Confidence not reported. Please review", "fields": f}

@app.post("/api/apps/{aid}/docs")
async def upload(aid: int, type: str = Form(...), file: UploadFile = File(...), u=Depends(me), s=Depends(db)):
    a = get_app(s, u, aid)
    if u.role == "admin": raise HTTPException(403, "Only customers upload documents")
    if type not in ["Aadhaar", "PAN", "Passport", "Driving Licence"]: raise HTTPException(400, "Unsupported document type")
    ext = (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in ["pdf", "jpg", "jpeg", "png"]: raise HTTPException(400, "Only PDF, JPG, JPEG, PNG allowed")
    data = await file.read()
    if len(data) > 8_000_000: raise HTTPException(400, "File too large (max 8 MB)")
    sha = hashlib.sha256(data).hexdigest()
    if s.query(Doc).filter_by(sha=sha).first(): raise HTTPException(409, "Duplicate document detected")
    q = quality(data, ext); q["screening"] = screen(data, ext); o = ocr(data, ext, type)
    p = os.path.join(STORE, sha + "." + ext)
    with open(p, "wb") as stored_file:
        stored_file.write(data)
    s.add(Doc(app_id=a.id, type=type, path=p, sha=sha, quality=json.dumps(q), ocr=json.dumps(o), fields=json.dumps(o["fields"])))
    s.commit(); log(s, a.id, u.email, f"Uploaded {type}"); return ser(a, s)
@app.get("/api/docs/{did}/file")
def getfile(did: int, u=Depends(me), s=Depends(db)):
    d = s.get(Doc, did)
    if not d or not d.path: raise HTTPException(404, "No file stored for this record")
    get_app(s, u, d.app_id)
    if not os.path.isfile(d.path): raise HTTPException(404, "Stored file not found")
    return FileResponse(d.path)
@app.put("/api/docs/{did}/fields")
def setf(did: int, f: Fields, u=Depends(me), s=Depends(db)):
    d = s.get(Doc, did)
    if not d: raise HTTPException(404, "Not found")
    a = get_app(s, u, d.app_id); d.fields = json.dumps(f.model_dump()); s.commit(); log(s, a.id, u.email, f"Confirmed fields for {d.type}"); return {"ok": True}
@app.post("/api/apps/{aid}/verify")
def verify(aid: int, u=Depends(me), s=Depends(db)):
    a = get_app(s, u, aid); docs = s.query(Doc).filter_by(app_id=aid).all(); an = analyze(docs)
    if len(docs) < 2: raise HTTPException(400, "Upload at least 2 documents first")
    a.status = "manual_review" if (an["mismatches"] or an["flags"]) else ("draft" if an["missing"] else "ready_for_review")
    s.commit(); log(s, a.id, u.email, "Cross-document verification run"); return ser(a, s)
@app.post("/api/apps/{aid}/decision")
def decide(aid: int, d: Decision, u=Depends(me), s=Depends(db)):
    if u.role != "admin": raise HTTPException(403, "Admin only")
    m = {"approve": "approved", "reject": "rejected", "resubmit": "resubmission_requested"}
    if d.action not in m: raise HTTPException(400, "Invalid action")
    if len(d.reason.strip()) < 5: raise HTTPException(400, "Reason must be at least 5 characters")
    a = get_app(s, u, aid)
    a.status = m[d.action]; a.reason = d.reason.strip(); s.commit(); log(s, aid, u.email, f"{d.action}: {d.reason.strip()}"); return ser(a, s)
@app.get("/api/apps/{aid}/report")
def report(aid: int, u=Depends(me), s=Depends(db)):
    from reportlab.lib.pagesizes import A4; from reportlab.pdfgen import canvas
    a = get_app(s, u, aid); r = ser(a, s); p = os.path.join(STORE, f"report_{a.ref}.pdf"); c = canvas.Canvas(p, pagesize=A4); y = [800]
    def w(t, sz=10):
        if y[0] < 60: c.showPage(); y[0] = 800
        c.setFont("Helvetica", sz); c.drawString(40, y[0], t[:105]); y[0] -= sz + 6
    w("SmartKYC Verification Report (academic project)", 15); w(f"Reference: {a.ref}   Customer: {r['owner']}   Status: {a.status}"); w(f"Readiness score: {r['readiness']['score']}/100 (not a fraud score)"); w(f"Decision reason: {a.reason or '-'}"); y[0] -= 6
    for d in r["docs"]: w(f"{d['type']}: {d['fields'].get('name', '-')} | DOB {d['fields'].get('dob', '-')} | No. {d['masked'] or '-'}")
    an = r["analysis"]; y[0] -= 6
    for t, k in [("Mismatch", "mismatches"), ("Warning", "warnings"), ("Missing", "missing"), ("Passed", "passed"), ("Quality", "quality_issues"), ("Screening", "flags")]:
        for i in an[k]: w(f"{t}: {i}")
    w(an["face_verification"]); y[0] -= 6; w("Preliminary automated screening only. Not an official verification."); c.save()
    return FileResponse(p, media_type="application/pdf", filename=f"{a.ref}.pdf")
