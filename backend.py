"""
BOCRA Backend API — Python/Flask for Render.com
================================================
Render natively supports Python — no Docker needed.
Uses SQLite (file stored on Render's disk) for data.
"""

from flask import Flask, request, jsonify
import sqlite3, os, uuid, hashlib, hmac, datetime, re

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, 'bocra.db')
SECRET      = os.environ.get('BOCRA_SECRET', 'bocra-render-secret-change-me')
UPLOAD_DIR  = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── CORS (allow frontend to call API) ──────────────────────────
@app.after_request
def cors(r):
    r.headers['Access-Control-Allow-Origin']  = '*'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return r

@app.route('/api/<path:p>', methods=['OPTIONS'])
def preflight(p): return '', 200

# ── Database ────────────────────────────────────────────────────
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def q(sql, p=(), one=False):
    with db() as con:
        cur = con.execute(sql, p)
        r   = cur.fetchone() if one else cur.fetchall()
        return dict(r) if (one and r) else ([dict(x) for x in r] if not one else None)

def run(sql, p=()):
    with db() as con:
        cur = con.execute(sql, p)
        con.commit()
        return cur.lastrowid

def ok(data=None, code=200, **kw):
    r = {'success': True, 'data': data}
    r.update(kw)
    return jsonify(r), code

def err(msg, code=400):
    return jsonify({'success': False, 'error': msg}), code

# ── Auth helpers ────────────────────────────────────────────────
def hash_pw(pw):
    salt = os.urandom(16).hex()
    h = hmac.new(SECRET.encode(), (salt+pw).encode(), hashlib.sha256).hexdigest()
    return f"{salt}:{h}"

def check_pw(pw, stored):
    try:
        salt, h = stored.split(':')
        return hmac.compare_digest(h, hmac.new(SECRET.encode(), (salt+pw).encode(), hashlib.sha256).hexdigest())
    except: return False

def current_user():
    auth = request.headers.get('Authorization','')
    if not auth.startswith('Bearer '): return None
    token = auth[7:]
    return q("SELECT * FROM users WHERE token=? AND token_expires>datetime('now')", (token,), one=True)

def need_auth():
    if not current_user(): return err('Unauthorized', 401)

def need_admin():
    u = current_user()
    if not u: return err('Unauthorized', 401)
    if u['role'] not in ('admin','superadmin'): return err('Forbidden', 403)

# ── Setup DB ─────────────────────────────────────────────────────
def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL, role TEXT DEFAULT 'user',
            token TEXT, token_expires TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS licences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            licence_no TEXT UNIQUE NOT NULL, operator_name TEXT NOT NULL,
            category TEXT NOT NULL, licence_type TEXT NOT NULL,
            status TEXT DEFAULT 'active', issued_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL, address TEXT,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
            email TEXT, phone TEXT, operator TEXT NOT NULL,
            category TEXT DEFAULT 'General', description TEXT NOT NULL,
            status TEXT DEFAULT 'Received',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS complaint_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER REFERENCES complaints(id),
            note TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, excerpt TEXT NOT NULL, body TEXT,
            category TEXT DEFAULT 'Press Release', tag TEXT DEFAULT 'Press Release',
            published_at TEXT DEFAULT (datetime('now')), is_published INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, category TEXT NOT NULL,
            doc_type TEXT NOT NULL, file_size TEXT, published_at TEXT,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS consultations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, body TEXT,
            status TEXT DEFAULT 'open', deadline TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        """)
        # Seed users from db.json
        if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            con.execute("INSERT INTO users (email,password_hash,full_name,role) VALUES (?,?,?,?)",
                ('admin@bocra.org.bw', hash_pw('Admin@BOCRA2026'), 'BOCRA Administrator', 'admin'))
            con.execute("INSERT INTO users (email,password_hash,full_name,role) VALUES (?,?,?,?)",
                ('citizen@example.com', hash_pw('Citizen@2024'), 'Citizen User', 'user'))
            con.commit()

        # Seed licences from db.json (exact data)
        if not con.execute("SELECT 1 FROM licences LIMIT 1").fetchone():
            lics = [
                ('BOCRA-ICT-2023-0852','TechSolutions Botswana (PTY) LTD','Telecommunications','Commercial value added network services','suspended','2023-10-14','2028-10-13','National (Botswana)'),
                ('B-12345','Orange Botswana','Telecommunications','Mobile telecommunications services','active','2020-01-15','2025-01-15','National (Botswana)'),
                ('BOCRA-TEL-2019-0423','Mascom Wireless','Telecommunications','Mobile network operator services','active','2019-06-01','2024-06-01','National (Botswana)'),
                ('BOCRA-POST-2018-0091','BotswanaPost','Postal Services','National postal services','active','2018-03-01','2028-03-01','National (Botswana)'),
                ('BOCRA-ISP-2022-0156','BTC Internet Services Ltd','Internet Service Provider','Internet service provider','active','2022-08-10','2027-08-10','National (Botswana)'),
                ('BOCRA-BRD-2021-0234','Botswana Television','Broadcasting','Television broadcasting services','active','2021-04-12','2026-04-12','National (Botswana)'),
            ]
            con.executemany("INSERT INTO licences (licence_no,operator_name,category,licence_type,status,issued_date,expiry_date,address) VALUES (?,?,?,?,?,?,?,?)", lics)
            con.commit()

        # Seed complaints from db.json (exact data)
        if not con.execute("SELECT 1 FROM complaints LIMIT 1").fetchone():
            cmps = [
                ('COM-2024-0001','Kagiso Molefe','kagiso@example.com','+267 71234567','Orange Botswana','Telecom','Poor network coverage in my area. Calls frequently drop and data speeds are very slow.','Investigating','2024-03-15T10:30:00Z','2024-03-16T14:20:00Z'),
                ('COM-2024-0002','Mpho Serame','mpho@example.com','+267 72345678','BotswanaPost','Postal','Package was lost during delivery. Tracking shows it was delivered but I never received it.','Resolved','2024-03-10T09:15:00Z','2024-03-18T16:45:00Z'),
                ('COM-2026-0004','Atang Wendy Gaamangwe','202200300@ub.ac.bw','+25472874504','Mascom','Telecom','bad internet','Submitted','2024-03-19T19:00:00Z','2024-03-19T19:00:00Z'),
            ]
            for c in cmps:
                cid = con.execute("INSERT INTO complaints (reference,full_name,email,phone,operator,category,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)", c).lastrowid
                notes = {
                    'COM-2024-0001': ['Complaint received and logged by BOCRA','Assigned to Consumer Affairs team','Formal notice issued to Orange Botswana'],
                    'COM-2024-0002': ['Complaint received — lost parcel reported','BotswanaPost contacted','Parcel traced at sorting facility','Resolved — parcel delivered to customer'],
                    'COM-2026-0004': ['Complaint submitted and reference number assigned'],
                }
                for note in notes.get(c[0],[]):
                    con.execute("INSERT INTO complaint_history (complaint_id,note) VALUES (?,?)",(cid,note))
            con.commit()

        # Seed news — db.json regulations surfaced as news
        if not con.execute("SELECT 1 FROM news LIMIT 1").fetchone():
            news = [
                ('Consumer Protection Guidelines Published','Guidelines for protecting telecommunications consumers including billing transparency, service quality, and complaint resolution procedures.','Regulation','Regulation','2024-02-01'),
                ('Mobile Network Quality Standards Established','BOCRA has established minimum quality standards for mobile network operators including call success rates, data speeds, and coverage requirements.','Regulation','Regulation','2024-01-01'),
                ('BOCRA Approves Reduced Data Prices for BTC','Following a comprehensive review, BOCRA has directed BTC to reduce retail data prices by 20%.','Public Notice','Public Notice','2026-03-14'),
                ('Botswana Collaborates with SADC to Harmonise Roaming Tariffs','BOCRA participated in a landmark SADC meeting agreeing to cap international roaming rates.','Press Release','Press Release','2026-03-10'),
                ('Public Consultation: National Broadband Strategy 2026-2030','BOCRA invites all stakeholders to submit written comments by 30 April 2026.','Consultation','Consultation','2026-03-03'),
            ]
            con.executemany("INSERT INTO news (title,excerpt,category,tag,published_at) VALUES (?,?,?,?,?)", news)
            con.commit()

        # Seed documents — db.json regulations + standard BOCRA docs
        if not con.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            docs = [
                ('Mobile Network Quality Standards','guidelines','Regulation','1.2 MB','2024-01-01'),
                ('Consumer Protection Guidelines','guidelines','Guideline','980 KB','2024-02-01'),
                ('Communications Regulatory Authority Act, 2012','legislation','Legislation','2.1 MB','2012-01-01'),
                ('Annual Telecoms Statistics Report 2025','reports','Statistics Report','4.8 MB','2025-12-01'),
                ('Cost Modelling Project - Interim Report','reports','Report','3.2 MB','2025-09-01'),
                ('Electronic Communications and Transactions Act','legislation','Legislation','1.8 MB','2014-01-01'),
            ]
            con.executemany("INSERT INTO documents (title,category,doc_type,file_size,published_at) VALUES (?,?,?,?,?)", docs)
            con.commit()

        # Seed consultations
        if not con.execute("SELECT 1 FROM consultations LIMIT 1").fetchone():
            cons = [
                ('National Broadband Strategy 2026-2030','Public consultation on the proposed national broadband strategy.','open','2026-04-30'),
                ('Draft Regulations on Data Protection & Privacy','Consultation on proposed data protection regulations.','open','2026-05-15'),
                ('Review of Interconnection & Wholesale Access Rates','Consultation on the review of regulated interconnection rates.','closed','2026-02-28'),
            ]
            con.executemany("INSERT INTO consultations (title,body,status,deadline) VALUES (?,?,?,?)", cons)
            con.commit()

# ── ROUTES ─────────────────────────────────────────────────────

@app.route('/api/health')
def health():
    return jsonify({'status':'ok','service':'BOCRA API','version':'1.0.0'})

@app.route('/api/system-status')
def system_status():
    try:
        db().execute("SELECT 1")
        up = True
    except: up = False
    return ok({'status':'operational' if up else 'degraded',
               'message':'All systems operational' if up else 'Database unavailable',
               'uptime':'99.98%','timestamp':datetime.datetime.utcnow().isoformat()+'Z'})

@app.route('/api/search')
def search():
    query = request.args.get('q','').strip()
    if len(query) < 2: return err('Query must be at least 2 characters')
    like = f'%{query}%'
    results = []
    for r in q("SELECT licence_no,operator_name,category,status FROM licences WHERE operator_name LIKE ? OR licence_no LIKE ? LIMIT 5",(like,like)):
        results.append({'title':r['operator_name'],'type':'Licence — '+r['category'],'url':f'/api/licences/{r["licence_no"]}','meta':r['licence_no']+' · '+r['status'].capitalize()})
    for r in q("SELECT title,doc_type,category FROM documents WHERE title LIKE ? AND is_active=1 LIMIT 4",(like,)):
        results.append({'title':r['title'],'type':r['doc_type'],'url':'/api/documents','meta':r['category']})
    for r in q("SELECT title,tag,published_at FROM news WHERE title LIKE ? AND is_published=1 LIMIT 3",(like,)):
        results.append({'title':r['title'],'type':r['tag'],'url':'/api/news','meta':r['published_at'][:10]})
    return ok(results, total=len(results), query=query)

@app.route('/api/licences/search')
def licences_search():
    query    = request.args.get('q','').strip()
    category = request.args.get('category','').strip()
    status   = request.args.get('status','').strip()
    page     = max(1,int(request.args.get('page',1)))
    per_page = min(50,int(request.args.get('per_page',20)))
    offset   = (page-1)*per_page
    conds, params = [], []
    if query:
        conds.append("(operator_name LIKE ? OR licence_no LIKE ? OR licence_type LIKE ?)")
        like = f'%{query}%'; params += [like,like,like]
    if category: conds.append("category=?"); params.append(category)
    if status:   conds.append("status=?");   params.append(status)
    where = "WHERE "+" AND ".join(conds) if conds else ""
    total = q(f"SELECT COUNT(*) as n FROM licences {where}", params, one=True)['n']
    rows  = q(f"SELECT * FROM licences {where} ORDER BY operator_name LIMIT ? OFFSET ?", params+[per_page,offset])
    return ok(rows, total=total, page=page, per_page=per_page)

@app.route('/api/licences/<licence_id>')
def licence_get(licence_id):
    r = q("SELECT * FROM licences WHERE licence_no=?", (licence_id,), one=True)
    if not r: return err('Licence not found', 404)
    return ok(r)

@app.route('/api/complaints/<ref>')
def complaint_get(ref):
    ref = ref.strip().upper()
    c = q("SELECT * FROM complaints WHERE reference=?", (ref,), one=True)
    if not c: return err('Reference number not found', 404)
    hist = q("SELECT note,created_at as date FROM complaint_history WHERE complaint_id=? ORDER BY created_at", (c['id'],))
    return ok({'reference':c['reference'],'status':c['status'],'operator':c['operator'],'category':c['category'],
               'updated_at':c['updated_at'],'created_at':c['created_at'],
               'history':[{'note':h['note'],'date':h['date'][:10]} for h in hist]})

@app.route('/api/complaints', methods=['POST'])
def complaint_submit():
    b       = request.get_json(silent=True) or {}
    name    = (b.get('name') or b.get('full_name') or '').strip()
    op      = (b.get('operator') or '').strip()
    desc    = (b.get('description') or '').strip()
    if not name:           return err('Full name is required')
    if not op:             return err('Operator is required')
    if len(desc) < 10:     return err('Description must be at least 10 characters')
    year = datetime.datetime.now().year
    last = q("SELECT reference FROM complaints ORDER BY id DESC LIMIT 1", one=True)
    num  = int(last['reference'].split('-')[-1])+1 if last else 1000
    ref  = f"COM-{year}-{num:04d}"
    cid  = run("INSERT INTO complaints (reference,full_name,email,phone,operator,category,description) VALUES (?,?,?,?,?,?,?)",
               (ref,name,b.get('email',''),b.get('phone',''),op,b.get('category','General'),desc))
    run("INSERT INTO complaint_history (complaint_id,note) VALUES (?,?)",(cid,'Complaint received and logged by BOCRA system'))
    return ok({'ref':ref,'reference':ref,'status':'Received','message':f'Complaint received. Reference: {ref}. You will be contacted within 5 working days.'}, code=201)

@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files: return err('No file provided')
    f    = request.files['file']
    ext  = f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else ''
    if ext not in {'png','jpg','jpeg','pdf','mp4','mp3','doc','docx'}: return err('File type not allowed')
    fid  = str(uuid.uuid4())
    f.save(os.path.join(UPLOAD_DIR, f"{fid}.{ext}"))
    return ok({'file_id':fid,'original_name':f.filename}, code=201)

@app.route('/api/auth/login', methods=['POST'])
def login():
    b       = request.get_json(silent=True) or {}
    email   = b.get('email','').strip().lower()
    pw      = b.get('password','')
    if not email or not pw: return err('Email and password are required')
    u = q("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not u or not check_pw(pw, u['password_hash']): return err('Invalid email or password', 401)
    token   = str(uuid.uuid4()).replace('-','')
    expires = (datetime.datetime.utcnow()+datetime.timedelta(hours=24)).isoformat()
    run("UPDATE users SET token=?,token_expires=? WHERE id=?", (token,expires,u['id']))
    return ok({'token':token,'user':{'id':u['id'],'email':u['email'],'full_name':u['full_name'],'role':u['role']},'expires':expires})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    u = current_user()
    if u: run("UPDATE users SET token=NULL,token_expires=NULL WHERE id=?", (u['id'],))
    return ok({'message':'Logged out'})

@app.route('/api/auth/me')
def me():
    u = current_user()
    if not u: return err('Unauthorized', 401)
    return ok({'id':u['id'],'email':u['email'],'full_name':u['full_name'],'role':u['role']})

@app.route('/api/news')
def news_list():
    cat      = request.args.get('category','').strip()
    page     = max(1,int(request.args.get('page',1)))
    per_page = min(50,int(request.args.get('per_page',10)))
    offset   = (page-1)*per_page
    where = "WHERE is_published=1"+(f" AND category='{cat}'" if cat else "")
    total = q(f"SELECT COUNT(*) as n FROM news {where}", one=True)['n']
    rows  = q(f"SELECT id,title,excerpt,category,tag,published_at FROM news {where} ORDER BY published_at DESC LIMIT ? OFFSET ?",(per_page,offset))
    return ok(rows, total=total, page=page)

@app.route('/api/documents')
def docs_list():
    cat = request.args.get('category','').strip()
    qry = request.args.get('q','').strip()
    conds = ["is_active=1"]
    params = []
    if cat: conds.append("category=?"); params.append(cat)
    if qry: conds.append("title LIKE ?"); params.append(f'%{qry}%')
    rows = q("SELECT id,title,category,doc_type,file_size,published_at FROM documents WHERE "+" AND ".join(conds)+" ORDER BY published_at DESC", params)
    return ok(rows, total=len(rows))

@app.route('/api/consultations')
def consultations():
    status = request.args.get('status','').strip()
    where  = f"WHERE status='{status}'" if status else ""
    rows   = q(f"SELECT * FROM consultations {where} ORDER BY created_at DESC")
    return ok(rows)

@app.route('/api/stats/telecoms')
def stats():
    active = q("SELECT COUNT(*) as n FROM licences WHERE status='active'", one=True)['n']
    return ok({'mobile_coverage_pct':98,'active_subscribers':3200000,'broadband_growth_pct':47,
               'complaints_resolved':12000,'licensed_operators':active,'year':2025})

@app.route('/api/admin/complaints')
def admin_complaints():
    u = current_user()
    if not u or u['role'] not in ('admin','superadmin'): return err('Forbidden',403)
    rows = q("SELECT reference,full_name,operator,category,status,created_at FROM complaints ORDER BY created_at DESC")
    return ok(rows, total=len(rows))

@app.errorhandler(404)
def e404(e): return jsonify({'success':False,'error':'Endpoint not found'}),404
@app.errorhandler(500)
def e500(e): return jsonify({'success':False,'error':'Internal server error'}),500

# ── Start ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"BOCRA API running on port {port}")
    app.run(host='0.0.0.0', port=port)

# Auto-init on import (for gunicorn)
init_db()
