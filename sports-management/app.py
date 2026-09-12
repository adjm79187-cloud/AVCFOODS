
import os, sqlite3, secrets, io, csv, shutil
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE,"instance","sports.db")
UPLOAD=os.path.join(BASE,"static","uploads")
os.makedirs(UPLOAD,exist_ok=True); os.makedirs(os.path.dirname(DB),exist_ok=True)

app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY","CHANGE_THIS_SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"]=8*1024*1024
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
ALLOWED={"jpg","jpeg","png","webp","gif"}

GAMES=["Athletics","Football","Cricket","Basketball","Volleyball","Badminton","Table Tennis","Tennis","Kho-Kho","Kabaddi","Chess","Carrom","Handball","Hockey","Throwball","Long Jump","High Jump","Shot Put","Discus Throw","Javelin Throw","100m","200m","400m","800m","1500m","Relay","Yoga","Skipping"]
DEFAULT_HOUSES=["Aryabhatta House","Ashoka House","Gautam House","Chanakya House"]
CATS=["Group A","Group B","Group C","Group D"]

def con():
    x=sqlite3.connect(DB); x.row_factory=sqlite3.Row; return x
def init_db():
    c=con()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,user_id TEXT UNIQUE,password_hash TEXT,role TEXT,active INTEGER DEFAULT 1,created_at TEXT);
    CREATE TABLE IF NOT EXISTS teachers(id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE,name TEXT,designation TEXT,house TEXT,photo TEXT);
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE,admission_no TEXT UNIQUE,name TEXT,class_name TEXT,section TEXT,roll_no TEXT,house TEXT,blood_group TEXT,dob TEXT,photo TEXT,height REAL,weight REAL,bmi REAL,body_age TEXT,guardian TEXT,phone TEXT,address TEXT,remarks TEXT,active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,name TEXT,category TEXT,game TEXT,event_date TEXT,house1 TEXT,house2 TEXT,venue TEXT,description TEXT);
    CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY,event_id INTEGER,house TEXT,position TEXT,points REAL,remarks TEXT);
    CREATE TABLE IF NOT EXISTS participation(id INTEGER PRIMARY KEY,event_id INTEGER,student_id INTEGER,performance TEXT,position TEXT,remarks TEXT);
    CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY,student_id INTEGER,assess_date TEXT,fitness TEXT,running TEXT,strength TEXT,flexibility TEXT,endurance TEXT,discipline TEXT,participation TEXT,remarks TEXT);
    CREATE TABLE IF NOT EXISTS annual(id INTEGER PRIMARY KEY,name TEXT,category TEXT,event_date TEXT,house TEXT,position TEXT,points REAL,remarks TEXT);
    CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY,student_id INTEGER,event_name TEXT,game TEXT,position TEXT,certificate_date TEXT,remarks TEXT);
    CREATE TABLE IF NOT EXISTS reset_requests(id INTEGER PRIMARY KEY,user_id TEXT,requested_at TEXT,status TEXT DEFAULT 'pending');
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id TEXT,action TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
    """)
    defaults={"school_name":"S.D. Public School","school_address":"Kumhrar, Patna-07","department":"SPORTS DEPARTMENT","principal_name":"","sports_teacher_name":"","school_logo":""}
    for i,h in enumerate(DEFAULT_HOUSES,1): defaults[f"house_{i}"]=h; defaults[f"house_logo_{i}"]=""
    for k,v in defaults.items(): c.execute("INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)",(k,v))
    if not c.execute("SELECT 1 FROM users WHERE user_id='owner'").fetchone():
        c.execute("INSERT INTO users(user_id,password_hash,role,created_at) VALUES(?,?,?,?)",("owner",generate_password_hash("ChangeMe123!"),"owner",datetime.now().isoformat()))
    c.commit(); c.close()
init_db()

def settings():
    c=con(); d={r["k"]:r["v"] for r in c.execute("SELECT k,v FROM settings")}; c.close(); return d
def houses():
    s=settings(); return [s.get("house_"+str(i),DEFAULT_HOUSES[i-1]) for i in range(1,5)]
def log(a):
    c=con(); c.execute("INSERT INTO audit(user_id,action,created_at) VALUES(?,?,?)",(session.get("user_id","system"),a,datetime.now().isoformat())); c.commit(); c.close()
def auth(*roles):
    def dec(f):
        @wraps(f)
        def w(*a,**kw):
            if "uid" not in session: return redirect(url_for("login"))
            if roles and session.get("role") not in roles: abort(403)
            return f(*a,**kw)
        return w
    return dec
def csrf_ok():
    return request.form.get("_csrf")==session.get("_csrf")
def upload(field):
    f=request.files.get(field)
    if not f or not f.filename: return ""
    ext=f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED: raise ValueError("केवल JPG/PNG/WEBP image allowed है")
    fn=secrets.token_hex(16)+"."+ext; f.save(os.path.join(UPLOAD,fn)); return fn
def calc_bmi(h,w):
    try:
        h=float(h)/100; w=float(w)
        return round(w/(h*h),2) if h>0 and w>0 else None
    except: return None

@app.context_processor
def common():
    if "_csrf" not in session: session["_csrf"]=secrets.token_hex(24)
    return {"S":settings(),"HOUSES":houses(),"GAMES":GAMES,"CATS":CATS}

@app.route("/")
def home(): return render_template("home.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        c=con(); u=c.execute("SELECT * FROM users WHERE user_id=? AND active=1",(request.form["user_id"].strip(),)).fetchone(); c.close()
        if u and check_password_hash(u["password_hash"],request.form["password"]):
            session.clear(); session["uid"]=u["id"]; session["user_id"]=u["user_id"]; session["role"]=u["role"]; session["_csrf"]=secrets.token_hex(24); log("Login"); return redirect(url_for("dashboard"))
        flash("User ID या password गलत है","error")
    return render_template("login.html")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@auth()
def dashboard():
    if session["role"]=="student": return redirect(url_for("my_report"))
    c=con(); counts=[("Students",c.execute("SELECT count(*) FROM students WHERE active=1").fetchone()[0]),("Teachers",c.execute("SELECT count(*) FROM teachers").fetchone()[0]),("Events",c.execute("SELECT count(*) FROM events").fetchone()[0]),("Results",c.execute("SELECT count(*) FROM results").fetchone()[0])]; c.close()
    return render_template("dashboard.html",counts=counts)

@app.route("/students")
@auth("owner","sports_teacher","house_teacher")
def students():
    c=con(); q="SELECT * FROM students WHERE active=1"; args=[]
    if session["role"]=="house_teacher":
        t=c.execute("SELECT house FROM teachers WHERE user_id=?",(session["uid"],)).fetchone(); q+=" AND house=?"; args.append(t["house"] if t else "")
    search=request.args.get("q","").strip()
    if search: q+=" AND (name LIKE ? OR admission_no LIKE ? OR class_name LIKE ?)"; args += ["%"+search+"%"]*3
    rows=c.execute(q+" ORDER BY house,name",args).fetchall(); c.close(); return render_template("students.html",rows=rows,search=search)

def house_allowed(c,house):
    if session["role"]!="house_teacher": return True
    t=c.execute("SELECT house FROM teachers WHERE user_id=?",(session["uid"],)).fetchone()
    return bool(t and t["house"]==house)

@app.route("/students/add",methods=["GET","POST"])
@auth("owner","sports_teacher","house_teacher")
def student_add():
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c=con(); h=request.form["house"]
        if not house_allowed(c,h): abort(403)
        try:
            ph=upload("photo")
            # The admission number is used as the student's initial login ID and password.
            admission_no=request.form["admission_no"].strip()
            c.execute("INSERT INTO users(user_id,password_hash,role,created_at) VALUES(?,?,?,?)", (admission_no,generate_password_hash(admission_no),"student",datetime.now().isoformat()))
            student_user_id=c.lastrowid
            c.execute("""INSERT INTO students(user_id,admission_no,name,class_name,section,roll_no,house,blood_group,dob,photo,height,weight,bmi,body_age,guardian,phone,address,remarks)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(student_user_id,admission_no,request.form["name"],request.form["class_name"],request.form["section"],request.form["roll_no"],h,request.form["blood_group"],request.form["dob"],ph,float(request.form.get("height") or 0),float(request.form.get("weight") or 0),calc_bmi(request.form.get("height"),request.form.get("weight")),request.form["body_age"],request.form["guardian"],request.form["phone"],request.form["address"],request.form["remarks"]))
            c.commit(); log("Added student"); flash("Student added","ok"); return redirect(url_for("students"))
        except Exception as e: c.rollback(); flash("Save failed: "+str(e),"error")
        finally: c.close()
    return render_template("student_form.html",row=None)

@app.route("/students/<int:sid>/edit",methods=["GET","POST"])
@auth("owner","sports_teacher","house_teacher")
def student_edit(sid):
    c=con(); s=c.execute("SELECT * FROM students WHERE id=?",(sid,)).fetchone()
    if not s: abort(404)
    if not house_allowed(c,s["house"]): abort(403)
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        if not house_allowed(c,request.form["house"]): abort(403)
        ph=s["photo"] or ""
        try: ph=upload("photo") or ph
        except Exception as e: flash(str(e),"error"); c.close(); return render_template("student_form.html",row=s)
        c.execute("""UPDATE students SET admission_no=?,name=?,class_name=?,section=?,roll_no=?,house=?,blood_group=?,dob=?,photo=?,height=?,weight=?,bmi=?,body_age=?,guardian=?,phone=?,address=?,remarks=? WHERE id=?""",
        (request.form["admission_no"],request.form["name"],request.form["class_name"],request.form["section"],request.form["roll_no"],request.form["house"],request.form["blood_group"],request.form["dob"],ph,float(request.form.get("height") or 0),float(request.form.get("weight") or 0),calc_bmi(request.form.get("height"),request.form.get("weight")),request.form["body_age"],request.form["guardian"],request.form["phone"],request.form["address"],request.form["remarks"],sid))
        c.commit(); c.close(); log("Edited student"); flash("Student updated","ok"); return redirect(url_for("students"))
    c.close(); return render_template("student_form.html",row=s)

@app.route("/students/<int:sid>/delete",methods=["POST"])
@auth("owner","sports_teacher","house_teacher")
def student_delete(sid):
    if not csrf_ok(): abort(400)
    c=con(); s=c.execute("SELECT * FROM students WHERE id=?",(sid,)).fetchone()
    if not s or not house_allowed(c,s["house"]): abort(403)
    c.execute("UPDATE students SET active=0 WHERE id=?",(sid,)); c.commit(); c.close(); log("Removed student"); flash("Student removed","ok"); return redirect(url_for("students"))

@app.route("/teachers",methods=["GET","POST"])
@auth("owner")
def teachers():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        try:
            uid=request.form["user_id"].strip()
            c.execute("INSERT INTO users(user_id,password_hash,role,created_at) VALUES(?,?,?,?)",(uid,generate_password_hash(request.form["password"]),request.form["role"],datetime.now().isoformat()))
            u=c.execute("SELECT id FROM users WHERE user_id=?",(uid,)).fetchone()
            c.execute("INSERT INTO teachers(user_id,name,designation,house,photo) VALUES(?,?,?,?,?)",(u["id"],request.form["name"],request.form["designation"],request.form["house"],upload("photo")))
            c.commit(); log("Created teacher"); flash("Teacher created","ok")
        except Exception as e: c.rollback(); flash("Create failed: "+str(e),"error")
    rows=c.execute("SELECT t.*,u.user_id,u.role,u.active FROM teachers t JOIN users u ON u.id=t.user_id ORDER BY t.name").fetchall(); c.close(); return render_template("teachers.html",rows=rows)

@app.route("/teachers/<int:tid>/disable",methods=["POST"])
@auth("owner")
def teacher_disable(tid):
    if not csrf_ok(): abort(400)
    c=con(); t=c.execute("SELECT user_id FROM teachers WHERE id=?",(tid,)).fetchone()
    if t: c.execute("UPDATE users SET active=0 WHERE id=?",(t["user_id"],)); c.commit()
    c.close(); log("Disabled teacher"); return redirect(url_for("teachers"))

@app.route("/owner-reset",methods=["GET","POST"])
@auth("owner")
def owner_reset():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c.execute("UPDATE users SET password_hash=? WHERE user_id=?",(generate_password_hash(request.form["password"]),request.form["user_id"])); c.commit(); log("Owner reset password"); flash("Password reset किया गया","ok")
    users=c.execute("SELECT user_id,role,active FROM users ORDER BY user_id").fetchall(); req=c.execute("SELECT * FROM reset_requests ORDER BY id DESC LIMIT 50").fetchall(); c.close()
    return render_template("owner_reset.html",users=users,requests=req)

@app.route("/change-password",methods=["GET","POST"])
@auth()
def change_password():
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c=con(); u=c.execute("SELECT password_hash FROM users WHERE id=?",(session["uid"],)).fetchone()
        if not check_password_hash(u["password_hash"],request.form["old"]): flash("Old password गलत है","error")
        elif request.form["new"]!=request.form["confirm"]: flash("Passwords match नहीं","error")
        elif len(request.form["new"])<8: flash("कम से कम 8 characters","error")
        else: c.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(request.form["new"]),session["uid"])); c.commit(); c.close(); log("Changed password"); flash("Password changed","ok"); return redirect(url_for("dashboard"))
        c.close()
    return render_template("form.html",title="Change Password",fields=[("old","Old Password","password"),("new","New Password","password"),("confirm","Confirm Password","password")])

@app.route("/forgot",methods=["GET","POST"])
def forgot():
    if request.method=="POST":
        c=con(); c.execute("INSERT INTO reset_requests(user_id,requested_at) VALUES(?,?)",(request.form["user_id"].strip(),datetime.now().isoformat())); c.commit(); c.close()
        flash("Request Owner को भेज दी गई. SMS/OTP नहीं है; Owner नया password सेट कर सकता है.","ok"); return redirect(url_for("login"))
    return render_template("form.html",title="Forgot Password",fields=[("user_id","User ID","text")])

@app.route("/events",methods=["GET","POST"])
@auth("owner","sports_teacher")
def events():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c.execute("INSERT INTO events(name,category,game,event_date,house1,house2,venue,description) VALUES(?,?,?,?,?,?,?,?)",(request.form["name"],request.form["category"],request.form["game"],request.form["event_date"],request.form["house1"],request.form["house2"],request.form["venue"],request.form["description"])); c.commit(); log("Created event"); flash("Event created","ok")
    rows=c.execute("SELECT * FROM events ORDER BY event_date DESC,id DESC").fetchall(); c.close(); return render_template("events.html",rows=rows)

@app.route("/events/<int:eid>/delete",methods=["POST"])
@auth("owner","sports_teacher")
def event_delete(eid):
    if not csrf_ok(): abort(400)
    c=con()
    for t in ["results","participation"]: c.execute(f"DELETE FROM {t} WHERE event_id=?",(eid,))
    c.execute("DELETE FROM events WHERE id=?",(eid,)); c.commit(); c.close(); log("Deleted event"); return redirect(url_for("events"))

@app.route("/results",methods=["GET","POST"])
@auth("owner","sports_teacher")
def results():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c.execute("INSERT INTO results(event_id,house,position,points,remarks) VALUES(?,?,?,?,?)",(request.form["event_id"],request.form["house"],request.form["position"],float(request.form["points"]),request.form["remarks"])); c.commit(); log("Added house result"); flash("House result saved","ok")
    ev=c.execute("SELECT * FROM events ORDER BY event_date DESC").fetchall(); rows=c.execute("SELECT r.*,e.name,e.game,e.event_date FROM results r JOIN events e ON e.id=r.event_id ORDER BY e.event_date DESC").fetchall(); c.close(); return render_template("results.html",events=ev,rows=rows)

@app.route("/participation",methods=["GET","POST"])
@auth("owner","sports_teacher","house_teacher")
def participation():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        s=c.execute("SELECT house FROM students WHERE id=?",(request.form["student_id"],)).fetchone()
        if not s or not house_allowed(c,s["house"]): abort(403)
        c.execute("INSERT INTO participation(event_id,student_id,performance,position,remarks) VALUES(?,?,?,?,?)",(request.form["event_id"],request.form["student_id"],request.form["performance"],request.form["position"],request.form["remarks"])); c.commit(); log("Added participation"); flash("Participation saved","ok")
    ev=c.execute("SELECT * FROM events ORDER BY event_date DESC").fetchall()
    if session["role"]=="house_teacher":
        t=c.execute("SELECT house FROM teachers WHERE user_id=?",(session["uid"],)).fetchone(); st=c.execute("SELECT * FROM students WHERE active=1 AND house=? ORDER BY name",(t["house"],)).fetchall()
    else: st=c.execute("SELECT * FROM students WHERE active=1 ORDER BY name").fetchall()
    rows=c.execute("SELECT p.*,e.name,e.game,e.event_date,s.name student_name FROM participation p JOIN events e ON e.id=p.event_id JOIN students s ON s.id=p.student_id ORDER BY e.event_date DESC").fetchall(); c.close()
    return render_template("participation.html",events=ev,students=st,rows=rows)

@app.route("/assessments",methods=["GET","POST"])
@auth("owner","sports_teacher","house_teacher")
def assessments():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        s=c.execute("SELECT house FROM students WHERE id=?",(request.form["student_id"],)).fetchone()
        if not s or not house_allowed(c,s["house"]): abort(403)
        keys=["assess_date","fitness","running","strength","flexibility","endurance","discipline","participation","remarks"]
        vals=[request.form.get(k,"") for k in keys]
        c.execute("INSERT INTO assessments(student_id,assess_date,fitness,running,strength,flexibility,endurance,discipline,participation,remarks) VALUES(?,?,?,?,?,?,?,?,?,?)",(request.form["student_id"],*vals)); c.commit(); log("Added assessment"); flash("Assessment saved","ok")
    if session["role"]=="house_teacher":
        t=c.execute("SELECT house FROM teachers WHERE user_id=?",(session["uid"],)).fetchone(); st=c.execute("SELECT * FROM students WHERE active=1 AND house=? ORDER BY name",(t["house"],)).fetchall()
    else: st=c.execute("SELECT * FROM students WHERE active=1 ORDER BY name").fetchall()
    rows=c.execute("SELECT a.*,s.name student_name FROM assessments a JOIN students s ON s.id=a.student_id ORDER BY a.assess_date DESC").fetchall(); c.close(); return render_template("assessments.html",students=st,rows=rows)

@app.route("/annual",methods=["GET","POST"])
@auth("owner","sports_teacher")
def annual():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c.execute("INSERT INTO annual(name,category,event_date,house,position,points,remarks) VALUES(?,?,?,?,?,?,?)",(request.form["name"],request.form["category"],request.form["event_date"],request.form["house"],request.form["position"],float(request.form["points"]),request.form["remarks"])); c.commit(); log("Added annual record"); flash("Annual record saved","ok")
    rows=c.execute("SELECT * FROM annual ORDER BY event_date DESC").fetchall(); c.close(); return render_template("annual.html",rows=rows)

@app.route("/scoreboard")
@auth()
def scoreboard():
    c=con(); rows=[]
    for h in houses():
        a=c.execute("SELECT COALESCE(SUM(points),0) FROM results WHERE house=?",(h,)).fetchone()[0]
        b=c.execute("SELECT COALESCE(SUM(points),0) FROM annual WHERE house=?",(h,)).fetchone()[0]
        rows.append((h,float(a+b)))
    rows.sort(key=lambda x:x[1],reverse=True); c.close(); return render_template("scoreboard.html",rows=rows)

def report_for(sid):
    c=con(); s=c.execute("SELECT * FROM students WHERE id=?",(sid,)).fetchone()
    if not s: abort(404)
    if session["role"]=="house_teacher" and not house_allowed(c,s["house"]): abort(403)
    a=c.execute("SELECT * FROM assessments WHERE student_id=? ORDER BY assess_date DESC LIMIT 1",(sid,)).fetchone()
    p=c.execute("SELECT p.*,e.name,e.game,e.event_date FROM participation p JOIN events e ON e.id=p.event_id WHERE p.student_id=? ORDER BY e.event_date DESC",(sid,)).fetchall()
    cert=c.execute("SELECT * FROM certificates WHERE student_id=? ORDER BY certificate_date DESC",(sid,)).fetchall()
    c.close(); return render_template("report.html",student=s,assessment=a,participation=p,certificates=cert)

@app.route("/my-report")
@auth("student")
def my_report():
    c=con(); s=c.execute("SELECT id FROM students WHERE user_id=?",(session["uid"],)).fetchone(); c.close()
    if not s: abort(404)
    return report_for(s["id"])

@app.route("/student-report/<int:sid>")
@auth("owner","sports_teacher","house_teacher")
def student_report(sid): return report_for(sid)

@app.route("/certificates",methods=["GET","POST"])
@auth("owner","sports_teacher")
def certificates():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        c.execute("INSERT INTO certificates(student_id,event_name,game,position,certificate_date,remarks) VALUES(?,?,?,?,?,?)",(request.form["student_id"],request.form["event_name"],request.form["game"],request.form["position"],request.form["certificate_date"],request.form["remarks"])); c.commit(); log("Created certificate record"); flash("Certificate record saved","ok")
    st=c.execute("SELECT * FROM students WHERE active=1 ORDER BY name").fetchall(); rows=c.execute("SELECT x.*,s.name student_name FROM certificates x JOIN students s ON s.id=x.student_id ORDER BY x.certificate_date DESC").fetchall(); c.close(); return render_template("certificates.html",students=st,rows=rows)

@app.route("/certificate/<int:cid>")
@auth("owner","sports_teacher","house_teacher","student")
def certificate(cid):
    c=con(); x=c.execute("SELECT x.*,s.name, s.class_name,s.section,s.house FROM certificates x JOIN students s ON s.id=x.student_id WHERE x.id=?",(cid,)).fetchone(); c.close()
    if not x: abort(404)
    if session["role"]=="student":
        c=con(); ok=c.execute("SELECT 1 FROM students WHERE id=? AND user_id=?",(x["student_id"],session["uid"])).fetchone(); c.close()
        if not ok: abort(403)
    return render_template("certificate.html",x=x)

@app.route("/settings",methods=["GET","POST"])
@auth("owner")
def app_settings():
    c=con()
    if request.method=="POST":
        if not csrf_ok(): abort(400)
        for k in ["school_name","school_address","principal_name","sports_teacher_name","house_1","house_2","house_3","house_4"]:
            c.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)",(k,request.form.get(k,"")))
        try: logo=upload("school_logo")
        except: logo=""
        if logo: c.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('school_logo',?)",(logo,))
        for i in range(1,5):
            try: fn=upload(f"house_logo_{i}")
            except: fn=""
            if fn: c.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)",(f"house_logo_{i}",fn))
        c.commit(); c.close(); log("Updated settings"); flash("Settings saved","ok"); return redirect(url_for("app_settings"))
    s={r["k"]:r["v"] for r in c.execute("SELECT k,v FROM settings")}; c.close(); return render_template("settings.html",s=s)

@app.route("/audit")
@auth("owner")
def audit():
    c=con(); rows=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall(); c.close(); return render_template("audit.html",rows=rows)

@app.route("/export/students.csv")
@auth("owner","sports_teacher")
def export_students():
    c=con(); rows=c.execute("SELECT admission_no,name,class_name,section,roll_no,house,blood_group,height,weight,bmi,body_age,guardian,phone,address FROM students WHERE active=1 ORDER BY house,name").fetchall(); c.close()
    out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ["admission_no","name"]); [w.writerow(tuple(r)) for r in rows]
    return send_file(io.BytesIO(out.getvalue().encode("utf-8-sig")),as_attachment=True,download_name="students.csv",mimetype="text/csv")

@app.route("/backup")
@auth("owner")
def backup():
    if not os.path.exists(DB): abort(404)
    return send_file(DB,as_attachment=True,download_name="sports_backup.db",mimetype="application/octet-stream")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
