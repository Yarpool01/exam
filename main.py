from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import sqlite3
import json
import random
import uuid
import html
import re
import csv
import io
import os
import base64
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

DB_PATH = "exam.db"
QUESTIONS_FILE = "questions.json"

TIME_LIMITS = {"3": 20, "4": 40, "5": 60}
ALLOWED_GRADES = {"3": [3], "4": [3, 4], "5": [3, 4, 5]}

# ═══════════════════════════════════════════════════
# CHANGE THIS PASSWORD BEFORE DEPLOYING!
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "exam2026")
# ═══════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Exam System", lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ─── Admin Auth ───
def check_admin_auth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic realm=\"Admin Panel\""}
        )
    try:
        creds = base64.b64decode(auth[6:]).decode("utf-8")
        username, password = creds.split(":", 1)
        if password != ADMIN_PASSWORD:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic realm=\"Admin Panel\""}
            )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic realm=\"Admin Panel\""}
        )

# ─── Security ───
def sanitize_input(text: str) -> str:
    if not text:
        return ""
    text = html.escape(text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    return text

# ─── Database ───
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                assigned_level TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'pending',
                bonus_status TEXT DEFAULT 'none',
                violations INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS exams (
                id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL,
                questions_json TEXT NOT NULL,
                answers_json TEXT,
                score INTEGER,
                max_score INTEGER NOT NULL,
                grade INTEGER,
                started_at TEXT,
                finished_at TEXT,
                is_bonus INTEGER DEFAULT 0,
                FOREIGN KEY (student_id) REFERENCES students(id)
            );
            CREATE TABLE IF NOT EXISTS violation_logs (
                id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL,
                exam_id INTEGER,
                violation_type TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id)
            );
        """)
        conn.commit()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─── Security Headers ───
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ─── Questions ───
def load_questions():
    with open(QUESTIONS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def select_questions(level: str):
    data = load_questions()
    level_data = data["levels"][level]
    theory_pool = level_data.get("theory", [])
    practical_pool = level_data.get("practical", [])
    selected_theory = random.sample(theory_pool, min(2, len(theory_pool))) if len(theory_pool) >= 2 else theory_pool
    selected_practical = []
    if level in ("4", "5") and practical_pool:
        selected_practical = random.sample(practical_pool, 1)
    all_q = selected_theory + selected_practical
    random.shuffle(all_q)
    return all_q

def select_bonus_questions():
    data = load_questions()
    pool = data.get("bonus", [])
    return random.sample(pool, min(2, len(pool))) if len(pool) >= 2 else pool

def get_question_by_id(qid, questions_data):
    for cat in questions_data["levels"].values():
        for q in cat.get("theory", []) + cat.get("practical", []):
            if q["id"] == qid:
                return q
    for q in questions_data.get("bonus", []):
        if q["id"] == qid:
            return q
    return None

def is_expired(started_at: str, level: str) -> bool:
    start = datetime.fromisoformat(started_at)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    limit = TIME_LIMITS.get(level, 60)
    return datetime.now(timezone.utc) > start + timedelta(minutes=limit)

# ─── Violation logging ───
def log_violation(student_id: int, vtype: str, details: str = "", exam_id: int = None):
    conn = get_db()
    conn.execute(
        "INSERT INTO violation_logs (student_id, exam_id, violation_type, details) VALUES (?, ?, ?, ?)",
        (student_id, exam_id, vtype, details)
    )
    conn.execute("UPDATE students SET violations = violations + 1 WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()

# ─── Admin ───
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    check_admin_auth(request)
    conn = get_db()
    students = conn.execute("""
        SELECT s.*, e.id as exam_id, e.score, e.max_score, e.grade, e.started_at, e.finished_at,
               e2.id as bonus_exam_id, e2.score as bonus_score, e2.max_score as bonus_max, 
               e2.grade as bonus_grade, e2.finished_at as bonus_finished
        FROM students s
        LEFT JOIN exams e ON e.student_id = s.id AND e.is_bonus = 0
        LEFT JOIN exams e2 ON e2.student_id = s.id AND e2.is_bonus = 1
        ORDER BY s.assigned_level, s.name
    """).fetchall()

    violations = conn.execute("""
        SELECT student_id, COUNT(*) as count FROM violation_logs GROUP BY student_id
    """).fetchall()
    vmap = {v["student_id"]: v["count"] for v in violations}

    conn.close()
    return templates.TemplateResponse("admin.html", {
        "request": request, 
        "students": students,
        "allowed_grades": ALLOWED_GRADES, 
        "vmap": vmap
    })

@app.post("/admin/add_student")
async def add_student(request: Request, name: str = Form(...), level: str = Form(...)):
    check_admin_auth(request)
    conn = get_db()
    token = str(uuid.uuid4())[:8]
    name = sanitize_input(name)
    conn.execute(
        "INSERT INTO students (name, assigned_level, token) VALUES (?, ?, ?)",
        (name, level, token)
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/import_csv")
async def import_csv(request: Request, file: UploadFile = File(...)):
    check_admin_auth(request)
    contents = await file.read()
    text = contents.decode('utf-8-sig')
    reader = csv.reader(io.StringIO(text), delimiter=';')

    conn = get_db()
    added = 0
    errors = []

    for i, row in enumerate(reader):
        if i == 0 and ('name' in row[0].lower() or 'фио' in row[0].lower()):
            continue
        if len(row) < 2:
            errors.append(f"Строка {i+1}: недостаточно колонок")
            continue

        name = sanitize_input(row[0].strip())
        level = row[1].strip()

        if level not in ('3', '4', '5'):
            errors.append(f"Строка {i+1}: неверный уровень '{level}'")
            continue

        token = str(uuid.uuid4())[:8]
        try:
            conn.execute(
                "INSERT INTO students (name, assigned_level, token) VALUES (?, ?, ?)",
                (name, level, token)
            )
            added += 1
        except sqlite3.IntegrityError:
            errors.append(f"Строка {i+1}: дубликат")

    conn.commit()
    conn.close()

    msg = f"Добавлено: {added}"
    if errors:
        msg += f", Ошибок: {len(errors)}"
    return RedirectResponse(f"/admin?msg={msg}", status_code=303)

@app.post("/admin/assign_bonus")
async def assign_bonus(request: Request, student_id: int = Form(...)):
    check_admin_auth(request)
    conn = get_db()
    conn.execute("UPDATE students SET bonus_status = 'assigned' WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/grade")
async def grade_exam(request: Request, exam_id: int = Form(...), grade: int = Form(...)):
    check_admin_auth(request)
    conn = get_db()
    exam = conn.execute(
        "SELECT e.*, s.assigned_level FROM exams e JOIN students s ON e.student_id = s.id WHERE e.id = ?",
        (exam_id,)
    ).fetchone()

    if not exam:
        conn.close()
        raise HTTPException(400, "Экзамен не найден")

    level = exam["assigned_level"]
    if grade not in ALLOWED_GRADES.get(level, []):
        conn.close()
        raise HTTPException(400, f"Оценка {grade} недоступна для билета на {level}")

    conn.execute("UPDATE exams SET grade = ? WHERE id = ?", (grade, exam_id))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin", status_code=303)

@app.get("/admin/view/{exam_id}", response_class=HTMLResponse)
async def view_answers(request: Request, exam_id: int):
    check_admin_auth(request)
    conn = get_db()
    exam = conn.execute(
        "SELECT e.*, s.name, s.assigned_level, s.token, s.violations FROM exams e JOIN students s ON e.student_id = s.id WHERE e.id = ?",
        (exam_id,)
    ).fetchone()

    vlogs = conn.execute(
        "SELECT * FROM violation_logs WHERE student_id = ? AND exam_id = ? ORDER BY created_at",
        (exam["student_id"], exam_id)
    ).fetchall() if exam else []

    conn.close()

    if not exam:
        raise HTTPException(404, "Экзамен не найден")

    questions_data = load_questions()
    q_ids = json.loads(exam["questions_json"])
    questions = [get_question_by_id(qid, questions_data) for qid in q_ids if get_question_by_id(qid, questions_data)]
    answers = json.loads(exam["answers_json"]) if exam["answers_json"] else {}

    return templates.TemplateResponse("view_answers.html", {
        "request": request, "exam": dict(exam), "questions": questions,
        "answers": answers, "allowed_grades": ALLOWED_GRADES, "vlogs": vlogs
    })

# ─── Violation endpoint ───
@app.post("/{token}/violation")
async def report_violation(token: str, request: Request):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400)

    data = await request.json()
    vtype = sanitize_input(data.get("type", ""))[:50]
    details = sanitize_input(data.get("details", ""))[:500]

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student:
        conn.close()
        raise HTTPException(404)

    exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 0 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()
    exam_id = exam["id"] if exam else None

    log_violation(student["id"], vtype, details, exam_id)
    conn.close()
    return {"status": "logged"}

# ─── Student ───
@app.get("/{token}", response_class=HTMLResponse)
async def student_page(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    conn.close()
    if not student:
        raise HTTPException(404, "Студент не найден")

    if student["status"] == "done" and student["bonus_status"] == "assigned":
        return RedirectResponse(f"/{token}/bonus")
    if student["status"] in ("done", "bonus_done"):
        return RedirectResponse(f"/{token}/result")

    return templates.TemplateResponse("index.html", {
        "request": request, "student": dict(student), "token": token,
        "time_limit": TIME_LIMITS.get(student["assigned_level"], 60)
    })

@app.post("/{token}/start")
async def start_exam(token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student or student["status"] != "pending":
        conn.close()
        raise HTTPException(403, "Недоступно")

    level = student["assigned_level"]
    selected = select_questions(level)
    if not selected:
        conn.close()
        raise HTTPException(500, "Нет вопросов")

    max_score = len(selected) * 5
    q_ids = [q["id"] for q in selected]

    conn.execute(
        "INSERT INTO exams (student_id, questions_json, max_score, started_at) VALUES (?, ?, ?, ?)",
        (student["id"], json.dumps(q_ids), max_score, datetime.now(timezone.utc).isoformat())
    )
    conn.execute("UPDATE students SET status = 'done' WHERE id = ?", (student["id"],))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/{token}/exam", status_code=303)

@app.get("/{token}/exam", response_class=HTMLResponse)
async def exam_page(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student:
        conn.close()
        raise HTTPException(404)

    exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 0 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()
    conn.close()

    if not exam:
        return RedirectResponse(f"/{token}")

    if is_expired(exam["started_at"], student["assigned_level"]):
        return RedirectResponse(f"/{token}/result")

    questions_data = load_questions()
    q_ids = json.loads(exam["questions_json"])
    exam_questions = [get_question_by_id(qid, questions_data) for qid in q_ids if get_question_by_id(qid, questions_data)]

    expires = datetime.fromisoformat(exam["started_at"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    expires = expires + timedelta(minutes=TIME_LIMITS.get(student["assigned_level"], 60))

    return templates.TemplateResponse("exam.html", {
        "request": request, "student": dict(student), "questions": exam_questions,
        "token": token, "expires": expires.isoformat(),
        "time_limit": TIME_LIMITS.get(student["assigned_level"], 60),
        "exam_id": exam["id"]
    })

@app.post("/{token}/submit")
async def submit_exam(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    form = await request.form()
    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student:
        conn.close()
        raise HTTPException(404)

    exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 0 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()

    if not exam or is_expired(exam["started_at"], student["assigned_level"]):
        conn.close()
        return RedirectResponse(f"/{token}/result")

    answers = {}
    for k, v in form.items():
        if k.startswith("q_"):
            answers[k.replace("q_", "")] = sanitize_input(v)

    conn.execute(
        "UPDATE exams SET answers_json = ?, finished_at = ? WHERE id = ?",
        (json.dumps(answers), datetime.now(timezone.utc).isoformat(), exam["id"])
    )
    conn.commit()
    conn.close()

    if student["bonus_status"] == "assigned":
        return RedirectResponse(f"/{token}/bonus", status_code=303)
    return RedirectResponse(f"/{token}/result", status_code=303)

# ─── Bonus ───
@app.get("/{token}/bonus", response_class=HTMLResponse)
async def bonus_page(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student or student["bonus_status"] not in ("assigned", "done"):
        conn.close()
        return RedirectResponse(f"/{token}/result")

    exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 1 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()

    if not exam:
        selected = select_bonus_questions()
        if not selected:
            conn.close()
            return RedirectResponse(f"/{token}/result")
        max_score = len(selected) * 5
        q_ids = [q["id"] for q in selected]
        conn.execute(
            "INSERT INTO exams (student_id, questions_json, max_score, started_at, is_bonus) VALUES (?, ?, ?, ?, 1)",
            (student["id"], json.dumps(q_ids), max_score, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        exam = conn.execute(
            "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 1 ORDER BY id DESC LIMIT 1",
            (student["id"],)
        ).fetchone()

    conn.close()

    if is_expired(exam["started_at"], "3"):
        return RedirectResponse(f"/{token}/result")

    questions_data = load_questions()
    q_ids = json.loads(exam["questions_json"])
    bonus_questions = [get_question_by_id(qid, questions_data) for qid in q_ids if get_question_by_id(qid, questions_data)]

    expires = datetime.fromisoformat(exam["started_at"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    expires = expires + timedelta(minutes=TIME_LIMITS["3"])

    return templates.TemplateResponse("bonus.html", {
        "request": request, "student": dict(student), "questions": bonus_questions,
        "token": token, "expires": expires.isoformat(), "time_limit": TIME_LIMITS["3"],
        "exam_id": exam["id"]
    })

@app.post("/{token}/submit_bonus")
async def submit_bonus(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    form = await request.form()
    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student:
        conn.close()
        raise HTTPException(404)

    exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 1 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()

    if not exam or is_expired(exam["started_at"], "3"):
        conn.close()
        return RedirectResponse(f"/{token}/result")

    answers = {}
    for k, v in form.items():
        if k.startswith("q_"):
            answers[k.replace("q_", "")] = sanitize_input(v)

    conn.execute(
        "UPDATE exams SET answers_json = ?, finished_at = ? WHERE id = ?",
        (json.dumps(answers), datetime.now(timezone.utc).isoformat(), exam["id"])
    )
    conn.execute("UPDATE students SET bonus_status = 'done' WHERE id = ?", (student["id"],))
    conn.commit()
    conn.close()
    return RedirectResponse(f"/{token}/result", status_code=303)

# ─── Result ───
@app.get("/{token}/result", response_class=HTMLResponse)
async def result_page(request: Request, token: str):
    if not re.match(r'^[a-f0-9]{8}$', token):
        raise HTTPException(400, "Неверный формат ссылки")

    conn = get_db()
    student = conn.execute("SELECT * FROM students WHERE token = ?", (token,)).fetchone()
    if not student:
        conn.close()
        raise HTTPException(404)

    main_exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 0 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()

    bonus_exam = conn.execute(
        "SELECT * FROM exams WHERE student_id = ? AND is_bonus = 1 ORDER BY id DESC LIMIT 1",
        (student["id"],)
    ).fetchone()

    conn.close()

    questions_data = load_questions()

    main_q, bonus_q = [], []
    main_answers, bonus_answers = {}, {}

    if main_exam:
        q_ids = json.loads(main_exam["questions_json"])
        main_q = [get_question_by_id(qid, questions_data) for qid in q_ids if get_question_by_id(qid, questions_data)]
        main_answers = json.loads(main_exam["answers_json"]) if main_exam["answers_json"] else {}

    if bonus_exam:
        q_ids = json.loads(bonus_exam["questions_json"])
        bonus_q = [get_question_by_id(qid, questions_data) for qid in q_ids if get_question_by_id(qid, questions_data)]
        bonus_answers = json.loads(bonus_exam["answers_json"]) if bonus_exam["answers_json"] else {}

    return templates.TemplateResponse("result.html", {
        "request": request, "student": dict(student),
        "main_exam": dict(main_exam) if main_exam else None,
        "bonus_exam": dict(bonus_exam) if bonus_exam else None,
        "main_questions": main_q, "bonus_questions": bonus_q,
        "main_answers": main_answers, "bonus_answers": bonus_answers,
        "token": token
    })

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)