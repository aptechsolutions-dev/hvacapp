from flask import Flask, render_template, request, redirect, url_for, abort, session
from datetime import date, datetime
import sqlite3
from pathlib import Path
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import os
import secrets


app = Flask(__name__)
app.secret_key = "change-this-to-a-long-random-string"

DB_PATH = Path(os.environ.get("DB_PATH", "/var/data/hvacapp.db"))



# -----------------------------
# Database helpers
# -----------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def ensure_column(conn: sqlite3.Connection, table: str, col: str, coltype_sql: str):
    cols = table_columns(conn, table)
    if col not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype_sql}")


def init_db():
    with get_db() as conn:
        # Phase 1 multi-tenant tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER ,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            )
        """)

        # Existing tables (create if missing)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id INTEGER,
                customer_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Scheduled',
                created_at TEXT NOT NULL,
                FOREIGN KEY (lead_id) REFERENCES leads(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Unpaid',
                created_at TEXT NOT NULL,
                paid_at TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                job_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                due_date TEXT,
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id),
                FOREIGN KEY(job_id) REFERENCES jobs(id)
            )
        """)

        conn.commit()
        
        # Upgrade columns (safe migrations)
        ensure_column(conn, "leads", "service_type", "TEXT")
        ensure_column(conn, "leads", "source", "TEXT")
        ensure_column(conn, "leads", "address", "TEXT")
        ensure_column(conn, "leads", "notes", "TEXT")

        ensure_column(conn, "jobs", "scheduled_date", "TEXT")
        ensure_column(conn, "jobs", "technician", "TEXT")
        ensure_column(conn, "jobs", "notes", "TEXT")

        ensure_column(conn, "invoices", "due_date", "TEXT")
        ensure_column(conn, "invoices", "public_token", "TEXT")
        ensure_column(conn, "invoices", "customer_email", "TEXT")



        # Multi-tenant scoping columns
        ensure_column(conn, "leads", "company_id", "INTEGER")
        ensure_column(conn, "jobs", "company_id", "INTEGER")
        ensure_column(conn, "invoices", "company_id", "INTEGER")

        # If you had data before Phase 1, it might have NULL company_id.
        # We'll assign everything to the first company if it exists (or later during setup).
        conn.commit()
        


def ensure_super_admin():
    with get_db() as conn:
        # Ensure owner company exists
        row = conn.execute(
            "SELECT id FROM companies WHERE name=?",
            ("APtech Solutions",)
        ).fetchone()

        if row:
            owner_company_id = row["id"]
        else:
            conn.execute(
                "INSERT INTO companies (name, created_at) VALUES (?, ?)",
                ("APtech Solutions", datetime.now().isoformat())
            )
            conn.commit()
            owner_company_id = conn.execute(
                "SELECT last_insert_rowid() AS id"
            ).fetchone()["id"]

        # Ensure super admin exists
        exists = conn.execute(
            "SELECT 1 FROM users WHERE role='super_admin' LIMIT 1"
        ).fetchone()

        if exists:
            return  # already created

        password = os.environ.get("SUPER_ADMIN_PASSWORD")
        if not password:
            raise RuntimeError("SUPER_ADMIN_PASSWORD is not set")

        conn.execute(
            """
            INSERT INTO users (company_id, username, password_hash, role, created_at)
            VALUES (?, ?, ?, 'super_admin', ?)
            """,
            (
                owner_company_id,
                "aptech_owner",
                generate_password_hash(password),
                datetime.now().isoformat()
            )
        )
        conn.commit()




        
#  runs once when app imports (Render + gunicorn)

init_db()
ensure_super_admin()


def parse_date_yyyy_mm_dd(s: str) -> str | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s
    except ValueError:
        return None


# -----------------------------
# Auth helpers
# -----------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or not session.get("company_id"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def current_company_id() -> int:
    cid = session.get("company_id")
    if not cid:
        abort(401)
    return int(cid)


def any_users_exist() -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return row["c"] > 0

def super_admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        with get_db() as conn:
            user = conn.execute(
                "SELECT role FROM users WHERE id=?",
                (session["user_id"],)
            ).fetchone()

        if not user or user["role"] != "super_admin":
            abort(403)

        return view_func(*args, **kwargs)
    return wrapper


# -----------------------------
# One-time setup (creates first company + admin)
# -----------------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    # If already set up, block this route
    if any_users_exist():
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not company_name or not username or not password:
            error = "All fields are required."
        else:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO companies (name, created_at) VALUES (?, ?)",
                    (company_name, datetime.now().isoformat())
                )
                company_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

                conn.execute(
                    """
                    INSERT INTO users (company_id, username, password_hash, role, created_at)
                    VALUES (?, ?, ?, 'admin', ?)
                    """,
                    (company_id, username, generate_password_hash(password), datetime.now().isoformat())
                )

                # Backfill any existing rows (if you had old data)
                conn.execute("UPDATE leads SET company_id=? WHERE company_id IS NULL", (company_id,))
                conn.execute("UPDATE jobs SET company_id=? WHERE company_id IS NULL", (company_id,))
                conn.execute("UPDATE invoices SET company_id=? WHERE company_id IS NULL", (company_id,))

                conn.commit()

            return redirect(url_for("login"))

    return render_template("setup.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    Public signup:
    - creates a new company
    - creates the company's first admin user
    - logs them in
    """
    error = None

    if request.method == "POST":
        company_name = (request.form.get("company_name") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not company_name or not username or not password:
            error = "All fields are required."
            return render_template("signup.html", error=error)

        # Basic safety: prevent someone signing up with your owner username
        if username.lower() == "aptech_owner":
            error = "That username is reserved. Please choose another."
            return render_template("signup.html", error=error)

        with get_db() as conn:
            # Make sure username is unique
            existing = conn.execute(
                "SELECT 1 FROM users WHERE username=?",
                (username,)
            ).fetchone()

            if existing:
                error = "That username is already taken. Try another."
                return render_template("signup.html", error=error)

            # Create company
            conn.execute(
                "INSERT INTO companies (name, created_at) VALUES (?, ?)",
                (company_name, datetime.now().isoformat())
            )
            conn.commit()
            company_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

            # Create admin user for that company
            conn.execute(
                """
                INSERT INTO users (company_id, username, password_hash, role, created_at)
                VALUES (?, ?, ?, 'admin', ?)
                """,
                (company_id, username, generate_password_hash(password), datetime.now().isoformat())
            )
            conn.commit()

            # Log them in
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()

        session.clear()
        session["user_id"] = user["id"]
        session["company_id"] = user["company_id"]

        return redirect(url_for("dashboard"))

    return render_template("signup.html", error=error)



# -----------------------------
# Login / Logout
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    # If not set up yet, go to setup
    if not any_users_exist():
        return redirect(url_for("setup"))

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["company_id"] = user["company_id"]
            return redirect(url_for("dashboard"))

        error = "Wrong username or password."

    return render_template(
        "login.html",
        error=error,
        today=date.today().isoformat()
    )

 


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------------
# Owner / Super Admin
# -----------------------------
@app.route("/owner/companies")
@super_admin_required
def owner_companies():
    with get_db() as conn:
        companies = conn.execute("""
            SELECT
                c.id,
                c.name,
                c.created_at,
                COUNT(u.id) AS user_count
            FROM companies c
            LEFT JOIN users u ON u.company_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """).fetchall()

    return render_template(
        "owner_companies.html",
        companies=companies
    )


# -----------------------------
# Dashboard (company-scoped)
# -----------------------------
@app.route("/")
@login_required
def dashboard():
    today = date.today().isoformat()
    cid = current_company_id()

    with get_db() as conn:
        company = conn.execute("SELECT * FROM companies WHERE id=?", (cid,)).fetchone()
        company_name = company["name"] if company else "Company"

        leads = conn.execute(
            "SELECT * FROM leads WHERE company_id=? ORDER BY id DESC", (cid,)
        ).fetchall()

        jobs = conn.execute(
            "SELECT * FROM jobs WHERE company_id=? ORDER BY id DESC", (cid,)
        ).fetchall()

        tasks = conn.execute(
            "SELECT * FROM tasks WHERE company_id=? ORDER BY id DESC", (cid,)
        ).fetchall()

        invoices = conn.execute(
            "SELECT * FROM invoices WHERE company_id=? ORDER BY id DESC", (cid,)
        ).fetchall()

        missed_leads = conn.execute(
            "SELECT * FROM leads WHERE company_id=? AND status='New' ORDER BY id DESC",
            (cid,)
        ).fetchall()

        overdue_invoices = conn.execute(
            """
            SELECT * FROM invoices
            WHERE company_id=?
              AND status='Unpaid'
              AND due_date IS NOT NULL
              AND due_date < ?
            ORDER BY due_date ASC
            """,
            (cid, today),
        ).fetchall()

        unpaid_total = conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM invoices
            WHERE company_id=? AND status='Unpaid'
            """,
            (cid,),
        ).fetchone()["total"]

        jobs_today = conn.execute(
            "SELECT COUNT(*) AS c FROM jobs WHERE company_id=? AND scheduled_date=?",
            (cid, today),
        ).fetchone()["c"]

        leads_today = conn.execute(
            "SELECT COUNT(*) AS c FROM leads WHERE company_id=? AND substr(created_at,1,10)=?",
            (cid, today),
        ).fetchone()["c"]

    return render_template(
        "dashboard.html",
        company_name=company_name,
        leads=leads,
        jobs=jobs,
        tasks=tasks,
        invoices=invoices,
        missed_leads=missed_leads,
        overdue_invoices=overdue_invoices,
        unpaid_total=unpaid_total,
        jobs_today=jobs_today,
        leads_today=leads_today,
        today=today,
    )


# -----------------------------
# Actions (company-scoped)
# -----------------------------
@app.route("/add_lead", methods=["POST"])
@login_required
def add_lead():
    cid = current_company_id()

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    service_type = request.form.get("service_type", "").strip() or None
    source = request.form.get("source", "").strip() or None
    address = request.form.get("address", "").strip() or None
    notes = request.form.get("notes", "").strip() or None

    if not name or not phone:
        abort(400, "Name and phone are required.")

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO leads (company_id, name, phone, service_type, source, address, notes, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?)
            """,
            (cid, name, phone, service_type, source, address, notes, datetime.now().isoformat()),
        )
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/update_lead_status/<int:lead_id>", methods=["POST"])
@login_required
def update_lead_status(lead_id: int):
    cid = current_company_id()
    status = (request.form.get("status") or "New").strip()
    allowed = {"New", "Contacted", "Scheduled", "Won", "Lost"}
    if status not in allowed:
        abort(400, "Invalid lead status.")

    with get_db() as conn:
        lead = conn.execute("SELECT * FROM leads WHERE id=? AND company_id=?", (lead_id, cid)).fetchone()
        if not lead:
            abort(404)
        conn.execute("UPDATE leads SET status=? WHERE id=? AND company_id=?", (status, lead_id, cid))
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/convert_lead/<int:lead_id>", methods=["POST"])
@login_required
def convert_lead(lead_id: int):
    cid = current_company_id()
    scheduled_date = parse_date_yyyy_mm_dd(request.form.get("scheduled_date", ""))
    technician = (request.form.get("technician", "").strip() or None)

    with get_db() as conn:
        lead = conn.execute("SELECT * FROM leads WHERE id=? AND company_id=?", (lead_id, cid)).fetchone()
        if not lead:
            abort(404)

        conn.execute(
            """
            INSERT INTO jobs (company_id, lead_id, customer_name, status, scheduled_date, technician, created_at)
            VALUES (?, ?, ?, 'Scheduled', ?, ?, ?)
            """,
            (cid, lead_id, lead["name"], scheduled_date, technician, datetime.now().isoformat()),
        )
        conn.execute("UPDATE leads SET status='Scheduled' WHERE id=? AND company_id=?", (lead_id, cid))
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/update_job_status/<int:job_id>", methods=["POST"])
@login_required
def update_job_status(job_id: int):
    cid = current_company_id()
    status = (request.form.get("status") or "Scheduled").strip()
    allowed = {"Scheduled", "In Progress", "Completed", "Canceled"}
    if status not in allowed:
        abort(400)

    with get_db() as conn:
        job = conn.execute("SELECT * FROM jobs WHERE id=? AND company_id=?", (job_id, cid)).fetchone()
        if not job:
            abort(404)
        conn.execute("UPDATE jobs SET status=? WHERE id=? AND company_id=?", (status, job_id, cid))
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/create_invoice/<int:job_id>", methods=["POST"])
@login_required
def create_invoice(job_id: int):
    cid = current_company_id()
    amount_raw = (request.form.get("amount") or "").strip()
    due_date = parse_date_yyyy_mm_dd(request.form.get("due_date", ""))

    try:
        amount = float(amount_raw)
    except ValueError:
        abort(400, "Amount must be a number.")

    token = secrets.token_urlsafe(24)

    with get_db() as conn:
        job = conn.execute(
            "SELECT * FROM jobs WHERE id=? AND company_id=?",
            (job_id, cid)
        ).fetchone()

        if not job:
            abort(404)

        conn.execute(
            """
            INSERT INTO invoices (
                company_id, job_id, amount, status, due_date, created_at, paid_at, public_token
            )
            VALUES (?, ?, ?, 'Unpaid', ?, ?, NULL, ?)
            """,
            (cid, job_id, amount, due_date, datetime.now().isoformat(), token)
        )
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/pay/<token>", methods=["GET"])
def public_invoice(token: str):
    with get_db() as conn:
        inv = conn.execute(
            """
            SELECT i.*, c.name AS company_name, j.customer_name
            FROM invoices i
            JOIN companies c ON c.id = i.company_id
            JOIN jobs j ON j.id = i.job_id
            WHERE i.public_token = ?
            LIMIT 1
            """,
            (token,),
        ).fetchone()

    if not inv:
        abort(404)

    return render_template("public_invoice.html", invoice=inv)



@app.route("/mark_paid/<int:invoice_id>", methods=["POST"])
@login_required
def mark_paid(invoice_id: int):
    cid = current_company_id()
    with get_db() as conn:
        inv = conn.execute("SELECT * FROM invoices WHERE id=? AND company_id=?", (invoice_id, cid)).fetchone()
        if not inv:
            abort(404)
        conn.execute(
            "UPDATE invoices SET status='Paid', paid_at=? WHERE id=? AND company_id=?",
            (datetime.now().isoformat(), invoice_id, cid),
        )
        conn.commit()
    return redirect(url_for("dashboard"))

@app.route("/jobs/<int:job_id>/tasks/add", methods=["POST"])
@login_required
def add_task(job_id: int):
    cid = current_company_id()
    title = (request.form.get("title") or "").strip()
    due_date = parse_date_yyyy_mm_dd(request.form.get("due_date", ""))
    assigned_to = (request.form.get("assigned_to") or "").strip() or None

    if not title:
        abort(400, "Task title is required.")

    with get_db() as conn:
        job = conn.execute(
            "SELECT id FROM jobs WHERE id=? AND company_id=?",
            (job_id, cid),
        ).fetchone()
        if not job:
            abort(404)

        conn.execute(
            """
            INSERT INTO tasks (company_id, job_id, title, status, due_date, assigned_to, created_at)
            VALUES (?, ?, ?, 'todo', ?, ?, ?)
            """,
            (cid, job_id, title, due_date, assigned_to, datetime.now().isoformat()),
        )
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id: int):
    cid = current_company_id()
    with get_db() as conn:
        task = conn.execute(
            "SELECT id, status FROM tasks WHERE id=? AND company_id=?",
            (task_id, cid),
        ).fetchone()
        if not task:
            abort(404)

        new_status = "done" if task["status"] != "done" else "todo"

        conn.execute(
            "UPDATE tasks SET status=? WHERE id=? AND company_id=?",
            (new_status, task_id, cid),
        )
        conn.commit()

    return redirect(url_for("dashboard"))



if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)



