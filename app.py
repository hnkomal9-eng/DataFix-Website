from __future__ import annotations

import io
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import numpy as np
import pandas as pd
import pdfplumber

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from xml.sax.saxutils import escape

from flask import (
    Flask, jsonify, redirect, render_template_string,
    request, send_file, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# =========================================================
# DATAFIX CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "datafix_users.db"
SECRET_PATH = BASE_DIR / ".datafix_secret"

ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".pdf"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_secret_key():
    configured = os.environ.get("DATAFIX_SECRET_KEY")

    if configured:
        return configured

    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="utf-8").strip()

    key = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(key, encoding="utf-8")
    return key


app.secret_key = get_secret_key()

DATASETS = {}


# =========================================================
# DATABASE
# =========================================================

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


init_db()


# =========================================================
# AUTHENTICATION
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):

            if request.path.startswith("/api/"):
                return jsonify(
                    error="Please sign in to continue."
                ), 401

            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


def valid_email(email):
    return bool(
        re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or "")
    )


# =========================================================
# LOGIN PAGE
# =========================================================

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>DataFix Sign In</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    font-family: Arial;
    background: linear-gradient(135deg,#101a33,#315efb);
}

.login-box {
    background: white;
    padding: 35px;
    width: 420px;
    max-width: 95%;
    border-radius: 18px;
}

h1 {
    margin-bottom: 5px;
}

p {
    color: #68748a;
}

label {
    display: block;
    margin-top: 15px;
    font-weight: bold;
}

input {
    width: 100%;
    padding: 13px;
    margin-top: 7px;
    border: 1px solid #ddd;
    border-radius: 8px;
}

button {
    width: 100%;
    padding: 13px;
    margin-top: 20px;
    background: #315efb;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: bold;
}

a {
    color: #315efb;
    font-weight: bold;
    text-decoration: none;
}

.error {
    background: #ffe8e8;
    color: #b42335;
    padding: 10px;
    border-radius: 8px;
    margin: 12px 0;
}

</style>
</head>

<body>

<div class="login-box">

<h1>DataFix ✦</h1>

<p id="subtitle">
Sign in to access your data quality workspace.
</p>

<div id="error" class="error" style="display:none"></div>

<form id="authForm" method="POST" action="/login">

<label>Email address</label>
<input type="email" name="email" required>

<label>Password</label>
<input type="password" name="password" minlength="8" required>

<button id="submitButton">Sign in</button>

</form>

<p style="text-align:center;margin-top:20px">
<span id="switchText">New to DataFix?</span>
<a href="#" id="switchLink">Create an account</a>
</p>

</div>

<script>

let registering = false;

const form = document.getElementById("authForm");

document.getElementById("switchLink").onclick = function(event) {

    event.preventDefault();

    registering = !registering;

    form.action = registering ? "/register" : "/login";

    document.getElementById("subtitle").textContent =
        registering ? "Create your DataFix account." :
        "Sign in to access your workspace.";

    document.getElementById("submitButton").textContent =
        registering ? "Create account" : "Sign in";

    document.getElementById("switchText").textContent =
        registering ? "Already have an account?" : "New to DataFix?";

    this.textContent =
        registering ? "Sign in" : "Create an account";
};

const error = new URLSearchParams(location.search).get("error");

if (error) {
    const box = document.getElementById("error");
    box.style.display = "block";
    box.textContent = error;
}

</script>

</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        if session.get("user_id"):
            return redirect("/")

        return render_template_string(LOGIN_HTML)

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    with db_connect() as conn:

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password
    ):

        return redirect(
            "/login?error=Incorrect%20email%20or%20password"
        )

    session.clear()
    session["user_id"] = user["id"]
    session["email"] = user["email"]

    return redirect("/")


@app.route("/register", methods=["POST"])
def register():

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not valid_email(email):
        return redirect("/login?error=Enter%20a%20valid%20email")

    if len(password) < 8:
        return redirect(
            "/login?error=Password%20must%20be%20at%20least%208%20characters"
        )

    try:

        with db_connect() as conn:

            cursor = conn.execute(
                """
                INSERT INTO users(email,password_hash,created_at)
                VALUES(?,?,?)
                """,
                (
                    email,
                    generate_password_hash(password),
                    datetime.now(timezone.utc).isoformat()
                )
            )

            user_id = cursor.lastrowid

        session.clear()
        session["user_id"] = user_id
        session["email"] = email

        return redirect("/")

    except sqlite3.IntegrityError:

        return redirect(
            "/login?error=Account%20already%20exists"
        )


@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect("/login")


# =========================================================
# FILE UPLOAD AND EXTRACTION
# =========================================================

def read_upload(upload):

    filename = secure_filename(upload.filename or "dataset")
    extension = Path(filename.lower()).suffix

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file format.")

    raw = upload.read()

    if not raw:
        raise ValueError("The uploaded file is empty.")

    if extension == ".csv":

        try:
            df = pd.read_csv(io.BytesIO(raw))
        except UnicodeDecodeError:
            df = pd.read_csv(
                io.BytesIO(raw),
                encoding="latin-1"
            )

    elif extension in {".xlsx", ".xls"}:

        df = pd.read_excel(io.BytesIO(raw))

    else:

        rows = []

        with pdfplumber.open(io.BytesIO(raw)) as pdf:

            for page in pdf.pages:

                for table in page.extract_tables() or []:

                    for row in table:

                        if row:
                            rows.append([
                                "" if value is None else str(value).strip()
                                for value in row
                            ])

        if not rows:
            raise ValueError(
                "No selectable table found in PDF. "
                "Scanned PDFs require OCR."
            )

        width = max(len(row) for row in rows)

        rows = [
            row + [""] * (width - len(row))
            for row in rows
        ]

        df = pd.DataFrame(rows[1:], columns=rows[0])

    if df.empty or len(df.columns) == 0:
        raise ValueError("No usable data found in the file.")

    # Treat whitespace-only cells as missing while preserving non-empty text.
    for column in df.select_dtypes(include=["object", "string"]).columns:
        df[column] = df[column].map(
            lambda value: pd.NA if isinstance(value, str) and not value.strip() else value
        )

    names = []
    seen = {}

    for index, column in enumerate(df.columns):

        name = str(column).strip() or f"Column_{index + 1}"

        count = seen.get(name, 0)
        seen[name] = count + 1

        names.append(
            name if count == 0 else f"{name}_{count + 1}"
        )

    df.columns = names

    return df, filename


# =========================================================
# DATA QUALITY ANALYSIS
# =========================================================

def analyze_df(df):
    """Run transparent, rule-based quality checks on a dataframe."""
    missing = int(df.isna().sum().sum())
    duplicates = int(df.duplicated().sum())
    invalid_emails = 0
    invalid_dates = 0
    invalid_phones = 0
    invalid_numeric = 0
    extra_spaces = 0
    inconsistent_case = 0
    numeric_outliers = 0
    issues = []

    for column in df.columns:
        series = df[column]
        col_name = str(column)
        lower_name = col_name.lower()
        missing_count = int(series.isna().sum())

        if missing_count:
            issues.append({
                "title": f"Missing values in {col_name}",
                "detail": f"{missing_count} empty cells found.",
                "severity": "Medium",
                "category": "Completeness"
            })

        non_null = series.dropna()
        if non_null.empty:
            continue

        # Text-based checks
        if (pd.api.types.is_object_dtype(series)
                or pd.api.types.is_string_dtype(series)):
            values = non_null.astype(str)

            if "email" in lower_name:
                invalid = ~values.str.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
                count = int(invalid.sum())
                invalid_emails += count
                if count:
                    issues.append({
                        "title": f"Invalid email values in {col_name}",
                        "detail": f"{count} values do not match a basic email format.",
                        "severity": "High",
                        "category": "Validity"
                    })

            spaces = values.ne(values.str.strip())
            count = int(spaces.sum())
            extra_spaces += count
            if count:
                issues.append({
                    "title": f"Leading or trailing spaces in {col_name}",
                    "detail": f"{count} text values contain extra spaces.",
                    "severity": "Low",
                    "category": "Consistency"
                })

            # Case inconsistency is checked only for likely categorical columns.
            if any(token in lower_name for token in
                   ("city", "state", "country", "status", "category", "type", "gender")):
                nonempty = values[values.str.strip().ne("")]
                case_count = int((nonempty != nonempty.str.strip().str.lower()).sum())
                # This is an indicator only; it does not assume lowercase is correct.
                if case_count:
                    inconsistent_case += case_count
                    issues.append({
                        "title": f"Mixed capitalization in {col_name}",
                        "detail": f"{case_count} values may use inconsistent capitalization; review before standardizing.",
                        "severity": "Low",
                        "category": "Consistency"
                    })

            if any(token in lower_name for token in ("phone", "mobile", "contact")):
                digits = values.str.replace(r"\D", "", regex=True)
                invalid = digits.str.len().lt(7) | digits.str.len().gt(15)
                count = int(invalid.sum())
                invalid_phones += count
                if count:
                    issues.append({
                        "title": f"Unusual phone number length in {col_name}",
                        "detail": f"{count} values contain fewer than 7 or more than 15 digits.",
                        "severity": "Medium",
                        "category": "Validity"
                    })

        # Date-like column checks: count non-empty values that cannot be parsed.
        if any(token in lower_name for token in ("date", "time", "dob", "created", "updated")):
            parsed = pd.to_datetime(non_null, errors="coerce", dayfirst=False)
            count = int(parsed.isna().sum())
            invalid_dates += count
            if count:
                issues.append({
                    "title": f"Unparseable date values in {col_name}",
                    "detail": f"{count} non-empty values could not be interpreted as dates.",
                    "severity": "High",
                    "category": "Validity"
                })

        # Numeric-looking columns with non-empty values that cannot be parsed.
        numeric_tokens = ("age", "amount", "price", "quantity", "qty", "score", "salary", "count", "total", "cost")
        if any(token in lower_name for token in numeric_tokens):
            converted = pd.to_numeric(series, errors="coerce")
            invalid_mask = series.notna() & converted.isna()
            invalid_count = int(invalid_mask.sum())
            invalid_numeric += invalid_count
            if invalid_count:
                issues.append({
                    "title": f"Non-numeric values in {col_name}",
                    "detail": f"{invalid_count} non-empty values could not be converted to numbers.",
                    "severity": "High",
                    "category": "Validity"
                })

        # Numeric range and outlier checks. Outliers are flagged for review, not declared wrong.
        numeric = pd.to_numeric(series, errors="coerce").dropna()
        if len(numeric) >= 4:
            q1 = float(numeric.quantile(0.25))
            q3 = float(numeric.quantile(0.75))
            iqr = q3 - q1
            if iqr > 0:
                low, high = q1 - 1.5 * iqr, q3 + 1.5 * iqr
                count = int(((numeric < low) | (numeric > high)).sum())
                numeric_outliers += count
                if count:
                    issues.append({
                        "title": f"Potential numeric outliers in {col_name}",
                        "detail": f"{count} values fall outside the 1.5×IQR review range ({low:.3g} to {high:.3g}). These may be valid extremes.",
                        "severity": "Review",
                        "category": "Anomaly"
                    })

        # Flag negative values only where a non-negative domain is commonly expected.
        if any(token in lower_name for token in ("age", "amount", "price", "quantity", "qty", "score", "salary", "count")):
            numeric_all = pd.to_numeric(series, errors="coerce")
            count = int((numeric_all < 0).sum())
            if count:
                issues.append({
                    "title": f"Negative values in {col_name}",
                    "detail": f"{count} negative values found in a field that commonly expects non-negative values. Confirm the field's business rules.",
                    "severity": "High",
                    "category": "Domain"
                })

    if duplicates:
        issues.insert(0, {
            "title": "Duplicate rows",
            "detail": f"{duplicates} exact duplicate rows found.",
            "severity": "Medium",
            "category": "Uniqueness"
        })

    total_cells = max(1, df.shape[0] * df.shape[1])
    # Score is an indicative heuristic, not a certified quality standard.
    penalty = (
        missing + duplicates * max(1, df.shape[1]) + invalid_emails
        + extra_spaces + invalid_dates + invalid_phones
        + inconsistent_case + numeric_outliers + invalid_numeric
    )
    score = max(0, min(100, round(100 - penalty / total_cells * 100)))

    preview_df = df.head(10).astype(object).where(pd.notna(df.head(10)), None)
    preview = []
    for row in preview_df.values.tolist():
        clean_row = []
        for value in row:
            if value is None:
                clean_row.append(None)
            elif isinstance(value, (np.integer,)):
                clean_row.append(int(value))
            elif isinstance(value, (np.floating,)):
                clean_row.append(float(value))
            else:
                clean_row.append(str(value))
        preview.append(clean_row)

    return {
        "rows": int(df.shape[0]),
        "columns": int(df.shape[1]),
        "columns_names": [str(c) for c in df.columns],
        "missing": missing,
        "duplicates": duplicates,
        "invalid_emails": invalid_emails,
        "extra_spaces": extra_spaces,
        "invalid_dates": invalid_dates,
        "invalid_phones": invalid_phones,
        "invalid_numeric": invalid_numeric,
        "numeric_outliers": numeric_outliers,
        "inconsistent_case": inconsistent_case,
        "issue_count": len(issues),
        "issues": issues,
        "score": score,
        "preview": preview
    }


def current_dataset():

    key = session.get("dataset_key")

    if not key or key not in DATASETS:
        return None

    dataset = DATASETS[key]

    if dataset["user_id"] != session.get("user_id"):
        return None

    return dataset


# =========================================================
# MAIN DASHBOARD
# =========================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>

<title>DataFix | Autonomous Data Quality</title>

<meta name="viewport" content="width=device-width, initial-scale=1">

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial;
    background: #f4f6fb;
    color: #172033;
}

header {
    background: linear-gradient(110deg,#101a33,#243d78);
    color: white;
    padding: 18px 5%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
}

.brand {
    font-size: 23px;
    font-weight: bold;
}

.signout {
    background: white;
    color: #2446bb;
    border: none;
    padding: 10px 15px;
    border-radius: 8px;
    cursor: pointer;
}

.container {
    max-width: 1200px;
    margin: 30px auto;
    padding: 0 20px;
}

h1 {
    margin-bottom: 5px;
}

.subtitle {
    color: #68748a;
}

.stats {
    display: grid;
    grid-template-columns: repeat(3,1fr);
    gap: 15px;
    margin: 25px 0;
}

.card {
    background: white;
    border: 1px solid #e5e9f2;
    padding: 20px;
    border-radius: 14px;
    margin-bottom: 18px;
}

.stat strong {
    display: block;
    font-size: 25px;
    margin-top: 8px;
}

.layout {
    display: grid;
    grid-template-columns: 340px 1fr;
    gap: 18px;
}

.drop {
    border: 2px dashed #b9c8ec;
    padding: 22px;
    border-radius: 12px;
    background: #f8faff;
    text-align: center;
}

input[type=file] {
    width: 100%;
    margin: 15px 0;
}

button {
    background: #315efb;
    color: white;
    border: none;
    padding: 12px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: bold;
}

button:disabled {
    opacity: .6;
    cursor: wait;
}

.status {
    margin-top: 15px;
    overflow-wrap: anywhere;
}

.error {
    color: #c43c50;
}

.success {
    color: #12805c;
}

.muted {
    color: #68748a;
    font-size: 13px;
}

.table-wrap {
    overflow: auto;
    max-height: 400px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

th, td {
    padding: 10px;
    border-bottom: 1px solid #e5e9f2;
    text-align: left;
}

th {
    background: #f4f6fb;
    position: sticky;
    top: 0;
}

.issue {
    padding: 12px 0;
    border-bottom: 1px solid #eee;
}

.downloads {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

.downloads a {
    background: #eaf0ff;
    color: #2446bb;
    text-decoration: none;
    padding: 10px 12px;
    border-radius: 8px;
}

.hidden {
    display: none;
}

@media(max-width:850px) {
    .layout {
        grid-template-columns: 1fr;
    }
}

@media(max-width:600px) {
    .stats {
        grid-template-columns: 1fr;
    }
}


/* DataFix visual refresh - presentation only; existing routes and controls remain intact. */
body { background: linear-gradient(135deg,#eef3ff 0%,#f7f5ff 48%,#eefaf8 100%); }
header { background: linear-gradient(105deg,#101b45 0%,#2847a8 55%,#6236a8 100%); box-shadow: 0 8px 28px rgba(32,52,120,.18); }
.brand { letter-spacing: .2px; }
.container { max-width: 1320px; }
.card { border: 1px solid rgba(194,207,239,.75); border-radius: 18px; box-shadow: 0 10px 28px rgba(42,61,115,.07); transition: transform .18s ease, box-shadow .18s ease; }
.card:hover { transform: translateY(-2px); box-shadow: 0 14px 34px rgba(42,61,115,.11); }
.stats .card:nth-child(1) { border-top: 4px solid #4f72ff; background: linear-gradient(145deg,#fff,#f1f4ff); }
.stats .card:nth-child(2) { border-top: 4px solid #16a6a0; background: linear-gradient(145deg,#fff,#edfbf8); }
.stats .card:nth-child(3) { border-top: 4px solid #8b5cf6; background: linear-gradient(145deg,#fff,#f7f0ff); }
.stat strong { color: #172d69; }
.drop { border: 2px dashed #8198ec; background: linear-gradient(135deg,#f4f7ff,#f8f4ff); }
button { background: linear-gradient(100deg,#315efb,#6847e8); box-shadow: 0 5px 13px rgba(49,94,251,.2); transition: filter .15s ease, transform .15s ease; }
button:hover { filter: brightness(1.06); transform: translateY(-1px); }
.downloads a { background: #edf1ff; border: 1px solid #dce4ff; font-weight: 700; }
.downloads a:first-child { background:#e7f8f2; border-color:#c8efe0; color:#08785b; }
.issue { padding: 13px; margin: 8px 0; border: 1px solid #e4e9f5; border-left: 4px solid #f59e0b; border-radius: 10px; background: #fff; }
.issue:nth-child(3n+2) { border-left-color:#ef5da8; }
.issue:nth-child(3n+3) { border-left-color:#6475f5; }
.table-wrap { border: 1px solid #e2e8f4; border-radius: 12px; }
th { background: #edf2ff; color:#243c83; }
.status { padding: 8px 10px; border-radius: 9px; }
.status.success { background:#e8f8f0; }
.status.error { background:#fff0f1; }
@media(max-width:700px) { header { padding:16px 5%; } .container { margin:20px auto; } .stats { grid-template-columns:1fr; } }

</style>

</head>

<body>

<header>

<div class="brand">DataFix ✦</div>

<div>
Signed in as {{ email }}
</div>

<form method="POST" action="/logout">
<button class="signout">Sign out</button>
</form>

</header>

<div class="container">

<h1>Make your data reliable.</h1>

<p class="subtitle">
Upload a dataset, detect quality issues, review suggested repairs and export clean data.
</p>

<div class="stats">

<div class="card stat">
Dataset
<strong id="fileStat">Not uploaded</strong>
</div>

<div class="card stat">
Rows × Columns
<strong id="shapeStat">—</strong>
</div>

<div class="card stat">
Quality score
<strong id="scoreStat">—</strong>
</div>

</div>

<div class="layout">

<div>

<div class="card">

<h3>1. Upload dataset</h3>

<div class="drop">

<b>Choose a file to analyze</b>

<p class="muted">
Supported: CSV, XLSX, XLS, PDF
</p>

<input
type="file"
id="file"
accept=".csv,.xlsx,.xls,.pdf"
>

<button id="analyzeBtn" onclick="analyze()" type="button">
Analyze dataset
</button>

</div>

<div id="status" class="status"></div>

</div>

<div class="card hidden" id="repairArea">

<h3>2. Data repair</h3>

<label>
<input type="checkbox" id="dropDup" checked>
Remove duplicate rows
</label>

<br><br>

<label>
<input type="checkbox" id="fillMissing">
Fill missing numeric values using median
</label>

<br><br>

<label>
<input type="checkbox" id="trimText" checked>
Trim extra spaces
</label>

<br><br>

<label>
<input type="checkbox" id="normalizeEmail" checked>
Normalize email addresses (lowercase and trim)
</label>

<br><br>

<label>
<input type="checkbox" id="standardizeDates">
Standardize parseable date columns (YYYY-MM-DD)
</label>

<br><br>

<label>
<input type="checkbox" id="fillMissingText">
Fill missing text values using most frequent value
</label>

<br><br>

<button onclick="repair()" id="repairBtn">
Apply repairs
</button>

</div>

<div class="card hidden" id="downloadArea">

<h3>3. Downloads</h3>

<div class="downloads">

<a href="/download/cleaned.csv">Clean CSV</a>

<a href="/download/cleaned.xlsx">Clean Excel</a>

<a href="/download/report.pdf">Download PDF Report</a>
    <a href="/download/report.csv">Issue Report (CSV)</a>

</div>

</div>

</div>

<div>

<div class="card">

<h3>Data quality analysis</h3>

<div id="summary" class="muted">
Upload a dataset to see its analysis.
</div>

<div id="issues"></div>

<h3>Dataset preview</h3>

<div class="table-wrap" id="preview">
No dataset loaded.
</div>

</div>

</div>

</div>

</div>

<script>

async function readResponse(response) {

    const type = response.headers.get("content-type") || "";

    if (!type.includes("application/json")) {

        throw new Error(
            "Server returned an unexpected response. Check the Flask terminal."
        );

    }

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}


function escapeHTML(value) {

    return String(value).replace(/[&<>"']/g, function(char) {

        return {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[char];

    });

}


async function analyze() {

    const file = document.getElementById("file").files[0];
    const status = document.getElementById("status");
    const button = document.getElementById("analyzeBtn");

    if (!file) {

        status.textContent = "Please select a file first.";
        status.className = "status error";

        return;
    }

    button.disabled = true;

    status.textContent = "Uploading and analyzing...";
    status.className = "status";

    const formData = new FormData();

    formData.append("file", file);

    try {

        const response = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });

        const data = await readResponse(response);

        renderAnalysis(data);

        status.textContent = "Analysis completed successfully.";
        status.className = "status success";

        document.getElementById("repairArea").classList.remove("hidden");
        document.getElementById("downloadArea").classList.remove("hidden");

    } catch (error) {

        status.textContent = "Error: " + error.message;
        status.className = "status error";

    } finally {

        button.disabled = false;

    }

}


function renderAnalysis(data) {

    document.getElementById("fileStat").textContent = data.filename;

    document.getElementById("shapeStat").textContent =
        data.rows + " × " + data.columns;

    document.getElementById("scoreStat").textContent =
        data.score + "/100";

    document.getElementById("summary").innerHTML =
        "<p>" + data.issue_count + " findings detected.</p>" +
        "<p>" + data.missing + " missing cells · " +
        data.duplicates + " duplicate rows · " +
        data.invalid_emails + " invalid emails · " +
        data.invalid_dates + " invalid dates · " +
        data.invalid_phones + " unusual phone values · " +
        data.numeric_outliers + " potential numeric outliers · " +
        data.extra_spaces + " extra-space values.</p>" +
        "<p><b>Note:</b> Outliers and domain flags are review suggestions, not proof that a value is incorrect.</p>";

    const issues = document.getElementById("issues");

    issues.innerHTML = data.issues.length
        ? data.issues.map(issue =>
            '<div class="issue"><b>' +
            escapeHTML(issue.title) +
            '</b><p class="muted">' +
            escapeHTML(issue.category || "Quality") + ' · ' +
            escapeHTML(issue.severity || "Review") +
            '</p><p class="muted">' +
            escapeHTML(issue.detail) +
            '</p></div>'
          ).join("")
        : '<p class="success">No common quality issues detected.</p>';

    let html = "<table><thead><tr>";

    data.columns_names.forEach(column => {
        html += "<th>" + escapeHTML(column) + "</th>";
    });

    html += "</tr></thead><tbody>";

    data.preview.forEach(row => {

        html += "<tr>";

        row.forEach(value => {

            html += "<td>" +
                escapeHTML(value === null ? "" : value) +
                "</td>";

        });

        html += "</tr>";

    });

    html += "</tbody></table>";

    document.getElementById("preview").innerHTML = html;

}


async function repair() {

    const button = document.getElementById("repairBtn");
    const status = document.getElementById("status");

    button.disabled = true;

    try {

        const response = await fetch("/api/repair", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({

                drop_duplicates:
                    document.getElementById("dropDup").checked,

                fill_missing:
                    document.getElementById("fillMissing").checked,

                trim_text:
                    document.getElementById("trimText").checked,

                normalize_email:
                    document.getElementById("normalizeEmail").checked,

                standardize_dates:
                    document.getElementById("standardizeDates").checked,

                fill_missing_text:
                    document.getElementById("fillMissingText").checked

            })

        });

        const data = await readResponse(response);

        status.textContent =
            "Repairs applied. " +
            data.removed_duplicates + " duplicate rows removed. " +
            data.filled_cells + " numeric cells filled. " +
            (data.text_cells_filled || 0) + " text cells filled. " +
            (data.emails_normalized || 0) + " email values normalized. " +
            (data.dates_standardized || 0) + " dates standardized. " +
            data.rows + " rows remain.";

        status.className = "status success";

    } catch (error) {

        status.textContent = "Repair error: " + error.message;
        status.className = "status error";

    } finally {

        button.disabled = false;

    }

}

</script>

</body>
</html>
"""


@app.route("/")
@login_required
def home():

    return render_template_string(
        DASHBOARD_HTML,
        email=session.get("email", "")
    )


# =========================================================
# API: ANALYZE DATASET
# =========================================================

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():

    if "file" not in request.files:
        return jsonify(error="No file was selected."), 400

    try:

        df, filename = read_upload(request.files["file"])

        key = str(uuid.uuid4())

        DATASETS[key] = {
            "original": df.copy(),
            "cleaned": df.copy(),
            "filename": filename,
            "user_id": session["user_id"],
            "initial_analysis": analyze_df(df),
            "repair_summary": {
                "performed": False,
                "removed_duplicates": 0,
                "filled_cells": 0,
                "trim_text": False,
                "drop_duplicates": False,
                "fill_missing": False
            }
        }

        session["dataset_key"] = key

        result = analyze_df(df)

        result["filename"] = filename

        return jsonify(result)

    except Exception as error:

        app.logger.exception("Dataset analysis failed")

        return jsonify(error=str(error)), 400


# =========================================================
# API: REPAIR DATASET
# =========================================================

@app.route("/api/repair", methods=["POST"])
@login_required
def api_repair():

    dataset = current_dataset()

    if dataset is None:
        return jsonify(
            error="Upload and analyze a dataset first."
        ), 400

    options = request.get_json(silent=True) or {}

    df = dataset["original"].copy()

    original_rows = len(df)

    if options.get("drop_duplicates", True):
        df = df.drop_duplicates()

    removed_duplicates = original_rows - len(df)

    filled_cells = 0
    text_cells_filled = 0

    if options.get("fill_missing", False):

        numeric_columns = df.select_dtypes(
            include=[np.number]
        ).columns

        for column in numeric_columns:

            missing_count = int(df[column].isna().sum())

            if missing_count:

                median = df[column].median()

                if pd.notna(median):

                    df[column] = df[column].fillna(median)

                    filled_cells += missing_count

    if options.get("fill_missing_text", False):
        text_columns = df.select_dtypes(include=["object", "string"]).columns
        for column in text_columns:
            non_missing = df[column].dropna()
            if not non_missing.empty:
                mode_values = non_missing.mode()
                if not mode_values.empty:
                    count = int(df[column].isna().sum())
                    df[column] = df[column].fillna(mode_values.iloc[0])
                    text_cells_filled += count

    if options.get("trim_text", True):
        text_columns = df.select_dtypes(include=["object", "string"]).columns
        for column in text_columns:
            df[column] = df[column].map(
                lambda value: value.strip() if isinstance(value, str) else value
            )

    emails_normalized = 0
    if options.get("normalize_email", False):
        for column in df.columns:
            if "email" in str(column).lower():
                before = df[column].copy()
                df[column] = df[column].map(
                    lambda value: value.strip().lower() if isinstance(value, str) else value
                )
                emails_normalized += int((before.fillna("").astype(str) != df[column].fillna("").astype(str)).sum())

    dates_standardized = 0
    if options.get("standardize_dates", False):
        for column in df.columns:
            if any(token in str(column).lower() for token in ("date", "time", "dob", "created", "updated")):
                before = df[column].copy()
                parsed = pd.to_datetime(df[column], errors="coerce", dayfirst=True)
                valid_mask = df[column].notna() & parsed.notna()
                df.loc[valid_mask, column] = parsed.loc[valid_mask].dt.strftime("%Y-%m-%d")
                dates_standardized += int(valid_mask.sum())

    dataset["cleaned"] = df
    dataset["repair_summary"] = {
        "performed": True,
        "removed_duplicates": int(removed_duplicates),
        "filled_cells": int(filled_cells),
        "trim_text": bool(options.get("trim_text", True)),
        "drop_duplicates": bool(options.get("drop_duplicates", True)),
        "fill_missing": bool(options.get("fill_missing", False)),
        "fill_missing_text": bool(options.get("fill_missing_text", False)),
        "text_cells_filled": int(text_cells_filled),
        "normalize_email": bool(options.get("normalize_email", False)),
        "emails_normalized": int(emails_normalized),
        "standardize_dates": bool(options.get("standardize_dates", False)),
        "dates_standardized": int(dates_standardized)
    }

    return jsonify({

        "rows": int(len(df)),

        "columns": int(len(df.columns)),

        "removed_duplicates": int(removed_duplicates),

        "filled_cells": int(filled_cells),
        "text_cells_filled": int(text_cells_filled),
        "emails_normalized": int(emails_normalized),
        "dates_standardized": int(dates_standardized)

    })


# =========================================================
# DOWNLOAD CLEAN CSV
# =========================================================

@app.route("/download/cleaned.csv")
@login_required
def download_csv():

    dataset = current_dataset()

    if dataset is None:
        return "Upload a dataset first.", 400

    output = io.BytesIO(
        dataset["cleaned"].to_csv(
            index=False
        ).encode("utf-8-sig")
    )

    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="datafix_cleaned.csv"
    )


# =========================================================
# DOWNLOAD CLEAN EXCEL
# =========================================================

@app.route("/download/cleaned.xlsx")
@login_required
def download_excel():

    dataset = current_dataset()

    if dataset is None:
        return "Upload a dataset first.", 400

    output = io.BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl"
    ) as writer:

        dataset["cleaned"].to_excel(
            writer,
            index=False,
            sheet_name="Cleaned Data"
        )

    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="datafix_cleaned.xlsx"
    )


# =========================================================
# DOWNLOAD ISSUE REPORT
# =========================================================

@app.route("/download/report.csv")
@login_required
def download_report():

    dataset = current_dataset()

    if dataset is None:
        return "Upload a dataset first.", 400

    result = analyze_df(dataset["cleaned"])

    report = pd.DataFrame(
        result["issues"],
        columns=["title", "detail"]
    )

    output = io.BytesIO(
        report.to_csv(index=False).encode("utf-8-sig")
    )

    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="datafix_issue_report.csv"
    )



# =========================================================
# DOWNLOAD DETAILED PDF QUALITY REPORT
# =========================================================

@app.route("/download/report.pdf")
@login_required
def download_pdf_report():
    dataset = current_dataset()

    if dataset is None:
        return "Upload and analyze a dataset first.", 400

    original_df = dataset["original"]
    cleaned_df = dataset["cleaned"]
    before = dataset.get("initial_analysis") or analyze_df(original_df)
    after = analyze_df(cleaned_df)
    repair = dataset.get("repair_summary", {})
    generated_at = datetime.now().astimezone().strftime("%d %B %Y, %I:%M %p %Z")

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="DataFix Data Quality Report",
        author="DataFix - Autonomous Data Quality and Repair Engine"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        textColor=colors.HexColor("#18346b"),
        alignment=TA_CENTER,
        spaceAfter=5
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#18346b"),
        spaceBefore=12,
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="SmallCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        wordWrap="CJK"
    ))
    styles.add(ParagraphStyle(
        name="SmallMuted",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#596579")
    ))

    story = []
    filename = escape(str(dataset.get("filename", "Uploaded dataset")))
    story.append(Paragraph("DATAFIX", styles["ReportTitle"]))
    story.append(Paragraph(
        "AUTONOMOUS DATA QUALITY AND REPAIR ENGINE",
        ParagraphStyle(
            "BrandSub",
            parent=styles["Normal"],
            alignment=TA_CENTER,
            fontSize=9,
            textColor=colors.HexColor("#596579"),
            spaceAfter=12
        )
    ))
    story.append(Paragraph("Data Quality Assessment Report", styles["Heading1"]))
    story.append(Paragraph(
        f"<b>Dataset:</b> {filename}<br/>"
        f"<b>Generated:</b> {escape(generated_at)}<br/>"
        f"<b>Account:</b> {escape(str(session.get('email', '')))}",
        styles["BodyText"]
    ))

    story.append(Paragraph("1. Executive summary", styles["SectionHeading"]))
    summary_data = [
        ["Measure", "Before repair", "After repair"],
        ["Rows", str(len(original_df)), str(len(cleaned_df))],
        ["Columns", str(len(original_df.columns)), str(len(cleaned_df.columns))],
        ["Quality score", f"{before['score']}/100", f"{after['score']}/100"],
        ["Missing cells", str(before["missing"]), str(after["missing"])],
        ["Duplicate rows", str(before["duplicates"]), str(after["duplicates"])],
        ["Invalid email values", str(before["invalid_emails"]), str(after["invalid_emails"])],
        ["Unparseable dates", str(before.get("invalid_dates", 0)), str(after.get("invalid_dates", 0))],
        ["Unusual phone values", str(before.get("invalid_phones", 0)), str(after.get("invalid_phones", 0))],
        ["Potential numeric outliers", str(before.get("numeric_outliers", 0)), str(after.get("numeric_outliers", 0))],
        ["Values with extra spaces", str(before["extra_spaces"]), str(after["extra_spaces"])],
        ["Detected findings", str(before["issue_count"]), str(after["issue_count"])]
    ]
    summary_table = Table(summary_data, colWidths=[65*mm, 48*mm, 48*mm], repeatRows=1)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18346b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7deea")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f6fb")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))
    story.append(summary_table)

    story.append(Paragraph("2. Dataset profile", styles["SectionHeading"]))
    story.append(Paragraph(
        f"<b>File name:</b> {filename}<br/>"
        f"<b>Number of records:</b> {len(original_df)}<br/>"
        f"<b>Number of fields:</b> {len(original_df.columns)}<br/>"
        f"<b>Field names:</b> {escape(', '.join(map(str, original_df.columns)))}<br/>"
        "<b>Input formats supported by this application:</b> CSV, XLSX, XLS and "
        "text-based/table PDFs. Scanned PDFs require OCR and are not processed by "
        "the current PDF extraction method.",
        styles["BodyText"]
    ))

    story.append(Paragraph("3. Detected data quality issues", styles["SectionHeading"]))
    if before["issues"]:
        issue_rows = [["Issue", "Details"]]
        for issue in before["issues"]:
            issue_rows.append([
                Paragraph(escape(str(issue.get("title", "")),), styles["SmallCell"]),
                Paragraph(escape(str(issue.get("detail", ""))), styles["SmallCell"])
            ])
        issue_table = Table(issue_rows, colWidths=[58*mm, 103*mm], repeatRows=1)
        issue_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18346b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7deea")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ]))
        story.append(issue_table)
    else:
        story.append(Paragraph(
            "No issues from the checks implemented in this version were detected.",
            styles["BodyText"]
        ))

    story.append(Paragraph("4. Repair activity", styles["SectionHeading"]))
    if repair.get("performed"):
        repair_lines = [
            f"Duplicate removal selected: {'Yes' if repair.get('drop_duplicates') else 'No'}",
            f"Duplicate rows removed: {repair.get('removed_duplicates', 0)}",
            f"Fill missing numeric values using median selected: {'Yes' if repair.get('fill_missing') else 'No'}",
            f"Numeric cells filled: {repair.get('filled_cells', 0)}",
            f"Text cells filled: {repair.get('text_cells_filled', 0)}",
            f"Email values normalized: {repair.get('emails_normalized', 0)}",
            f"Dates standardized: {repair.get('dates_standardized', 0)}",
            f"Trim extra spaces selected: {'Yes' if repair.get('trim_text') else 'No'}"
        ]
    else:
        repair_lines = ["No repair operation has been recorded for this dataset."]
    story.append(Paragraph("<br/>".join(escape(line) for line in repair_lines), styles["BodyText"]))

    story.append(Paragraph("5. Remaining issues after repair", styles["SectionHeading"]))
    if after["issues"]:
        remaining = [["Remaining issue", "Details"]]
        for issue in after["issues"]:
            remaining.append([
                Paragraph(escape(str(issue.get("title", "")),), styles["SmallCell"]),
                Paragraph(escape(str(issue.get("detail", ""))), styles["SmallCell"])
            ])
        remaining_table = Table(remaining, colWidths=[58*mm, 103*mm], repeatRows=1)
        remaining_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18346b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7deea")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ]))
        story.append(remaining_table)
    else:
        story.append(Paragraph(
            "No issues from the implemented checks remain after the recorded repair.",
            styles["BodyText"]
        ))

    story.append(Paragraph("6. Recommendations", styles["SectionHeading"]))
    recommendations = []
    if after["missing"]:
        recommendations.append("Review missing values. Confirm whether each field should be completed, excluded or left blank; do not fill values without a suitable business rule.")
    if after["duplicates"]:
        recommendations.append("Review duplicate records and confirm whether they represent repeated transactions or genuinely duplicated entries before removing them.")
    if after["invalid_emails"]:
        recommendations.append("Validate email addresses against the source system or contact owner before using them for communication.")
    if after["extra_spaces"]:
        recommendations.append("Normalize leading and trailing spaces in text fields and verify that the changes do not alter meaningful values.")
    if after.get("invalid_dates", 0):
        recommendations.append("Review date values that could not be parsed. Confirm the intended date format and resolve ambiguous day/month ordering with the data owner.")
    if after.get("invalid_phones", 0):
        recommendations.append("Review phone values with unusual digit counts. Country codes and local numbering rules may affect the expected length.")
    if after.get("numeric_outliers", 0):
        recommendations.append("Investigate potential numeric outliers using domain knowledge. The IQR method flags unusual values for review and does not automatically classify them as errors.")
    if not recommendations:
        recommendations.append("The implemented checks found no remaining issues. Continue with domain-specific validation before using the dataset in production.")
    recommendations.append("This report reflects only the checks currently implemented in DataFix. It is not a guarantee that every possible data quality issue has been detected.")
    for item in recommendations:
        story.append(Paragraph(f"&bull; {escape(item)}", styles["BodyText"]))
        story.append(Spacer(1, 3))

    story.append(Paragraph("7. Preview of cleaned dataset", styles["SectionHeading"]))
    preview = cleaned_df.head(8).copy()
    if len(preview.columns):
        preview_rows = [[Paragraph(escape(str(c)), styles["SmallCell"]) for c in preview.columns]]
        for _, row in preview.iterrows():
            preview_rows.append([
                Paragraph(escape("" if pd.isna(value) else str(value))[:300], styles["SmallCell"])
                for value in row.tolist()
            ])
        available_width = A4[0] - 36*mm
        col_width = available_width / max(1, len(preview.columns))
        preview_table = Table(
            preview_rows,
            colWidths=[col_width] * len(preview.columns),
            repeatRows=1
        )
        preview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18346b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d7deea")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(preview_table)
        story.append(Paragraph(
            "The preview is limited to the first 8 rows. Download the cleaned CSV or Excel file for the complete dataset.",
            styles["SmallMuted"]
        ))

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Generated by DataFix. Review the dataset and recommendations before relying on the results for operational or business decisions.",
        styles["SmallMuted"]
    ))

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#68748a"))
        canvas.drawString(18*mm, 10*mm, "DataFix - Data Quality Report")
        canvas.drawRightString(A4[0] - 18*mm, 10*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    output.seek(0)

    safe_base = Path(dataset.get("filename", "dataset")).stem or "dataset"
    return send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"datafix_{secure_filename(safe_base)}_quality_report.pdf"
    )


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(413)
def file_too_large(error):

    return jsonify(
        error="File too large. Maximum size is 25 MB."
    ), 413


@app.errorhandler(500)
def internal_error(error):

    app.logger.exception("Internal server error")

    return jsonify(
        error="Internal server error. Check the Flask terminal."
    ), 500


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )