"""
NutrioSite - Flask Authentication Backend
==========================================
Handles user signup/signin and serves the static site.

Run:
    pip install flask werkzeug
    python app.py

Then visit: http://localhost:5000
"""

import os
import sqlite3
from functools import wraps

from flask import (
    Flask, request, redirect, url_for,
    render_template, session, flash, send_from_directory, g
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(
    __name__,
    static_folder=".",       # serve nutriosite root as static
    template_folder="templates"
)

# Secret key for signing session cookies.
# In production replace this with a long random string, e.g.
#   python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key = os.environ.get("SECRET_KEY", "nutriosite-dev-secret-change-me")

DATABASE = os.path.join(app.root_path, "nutriosite.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request SQLite connection stored on Flask's `g` object."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row   # rows behave like dicts
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the users table if it doesn't exist yet."""
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                name      TEXT    NOT NULL,
                email     TEXT    NOT NULL UNIQUE,
                password  TEXT    NOT NULL,
                created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(view):
    """Decorator — redirects unauthenticated users to /signin."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("signin"))
        return view(*args, **kwargs)
    return wrapped


def get_user_by_email(email):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def create_user(name, email, password):
    db = get_db()
    hashed = generate_password_hash(password)
    db.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed)
    )
    db.commit()


# ---------------------------------------------------------------------------
# Static file routes  (serve the existing nutriosite HTML/CSS/JS/images)
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def home():
    """Serve the root index.html."""
    return send_from_directory(".", "index.html")


@app.route("/<filename>.html")
@login_required
def serve_html(filename):
    """
    Serve HTML files from the root or HTML/ folder without the prefix.
    """
    file_with_ext = f"{filename}.html"

    if file_with_ext == "signin.html":
        return redirect(url_for("signin"))
    if file_with_ext == "signup.html":
        return redirect(url_for("signup"))

    # Check in root first (index.html)
    if os.path.exists(os.path.join(app.root_path, file_with_ext)):
        return send_from_directory(".", file_with_ext)

    # Check in HTML/ folder
    html_path = os.path.join(app.root_path, "HTML", file_with_ext)
    if os.path.exists(html_path):
        return send_from_directory("HTML", file_with_ext)

    return "File not found", 404


@app.route("/css/<path:filename>")
def css_files(filename):
    return send_from_directory("css", filename)


@app.route("/js/<path:filename>")
def js_files(filename):
    return send_from_directory("js", filename)


@app.route("/image/<path:filename>")
def image_files(filename):
    return send_from_directory("image", filename)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Already logged in — send straight to the site
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        name             = request.form.get("name", "").strip()
        email            = request.form.get("email", "").strip().lower()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- Server-side validation ---
        errors = []

        if not name:
            errors.append("Full name is required.")
        elif len(name) < 2:
            errors.append("Name must be at least 2 characters.")

        if not email or "@" not in email:
            errors.append("A valid email address is required.")

        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")

        if password != confirm_password:
            errors.append("Passwords do not match.")

        if not errors and get_user_by_email(email):
            errors.append("An account with that email already exists.")

        if errors:
            for error in errors:
                flash(error, "error")
            # Re-render with the values already filled in (except passwords)
            return render_template("auth_page.html", active_tab="signup", name=name, email=email)

        # --- All good — create account and log in ---
        create_user(name, email, password)
        user = get_user_by_email(email)
        session.clear()
        session["user_id"]   = user["id"]
        session["user_name"] = user["name"]
        flash(f"Welcome to NutrioSite, {name}! Your account has been created.", "success")
        return redirect(url_for("home"))

    return render_template("auth_page.html", active_tab="signup", name="", email="")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    # Already logged in
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # --- Server-side validation ---
        errors = []

        if not email or "@" not in email:
            errors.append("Please enter a valid email address.")

        if not password:
            errors.append("Password is required.")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("auth_page.html", active_tab="signin", email=email)

        # --- Verify credentials ---
        user = get_user_by_email(email)

        # Use a generic message to avoid revealing whether the email exists
        if not user or not check_password_hash(user["password"], password):
            flash("Incorrect email or password. Please try again.", "error")
            return render_template("auth_page.html", active_tab="signin", email=email)

        # --- Success ---
        session.clear()
        session["user_id"]   = user["id"]
        session["user_name"] = user["name"]
        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for("home"))

    return render_template("auth_page.html", active_tab="signin", email="")


@app.route("/signout")
def signout():
    """Clear the session and return to the sign-in page."""
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("signin"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("NutrioSite backend running at http://localhost:1234")
    app.run(debug=True, host="0.0.0.0", port=1234)
