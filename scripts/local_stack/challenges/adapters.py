"""
Adapters for the six `sec-challenges/Web/` applications behind the Firewall-IA local stack.

LAB ONLY. These are deliberately vulnerable CTF web applications. Their source and their
vulnerabilities are kept BYTE-FOR-BYTE intact: this package never edits a file under the applications
repository. Each adapter only says how to BUILD an image from the application's own tree and how to RUN
that image in isolation (internal Docker network, no route out) behind the stack's shared TLS/HTTP-2
front and gateway. Everything the application-specific logic needs it gets from the image the
application itself defines, or, for the three applications that ship no Dockerfile, from an adapter
Dockerfile under `dockerfiles/` that only installs the pinned requirements and runs the unmodified
entry file.

Applications repository (pinned in the evidence):
    /home/sebas/Documents/Codex/2026-11-02/sec-challenges   branch master
    commit be8e4e8f1c6aa12a17430146d569870d96d43dd5          folder Web/   (capital W)

Single source of truth: `challenge_stack.py` (runtime), the smoke checks and the per-application
reports all import `ADAPTERS` from here so the route map, ports and session facts never drift.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKERFILES = os.path.join(HERE, "dockerfiles")

# The applications repository and the exact commit the integration was pinned to.
DEFAULT_APPS_ROOT = "/home/sebas/Documents/Codex/2026-11-02/sec-challenges"
PINNED_APPS_COMMIT = "be8e4e8f1c6aa12a17430146d569870d96d43dd5"
WEB_SUBDIR = "Web"          # capital W

# Exact public static resources at the pinned commit. The experimental Fast Path
# can allow one of these only when the complete request matches an app-bound rule.
# No login, query, dynamic or effect route is eligible.
FAST_PATH_STATIC = {
    "An0nB0ard": "/static/css/style.css",
    "CatP1cs": "/static/img/favicon.ico",
    "D33pTh0ught": "/static/img/machine.jpg",
    "Inf3ct": "/static/img/anon.png",
    "ObC00ki3s": "/static/js/cks.js",
    "ag3ncy": "/static/img/avatar.png",
}

# Security options for the deliberately vulnerable Python application containers. Identical in spirit to
# the fwlab-notes application container in stack.py: non-root, read-only root filesystem, every capability
# dropped, no privilege escalation, a small writable tmpfs for anything the runtime insists on writing.
PY_RUN_OPTS = [
    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "128", "--memory", "256m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,nosuid,noexec,size=64m", "--user", "1000:1000",
]

# MySQL 5.7 sidecar for An0nB0ard. Its official entrypoint chowns the data directory and drops privilege
# with gosu, so it needs a writable root and a few capabilities; it is still confined to the internal
# network with no route out, and its storage is an ephemeral tmpfs so every run starts from members.sql.
DB_RUN_OPTS = [
    "--cap-drop", "ALL",
    "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
    "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256", "--memory", "512m", "--cpus", "1",
    "--tmpfs", "/var/lib/mysql:rw,size=512m",
    "--tmpfs", "/tmp:rw,size=32m", "--tmpfs", "/run/mysqld:rw,size=16m",
]


ADAPTERS = {
    # ───────────────────────────────── An0nB0ard ─────────────────────────────────
    "An0nB0ard": {
        "source_subdir": "An0nB0ard",
        "image": "fwlab-challenge/an0nb0ard:lab",
        "hostname": "an0nb0ard.fwlab.test",
        "internal_port": 1337,
        "ready_path": "/",            # GET / renders the login form without touching the DB
        "run_opts": PY_RUN_OPTS,
        # The application's own Dockerfile (python:3.9-slim + Flask + pymysql), code COPYed in, unmodified.
        "build": {"dockerfile": None, "context": "An0nB0ard"},
        "env": {
            "MYSQL_HOST": "{db_host}", "MYSQL_USER": "root", "MYSQL_PASSWORD": "rootpassword",
            "MYSQL_DB": "members",
            # Fake learning values, copied verbatim from the application's docker-compose.yml.
            "ADMIN_USER": "admin_test", "ADMIN_PASS": "password123",
            "FLAG": "Flag{T3st1ng_f4k3_fl4g}",
        },
        "sidecars": [{
            "name": "db", "image": "mysql:5.7", "ip_offset": 2, "run_opts": DB_RUN_OPTS,
            "env": {"MYSQL_ROOT_PASSWORD": "rootpassword", "MYSQL_DATABASE": "members"},
            "mounts": [("An0nB0ard/members.sql", "/docker-entrypoint-initdb.d/init.sql:ro")],
            "ready": {"kind": "mysql_ping"},
        }],
        "vuln_class": "SQL injection (string-concatenated queries)",
        "effect_observable": True,
        "effect_note": "Auth-bypass renders admin.html carrying the FLAG string; UNION/boolean SQLi is "
                       "observable as changed response bodies. The flag here is the fake learning value.",
        "sessions": "None. blog.py imports flask.session but never sets a secret key or writes a session; "
                    "no server-side session or auth cookie is issued.",
        "state": "MySQL tables `members` and `posts`. Ephemeral: the DB sidecar stores data on a tmpfs and "
                 "re-seeds from members.sql on every `up`, so state resets with the run.",
        "routes": [
            ("GET", "/", "login form (sign.html)", "entry"),
            ("GET", "/register", "registration form", "entry"),
            ("POST", "/login", "username+password; SQLi in get_password (string concat)", "SQLi / auth bypass"),
            ("GET", "/messages", "list all posts", "read"),
            ("POST", "/new", "create user (username+password)", "write"),
            ("POST", "/addentry", "insert post (id+entry); SQLi (string concat)", "SQLi"),
            ("GET|POST", "/post?id=", "fetch post by id; SQLi in get_entry", "SQLi"),
            ("GET", "/static/css/*", "bootstrap css assets", "static"),
        ],
    },

    # ───────────────────────────────── CatP1cs ─────────────────────────────────
    "CatP1cs": {
        "source_subdir": "CatP1cs",
        "image": "fwlab-challenge/catp1cs:lab",
        "hostname": "catp1cs.fwlab.test",
        "internal_port": 1337,
        "ready_path": "/",
        "run_opts": PY_RUN_OPTS,
        # Own Dockerfile (python:3-alpine). It also COPYs flag.txt to /flag.txt (the fake learning flag).
        "build": {"dockerfile": None, "context": "CatP1cs"},
        "env": {},
        "sidecars": [],
        "vuln_class": "Path traversal / local file read (blocklist bypass)",
        "effect_observable": True,
        "effect_note": "A successful traversal returns file bytes in the response body (e.g. /flag.txt). "
                       "The substring blocklist ['./','..','etc','passwd','flag'] is checked against "
                       "request.full_path, so bypass requires encoding tricks; the effect is the file content.",
        "sessions": "None.",
        "state": "None. A POST to / returns a random message id; nothing is stored.",
        "routes": [
            ("GET", "/", "cat gallery (index.html)", "entry"),
            ("POST", "/", "message form; returns a random token id", "write (no store)"),
            ("GET", "/show?img=", "send_file('static/img/'+img); traversal if blocklist bypassed", "path traversal"),
            ("GET", "/static/img/*", "cat images + favicon", "static"),
        ],
    },

    # ───────────────────────────────── D33pTh0ught ─────────────────────────────────
    "D33pTh0ught": {
        "source_subdir": "D33pTh0ught",
        "image": "fwlab-challenge/d33pth0ught:lab",
        "hostname": "d33pth0ught.fwlab.test",
        "internal_port": 3030,         # D33p.py binds port 3030
        "ready_path": "/",
        "run_opts": PY_RUN_OPTS,
        # Ships no Dockerfile: adapter Dockerfile installs requirements.txt and runs the unmodified D33p.py.
        "build": {"dockerfile": os.path.join(DOCKERFILES, "D33pTh0ught.Dockerfile"), "context": "D33pTh0ught"},
        "env": {},
        "sidecars": [],
        "vuln_class": "Guessable password → AES-GCM flag decryption (weak secret)",
        "effect_observable": True,
        "effect_note": "Correct answer (the form hints at 'the answer to Life') derives the key and the "
                       "decrypted flag is rendered into index.html. Effect = flag present in the response.",
        "sessions": "None.",
        "state": "None (flag ciphertext is a module constant).",
        "routes": [
            ("GET", "/", "question form (index.html)", "entry"),
            ("POST", "/", "answer field; PBKDF2(answer) decrypts the flag if correct", "crypto guess"),
            ("GET", "/static/img/*", "machine.jpg", "static"),
        ],
    },

    # ───────────────────────────────── Inf3ct ─────────────────────────────────
    "Inf3ct": {
        "source_subdir": "Inf3ct",
        "image": "fwlab-challenge/inf3ct:lab",
        "hostname": "inf3ct.fwlab.test",
        "internal_port": 1337,
        "ready_path": "/",
        "run_opts": PY_RUN_OPTS,
        # Own Dockerfile (python:3-alpine). COPYs flag.txt to /flag.txt.
        "build": {"dockerfile": None, "context": "Inf3ct"},
        "env": {},
        "sidecars": [],
        "vuln_class": "Server-side template injection (character-filtered)",
        "effect_observable": True,
        "effect_note": "/log concatenates recent request logs into a template passed to "
                       "render_template_string → SSTI. bad_chars \"{'_#&;}\" are stripped from the POSTed "
                       "msg, so a payload must avoid them. Effect = evaluated template output in /log.",
        "sessions": "None.",
        "state": "In-memory log_array of the last 5 requests; resets when the container restarts.",
        "routes": [
            ("GET", "/", "message form (index.html)", "entry"),
            ("POST", "/", "msg field; filtered then stored in the in-memory log", "SSTI source"),
            ("GET", "/log", "renders the recent log via render_template_string", "SSTI sink"),
            ("GET", "/static/img/*", "anon.png", "static"),
        ],
    },

    # ───────────────────────────────── ObC00ki3s ─────────────────────────────────
    "ObC00ki3s": {
        "source_subdir": "ObC00ki3s",
        "image": "fwlab-challenge/obc00ki3s:lab",
        "hostname": "obc00ki3s.fwlab.test",
        "internal_port": 5000,         # server.py uses the Flask default port 5000
        "ready_path": "/",
        "run_opts": PY_RUN_OPTS,
        # Ships no Dockerfile: adapter Dockerfile installs Flask and runs the unmodified server.py.
        "build": {"dockerfile": os.path.join(DOCKERFILES, "ObC00ki3s.Dockerfile"), "context": "ObC00ki3s"},
        "env": {},
        "sidecars": [],
        "vuln_class": "Client-side only (obfuscated JavaScript cookie puzzle)",
        "effect_observable": False,
        "effect_note": "The server only serves index.html and two static JS files (cks.js, asking.js); all "
                       "logic runs in the browser. The firewall sees GET / and static fetches only, so for "
                       "this application only DELIVERY and CLASSIFICATION are measurable server-side, never "
                       "an exploit effect.",
        "sessions": "Client-side cookies set by JavaScript in the browser; the server issues none.",
        "state": "None server-side.",
        "routes": [
            ("GET", "/", "index.html (loads the puzzle JS)", "entry"),
            ("GET", "/static/js/cks.js", "obfuscated client logic", "static"),
            ("GET", "/static/js/asking.js", "obfuscated client logic", "static"),
            ("GET", "/static/img/*", "bunchofcookies.jpeg", "static"),
        ],
    },

    # ───────────────────────────────── ag3ncy ─────────────────────────────────
    "ag3ncy": {
        "source_subdir": "ag3ncy",
        "image": "fwlab-challenge/ag3ncy:lab",
        "hostname": "ag3ncy.fwlab.test",
        "internal_port": 5000,         # agency.py binds port 5000
        "ready_path": "/",
        "run_opts": PY_RUN_OPTS,
        # Ships no Dockerfile: adapter Dockerfile installs requirements.txt and runs the unmodified agency.py.
        "build": {"dockerfile": os.path.join(DOCKERFILES, "ag3ncy.Dockerfile"), "context": "ag3ncy"},
        "env": {},
        "sidecars": [],
        "vuln_class": "Guessable password → AES-GCM flag decryption (weak secret)",
        "effect_observable": True,
        "effect_note": "POST /auth with the right password ('may the force be with you' hint) derives the "
                       "key and renders admin.html with the flag; a wrong password renders error.html. "
                       "Effect = admin.html/flag vs error.html in the response.",
        "sessions": "None.",
        "state": "None (flag ciphertext is a module constant).",
        "routes": [
            ("GET", "/", "landing page (index.html)", "entry"),
            ("POST", "/auth", "password field; decrypts the flag if correct", "crypto guess"),
            ("GET", "/static/img/*", "avatar.png", "static"),
        ],
    },
}

APP_NAMES = tuple(ADAPTERS)


def web_dir(apps_root):
    return os.path.join(apps_root, WEB_SUBDIR)


def context_dir(apps_root, adapter):
    return os.path.join(web_dir(apps_root), adapter["build"]["context"])
