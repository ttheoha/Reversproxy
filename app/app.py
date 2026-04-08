import json
import os
import subprocess
import time
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

CONFIG_FILE = "/data/routes.json"
TILES_FILE = "/data/tiles.json"
LOGOS_DIR = "/data/logos"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico"}

# Rate limiting: {ip: {"attempts": int, "blocked_until": float}}
login_attempts = {}

MAX_ATTEMPTS = 6
BLOCK_DURATION = 600  # 10 minutes


def get_client_ip():
    return request.headers.get("X-Real-IP", request.remote_addr)


def is_blocked(ip):
    if ip in login_attempts:
        info = login_attempts[ip]
        if info.get("blocked_until") and time.time() < info["blocked_until"]:
            return True
        if info.get("blocked_until") and time.time() >= info["blocked_until"]:
            del login_attempts[ip]
    return False


def record_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {"attempts": 0, "blocked_until": None}
    login_attempts[ip]["attempts"] += 1
    if login_attempts[ip]["attempts"] >= MAX_ATTEMPTS:
        login_attempts[ip]["blocked_until"] = time.time() + BLOCK_DURATION


def clear_attempts(ip):
    if ip in login_attempts:
        del login_attempts[ip]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# --- Routes (proxy) ---

def load_routes():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return []


def save_routes(routes):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(routes, f, indent=2)


# --- Tiles ---

def load_tiles():
    if os.path.exists(TILES_FILE):
        with open(TILES_FILE) as f:
            return json.load(f)
    return []


def save_tiles(tiles):
    os.makedirs(os.path.dirname(TILES_FILE), exist_ok=True)
    with open(TILES_FILE, "w") as f:
        json.dump(tiles, f, indent=2)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_nginx_conf(routes):
    """Generate nginx upstream config from routes."""
    conf_path = "/etc/nginx/conf.d/proxy.conf"
    lines = []
    for route in routes:
        domain = route["domain"]
        target = route["target"]
        listen_port = route.get("listen_port", "443")
        ssl_on = " ssl" if listen_port != "80" else ""
        ssl_lines = ""
        if listen_port != "80":
            ssl_lines = """
    ssl_certificate /etc/nginx/certs/selfsigned.crt;
    ssl_certificate_key /etc/nginx/certs/selfsigned.key;"""
        lines.append(f"""server {{
    listen {listen_port}{ssl_on};
    server_name {domain};{ssl_lines}

    location / {{
        proxy_pass {target};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
""")
    with open(conf_path, "w") as f:
        f.write("\n".join(lines) if lines else "# No routes configured\n")


def reload_nginx():
    try:
        subprocess.run(["nginx", "-t"], check=True, capture_output=True, text=True)
        subprocess.run(["nginx", "-s", "reload"], check=True, capture_output=True, text=True)
        return True, "Nginx rechargé avec succès."
    except subprocess.CalledProcessError as e:
        return False, f"Erreur Nginx: {e.stderr}"


# --- Auth routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()

    if is_blocked(ip):
        remaining = int(login_attempts[ip]["blocked_until"] - time.time())
        minutes = remaining // 60
        seconds = remaining % 60
        return render_template("login.html",
                               error=f"IP bloquée. Réessayez dans {minutes}m {seconds}s.",
                               blocked=True)

    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["logged_in"] = True
            clear_attempts(ip)
            return redirect(url_for("admin"))
        else:
            record_failed_attempt(ip)
            attempts_left = MAX_ATTEMPTS - login_attempts.get(ip, {}).get("attempts", 0)
            if is_blocked(ip):
                return render_template("login.html",
                                       error="Trop de tentatives. IP bloquée pour 10 minutes.",
                                       blocked=True)
            return render_template("login.html",
                                   error=f"Mot de passe incorrect. {attempts_left} tentative(s) restante(s).")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    flash("Déconnexion réussie.", "success")
    return redirect(url_for("login"))


# --- Public home ---

@app.route("/")
def home():
    tiles = load_tiles()
    tiles.sort(key=lambda t: t.get("position", 999))
    return render_template("home.html", tiles=tiles)


@app.route("/logos/<filename>")
def serve_logo(filename):
    return send_from_directory(LOGOS_DIR, filename)


# --- Admin ---

@app.route("/admin")
@login_required
def admin():
    routes = load_routes()
    tiles = load_tiles()
    tiles.sort(key=lambda t: t.get("position", 999))
    return render_template("index.html", routes=routes, tiles=tiles)


# --- Proxy route CRUD ---

@app.route("/add", methods=["POST"])
@login_required
def add_route():
    domain = request.form.get("domain", "").strip()
    target = request.form.get("target", "").strip()
    listen_port = request.form.get("listen_port", "443").strip()

    if not domain or not target:
        flash("Le domaine et la cible sont obligatoires.", "error")
        return redirect(url_for("admin"))

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    routes = load_routes()
    routes.append({
        "domain": domain,
        "target": target,
        "listen_port": listen_port,
    })
    save_routes(routes)
    generate_nginx_conf(routes)
    ok, msg = reload_nginx()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("admin"))


@app.route("/delete/<int:route_id>", methods=["POST"])
@login_required
def delete_route(route_id):
    routes = load_routes()
    if 0 <= route_id < len(routes):
        removed = routes.pop(route_id)
        save_routes(routes)
        generate_nginx_conf(routes)
        ok, msg = reload_nginx()
        flash(f"Route {removed['domain']} supprimée. {msg}", "success" if ok else "error")
    else:
        flash("Route introuvable.", "error")
    return redirect(url_for("admin"))


@app.route("/edit/<int:route_id>", methods=["POST"])
@login_required
def edit_route(route_id):
    routes = load_routes()
    if 0 <= route_id < len(routes):
        domain = request.form.get("domain", "").strip()
        target = request.form.get("target", "").strip()
        listen_port = request.form.get("listen_port", "443").strip()

        if not domain or not target:
            flash("Le domaine et la cible sont obligatoires.", "error")
            return redirect(url_for("admin"))

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        routes[route_id] = {
            "domain": domain,
            "target": target,
            "listen_port": listen_port,
        }
        save_routes(routes)
        generate_nginx_conf(routes)
        ok, msg = reload_nginx()
        flash(msg, "success" if ok else "error")
    else:
        flash("Route introuvable.", "error")
    return redirect(url_for("admin"))


# --- Tile CRUD ---

@app.route("/tile/add", methods=["POST"])
@login_required
def add_tile():
    name = request.form.get("tile_name", "").strip()
    url = request.form.get("tile_url", "").strip()
    position = request.form.get("tile_position", "0").strip()

    if not name or not url:
        flash("Le nom et l'URL de la tuile sont obligatoires.", "error")
        return redirect(url_for("admin"))

    try:
        position = int(position)
    except ValueError:
        position = 0

    logo_filename = ""
    if "tile_logo" in request.files:
        file = request.files["tile_logo"]
        if file and file.filename and allowed_file(file.filename):
            ext = file.filename.rsplit(".", 1)[1].lower()
            logo_filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(LOGOS_DIR, exist_ok=True)
            file.save(os.path.join(LOGOS_DIR, logo_filename))

    tiles = load_tiles()
    tiles.append({
        "id": uuid.uuid4().hex[:8],
        "name": name,
        "url": url,
        "position": position,
        "logo": logo_filename,
    })
    save_tiles(tiles)
    flash(f"Tuile \"{name}\" ajoutée.", "success")
    return redirect(url_for("admin"))


@app.route("/tile/edit/<tile_id>", methods=["POST"])
@login_required
def edit_tile(tile_id):
    tiles = load_tiles()
    tile = next((t for t in tiles if t["id"] == tile_id), None)
    if not tile:
        flash("Tuile introuvable.", "error")
        return redirect(url_for("admin"))

    name = request.form.get("tile_name", "").strip()
    url = request.form.get("tile_url", "").strip()
    position = request.form.get("tile_position", "0").strip()

    if not name or not url:
        flash("Le nom et l'URL sont obligatoires.", "error")
        return redirect(url_for("admin"))

    try:
        position = int(position)
    except ValueError:
        position = 0

    tile["name"] = name
    tile["url"] = url
    tile["position"] = position

    if "tile_logo" in request.files:
        file = request.files["tile_logo"]
        if file and file.filename and allowed_file(file.filename):
            # Remove old logo
            if tile.get("logo"):
                old_path = os.path.join(LOGOS_DIR, tile["logo"])
                if os.path.exists(old_path):
                    os.remove(old_path)
            ext = file.filename.rsplit(".", 1)[1].lower()
            logo_filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(LOGOS_DIR, exist_ok=True)
            file.save(os.path.join(LOGOS_DIR, logo_filename))
            tile["logo"] = logo_filename

    save_tiles(tiles)
    flash(f"Tuile \"{name}\" modifiée.", "success")
    return redirect(url_for("admin"))


@app.route("/tile/delete/<tile_id>", methods=["POST"])
@login_required
def delete_tile(tile_id):
    tiles = load_tiles()
    tile = next((t for t in tiles if t["id"] == tile_id), None)
    if not tile:
        flash("Tuile introuvable.", "error")
        return redirect(url_for("admin"))

    # Remove logo file
    if tile.get("logo"):
        logo_path = os.path.join(LOGOS_DIR, tile["logo"])
        if os.path.exists(logo_path):
            os.remove(logo_path)

    tiles = [t for t in tiles if t["id"] != tile_id]
    save_tiles(tiles)
    flash(f"Tuile \"{tile['name']}\" supprimée.", "success")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    generate_nginx_conf(load_routes())
    app.run(host="0.0.0.0", port=5000)
