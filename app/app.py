import base64
import json
import os
import subprocess
import time
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, Response

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

CONFIG_FILE = "/data/routes.json"
TILES_FILE = "/data/tiles.json"
LOGOS_DIR = "/data/logos"
LDAP_CONFIG_FILE = "/data/ldap_config.json"
LETSENCRYPT_CONFIG_FILE = "/data/letsencrypt_config.json"
CERTS_DIR = "/data/certs"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

BLOCK_HISTORY_FILE = "/data/block_history.json"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico"}

# Rate limiting: {ip: {"attempts": int, "blocked_until": float}}
login_attempts = {}

MAX_ATTEMPTS = 6
BLOCK_DURATION = 600  # 10 minutes


def load_block_history():
    if os.path.exists(BLOCK_HISTORY_FILE):
        with open(BLOCK_HISTORY_FILE) as f:
            return json.load(f)
    return []


def save_block_history(history):
    os.makedirs(os.path.dirname(BLOCK_HISTORY_FILE), exist_ok=True)
    with open(BLOCK_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def record_block_event(ip, reason="6 tentatives echouees"):
    history = load_block_history()
    history.insert(0, {
        "ip": ip,
        "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "reason": reason,
    })
    # Garder les 200 derniers evenements
    history = history[:200]
    save_block_history(history)


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
        record_block_event(ip)


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


# --- Tiles (sections model) ---

def load_tiles():
    """Load sections. Migrates from old flat tile list if needed."""
    if os.path.exists(TILES_FILE):
        with open(TILES_FILE) as f:
            data = json.load(f)
        # Migration: old format was a flat list of tiles
        if isinstance(data, list):
            sections = [{
                "id": uuid.uuid4().hex[:8],
                "name": "Services",
                "position": 0,
                "tiles": data,
            }]
            save_tiles(sections)
            return sections
        if isinstance(data, dict) and "sections" in data:
            return data["sections"]
        return data if isinstance(data, list) else []
    return []


def save_tiles(sections):
    os.makedirs(os.path.dirname(TILES_FILE), exist_ok=True)
    with open(TILES_FILE, "w") as f:
        json.dump({"sections": sections}, f, indent=2)


def find_section(sections, section_id):
    return next((s for s in sections if s["id"] == section_id), None)


def find_tile_in_sections(sections, tile_id):
    for section in sections:
        for tile in section.get("tiles", []):
            if tile["id"] == tile_id:
                return section, tile
    return None, None


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
        lines.append(f"""server {{
    listen {listen_port}{ssl_on};
    server_name {domain};

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

def ldap_authenticate(username, password):
    """Try to authenticate user via LDAP. Returns (success, error_message)."""
    config = load_ldap_config()
    if not config.get("enabled"):
        return False, "LDAP non active"

    try:
        import ldap
    except ImportError:
        return False, "Module LDAP non installe"

    server_url = config.get("server_url", "")
    port = config.get("port", 389)
    use_ssl = config.get("use_ssl", False)

    if "://" not in server_url:
        proto = "ldaps" if use_ssl else "ldap"
        server_url = f"{proto}://{server_url}"
    if f":{port}" not in server_url:
        server_url = f"{server_url}:{port}"

    try:
        conn = ldap.initialize(server_url)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        if use_ssl:
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        # Bind with service account to search for user
        bind_dn = config.get("bind_dn", "")
        bind_password = config.get("bind_password", "")
        if bind_dn:
            conn.simple_bind_s(bind_dn, bind_password)
        else:
            conn.simple_bind_s("", "")

        # Search for user
        base_dn = config.get("base_dn", "")
        user_filter = config.get("user_filter", "(uid={username})")
        search_filter = user_filter.replace("{username}", username)

        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, ["dn", "memberOf"])
        if not result:
            conn.unbind_s()
            return False, "Utilisateur introuvable dans l'annuaire"

        user_dn = result[0][0]
        user_attrs = result[0][1] if len(result[0]) > 1 else {}

        # Try to bind as the user to verify password
        user_conn = ldap.initialize(server_url)
        user_conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        user_conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        user_conn.set_option(ldap.OPT_REFERRALS, 0)
        if use_ssl:
            user_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            user_conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        user_conn.simple_bind_s(user_dn, password)
        user_conn.unbind_s()

        # Check admin group membership if configured
        admin_group = config.get("admin_group", "").strip()
        if admin_group:
            member_of = user_attrs.get("memberOf", [])
            # Decode bytes if needed
            member_of = [g.decode("utf-8") if isinstance(g, bytes) else g for g in member_of]

            if admin_group not in member_of:
                # Also check by querying the group directly
                try:
                    group_filter = f"(|(member={user_dn})(uniqueMember={user_dn}))"
                    group_result = conn.search_s(admin_group, ldap.SCOPE_BASE, group_filter, ["dn"])
                    if not group_result:
                        conn.unbind_s()
                        return False, "Utilisateur non membre du groupe administrateur"
                except ldap.NO_SUCH_OBJECT:
                    conn.unbind_s()
                    return False, "Groupe administrateur introuvable"

        conn.unbind_s()
        return True, None

    except ldap.INVALID_CREDENTIALS:
        return False, "Mot de passe LDAP incorrect"
    except ldap.SERVER_DOWN:
        return False, "Serveur LDAP injoignable"
    except Exception as e:
        return False, f"Erreur LDAP: {str(e)}"


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()
    ldap_config = load_ldap_config()
    ldap_enabled = ldap_config.get("enabled", False)

    if is_blocked(ip):
        remaining = int(login_attempts[ip]["blocked_until"] - time.time())
        minutes = remaining // 60
        seconds = remaining % 60
        return render_template("login.html",
                               error=f"IP bloquée. Réessayez dans {minutes}m {seconds}s.",
                               blocked=True, ldap_enabled=ldap_enabled)

    if request.method == "POST":
        password = request.form.get("password", "")
        username = request.form.get("username", "").strip()

        authenticated = False
        error_msg = ""

        # Try LDAP first if enabled and username provided
        if ldap_enabled and username:
            success, ldap_error = ldap_authenticate(username, password)
            if success:
                authenticated = True
            else:
                error_msg = ldap_error

        # Fallback to local password (no username needed)
        if not authenticated and not username and password == ADMIN_PASSWORD:
            authenticated = True

        if authenticated:
            session["logged_in"] = True
            clear_attempts(ip)
            return redirect(url_for("admin"))
        else:
            record_failed_attempt(ip)
            attempts_left = MAX_ATTEMPTS - login_attempts.get(ip, {}).get("attempts", 0)
            if is_blocked(ip):
                return render_template("login.html",
                                       error="Trop de tentatives. IP bloquée pour 10 minutes.",
                                       blocked=True, ldap_enabled=ldap_enabled)
            if not error_msg:
                error_msg = f"Identifiants incorrects. {attempts_left} tentative(s) restante(s)."
            else:
                error_msg = f"{error_msg}. {attempts_left} tentative(s) restante(s)."
            return render_template("login.html", error=error_msg, ldap_enabled=ldap_enabled)

    return render_template("login.html", ldap_enabled=ldap_enabled)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    flash("Déconnexion réussie.", "success")
    return redirect(url_for("home"))


# --- Public home ---

@app.route("/")
def home():
    sections = load_tiles()
    sections.sort(key=lambda s: s.get("position", 999))
    for section in sections:
        section.get("tiles", []).sort(key=lambda t: t.get("position", 999))
    return render_template("home.html", sections=sections)


@app.route("/logos/<filename>")
def serve_logo(filename):
    return send_from_directory(LOGOS_DIR, filename)


# --- Admin ---

def get_blocked_ips():
    now = time.time()
    blocked = []
    for ip, info in list(login_attempts.items()):
        if info.get("blocked_until") and now < info["blocked_until"]:
            remaining = int(info["blocked_until"] - now)
            blocked.append({
                "ip": ip,
                "attempts": info["attempts"],
                "remaining": remaining,
                "remaining_min": remaining // 60,
                "remaining_sec": remaining % 60,
            })
    return blocked


@app.route("/admin")
@login_required
def admin():
    routes = load_routes()
    sections = load_tiles()
    sections.sort(key=lambda s: s.get("position", 999))
    for section in sections:
        section.get("tiles", []).sort(key=lambda t: t.get("position", 999))
    blocked_ips = get_blocked_ips()
    block_history = load_block_history()
    return render_template("index.html", routes=routes, sections=sections, blocked_ips=blocked_ips, block_history=block_history)


@app.route("/unblock/<path:ip>", methods=["POST"])
@login_required
def unblock_ip(ip):
    if ip in login_attempts:
        del login_attempts[ip]
        flash(f"IP {ip} debloquee.", "success")
    else:
        flash(f"IP {ip} non trouvee.", "error")
    return redirect(url_for("admin"))


@app.route("/clear-history", methods=["POST"])
@login_required
def clear_history():
    save_block_history([])
    flash("Historique des blocages efface.", "success")
    return redirect(url_for("admin"))


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


# --- Section CRUD ---

@app.route("/section/add", methods=["POST"])
@login_required
def add_section():
    name = request.form.get("section_name", "").strip()
    if not name:
        flash("Le nom de la section est obligatoire.", "error")
        return redirect(url_for("admin"))

    sections = load_tiles()
    max_pos = max((s.get("position", 0) for s in sections), default=-1)
    sections.append({
        "id": uuid.uuid4().hex[:8],
        "name": name,
        "position": max_pos + 1,
        "tiles": [],
    })
    save_tiles(sections)
    flash(f"Section \"{name}\" ajoutee.", "success")
    return redirect(url_for("admin"))


@app.route("/section/edit/<section_id>", methods=["POST"])
@login_required
def edit_section(section_id):
    sections = load_tiles()
    section = find_section(sections, section_id)
    if not section:
        flash("Section introuvable.", "error")
        return redirect(url_for("admin"))

    name = request.form.get("section_name", "").strip()
    position = request.form.get("section_position", "0").strip()

    if name:
        section["name"] = name
    try:
        section["position"] = int(position)
    except ValueError:
        pass

    save_tiles(sections)
    flash(f"Section \"{section['name']}\" modifiee.", "success")
    return redirect(url_for("admin"))


@app.route("/section/delete/<section_id>", methods=["POST"])
@login_required
def delete_section(section_id):
    sections = load_tiles()
    section = find_section(sections, section_id)
    if not section:
        flash("Section introuvable.", "error")
        return redirect(url_for("admin"))

    # Remove all logos in this section
    for tile in section.get("tiles", []):
        if tile.get("logo"):
            logo_path = os.path.join(LOGOS_DIR, tile["logo"])
            if os.path.exists(logo_path):
                os.remove(logo_path)

    name = section["name"]
    sections = [s for s in sections if s["id"] != section_id]
    save_tiles(sections)
    flash(f"Section \"{name}\" supprimee.", "success")
    return redirect(url_for("admin"))


@app.route("/section/move/<section_id>/<direction>", methods=["POST"])
@login_required
def move_section(section_id, direction):
    sections = load_tiles()
    sections.sort(key=lambda s: s.get("position", 999))

    idx = next((i for i, s in enumerate(sections) if s["id"] == section_id), None)
    if idx is None:
        flash("Section introuvable.", "error")
        return redirect(url_for("admin"))

    if direction == "up" and idx > 0:
        sections[idx], sections[idx - 1] = sections[idx - 1], sections[idx]
    elif direction == "down" and idx < len(sections) - 1:
        sections[idx], sections[idx + 1] = sections[idx + 1], sections[idx]

    for i, s in enumerate(sections):
        s["position"] = i

    save_tiles(sections)
    return redirect(url_for("admin"))


# --- Tile CRUD ---

@app.route("/tile/add/<section_id>", methods=["POST"])
@login_required
def add_tile(section_id):
    sections = load_tiles()
    section = find_section(sections, section_id)
    if not section:
        flash("Section introuvable.", "error")
        return redirect(url_for("admin"))

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

    section.setdefault("tiles", []).append({
        "id": uuid.uuid4().hex[:8],
        "name": name,
        "url": url,
        "position": position,
        "logo": logo_filename,
    })
    save_tiles(sections)
    flash(f"Tuile \"{name}\" ajoutee.", "success")
    return redirect(url_for("admin"))


@app.route("/tile/edit/<tile_id>", methods=["POST"])
@login_required
def edit_tile(tile_id):
    sections = load_tiles()
    section, tile = find_tile_in_sections(sections, tile_id)
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
            if tile.get("logo"):
                old_path = os.path.join(LOGOS_DIR, tile["logo"])
                if os.path.exists(old_path):
                    os.remove(old_path)
            ext = file.filename.rsplit(".", 1)[1].lower()
            logo_filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(LOGOS_DIR, exist_ok=True)
            file.save(os.path.join(LOGOS_DIR, logo_filename))
            tile["logo"] = logo_filename

    save_tiles(sections)
    flash(f"Tuile \"{name}\" modifiee.", "success")
    return redirect(url_for("admin"))


@app.route("/tile/delete/<tile_id>", methods=["POST"])
@login_required
def delete_tile(tile_id):
    sections = load_tiles()
    section, tile = find_tile_in_sections(sections, tile_id)
    if not tile:
        flash("Tuile introuvable.", "error")
        return redirect(url_for("admin"))

    if tile.get("logo"):
        logo_path = os.path.join(LOGOS_DIR, tile["logo"])
        if os.path.exists(logo_path):
            os.remove(logo_path)

    tile_name = tile["name"]
    section["tiles"] = [t for t in section["tiles"] if t["id"] != tile_id]
    save_tiles(sections)
    flash(f"Tuile \"{tile_name}\" supprimee.", "success")
    return redirect(url_for("admin"))


# --- LDAP Configuration ---

def load_ldap_config():
    if os.path.exists(LDAP_CONFIG_FILE):
        with open(LDAP_CONFIG_FILE) as f:
            return json.load(f)
    return {
        "enabled": False,
        "server_url": "",
        "bind_dn": "",
        "bind_password": "",
        "base_dn": "",
        "user_filter": "(uid={username})",
        "admin_group": "",
        "use_ssl": True,
        "port": 636,
    }


def save_ldap_config(config):
    os.makedirs(os.path.dirname(LDAP_CONFIG_FILE), exist_ok=True)
    with open(LDAP_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


@app.route("/admin/ldap")
@login_required
def ldap_config():
    config = load_ldap_config()
    return render_template("ldap.html", config=config)


@app.route("/admin/ldap/save", methods=["POST"])
@login_required
def ldap_save():
    config = {
        "enabled": "ldap_enabled" in request.form,
        "server_url": request.form.get("server_url", "").strip(),
        "bind_dn": request.form.get("bind_dn", "").strip(),
        "bind_password": request.form.get("bind_password", "").strip(),
        "base_dn": request.form.get("base_dn", "").strip(),
        "user_filter": request.form.get("user_filter", "(uid={username})").strip(),
        "admin_group": request.form.get("admin_group", "").strip(),
        "use_ssl": "use_ssl" in request.form,
        "port": int(request.form.get("port", 636)),
    }
    save_ldap_config(config)
    flash("Configuration LDAP sauvegardée.", "success")
    return redirect(url_for("ldap_config"))


@app.route("/admin/ldap/test", methods=["POST"])
@login_required
def ldap_test():
    config = load_ldap_config()
    results = []

    # Step 1: Check config
    if not config.get("server_url"):
        flash("Test echoue : URL du serveur LDAP non configuree.", "error")
        return redirect(url_for("ldap_config"))

    try:
        import ldap
    except ImportError:
        flash("Test echoue : module python-ldap non installe.", "error")
        return redirect(url_for("ldap_config"))

    server_url = config["server_url"]
    port = config.get("port", 389)
    use_ssl = config.get("use_ssl", False)

    # Build full URL
    if "://" not in server_url:
        proto = "ldaps" if use_ssl else "ldap"
        server_url = f"{proto}://{server_url}"
    if f":{port}" not in server_url:
        server_url = f"{server_url}:{port}"

    results.append(f"Connexion a {server_url}...")

    try:
        # Step 2: Connect
        conn = ldap.initialize(server_url)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        if use_ssl:
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        results.append("Connexion TCP/TLS etablie.")

        # Step 3: Bind
        bind_dn = config.get("bind_dn", "")
        bind_password = config.get("bind_password", "")

        if bind_dn:
            conn.simple_bind_s(bind_dn, bind_password)
            results.append(f"Bind reussi avec {bind_dn}.")
        else:
            conn.simple_bind_s("", "")
            results.append("Bind anonyme reussi.")

        # Step 4: Search base DN
        base_dn = config.get("base_dn", "")
        if base_dn:
            result = conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectClass=*)")
            if result:
                results.append(f"Base DN {base_dn} trouvee.")
            else:
                results.append(f"Base DN {base_dn} non trouvee.")

            # Step 5: Test user filter
            user_filter = config.get("user_filter", "(uid={username})")
            test_filter = user_filter.replace("{username}", "*")
            try:
                search_result = conn.search_ext_s(base_dn, ldap.SCOPE_SUBTREE, test_filter, ["dn"], sizelimit=5)
                count = len(search_result)
                results.append(f"Recherche utilisateurs : {count} entree(s) trouvee(s) (limite a 5).")
            except ldap.SIZELIMIT_EXCEEDED:
                results.append("Recherche utilisateurs : plus de 5 entrees trouvees (OK).")
            except ldap.FILTER_ERROR:
                results.append(f"Filtre utilisateur invalide : {test_filter}")

        conn.unbind_s()
        results.append("Test termine avec succes.")
        flash(" | ".join(results), "success")

    except ldap.SERVER_DOWN:
        results.append(f"ERREUR : impossible de se connecter a {server_url}. Verifiez l'URL et le port.")
        flash(" | ".join(results), "error")
    except ldap.INVALID_CREDENTIALS:
        results.append("ERREUR : identifiants Bind DN invalides.")
        flash(" | ".join(results), "error")
    except ldap.NO_SUCH_OBJECT:
        results.append(f"ERREUR : Base DN introuvable ({config.get('base_dn', '')}).")
        flash(" | ".join(results), "error")
    except Exception as e:
        results.append(f"ERREUR : {str(e)}")
        flash(" | ".join(results), "error")

    return redirect(url_for("ldap_config"))


# --- Backup / Restore ---

@app.route("/admin/backup")
@login_required
def backup():
    # Encode logos as base64
    logos = {}
    if os.path.isdir(LOGOS_DIR):
        for filename in os.listdir(LOGOS_DIR):
            filepath = os.path.join(LOGOS_DIR, filename)
            if os.path.isfile(filepath):
                with open(filepath, "rb") as img:
                    logos[filename] = base64.b64encode(img.read()).decode("ascii")

    data = {
        "routes": load_routes(),
        "tiles": load_tiles(),
        "logos": logos,
        "ldap_config": load_ldap_config(),
        "block_history": load_block_history(),
    }
    response = Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=reverseproxy_backup.json"}
    )
    return response


@app.route("/admin/restore", methods=["POST"])
@login_required
def restore():
    if "backup_file" not in request.files:
        flash("Aucun fichier fourni.", "error")
        return redirect(url_for("admin"))

    file = request.files["backup_file"]
    if not file or not file.filename:
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("admin"))

    try:
        data = json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError):
        flash("Fichier JSON invalide.", "error")
        return redirect(url_for("admin"))

    if "routes" in data:
        save_routes(data["routes"])
        generate_nginx_conf(data["routes"])
        reload_nginx()
    if "tiles" in data:
        save_tiles(data["tiles"])
    if "logos" in data:
        os.makedirs(LOGOS_DIR, exist_ok=True)
        for filename, b64data in data["logos"].items():
            filepath = os.path.join(LOGOS_DIR, filename)
            with open(filepath, "wb") as img:
                img.write(base64.b64decode(b64data))
    if "ldap_config" in data:
        save_ldap_config(data["ldap_config"])
    if "block_history" in data:
        save_block_history(data["block_history"])

    flash("Restauration effectuée avec succès.", "success")
    return redirect(url_for("admin"))


# --- Certificates ---

def get_cert_info():
    """Read current certificate info via openssl."""
    cert_path = os.path.join(CERTS_DIR, "selfsigned.crt")
    if not os.path.exists(cert_path):
        return None
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout",
             "-subject", "-issuer", "-dates", "-fingerprint"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            info = {}
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    if key == "subject":
                        info["subject"] = val.strip()
                    elif key == "issuer":
                        info["issuer"] = val.strip()
                    elif key == "notBefore":
                        info["not_before"] = val.strip()
                    elif key == "notAfter":
                        info["not_after"] = val.strip()
                    elif "Fingerprint" in key:
                        info["fingerprint"] = val.strip()
            return info
    except Exception:
        pass
    return None


def load_letsencrypt_config():
    if os.path.exists(LETSENCRYPT_CONFIG_FILE):
        with open(LETSENCRYPT_CONFIG_FILE) as f:
            return json.load(f)
    return {
        "enabled": False,
        "domain": "",
        "email": "",
        "auto_renew": True,
    }


def save_letsencrypt_config(config):
    os.makedirs(os.path.dirname(LETSENCRYPT_CONFIG_FILE), exist_ok=True)
    with open(LETSENCRYPT_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


@app.route("/admin/certs")
@login_required
def certs():
    cert_info = get_cert_info()
    le_config = load_letsencrypt_config()
    return render_template("certs.html", cert_info=cert_info, le_config=le_config)


@app.route("/admin/certs/selfsigned", methods=["POST"])
@login_required
def certs_selfsigned():
    cn = request.form.get("cn", "localhost").strip() or "localhost"
    days = request.form.get("days", "3650").strip() or "3650"
    try:
        days_int = int(days)
        if days_int < 1:
            days_int = 3650
    except ValueError:
        days_int = 3650

    os.makedirs(CERTS_DIR, exist_ok=True)
    key_path = os.path.join(CERTS_DIR, "selfsigned.key")
    cert_path = os.path.join(CERTS_DIR, "selfsigned.crt")

    try:
        subprocess.run([
            "openssl", "req", "-x509", "-nodes",
            "-days", str(days_int),
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-subj", f"/C=FR/ST=Local/L=Local/O=ReverseProxy/CN={cn}"
        ], check=True, capture_output=True, text=True)
        reload_nginx()
        flash(f"Certificat auto-signe genere pour CN={cn} ({days_int} jours).", "success")
    except subprocess.CalledProcessError as e:
        flash(f"Erreur lors de la generation : {e.stderr}", "error")

    return redirect(url_for("certs"))


@app.route("/admin/certs/upload", methods=["POST"])
@login_required
def certs_upload():
    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")

    if not cert_file or not cert_file.filename:
        flash("Fichier certificat (.crt/.pem) requis.", "error")
        return redirect(url_for("certs"))
    if not key_file or not key_file.filename:
        flash("Fichier cle privee (.key/.pem) requis.", "error")
        return redirect(url_for("certs"))

    os.makedirs(CERTS_DIR, exist_ok=True)
    cert_path = os.path.join(CERTS_DIR, "selfsigned.crt")
    key_path = os.path.join(CERTS_DIR, "selfsigned.key")

    cert_file.save(cert_path)
    key_file.save(key_path)

    # Verify the certificate is valid
    try:
        subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout"],
            check=True, capture_output=True, text=True
        )
        subprocess.run(
            ["openssl", "rsa", "-in", key_path, "-check", "-noout"],
            check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError:
        flash("Certificat ou cle privee invalide. Verifiez vos fichiers.", "error")
        return redirect(url_for("certs"))

    ok, msg = reload_nginx()
    if ok:
        flash("Certificat public importe avec succes.", "success")
    else:
        flash(f"Certificat importe mais erreur Nginx : {msg}", "error")

    return redirect(url_for("certs"))


@app.route("/admin/certs/letsencrypt", methods=["POST"])
@login_required
def certs_letsencrypt_save():
    config = {
        "enabled": "le_enabled" in request.form,
        "domain": request.form.get("le_domain", "").strip(),
        "email": request.form.get("le_email", "").strip(),
        "auto_renew": "le_auto_renew" in request.form,
    }
    save_letsencrypt_config(config)
    flash("Configuration Let's Encrypt sauvegardee.", "success")
    return redirect(url_for("certs"))


# Generate nginx conf at module load (works with gunicorn too)
generate_nginx_conf(load_routes())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
