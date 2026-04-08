import json
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

CONFIG_FILE = "/data/routes.json"


def load_routes():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return []


def save_routes(routes):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(routes, f, indent=2)


def generate_nginx_conf(routes):
    """Generate nginx upstream config from routes."""
    conf_path = "/etc/nginx/conf.d/proxy.conf"
    lines = []
    for route in routes:
        domain = route["domain"]
        target = route["target"]
        listen_port = route.get("listen_port", "443")
        lines.append(f"""server {{
    listen {listen_port} ssl;
    server_name {domain};

    ssl_certificate /etc/nginx/certs/selfsigned.crt;
    ssl_certificate_key /etc/nginx/certs/selfsigned.key;

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


@app.route("/")
def index():
    routes = load_routes()
    return render_template("index.html", routes=routes)


@app.route("/add", methods=["POST"])
def add_route():
    domain = request.form.get("domain", "").strip()
    target = request.form.get("target", "").strip()
    listen_port = request.form.get("listen_port", "443").strip()

    if not domain or not target:
        flash("Le domaine et la cible sont obligatoires.", "error")
        return redirect(url_for("index"))

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
    return redirect(url_for("index"))


@app.route("/delete/<int:route_id>", methods=["POST"])
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
    return redirect(url_for("index"))


@app.route("/edit/<int:route_id>", methods=["POST"])
def edit_route(route_id):
    routes = load_routes()
    if 0 <= route_id < len(routes):
        domain = request.form.get("domain", "").strip()
        target = request.form.get("target", "").strip()
        listen_port = request.form.get("listen_port", "443").strip()

        if not domain or not target:
            flash("Le domaine et la cible sont obligatoires.", "error")
            return redirect(url_for("index"))

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
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Ensure proxy.conf exists on startup
    generate_nginx_conf(load_routes())
    app.run(host="0.0.0.0", port=5000)
