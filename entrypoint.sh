#!/bin/sh
set -e

LOG_DIR="/var/log/reverseproxy"
mkdir -p /data/certs /data/logos /var/www/certbot \
         /etc/nginx/sites-available /etc/nginx/sites-enabled \
         /etc/letsencrypt "$LOG_DIR"

# Replace default nginx symlinks (/dev/stdout, /dev/stderr) with real files
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log

# ── Couleurs ──
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo ""
    echo "${CYAN}============================================${NC}"
    echo "${CYAN}   Reverse Proxy Manager — Demarrage${NC}"
    echo "${CYAN}============================================${NC}"
    echo ""
}

# ── 1. Certificats auto-signes par defaut ──
ensure_certs() {
    if [ ! -f /data/certs/selfsigned.crt ] || [ ! -f /data/certs/selfsigned.key ]; then
        echo "${YELLOW}[CERTS]${NC} Aucun certificat trouve, generation d'un certificat auto-signe..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout /data/certs/selfsigned.key \
            -out /data/certs/selfsigned.crt \
            -subj "/C=FR/ST=Local/L=Local/O=ReverseProxy/CN=localhost" \
            2>/dev/null
        echo "${GREEN}[CERTS]${NC} Certificat auto-signe genere avec succes."
    fi
}

# ── 2. Verification du certificat global ──
check_cert_validity() {
    CERT="/data/certs/selfsigned.crt"
    if [ ! -f "$CERT" ]; then
        echo "${RED}[CERTS]${NC} Certificat global introuvable : $CERT"
        return
    fi

    SUBJECT=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/subject=//')
    ISSUER=$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    NOT_AFTER=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')

    echo "${GREEN}[CERTS]${NC} Certificat global (fallback) :"
    echo "         Sujet    : ${SUBJECT}"
    echo "         Emetteur : ${ISSUER}"
    echo "         Expire   : ${NOT_AFTER}"

    if openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1; then
        if ! openssl x509 -in "$CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
            echo "${YELLOW}[CERTS]${NC} ATTENTION : Le certificat global expire dans moins de 30 jours !"
        else
            echo "${GREEN}[CERTS]${NC} Certificat global valide."
        fi
    else
        echo "${RED}[CERTS]${NC} ERREUR : Le certificat global a expire !"
    fi
}

# ── 3. Verification des certificats Let's Encrypt ──
check_le_certs() {
    LE_CONFIG="/data/letsencrypt_config.json"
    if [ ! -f "$LE_CONFIG" ]; then
        return
    fi

    DOMAINS=$(python3 -c "
import json
data = json.load(open('$LE_CONFIG'))
for d in data.get('domains', []):
    print(d['domain'])
" 2>/dev/null)

    if [ -z "$DOMAINS" ]; then
        echo "${YELLOW}[LE]${NC} Aucun domaine Let's Encrypt configure."
        return
    fi

    echo "${CYAN}[LE]${NC} Verification des certificats Let's Encrypt :"
    echo "$DOMAINS" | while IFS= read -r DOMAIN; do
        [ -z "$DOMAIN" ] && continue
        # Wildcard certs are stored under the base domain name
        CERT_NAME="$DOMAIN"
        case "$DOMAIN" in \*.*) CERT_NAME="${DOMAIN#\*.}" ;; esac
        LE_CERT="/etc/letsencrypt/live/$CERT_NAME/fullchain.pem"
        if [ -f "$LE_CERT" ]; then
            NOT_AFTER=$(openssl x509 -in "$LE_CERT" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
            if openssl x509 -in "$LE_CERT" -noout -checkend 0 >/dev/null 2>&1; then
                if ! openssl x509 -in "$LE_CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
                    echo "  ${YELLOW}$DOMAIN${NC} — expire bientot ($NOT_AFTER)"
                else
                    echo "  ${GREEN}$DOMAIN${NC} — valide (expire $NOT_AFTER)"
                fi
            else
                echo "  ${RED}$DOMAIN${NC} — EXPIRE !"
            fi
        else
            echo "  ${YELLOW}$DOMAIN${NC} — certificat introuvable"
        fi
    done
}

# ── 4. Ecriture du fichier credentials OVH si configure ──
setup_ovh_credentials() {
    LE_CONFIG="/data/letsencrypt_config.json"
    if [ -f "$LE_CONFIG" ]; then
        python3 -c "
import json, os
data = json.load(open('$LE_CONFIG'))
ovh = data.get('ovh', {})
if ovh.get('application_key') and ovh.get('application_secret') and ovh.get('consumer_key'):
    ini = f\"\"\"dns_ovh_endpoint = {ovh.get('endpoint', 'ovh-eu')}
dns_ovh_application_key = {ovh['application_key']}
dns_ovh_application_secret = {ovh['application_secret']}
dns_ovh_consumer_key = {ovh['consumer_key']}
\"\"\"
    with open('/data/ovh-credentials.ini', 'w') as f:
        f.write(ini)
    os.chmod('/data/ovh-credentials.ini', 0o600)
    print('OVH credentials INI ecrit.')
else:
    print('OVH credentials non configures.')
" 2>/dev/null
        echo "${GREEN}[OVH]${NC} Fichier credentials verifie."
    fi
}

# ── 5. Generation de la config Nginx depuis les routes ──
generate_configs() {
    echo "${CYAN}[NGINX]${NC} Generation de la configuration des sites..."
    cd /app && python3 -c "from app import generate_nginx_conf, load_routes; generate_nginx_conf(load_routes())"
    echo "${GREEN}[NGINX]${NC} Configuration des sites generee."
}

# ── 5. Verification de la config Nginx ──
check_nginx() {
    echo "${CYAN}[NGINX]${NC} Verification de la configuration..."
    if nginx -t 2>"$LOG_DIR/nginx-check.log"; then
        echo "${GREEN}[NGINX]${NC} Configuration valide."
    else
        echo "${RED}[NGINX]${NC} ERREUR dans la configuration Nginx :"
        cat "$LOG_DIR/nginx-check.log"
        echo "${YELLOW}[NGINX]${NC} Demarrage avec la configuration par defaut..."
    fi
}

# ── Execution ──
banner
ensure_certs
check_cert_validity
check_le_certs
setup_ovh_credentials
generate_configs
check_nginx

echo ""
echo "${GREEN}[START]${NC} Demarrage des services (Nginx + Flask + Certbot renewal)..."
echo "${CYAN}============================================${NC}"
echo ""

exec "$@"
