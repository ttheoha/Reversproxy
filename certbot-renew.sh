#!/bin/sh
# Script de renouvellement automatique des certificats Let's Encrypt
# Execute toutes les 12 heures par supervisord

LOG_DIR="/var/log/reverseproxy"
mkdir -p "$LOG_DIR"

LE_CONFIG="/data/letsencrypt_config.json"

# Verifier si Let's Encrypt est configure
if [ ! -f "$LE_CONFIG" ]; then
    exit 0
fi

AUTO_RENEW=$(python3 -c "import json; print(json.load(open('$LE_CONFIG')).get('auto_renew', False))" 2>/dev/null || echo "False")
DOMAINS=$(python3 -c "
import json
data = json.load(open('$LE_CONFIG'))
for d in data.get('domains', []):
    print(d['domain'])
" 2>/dev/null)

if [ "$AUTO_RENEW" != "True" ] || [ -z "$DOMAINS" ]; then
    exit 0
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Tentative de renouvellement Let's Encrypt" >> "$LOG_DIR/certbot.log"

# Renouveler tous les certificats existants
certbot renew --webroot -w /var/www/certbot --quiet --no-random-sleep-on-renew 2>>"$LOG_DIR/certbot.log"
RESULT=$?

if [ $RESULT -eq 0 ]; then
    # Regenerer les configs nginx pour pointer vers les bons certs
    cd /app && python3 -c "from app import generate_nginx_conf, load_routes; generate_nginx_conf(load_routes())" 2>>"$LOG_DIR/certbot.log"

    # Recharger Nginx
    nginx -s reload 2>>"$LOG_DIR/certbot.log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Renouvellement termine, Nginx recharge." >> "$LOG_DIR/certbot.log"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Echec du renouvellement (code $RESULT)." >> "$LOG_DIR/certbot.log"
fi
