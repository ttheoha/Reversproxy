FROM nginx:1.27-alpine

# Install Python and pip
RUN apk add --no-cache python3 py3-pip supervisor openssl expat expat-dev \
    openldap-dev gcc musl-dev python3-dev

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application
COPY app/ /app/

# Copy nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Create directories
RUN mkdir -p /etc/nginx/conf.d /data/certs /data/logos

# Copy initial self-signed certs
COPY certs/ /data/certs/

# Remove default nginx config, create empty proxy.conf
RUN rm -f /etc/nginx/conf.d/default.conf && \
    echo "# No routes configured" > /etc/nginx/conf.d/proxy.conf

# Entrypoint script to ensure certs exist
RUN printf '#!/bin/sh\n\
mkdir -p /data/certs\n\
if [ ! -f /data/certs/selfsigned.crt ] || [ ! -f /data/certs/selfsigned.key ]; then\n\
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \\\n\
    -keyout /data/certs/selfsigned.key \\\n\
    -out /data/certs/selfsigned.crt \\\n\
    -subj "/C=FR/ST=Local/L=Local/O=ReverseProxy/CN=localhost"\n\
fi\n\
# Generate nginx proxy conf from routes before starting services\n\
cd /app && python3 -c "from app import generate_nginx_conf, load_routes; generate_nginx_conf(load_routes())"\n\
exec "$@"\n' > /entrypoint.sh && chmod +x /entrypoint.sh

# Supervisor config to run both nginx and flask
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
