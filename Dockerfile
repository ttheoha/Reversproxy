FROM nginx:1.27-alpine

# Install Python and pip
RUN apk add --no-cache python3 py3-pip supervisor openssl expat expat-dev \
    openldap-dev gcc musl-dev python3-dev certbot

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages certbot-dns-ovh

# Copy application
COPY app/ /app/

# Copy nginx config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Create directories
RUN mkdir -p /etc/nginx/conf.d /data/certs /data/logos /var/www/certbot

# Copy initial self-signed certs
COPY certs/ /data/certs/

# Remove default nginx config, create empty proxy.conf
RUN rm -f /etc/nginx/conf.d/default.conf && \
    echo "# No routes configured" > /etc/nginx/conf.d/proxy.conf

# Entrypoint and certbot renewal scripts
COPY entrypoint.sh /entrypoint.sh
COPY certbot-renew.sh /certbot-renew.sh
RUN chmod +x /entrypoint.sh /certbot-renew.sh

# Supervisor config to run both nginx and flask
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
