FROM nginx:1.27-alpine

# Install Python and pip
RUN apk add --no-cache python3 py3-pip supervisor

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
RUN mkdir -p /etc/nginx/conf.d /data /etc/nginx/certs

# Create empty proxy.conf
RUN echo "# No routes configured" > /etc/nginx/conf.d/proxy.conf

# Supervisor config to run both nginx and flask
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 80 443

CMD ["supervisord", "-c", "/etc/supervisord.conf"]
