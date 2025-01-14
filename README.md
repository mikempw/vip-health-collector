# vip-health-collector
Health status for integration within the AST tool
```
Folder structure and files to modify:
application-study-tool
    docker-compose.yaml (modify it - example below)
    .env (modify it - example below)
    vip-health-collector (make the folder)
          Dockerfile
          vip_health_collector.py
          requirements.txt
          config (make the folder)
              config.json
```
```
1. Create an admin user in Grafana and insert the token into the GRAFANA_TOKEN .env variable
2. mkdir -p application-study-tool/vip-health-collector/config
   chmod 755 vip-health-collector
3. Add all the appropriate files
4. docker compose build vip-health-collector
```

Modify the existing AST .env file
Example:
root@docker:/home/mike/application-study-tool# cat .env
```
# Grafana Environment Variables
# These should be updated to more secure values outside of testing environments.
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=admin

# Optional Parameters Required for metrics export to F5 DataFabric
SENSOR_SECRET_TOKEN="YOUR_TOKEN"
SENSOR_ID="YOUR_ID"

# Grafana API key to run config helpers
GRAFANA_TOKEN=glsa_blahblahblah
```
Modify the AST docker-compose.yaml with the following additional content
```
version: '3'
volumes:
  prometheus:
  grafana:
  clickhouse-data:

services:
  prometheus:
    image: prom/prometheus:v2.54.1
    container_name: prometheus
    restart: unless-stopped
    stop_grace_period: 5m
    volumes:
      - ./services/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--enable-feature=otlp-write-receiver'
      - '--storage.tsdb.retention.time=1y'
    ports:
      - 9090:9090
    networks:
      - 7lc_network

  otel-collector:
    image: ghcr.io/f5devcentral/application-study-tool/otel_custom_collector:v0.7.0
    container_name: otel-collector
    restart: unless-stopped
    volumes:
      - ./services/otel_collector:/etc/otel-collector-config
    command:
      - "--config=/etc/otel-collector-config/defaults/bigip-scraper-config.yaml"
    env_file:
      - ".env"
      - ".env.device-secrets"
    networks:
      - 7lc_network

  grafana:
    image: grafana/grafana:11.2.0
    container_name: grafana
    restart: unless-stopped
    ports:
      - 3000:3000
    volumes:
      - grafana:/var/lib/grafana
      - ./services/grafana/provisioning/:/etc/grafana/provisioning
      - ./services/grafana/dashboards:/etc/grafana/dashboards
    environment:
      - GF_INSTALL_PLUGINS=grafana-clickhouse-datasource
    env_file: 
      - ".env"
    networks:
      - 7lc_network

  clickhouse:
    image: clickhouse/clickhouse-server
    container_name: clickhouse
    restart: unless-stopped
    ports:
      - "8123:8123"  # HTTP interface
      - "9000:9000"  # Native interface
    volumes:
      - clickhouse-data:/var/lib/clickhouse
    environment:
      - CLICKHOUSE_DB=vip_health
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
    networks:
      - 7lc_network

  vip-health-collector:
    build:
      context: ./vip-health-collector
      dockerfile: Dockerfile
    container_name: vip-health-collector
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - GRAFANA_URL=http://grafana:3000
      - PROMETHEUS_URL=http://prometheus:9090
      - CLICKHOUSE_HOST=clickhouse
    env_file:
      - ".env"
    volumes:
      - ./vip-health-collector/config:/app/config
    networks:
      - 7lc_network
    depends_on:
      - grafana
      - prometheus
      - clickhouse

networks:
  7lc_network:
```

