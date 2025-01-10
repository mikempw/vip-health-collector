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
vip-health-collector:
    build:
      context: ./vip-health-collector
      dockerfile: Dockerfile
    container_name: vip-health-collector
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - GRAFANA_URL=http://grafana:3000     # Use service name instead of IP
      - PROMETHEUS_URL=http://prometheus:9090 # Use service name instead of IP
    env_file:
      - ".env"
    volumes:
      - ./vip-health-collector/config:/app/config
    networks:
      - 7lc_network
    depends_on:
      - grafana
      - prometheus
```

