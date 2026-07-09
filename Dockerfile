FROM python:3.12-slim

# CLIs needed to read host firewall/ban state:
#   nftables  -> nft
#   iproute2  -> ss
#   fail2ban  -> fail2ban-client (talks to the host socket)
# curl/ca-certificates are used to fetch the GeoIP database at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nftables iproute2 fail2ban curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Fetch the free DB-IP IP-to-Country database (CC BY 4.0, no account).
# Non-fatal: if the download fails the app still runs, just without countries.
COPY scripts/download-geoip.sh /usr/local/bin/download-geoip.sh
RUN chmod +x /usr/local/bin/download-geoip.sh \
    && /usr/local/bin/download-geoip.sh /geoip/dbip-country-lite.mmdb || echo "GeoIP download skipped"
ENV BASTION_GEOIP_DB=/geoip/dbip-country-lite.mmdb

COPY bastion ./bastion

EXPOSE 8009
CMD ["uvicorn", "bastion.web.app:app", "--host", "0.0.0.0", "--port", "8009"]
