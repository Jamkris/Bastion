FROM python:3.12-slim

# 호스트 방화벽/차단 상태를 읽기 위한 CLI들:
#   nftables      → nft
#   iproute2      → ss
#   fail2ban      → fail2ban-client (호스트 소켓과 통신)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 fail2ban \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bastion ./bastion

EXPOSE 8009
CMD ["uvicorn", "bastion.web.app:app", "--host", "0.0.0.0", "--port", "8009"]
