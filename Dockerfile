FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/kingenbomb/Nodes" \
      org.opencontainers.image.revision="1216835354d0c68b768b59ce137b75f40fe3e9ac" \
      org.opencontainers.image.version="1216835-yunxin4-dashboard"

ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DISPLAY=:99

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        fonts-noto-cjk \
        xauth \
        xvfb \
    && ln -sf /usr/bin/chromium /usr/bin/google-chrome \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . ./
RUN mkdir -p /app/account /app/node /app/web-data

COPY entrypoint.sh /usr/local/bin/nodes-entrypoint
RUN chmod 755 /usr/local/bin/nodes-entrypoint

ENTRYPOINT ["/usr/local/bin/nodes-entrypoint"]
CMD ["python", "proxyscrape_register.py"]
