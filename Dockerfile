# NetAtlas – IT-inventarie med planritningar, nätverksskanning och krypterade lösenord.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETATLAS_DATA_DIR=/data \
    PORT=8770 \
    PUID=99 \
    PGID=100 \
    TZ=Europe/Stockholm

# ping (skanning och Live), ssh (import av rutiner), openssl (självsignerat certifikat)
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping openssh-client openssl tzdata \
 && rm -rf /var/lib/apt/lists/*

# Appen körs som en vanlig användare. 99:100 = nobody:users, som Unraid använder för appdata (ändras med PUID/PGID).
RUN useradd --uid 99 --gid 100 --home-dir /data/home --no-create-home --shell /usr/sbin/nologin netatlas

WORKDIR /app

# beroenden i ett eget lager så att de cachas mellan byggen
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY netatlas-helper.py netatlas.html ./
COPY server/ ./server/
RUN python server/strip_plans.py netatlas.html \
 && chmod 755 server/entrypoint.sh \
 && python -m compileall -q server netatlas-helper.py

VOLUME ["/data"]
EXPOSE 8770
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 CMD ["python", "-m", "server.healthcheck"]
ENTRYPOINT ["/app/server/entrypoint.sh"]
