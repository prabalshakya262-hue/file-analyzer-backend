FROM python:3.10-slim

WORKDIR /app

# Install hardening tools (optional but recommended)
RUN apt-get update && apt-get install -y --no-install-recommends \
    apktool \
    osslsigncode \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

CMD ["/app/entrypoint.sh"]