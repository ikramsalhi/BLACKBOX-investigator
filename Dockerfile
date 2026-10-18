FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd -r -m -u 10001 blackbox
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /var/lib/blackbox && chown -R blackbox:blackbox /var/lib/blackbox
USER blackbox
ENV BLACKBOX_DATA_DIR=/var/lib/blackbox
EXPOSE 8000
CMD ["sh","deploy_bootstrap.sh"]
