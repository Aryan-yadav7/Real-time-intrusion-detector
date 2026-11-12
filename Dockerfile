FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    GUARD_DB=/data/guard.db

RUN mkdir -p /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ids /app/ids

EXPOSE 9000

VOLUME ["/data"]

CMD ["uvicorn", "ids.platform_app:create_app", "--factory", "--host", "0.0.0.0", "--port", "9000"]

