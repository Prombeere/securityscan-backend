FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

EXPOSE $PORT

CMD gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 app:app
