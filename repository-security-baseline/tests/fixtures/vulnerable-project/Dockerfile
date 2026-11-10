# Deliberately insecure Dockerfile for the security baseline self-test. Do not use.
FROM python:latest
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD ["python", "-m", "http.server"]
