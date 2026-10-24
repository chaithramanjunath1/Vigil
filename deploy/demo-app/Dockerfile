# The instrumented demo microservice. Build from the repo root:
#   docker build -f deploy/demo-app/Dockerfile -t vigil-demo-app .
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY deploy/demo-app/app.py .
USER 10001
EXPOSE 8080
CMD ["python", "app.py"]
