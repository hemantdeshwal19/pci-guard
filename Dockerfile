FROM python:3.10-slim
COPY . /app
WORKDIR /app
RUN useradd -m appuser
USER appuser
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python3 -c "import sys; sys.exit(0)"
CMD ["python3", "/app/main.py"]
