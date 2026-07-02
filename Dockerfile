FROM ubuntu:20.04
RUN apt-get update
COPY . /app
CMD ["python3", "/app/main.py"]
