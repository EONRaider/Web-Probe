# python:3.9.6-slim-buster
# https://hub.docker.com/layers/python/library/python/3.9.6-slim-buster/images/sha256-ab2e6f2a33c44bd0cda2138a8308ca45145edd21ba80a125c9df57c46a255839?context=explore
FROM python@sha256:ab2e6f2a33c44bd0cda2138a8308ca45145edd21ba80a125c9df57c46a255839

LABEL org.label-schema.schema-version = "1.0"
LABEL org.label-schema.name = "eonraider/webprobe:latest"
LABEL org.label-schema.url="https://github.com/EONRaider/Web-Probe"
LABEL org.label-schema.docker.cmd.help = "docker run -it eonraider/webprobe:latest --help"

RUN useradd webprobe

WORKDIR /webprobe

COPY requirements.txt src ./

RUN apt update -y \
    && apt install -y python3-dev build-essential \
    && pip install --upgrade pip \
    && pip3 install --no-cache-dir -r requirements.txt

USER webprobe

ENTRYPOINT ["python3", "webprobe.py"]