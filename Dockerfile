# Image: python:3.9.6-slim-buster
FROM python@sha256:ab2e6f2a33c44bd0cda2138a8308ca45145edd21ba80a125c9df57c46a255839 as build

LABEL org.label-schema.schema-version = "1.0"
LABEL org.label-schema.name = "eonraider/webprobe:latest"
LABEL org.label-schema.url="https://github.com/EONRaider/Web-Probe"
LABEL org.label-schema.docker.cmd.help = "docker run -it eonraider/webprobe:latest --help"

RUN apt update \
    && apt upgrade -y \
    && apt install -y python3-dev build-essential

ENV VIRTUAL_ENV=/tmp/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt


# Image: python:3.9.6-alpine3.14
FROM python@sha256:3e7e8a57a959c393797f0c90fa7b0fdbf7a40c4a274028e3f28a4f33d4783866

WORKDIR /home/webprobe

RUN adduser \
    --home "$(pwd)" \
    --gecos "" \
    --disabled-password \
    webprobe

COPY --from=build /tmp/venv .venv/
COPY src src/

USER webprobe
ENV PYTHONPATH=/home/webprobe
ENTRYPOINT [".venv/bin/python3", "src/webprobe.py"]