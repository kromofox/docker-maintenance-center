FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Asia/Shanghai
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 maintenance \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin maintenance
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock
COPY maintenance_center /app/maintenance_center
COPY LICENSE /app/LICENSE
COPY third_party /app/third_party
USER 10001:10001
EXPOSE 8767
ENTRYPOINT ["python", "-m", "maintenance_center.web"]
CMD ["--state-dir", "/state", "--runtime-config", "/config/runtime.json", "--telegram-key", "/run/secrets/telegram.key"]
