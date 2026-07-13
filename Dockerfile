FROM python:3.11-slim-bookworm

ARG NIKTO_VERSION=2.5.0
ARG NUCLEI_VERSION=3.9.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        libio-socket-ssl-perl \
        libmagic1 \
        libnet-ssleay-perl \
        nmap \
        openssl \
        perl \
        testssl.sh \
        unzip \
    && ln -sf /usr/bin/testssl /usr/local/bin/testssl.sh \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "${VIRTUAL_ENV}"

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) nuclei_arch="amd64" ;; \
        arm64) nuclei_arch="arm64" ;; \
        *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/nikto.tar.gz "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" \
    && mkdir -p /opt/nikto \
    && tar -xzf /tmp/nikto.tar.gz --strip-components=1 -C /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto.pl \
    && chmod +x /opt/nikto/program/nikto.pl /usr/local/bin/nikto /usr/local/bin/nikto.pl \
    && rm -f /tmp/nikto.tar.gz \
    && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip" \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && mkdir -p "${NUCLEI_TEMPLATES_DIR}"

COPY docker/zircon-entrypoint.sh /usr/local/bin/zircon-entrypoint.sh
COPY docker/verify-vuln-tools.sh /usr/local/bin/verify-vuln-tools
RUN chmod +x /usr/local/bin/zircon-entrypoint.sh /usr/local/bin/verify-vuln-tools

COPY . /app

EXPOSE 8181 8443

ENTRYPOINT ["zircon-entrypoint.sh"]
CMD ["python", "start.py"]
