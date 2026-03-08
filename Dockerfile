# Vigil v1.0 — Ubuntu 24.04 + Node.js 22 + Security Tools
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates git openssh-client bash sudo \
    python3 make g++ \
    procps htop net-tools iproute2 lsb-release \
    # Security tools
    nmap nikto dnsutils whois \
    openssl libssl-dev \
    cron \
    && rm -rf /var/lib/apt/lists/*

# PostgreSQL 17 client
RUN sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list' && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg && \
    apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 && \
    rm -rf /var/lib/apt/lists/*

# Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Docker CLI
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# Nuclei scanner
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_linux_amd64.zip -o /tmp/nuclei.zip 2>/dev/null && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ 2>/dev/null && rm -f /tmp/nuclei.zip || true

# Trivy scanner
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true

# AI CLIs (BYOK) — install globally + symlink to /usr/local/bin
RUN npm install -g @anthropic-ai/claude-code @openai/codex 2>/dev/null || true && \
    NPM_BIN=$(npm prefix -g)/bin && \
    for bin in claude codex; do \
      [ -f "$NPM_BIN/$bin" ] && [ ! -f "/usr/local/bin/$bin" ] && ln -sf "$NPM_BIN/$bin" /usr/local/bin/$bin; \
    done; true

# Non-root user
RUN useradd -m -s /bin/bash -G sudo vigil && \
    echo 'vigil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY server.js ./
COPY routes/ ./routes/
COPY lib/ ./lib/
COPY data/ ./data/
COPY docs/ ./docs/
COPY public/ ./public/

RUN mkdir -p /app/data/reports /app/data/backups && chown -R vigil:vigil /app

ENV NODE_ENV=production
ENV VIGIL_PORT=4100

EXPOSE 4100

USER vigil

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -sf http://localhost:4100/api/health || exit 1

CMD ["node", "server.js"]
