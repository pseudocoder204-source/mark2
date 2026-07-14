FROM alpine:latest

# curl needed to install trivy/nuclei; python3 + pip for agents;
# clamav for malware scanning (clamscan + freshclam only — clamav_parser.py deliberately
# never starts clamd, so the daemon package is not installed)
RUN apk add --no-cache bash python3 py3-pip curl unzip clamav

# ── Nmap is deliberately NOT bundled ──────────────────────────────────────────
# Nmap is licensed under the NPSL (https://nmap.org/npsl/), not a standard open
# source license. Redistributing the Nmap binary exercises rights the NPSL grants,
# which drags the redistributed work under the NPSL's terms and — for a commercial
# or proprietary product — requires an Nmap OEM license.
#
# Merely *executing* an Nmap that the end user already installed, and parsing its
# output, is expressly carved out by the NPSL ("Licensor does not purport to
# control ... any software which does not require the rights granted herein").
# So mark2 shells out to a host-provided Nmap and ships none of its own.
# nmap_parser.py finds it via bin_resolver.resolve() → $NMAP_BINARY, then $PATH.
#
# For LOCAL use only, you may build an image with Nmap baked in:
#     docker build --build-arg INSTALL_NMAP=true -t mark2 .
#
# Building such an image for your own use is not redistribution. PUBLISHING it —
# to Docker Hub, any registry, or any third party — IS redistribution, and needs
# an Nmap OEM license (licensing@nmap.com). The default is `false` so that the
# image this Dockerfile produces is safe to share.
ARG INSTALL_NMAP=false
RUN if [ "$INSTALL_NMAP" = "true" ]; then \
        echo "[mark2] Bundling Nmap — this image MUST NOT be redistributed (NPSL)." && \
        apk add --no-cache nmap nmap-scripts; \
    else \
        echo "[mark2] Nmap not bundled. Mount or install it at runtime; see README."; \
    fi

# Seed virus definitions at build time so the first container run isn't stuck downloading
# ~200MB+ before it can scan anything. Best-effort: some sandboxed build environments block
# outbound network, so a failure here just means the first freshclam at runtime does the work.
RUN freshclam --quiet || true

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -version \
    && nuclei -update-templates

# Lynis has no binary release assets; install from the source archive.
RUN LYNIS_VERSION=$(curl -s https://api.github.com/repos/CISOfy/lynis/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VERSION}.tar.gz" \
       -o /tmp/lynis.tar.gz \
    && tar xzf /tmp/lynis.tar.gz -C /usr/local/ \
    && mv /usr/local/lynis-${LYNIS_VERSION} /usr/local/lynis \
    && ln -s /usr/local/lynis/lynis /usr/local/bin/lynis \
    && rm /tmp/lynis.tar.gz \
    && lynis --version

# Create a virtual environment so pip installs don't conflict with system packages
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

# Runtime config — override at docker run time with -e
ENV TARGET=127.0.0.1
# NVD_API_KEY is intentionally left unset here — pass it at `docker run -e NVD_API_KEY=...`
# time. Never bake a real key into the image; without one, NVD sync just rate-limits harder.
ENV LLM_PROVIDER=ollama
# Matches agent.DEFAULT_OLLAMA_MODEL. Ollama runs on the host, so the host must have
# pulled this model (`ollama pull pseudocoder204/mark2-report`) for the report stage to work.
ENV OLLAMA_MODEL=pseudocoder204/mark2-report
# Ollama runs on the HOST, not in this container.
# Docker Desktop: host.docker.internal works out of the box.
# Linux (non-Desktop): use --network=host and set OLLAMA_HOST=http://localhost:11434
ENV OLLAMA_HOST=http://host.docker.internal:11434
ENV DB_PATH=/vulnerability_cache.db
# clamav_manifest.db is deliberately NOT baked into the image like vulnerability_cache.db is —
# it's per-host scan state (which files have been seen) and is meant to be bind-mounted from a
# persistent path on the host so it survives across --rm container runs.
ENV CLAMAV_MANIFEST_DB=/clamav_manifest.db

COPY entrypoint.sh          /entrypoint.sh
COPY nmap_parser.py         /nmap_parser.py
COPY nmap_subgraph.py       /nmap_subgraph.py
COPY trivy_parser.py        /trivy_parser.py
COPY trivy_subgraph.py      /trivy_subgraph.py
COPY nuclei_parser.py       /nuclei_parser.py
COPY nuclei_subgraph.py     /nuclei_subgraph.py
COPY lynis_parser.py        /lynis_parser.py
COPY lynis_subgraph.py      /lynis_subgraph.py
COPY clamav_parser.py       /clamav_parser.py
COPY clamav_subgraph.py     /clamav_subgraph.py
COPY tools.py               /tools.py
COPY agent.py               /agent.py
COPY vulnerability_cache.db /vulnerability_cache.db
COPY display_graph.py       /display_graph.py

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
