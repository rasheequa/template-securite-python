FROM python:3.12-slim-bookworm

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

# Outils système : build, libmagic (python-magic), libpcap/tcpdump (scapy),
# tesseract (OCR), outils réseau de base, setcap pour les capabilities.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential \
        libmagic1 libpcap0.8 tcpdump \
        tesseract-ocr \
        iproute2 iputils-ping dnsutils netcat-openbsd nmap \
        file binutils xxd less vim \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Poetry + pre-commit, installés via pipx (isolés du projet)
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir pipx \
    && pipx install poetry \
    && pipx install pre-commit

# Scapy a besoin de raw sockets : on donne la capability au binaire python
# plutôt que de travailler en root (pas de sudo dans le conteneur).
RUN setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/local/bin/python3)" \
    && setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/bin/tcpdump)"

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME}

USER ${USERNAME}
# venv dans le projet (.venv) → VS Code le détecte automatiquement
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
