FROM lscr.io/linuxserver/wireguard:latest


RUN \
    echo "**** install dependencies ****" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    netcat && \
    echo "**** cleanup ****" && \
    apt-get autoremove && \
    apt-get clean && \
    rm -rf \
    /tmp/* \
    /var/lib/apt/lists/* \
    /var/tmp/*
