FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl libssl-dev libpcre2-dev zlib1g-dev perl python3 \
    && rm -rf /var/lib/apt/lists/*
# OpenResty 1.25's bundled modules still require the PCRE1 API.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libpcre3-dev php-cli && rm -rf /var/lib/apt/lists/*
WORKDIR /src
CMD ["bash", "scripts/matrix.sh"]
