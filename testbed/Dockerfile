FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    bash \
    curl \
    git \
    python3 \
    python3-pip \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://omp.sh/install | sh
ENV PATH="/root/.local/bin:${PATH}"

# mediums for test cases
RUN mkdir -p /shared && chmod 777 /shared

WORKDIR /workspace

CMD ["sleep", "infinity"]