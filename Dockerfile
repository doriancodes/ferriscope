FROM rust:latest

# Install libpcap and other dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpreplay \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all files needed for build
COPY Cargo.toml ./
COPY benches/ ./benches/
COPY src/ ./src/

# Install nightly for benchmarks
RUN rustup default nightly

# Build release version and run benches
CMD ["cargo", "bench", "--verbose"]