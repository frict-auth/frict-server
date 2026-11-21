FROM docker.io/library/ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zbar-tools \
 && rm -rf /var/lib/apt/lists/*
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["sh", "-c", "cat > qr.png && zbarimg --quiet --raw qr.png"]
