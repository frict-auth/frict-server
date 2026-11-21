FROM docker.io/library/ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zbar-tools \
 && rm -rf /var/lib/apt/lists/*
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["sh", "-c", "cat > qr.png && zbarimg --quiet --raw qr.png"]
