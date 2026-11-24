# The deployment server: Ubuntu with sshd, sudo and a Docker daemon.
FROM docker.io/library/docker:29.10.0-dind@sha256:4bbc7223f81db790097c6dea42fb93e05b8fead4f0431fbe6ccaba6e8473201c AS docker

FROM docker.io/library/ubuntu:noble-20261024.1@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables openssh-server sudo
COPY --from=docker /usr/local/bin/ /usr/local/bin/
COPY --from=docker /usr/local/libexec/docker/ /usr/local/libexec/docker/
RUN groupadd --system docker && mkdir /run/sshd
CMD ["sh", "-c", "/usr/sbin/sshd && exec dind dockerd"]
