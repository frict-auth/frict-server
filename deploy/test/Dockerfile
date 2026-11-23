# The box: Ubuntu with sshd, a Docker daemon and a deploy user.
FROM docker.io/library/docker:29.3.1-dind@sha256:686d2c5464787b0ca42420e0aa03a94fc9781ff9bf8b5ff947614b9fa4c3c3e0 AS docker

FROM docker.io/library/ubuntu:noble-20261024.1@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iptables openssh-server
COPY --from=docker /usr/local/bin/ /usr/local/bin/
COPY --from=docker /usr/local/libexec/docker/ /usr/local/libexec/docker/
RUN groupadd --system docker && adduser --disabled-password --gecos "" --uid 1001 deploy && usermod -aG docker deploy && mkdir /run/sshd
CMD ["sh", "-c", "/usr/sbin/sshd && exec dind dockerd"]
