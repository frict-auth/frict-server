FROM docker.io/library/ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sssd-ldap libpam-sss libnss-sss pamtester ldap-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN sed -i -E 's/^(passwd|group):(.*)$/\1:\2 sss/' /etc/nsswitch.conf \
 && printf 'auth required pam_sss.so\naccount required pam_permit.so\n' > /etc/pam.d/frict-test
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
