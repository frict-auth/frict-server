FROM docker.io/library/ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sssd-ldap libpam-sss libnss-sss pamtester ldap-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN sed -i -E 's/^(passwd|group):(.*)$/\1:\2 sss/' /etc/nsswitch.conf \
 && printf 'auth required pam_sss.so\naccount required pam_permit.so\n' > /etc/pam.d/frict-test
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
