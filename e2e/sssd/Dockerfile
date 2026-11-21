FROM docker.io/library/ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sssd-ldap libpam-sss libnss-sss pamtester ldap-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN sed -i -E 's/^(passwd|group):(.*)$/\1:\2 sss/' /etc/nsswitch.conf \
 && printf 'auth required pam_sss.so\naccount required pam_permit.so\n' > /etc/pam.d/frict-test
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
