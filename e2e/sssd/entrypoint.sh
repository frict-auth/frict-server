#!/bin/sh
# Installs the mounted sssd.conf plus the service account's bind password
# (kept out of the committed config) and runs sssd in the foreground.
set -eu
install -m 0600 -o root -g root /frict/sssd.conf /etc/sssd/sssd.conf
install -d -m 0711 /etc/sssd/conf.d
umask 077
printf '[domain/frict]\nldap_default_authtok = %s\n' "$(cat /secrets/ldap-svc-password)" > /etc/sssd/conf.d/bind-password.conf
dpkg-query -W sssd-common sssd-ldap libpam-sss
exec sssd -i --logger=stderr --debug-level=6 --debug-microseconds=1
