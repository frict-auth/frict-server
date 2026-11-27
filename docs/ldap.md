# LDAP and SSH login

Linux hosts log users in through SSSD against Authentik's LDAP outpost. The
outpost runs a bind flow with Frict in it, so an SSH or console password login
waits for a push on the user's phone. `e2e/ldap_test.go` builds exactly this
setup; the test names are given with each rule below.

## Design

| Object | Setting |
|---|---|
| Flow `ldap-bind` | `ldap-identification` → `ldap-password` → `ldap-frict-validate` → user login; authentication **Require Outpost** |
| Stage `ldap-identification` | Identification, user fields **Username** only |
| Stage `ldap-password` | Password, backends **User database + standard password** only |
| Stage `ldap-frict-validate` | Authenticator Validation, device classes **Duo** only, not configured: **deny** |
| Its binding in `ldap-bind` | evaluate when planned **off**, evaluate when run **on**, one policy binding: user `ldap-svc`, **negate** |
| User `ldap-svc` | type service account, password, no device, role `ldap-search` |
| Role `ldap-search` | *Search full LDAP directory* on provider `ldap` |
| Provider `ldap` | the only LDAP provider; bind and search mode direct; code-based MFA support **off** |
| Application `ldap` | bindings: group `ldap-login`, user `ldap-svc` |
| Stage `deny-ldap-svc` | Deny stage in the browser login flow, bound to user `ldap-svc` |
| Outpost `ldap` | reaches Authentik at `http://server:9000`; LDAPS only, on the tailnet address |

- The negated binding is evaluated against the user the flow identified, so
  only `ldap-svc` skips Frict. It names one user object: renaming or
  recreating that user makes its own binds fail, not anyone else's.
- A user in `ldap-login` with no Frict device cannot bind
  (`TestLDAPUserWithoutDeviceCannotBind`). Enrollment happens in the browser.
- Neither half of the service account's credentials works with the other's
  (`TestLDAPCredentialsDontMix`).
- Keep one provider. The outpost runs one bind flow per provider and only
  lets an account search the provider it bound through, so a separate
  provider for `ldap-svc` would send every user bind through its flow.
- The service account's password sits on every client. `deny-ldap-svc` keeps
  it out of the browser flow, where it could otherwise enroll a phone
  (`TestLDAPSvcDeniedOnBrowserFlow`). Require Outpost keeps browsers out of
  `ldap-bind`, where `ldap-svc` skips Frict: only a request carrying an
  outpost's token may run it (`TestLDAPBindFlowRefusesBrowser`).
- `ldap-bind` has its own stages. The default password stage also accepts
  app passwords and Kerberos or LDAP source passwords, and the default
  identification stage also matches email. In `ldap-password`, an app
  password binds no one (`TestLDAPCredentialsDontMix`).
- No OTP over LDAP: code-based MFA support stays off and Frict is the only
  second factor.

## Authentik admin steps

In this order; each step can be checked and repeated. Names are those in the
table.

1. **Service account.** Directory → Users → New Service Account, username
   `ldap-svc`. Then on the user's page, Set password: a long random one, kept
   for the clients.
2. **Keep it out of the browser.** Flows and Stages → Stages → Create → Deny
   Stage `deny-ldap-svc`. In the browser login flow (the brand's
   authentication flow) → Stage Bindings → Bind existing stage:
   `deny-ldap-svc`, order right after the identification stage, *Evaluate
   when flow is planned* off, *Evaluate when stage is run* on. Expand that
   binding → Bind existing policy/group/user → User `ldap-svc`, not negated.
3. **Validation stage.** Create → Authenticator Validation Stage
   `ldap-frict-validate`: device classes Duo only, not configured action
   *Deny*. Leave the browser flow's validation stage alone.
4. **Group** `ldap-login` with the users who may log in over LDAP.
5. **Flow** `ldap-bind`, designation Authentication, Behavior settings →
   Authentication **Require Outpost**. Create Identification Stage
   `ldap-identification` (user fields: Username only) and Password Stage
   `ldap-password` (backends: User database + standard password only); don't
   reuse the default stages. Bind, in order: `ldap-identification`,
   `ldap-password`, `ldap-frict-validate`, a user login stage. On the
   `ldap-frict-validate` binding: planned off, run on, then bind User
   `ldap-svc` with **Negate** on.
6. **Certificate.** System → Certificates lists a keypair named after the
   server's MagicDNS name. The deployment server's `tailscale cert` timer
   writes it and the worker discovers it (hetzner-setup).
7. **Provider.** Applications → Providers → Create → LDAP Provider `ldap`:
   bind flow `ldap-bind`, unbind flow `default-invalidation-flow`, base DN,
   certificate and TLS server name the MagicDNS name, bind mode and search
   mode *Direct*, code-based MFA support **off**.
8. **Role** `ldap-search`: permission *Search full LDAP directory* on
   provider `ldap`, assigned to `ldap-svc`.
9. **Application** `ldap` with provider `ldap`. Policy/Group/User Bindings:
   group `ldap-login`, user `ldap-svc`.
10. **Outpost** `ldap`: type LDAP, no integration, application `ldap`. Copy
    the token from *View deployment info* into the deployment server's
    `.env`. The compose service sets `AUTHENTIK_HOST=http://server:9000` and
    no `AUTHENTIK_INSECURE`, which only applies to `https://`.

Then on the deployment server: Frict's `FRICT_CHALLENGE_TTL` **≤ 85 s**
(default 60 s). SSSD's PAM responder gives up at about 88–90 s.

## SSSD client

On Ubuntu:

```sh
sudo apt install sssd-ldap libpam-sss libnss-sss
sudo pam-auth-update --enable sss mkhomedir
```

`/etc/nsswitch.conf` needs `sss` on its `passwd:` and `group:` lines; the
package normally adds it.

`/etc/sssd/sssd.conf`, root 0600. It is `e2e/sssd/sssd.conf` with real
values; `TestTunedSSSDIsDefaultsPlusPushTimeouts` keeps that file honest.

```ini
[sssd]
services = nss, pam
domains = authentik

[domain/authentik]
id_provider = ldap
auth_provider = ldap
access_provider = permit
chpass_provider = none
cache_credentials = false
ldap_uri = ldaps://<MagicDNS name>
ldap_tls_reqcert = demand
ldap_schema = rfc2307bis
ldap_search_base = <base DN>
ldap_user_search_base = ou=users,<base DN>
ldap_group_search_base = ou=groups,<base DN>
ldap_user_object_class = user
ldap_user_name = cn
ldap_group_object_class = group
ldap_group_name = cn
ldap_default_bind_dn = cn=ldap-svc,ou=users,<base DN>
ldap_opt_timeout = 90
```

`/etc/sssd/conf.d/bind-password.conf`, root 0600:

```ini
[domain/authentik]
ldap_default_authtok = <ldap-svc password>
```

Then `sudo systemctl restart sssd`.

| Setting | Why |
|---|---|
| `ldap_opt_timeout = 90` | The user's bind waits for the push. At the 8 s default SSSD gives up on the bind, binds again and pushes again: 10–11 pushes per login and the login fails (`TestSSSDDefaultTimeoutsLosePush`). |
| `cache_credentials = false` | Cached credentials would log in with the password alone while Authentik is unreachable. |
| `ldaps://` + `ldap_tls_reqcert = demand` | The certificate is Let's Encrypt, so the system CA bundle verifies it; no CA file to hand out. The name resolves only on the tailnet. |
| `access_provider = permit` | Authentik decides who may log in: group `ldap-login` on application `ldap`. |
| `ldap_default_bind_dn` | `ldap-svc` searches for users and groups with its password alone (`TestLDAPSvcBindsWithPasswordOnly`). |

**Rule:** no client binds against `ldap-bind` without `ldap_opt_timeout = 90`
already in its config. Set clients up only from this file.

### sshd, sudo and the wait

- sshd: `UsePAM yes` and `KbdInteractiveAuthentication yes`. The default
  `LoginGraceTime 120` covers the wait.
- After the password, PAM waits silently for the push; there is no "check
  your phone" prompt. Approve within the push expiry.
- `sudo` through `pam_sss` pushes on every run its timestamp doesn't cover.
- Keep a local break-glass account on every client for when Authentik, Frict,
  the phone or the tailnet is unavailable: an SSH key on servers, a local
  password for the console on desktops and laptops.

### Network and offline use

LDAPS is reachable only on the tailnet, and `cache_credentials = false` means
SSSD never logs anyone in without reaching the outpost. So:

- Every client is on the tailnet with key expiry disabled: admin console →
  Machines → the machine's menu → Disable key expiry. A device tagged when it
  authenticates starts with expiry disabled; check the Machines page anyway.
  Tags are for unattended machines such as servers, not ones people use.
- A laptop with no network, or with Tailscale down, cannot log in an LDAP
  user. Its user logs in with the local break-glass account until it is back
  online.

### Check a new client

1. `id <user>` resolves (the service account's search works).
2. `ldapsearch -H ldaps://<MagicDNS name> -D cn=ldap-svc,ou=users,<base DN> -W -b <base DN> -s base`
   answers with no push.
3. `sudo pamtester login <user> authenticate`: one push; approve →
   authenticated, deny → `Authentication failure`
   (`TestSSSDTunedSurvivesPush`, `TestSSSDTunedFailsWhenPushDenied`).
4. `ssh <user>@localhost`: one push.
