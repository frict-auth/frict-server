# Authentik side

Frict answers the Duo API; alerting is Authentik's job.

## Alert on "Not me"

Frict reports "Not me" as Duo status `fraud`, which Authentik records in its
`login_failed` event. Create this expression policy:

```python
event = request.context.get("event")
if not event or event.action != "login_failed":
    return False
args = event.context.get("auth_method_args") or {}
return (args.get("duo_response") or {}).get("status") == "fraud"
```

Bind it to a notification rule: Events → Notification Rules → expand the
rule's row → Create or bind... → existing policy. A rule with no transport, or
no enabled policy binding, does nothing.

## Configuration-error emails

Authentik's login page re-sends the Duo request after every failure
([goauthentik/authentik#11368](https://github.com/goauthentik/authentik/issues/11368)).
After a phone is removed, each retry is a `configuration_error`, and the
default rule `default-notify-configuration-error` (email and local, to the
authentik Admins group) emails the admins once per retry.

- Disable that rule's policy binding, and add your own rule bound to
  `default-match-configuration-error` with the local transport only. Editing
  the default rule's transports is undone when its blueprint is re-applied.
- Give `akadmin` a real email address or none; its default is
  `root@example.com`.
