# Runbook — rolling back

## The shape of the risk

Identity's deploy is additive to Munaxa Work: Work verifies tokens it already knew how to verify,
and its behaviour with `PLATFORM_AUTH_*` unset is to run with `UnauthenticatedPort` and answer 401
to every business route. So the rollback question is only ever about Identity.

## Rolling back the service

Redeploy the previous image. Sessions and refresh lineages survive — they are rows, not process
state — and tokens signed by a key both versions hold keep verifying. Nothing needs to be re-issued.

**Unless the rollback crosses a signing-key rotation.** Then the old image holds the old private key
and Work may already have dropped the old public key. Check `IDENTITY_SIGNING_KID` on both sides
before rolling back across a rotation; if they disagree, re-add the old public key to Work first.

## Rolling back across a signing-key rotation

The one case that needs thought, spelled out because getting it wrong either strands every live
session or leaves an unintended key trusted.

There are two independent things in flight: which key **Identity signs with** (`IDENTITY_SIGNING_KID`)
and which keys **Work trusts** (`PLATFORM_AUTH_PUBLIC_KEYS`, a set). Work trusting a key is harmless;
Work _not_ trusting the key in a live token is a 401 for everybody holding one.

| Where you are                                                   | Roll back to                      | What to do first                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New key added to Work, Identity not yet switched                | old Identity image                | Nothing. Work trusts both; tokens are signed with the old key and keep verifying.                                                                                                                                                                                                                                                        |
| Identity switched to the new key, old key still trusted by Work | old Identity image                | Nothing. Tokens minted since the switch carry the new `kid`, which Work still trusts; new tokens carry the old one, which it also trusts. This overlap is the whole reason the old key is not removed until step 6.                                                                                                                      |
| Old key already removed from Work                               | old Identity image                | **Re-add the old public key to Work and deploy Work first.** Rolling back Identity alone makes it sign with a key Work no longer trusts — every sign-in succeeds and every subsequent request is a 401, which reads as a broken product rather than a bad rollback.                                                                      |
| Rolling back _because the new key leaked_                       | new Identity image, different key | Do not roll back to the old key. Generate a third, run the rotation forward, and remove the leaked key from Work **immediately** rather than waiting out the overlap. Every session signed with it dies and everybody signs in again — the correct trade, because a leaked signing key mints tokens for any account in any organisation. |

Tokens already issued are never recalled by any of this. A token signed by a key Work still trusts
stays valid until it expires, ≤ 15½ minutes. That is the property the whole stateless-verifier
design trades for, and a rollback does not change it.

Check before rolling back across a rotation:

```bash
curl -sf https://$PUBLIC_HOST/api/auth/health/ready | grep signingKid   # what Identity signs with
grep -o '"kid":"[^"]*"' deploy/.env                                     # what Work trusts
```

## Rolling back the schema

There is one migration and it is the baseline, so there is nothing to roll back to.

When there is a second, the rule is narrow on purpose: **only a migration that is reversible without
losing data may be rolled back, and only with a down-migration written and tested when the up was
authored.** A generated down-migration is not a rollback plan — it will happily drop a column, and
the data in it, to restore a shape.

An additive migration (a new table, a new nullable column, a new index) needs no rollback at all:
the previous application version does not read it. That is the shape to prefer, and it is why the
question usually does not arise.

A destructive migration deployed without a tested reversal is a one-way door. Roll the application
back, leave the schema, and fix forward.

## Turning authentication off

Unset the five `PLATFORM_AUTH_*` variables in Munaxa Work and redeploy. Work runs with
`UnauthenticatedPort` and refuses every business route — visibly, with a 401, rather than by
accepting anybody. A **partial** set fails startup instead, on purpose: a deployment that thinks it
is verifying tokens and is not is the failure mode that configuration refuses to allow.

This is a way to stop, not a way to run. There is no configuration of Munaxa Work that serves
business data without a verified token, and none should ever be added.
