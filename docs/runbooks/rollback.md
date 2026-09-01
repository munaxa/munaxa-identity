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

## Rolling back the schema

There is one migration and it is the baseline, so there is nothing to roll back to. When there is a
second: additive migrations need no rollback, and a destructive one needs a plan written when it is
authored, not when it is reverted.

## Turning authentication off

Unset the five `PLATFORM_AUTH_*` variables in Munaxa Work and redeploy. Work runs with
`UnauthenticatedPort` and refuses every business route — visibly, with a 401, rather than by
accepting anybody. A **partial** set fails startup instead, on purpose: a deployment that thinks it
is verifying tokens and is not is the failure mode that configuration refuses to allow.

This is a way to stop, not a way to run. There is no configuration of Munaxa Work that serves
business data without a verified token, and none should ever be added.
