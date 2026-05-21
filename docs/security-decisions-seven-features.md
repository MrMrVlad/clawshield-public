# Security decisions — seven-feature implementation

See [PR_factory research copy](https://github.com/MrMrVlad/PR_factory/blob/main/research/clawshield-public/security-decisions.md) for full trade-off tables.

## Summary

1. **Agent Hub actions** — Ordered apply (lockdown → key → policy → binary); HTTPS-only downloads; optional policy signature verification.
2. **Shadow mode** — `CLAWSHIELD_POLICY_SHADOW=1`; log-only dual evaluation; `clawshield_shadow_mismatches_total`.
3. **audit-rekey** — `clawshield-audit-rekey` CLI; old/new keys via env; `--dry-run`.
4. **Metrics** — Agent scrapes `/metrics` (512KiB cap) on check-in.
5. **Nested redaction** — Recursive `redactMap` (test enabled).
6. **Citation scanner** — `citation_scan` policy; warn-only audit entries.
7. **Key providers** — `CLAWSHIELD_KEY_PROVIDER=env|file|vault|aws-envelope`.

## Env reference

| Variable | Feature |
|----------|---------|
| `CLAWSHIELD_POLICY_SHADOW` | Shadow/canary |
| `CLAWSHIELD_HUB_PUBLIC_URL` | Binary download base |
| `CLAWSHIELD_AUDIT_ENCRYPTION_KEY_OLD` | Rekey CLI |
| `CLAWSHIELD_KEY_PROVIDER` | KMS/Vault/env |
| `CLAWSHIELD_VAULT_*` | Vault provider |
