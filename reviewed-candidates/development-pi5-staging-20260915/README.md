# Development Pi 5 native staging descriptor

This bounded public descriptor selects the Pi-local NVMe staging component for campaign `development-pi5-fc3652e-98999517`. It was built with the descriptor constructor at `0742d1f3e3a19ea1f0eec3e911ec99e4f2929399` against the independently verified campaign artifacts prepared at `570b7f99ff079e25c56f85e67f7db667b0c1bc71`.

The selected signed verifier remains `fc3652eca697b0f763be8214abcedf8aa746d5b3`; released OS provenance remains `206b204d2ddfdce2e1bb2843df5cd5c7c10d6622`. The descriptor contains exact public configuration and staging-plan bytes plus payload hashes, not payloads or recovery backups.

Staging-plan digest: `sha256:ff0c6a94c29e5529bf7112bc58709246aad91dacfabc94ae019343a8b9aa430e`.
Campaign packet digest: `sha256:8cbcb3108353712347d8af4cb9dddc9ae97a489cd2356b14551a199a1a00e0f6`.

Dispatch the **Native staging component** workflow only after the selected source commit is reviewed and on main, with this `descriptor.json` path. The workflow independently records that selected source commit; it is not embedded here to avoid a self-referential commit hash. Verify native build provenance and NAR hashes, then assemble locally against the original complete plan/payload inputs. A native component export alone is incomplete and authorizes no hardware action. See [the staging runbook](../../docs/stable-campaign-staging.md).
