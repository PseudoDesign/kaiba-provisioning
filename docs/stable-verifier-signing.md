# Signing one stable-verifier boot image

The physical campaign accepts the authenticated output of
`mkRpi5VerifiedStableVerifierSigning`. This supplies the missing handoff from
`mkRpi5StableVerifierUnsignedBoot` to `mkRpi5StableVerifierCampaignMedia` while
authorizing exactly one `rpi5.boot_image` input. The separate inspection
provisioner keeps its own signing intent, command and finalizer.

The verifier intent uses
`kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent/v1alpha1`,
with scope `stable_campaign_verifier_boot`. It binds the actual unsigned
manifest file, source revision, epoch, complete boot image digest/size, reviewed
public key file/fingerprint, customer key hash and signer policy. The verifier
manifest has no provisioner artifact-set digest; none is fabricated for this
route. Historical custom verifier intents and generic five-input release
intents are not accepted by this command.

## Prepare the public plan

Build the final unsigned verifier with its reviewed policy, policy-root public
key, TLS CA, firmware allowlist, source and Pi platform pins. Obtain native ARM
outputs from a native builder or trusted cache. The x86 signing workstation can
construct and verify the public plan from those existing immutable bytes.

For a consumer with `unsignedVerifier` already constructed:

```nix
signingPlan = kaiba.lib.mkRpi5StableVerifierSigningPlan {
  system = "x86_64-linux";
  sourceRevision = reviewedSourceRevision;
  sourceDateEpoch = reviewedSourceDateEpoch;
  stableVerifierUnsignedBoot = unsignedVerifier;
};
```

The constructor checks the actual unsigned manifest and image, including their
source, Pi platform, file inventory and size bindings. Its fixed public signer
profile comes from the repository's independent development-key review.
The resulting plan has exactly four files: `boot.img`, `public.pem`,
`release-intent.json` and `plan.json`. The unsigned manifest remains
available through the typed plan lineage for finalization. Plan loading checks
the actual boot and public-key bytes; its manifest digest is an explicit
approval input, not independent proof of build provenance.

The public `kaiba-rpi5-stable-verifier-signing` package supports `author`,
`validate-plan`, `validate-unsigned`, `validate-authorization` and `finalize`.
Its `sign` operation has no configured signing authority. These public constructors and validators
do not access the token, deploy a grant, write media or operate power.

## Review and execute the single grant

Review the exact unsigned manifest, plan, image size/digest, public trust and
platform inputs, source/CI record, signer bindings and bounded intended boot.
Only after explicit approval, use `author` to record reviewer attribution and
the approval interval, at most 24 hours. It writes one `approval.json` and one
`signing-grants.json` into a new directory. These records express a local
approval assertion; they do not authenticate the human reviewer.

Use the existing [signing-gate deployment procedure](../deploy/ubuntu-signing-gate/README.md)
to install the exact reviewed grant and configured runtime. A clean revisioned
checkout exports
`packages.x86_64-linux.kaiba-rpi5-stable-verifier-development-signing` (also
available natively on ARM). That closure exposes only the verifier command,
receipt tool, gate and fixed token backend. Its constructor selects
`stableVerifierOnly = true`; selecting both verifier and provisioner-only
profiles is rejected. Existing development/provisioner profiles retain their
previous command sets.

The configured command fixes the socket, signer/cohort, PKCS#11 URI and public
key at build time. It has no runtime authority selector. Invoke its `sign`
operation only against the reviewed plan and a new output directory. Retain
the exact `boot.sig`, `signing-result.json` and authenticated receipt export.
The successful one-grant path requires at least one artifact-signing operation
and one receipt-attestation operation; it is not a one-touch or upper-bound
operation count. An incomplete grant is not retried under the same approval.

## Finalize and consume the evidence

Pass only public results back into Nix:

```nix
verifiedVerifier = kaiba.lib.mkRpi5VerifiedStableVerifierSigning {
  system = "x86_64-linux";
  inherit signingPlan;
  authorization = publicApprovalDirectory;
  signedOutput = publicSignedOutputDirectory;
  receiptExport = publicReceiptExportFile;
};

campaignMedia = kaiba.lib.mkRpi5StableVerifierCampaignMedia {
  system = "x86_64-linux";
  verifiedSignedBoot = verifiedVerifier;
  inherit campaignPlan campaignMutationInputs delegatedRelease;
  inherit rootDataPartitionGUID rootHashPartitionGUID;
};
```

The verified output retains exactly twelve files: the seven signed-boot files
(`boot.img`, `boot.sig`, `manifest.json`, `public.pem`, `release-intent.json`,
`signing-plan.json`, `signing-result.json`), plus `approval.json`,
`signing-grants.json`, `signing-receipts.json`, `receipt-verification.json`
and `unsigned-artifact-manifest.json`.

Campaign construction independently validates those bytes: it uses the
verifier-only loader, checks the actual unsigned manifest, verifies the boot
signature/result and exact one-grant authenticated receipt, and regenerates
the signed-boot and receipt-verification records for comparison. A passthru
label or supplied verification summary alone does not establish acceptance.
The existing seven-file generic signed-boot branch remains available under
its own generic intent contract.

Successful verification authenticates the signature and receipt under the
reviewed key. It does not authenticate Git/CI provenance, reviewer identity,
physical execution or qualification. Continue with the
[first physical baseline prerequisites](first-physical-baseline.md), including
the complete release/mutation set, packet, durable recovery backups, independent
readback and explicit staging/power approvals. All hardware/readiness claims
remain false until their separate evidence exists.
