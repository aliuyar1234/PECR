# Artifact Provenance and Signing Policy

## Scope
- Release artifacts for controller, gateway, and policy bundle distributions.
- Build-time provenance attestations and verification requirements.

## Required Artifacts
- Container images:
  - `pecr-controller`
  - `pecr-gateway`
- Policy bundle artifact.
- Release manifests/checksums.

## Signing and Attestation
- Release provenance uses GitHub Artifact Attestations (`actions/attest-build-provenance`) with GitHub OIDC keyless signing.
- Each release artifact must have:
  - immutable digest
  - signed provenance attestation (builder identity + source revision + build parameters)
  - signed checksum manifest for binary tarballs
- Release images (`pecr-gateway`, `pecr-controller`) must be attested by digest and pushed to GHCR with attestation linkage.
- Verification is a blocking gate in `.github/workflows/release.yml` before `Publish GitHub Release`.

## Key Management
- No long-lived signing key material is stored in this repository for release attestations.
- Trust is anchored in:
  - GitHub OIDC identity of the workflow run
  - workflow path binding (expected signer workflow: `.github/workflows/release.yml`)
  - repository/ref constraints enforced during verification
- Any migration away from keyless attestations requires a security review and runbook update.

## Verification Gates
- Pre-release:
  - verify checksum manifest integrity (`sha256sum --check`)
  - verify attestation validity for release tarballs and release manifests
  - verify attestation validity for digest-pinned release images in GHCR
  - verify signer workflow identity and expected source ref
  - verify dependency lock checks passed
- Runtime/deploy:
  - deployment pipeline rejects unsigned or unverified artifacts.

Reference implementation:
- `scripts/security/verify_release_attestations.py`
- workflow gate in `.github/workflows/release.yml` (`Verify release provenance attestations` step)

## Exception Handling
- No unsigned production releases.
- Emergency overrides require explicit incident ticket + post-incident review.

## Ownership
- Build/release owners maintain signing workflow integrity.
- Security owners maintain key governance and verification policy.
