# Release verification

Treat an artifact as published only when it appears on the GitHub release page and the corresponding release workflow has succeeded. A version number in `CHANGELOG.md` or a Git tag alone is not proof that binary publication completed.

## Release contents

Fellaga v0.8.1 contains seven assets:

- x86-64 and ARM64 GNU/Linux archives;
- an amd64 Debian package;
- one CycloneDX JSON SBOM for each architecture binary;
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`.

GitHub build-provenance attestations are attached to all seven assets.

## Verify checksums

Download the payload files and `SHA256SUMS` from the same release into one directory, then run:

```bash
sha256sum --check SHA256SUMS
```

If only one payload is present, use:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Do not copy a checksum from an unrelated web page. Verify the signed manifest or GitHub attestation as an additional provenance check.

## Verify GitHub provenance

Install the GitHub CLI, authenticate if required, and verify the downloaded artifact:

```bash
gh attestation verify \
  fellaga-v0.8.1-x86_64-unknown-linux-gnu.tar.gz \
  --repo Brahim-Fouad/Fellaga-SubDomainFinder
```

The command should identify `Brahim-Fouad/Fellaga-SubDomainFinder` and the repository release workflow as the trusted source. Repeat it for the Debian package, ARM64 archive, SBOMs, and checksum/signature files when those assets are part of your supply-chain policy.

## Verify the Sigstore checksum signature

Install Cosign and run:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/.github/workflows/release.yml@refs/tags/v0.8.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

The certificate identity binds the keyless signature to the release workflow at the exact `v0.8.1` tag.

## Verify the source identity

For a source checkout:

```bash
git fetch --tags origin
git rev-parse 'v0.8.1^{commit}'
git show --no-patch --format=fuller v0.8.1
```

The release pipeline also verifies that the tag version matches `Cargo.toml`, that the tagged commit is reachable from `main`, and that it will not overwrite an existing published release.

## Published release

- [Latest Fellaga release](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/latest)
- [Release workflow history](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/actions/workflows/release.yml)
