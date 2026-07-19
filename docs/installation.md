# Installation

Fellaga publishes GNU/Linux binaries for x86-64 and ARM64. The release workflow builds both architectures, smoke-tests them against pinned Kali environments, creates checksums and SBOMs, signs the checksum manifest with Sigstore, and attaches GitHub build-provenance attestations.

## Kali or Debian package on x86-64

The Debian package is the simplest installation method on an x86-64 Kali or Debian system:

```bash
curl -fLO https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/download/v0.10.1/fellaga_0.10.1-1_amd64.deb
sudo apt install ./fellaga_0.10.1-1_amd64.deb
fellaga --version
```

APT checks the package dependencies and installs the binary as `/usr/bin/fellaga`.
The English README and detailed guides are installed under `/usr/share/doc/fellaga/`.

## Portable archives

Choose the archive that matches `uname -m`:

| `uname -m` | Release archive |
| --- | --- |
| `x86_64` | `fellaga-v0.10.1-x86_64-unknown-linux-gnu.tar.gz` |
| `aarch64` or `arm64` | `fellaga-v0.10.1-aarch64-unknown-linux-gnu.tar.gz` |

Example for x86-64:

```bash
version=0.10.1
target=x86_64-unknown-linux-gnu
base="https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/download/v${version}"

curl -fLO "${base}/fellaga-v${version}-${target}.tar.gz"
curl -fLO "${base}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "fellaga-v${version}-${target}.tar.gz"
sudo install -m 0755 "fellaga-v${version}-${target}/fellaga" /usr/local/bin/fellaga
fellaga --version
```

Use `target=aarch64-unknown-linux-gnu` on ARM64. The release binaries target glibc-based GNU/Linux systems.

Each archive includes `Cargo.lock`, its architecture SBOM as `SBOM.cdx.json`,
and a self-contained `THIRD_PARTY_LICENSES.txt` alongside the binary and
documentation. The Debian package installs the same supply-chain files under
`/usr/share/doc/fellaga/`; they remain available without network access.

## Build from source

Install Rust 1.95 or newer and the build prerequisites. On Kali or Debian:

```bash
sudo apt update
sudo apt install build-essential cmake perl pkg-config git curl
```

Clone and run the source installer:

```bash
git clone https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder.git
cd Fellaga-SubDomainFinder
./install.sh
```

The script runs a locked release build with vendored OpenSSL and installs the binary in `${PREFIX:-$HOME/.local}/bin`. To choose another user-owned prefix:

```bash
PREFIX="$HOME/.local/fellaga" ./install.sh
```

`PREFIX` must be a directory prefix; the binary is installed below its `bin` directory.

## Verify an installation

```bash
fellaga --version
fellaga --help
```

For cryptographic verification of downloaded artifacts, follow the [release verification guide](release-verification.md).

## Upgrade

Install the newer `.deb` over the existing package, replace `/usr/local/bin/fellaga` with the binary from the new archive, or pull the source repository and run `./install.sh` again. Upgrading the executable does not remove the local SQLite inventory.

Fellaga performs database migrations transactionally. A migration backup is created before a schema change, and existing observations are preserved.

## Remove Fellaga

For a Debian-package installation:

```bash
sudo apt remove fellaga
```

For an archive installation, remove `/usr/local/bin/fellaga`. For a default source installation, remove `~/.local/bin/fellaga`.

Uninstalling the executable intentionally leaves user data in place. The default data and configuration paths are:

- `~/.local/share/fellaga/`
- `~/.config/fellaga/`

Review and back up those directories before deleting them manually.
