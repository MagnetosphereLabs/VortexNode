# Vortex Node

Vortex Node is a self-hosted Rust backend for Vortex Chat and Vortex Vault. Chat uses the Vortex fork of Fluxer’s web and desktop interface. Messages, attachments and call media are encrypted and decrypted on participants’ devices. Vault keeps its separate application and encrypted storage format.

The `vortex/preview` branch installs the matched **0.1.0-rc.1** web/Linux candidate. The Rust backend tested for this pair is `af65f171997af9d21874b443741757580070fc12`; the client source is `261a9ecb4ece935be04ecf6f4d37c2b80d94d971`. This is a candidate for hands-on testing, with additional Fluxer features and security review still required. Do not point an unmodified Fluxer client at this backend.

## Server installation

The server installer supports Ubuntu 22.04, 24.04 and 26.04 LTS with systemd. Point your domain at the server first. The interactive setup asks for the domain, account and application choice, then configures HTTPS, services, storage and the media relay.

Choose **Chat** or **Chat and Vault**. The browser client is installed automatically from the release pinned by the Node revision. Desktop clients are installed on users’ computers separately.

For a new installation or to update an existing Node to this candidate, run on the server:

```bash
(set -e; f="$(mktemp)"; trap 'rm -f "$f"' EXIT; curl --proto '=https' --tlsv1.2 -fsSL 'https://raw.githubusercontent.com/MagnetosphereLabs/VortexNode/vortex/preview/install.sh' -o "$f"; sudo bash "$f" install --repo https://github.com/MagnetosphereLabs/VortexNode --ref vortex/preview)
```

Back up an existing Node's data and configuration before updating. The installer recognizes the existing configuration, preserves its domain and account, and asks for application selection on a fresh installation. Add `--apps chat` or `--apps both` to explicitly select the applications.

This command tracks the matched preview branch for later manual updates. The existing `main` alpha is a different version. The release does not yet implement every upstream Fluxer feature; see the client's [scope and testing guide](https://github.com/MagnetosphereLabs/VortexChat/blob/vortex/integration-20261022/docs/vortex/TESTING.md).

## Updates and application selection

The installed updater remembers the repository, source reference, domain and application choice:

```bash
sudo /opt/vortex-node/install.sh update
```

On an integration release, change the application selection with:

```bash
sudo /opt/vortex-node/install.sh update --apps chat
sudo /opt/vortex-node/install.sh update --apps both
```

Disabling Vault does not delete its encrypted data. Keep a backup of the Node data and configuration before upgrades. Clients must preserve their own encryption keys and account recovery material; a server backup alone does not give the operator decryption access.

## Clients and administration

Install the Linux x86-64 client on your desktop computer with:

```bash
(set -e; f="$(mktemp)"; trap 'rm -f "$f"' EXIT; curl --proto '=https' --tlsv1.2 -fsSL 'https://raw.githubusercontent.com/MagnetosphereLabs/VortexChat/261a9ecb4ece935be04ecf6f4d37c2b80d94d971/install-linux.py' -o "$f"; sudo python3 "$f" --release vortex-v0.1.0-rc.1)
```

Then open **Vortex Chat**, choose **Add instance**, and enter your Node's HTTPS domain. Linux requires glibc 2.35 or newer and a working desktop keyring. The installer covers Ubuntu/Debian, Fedora and Arch families. See the [local build guide](https://github.com/MagnetosphereLabs/VortexChat/blob/vortex/integration-20261022/docs/vortex/BUILD_LINUX.md) to compile on your own PC instead.

Open the Node’s HTTPS domain for Chat and `/vault` for Vault when enabled. [Vortex Chat](https://github.com/MagnetosphereLabs/VortexChat) contains the shared web/desktop client, Linux installer, release workflows and platform documentation. Native clients ask for the Node address and account credentials.

The Node owner controls registration and invitations, account availability, per-user storage allowances and upload limits through the client’s Node settings. Owning the Node does not automatically make the owner a participant in private conversations.

## Source-built client updates

For the existing configured Linux checkout, run `bash "$HOME/VortexChat-Local/scripts/update-local.sh"` as the desktop user. It builds both clients locally, updates this backend when needed, then deploys the matching web client. Use that combined path while testing integration source; the published client lock above still selects rc.1.

The shared interface supports encrypted profiles, Node-wide and server expressions, private account-addressed server invitations, and Node account security. Password replacement rewraps the existing account keys on the client. Passkeys require WebAuthn PRF support on the Node website. Backend compilation requires OpenSSL development headers, installed by `install.sh` on supported Ubuntu hosts.

Chat permits framing by the same Node origin so Vault can embed it. Other origins remain excluded by the frame policy. Communication privacy settings are enforced using account relationship metadata while message and media contents remain encrypted.

## Security boundaries

A session authorizes access to encrypted records. It is not a decryption key. The server still sees routing metadata, account and membership identifiers, sizes, timing and network addresses. A web client also trusts the host supplying its JavaScript. Installed clients bundle their renderer, but still depend on a trusted device and release supply chain.

Removing a participant blocks future authorized access and triggers key rotation. It cannot erase data or keys that participant already saved. The current archive format retains history keys; it does not provide complete forward secrecy for stored history. See the [client security design](https://github.com/MagnetosphereLabs/VortexChat/blob/vortex/integration-20261022/docs/vortex/SECURITY.md).

Federation and donated public-node operation are outside this version.

## Development

```sh
cargo test --locked
cargo build --release --locked
python3 scripts/test-install-chat-client.py
```

The verification workflow pins the Rust toolchain. Browser and desktop acceptance checks live in Vortex Chat and pin the Node source revision they test.

## Uninstall

This command removes the installation **and its stored data**:

```bash
sudo /opt/vortex-node/uninstall.sh --delete-data
```

## License

AGPL-3.0-only. Bundled components retain their license notices.

### Capacity-aware Chat limits

Chat can use automatic file and total-storage limits (`maxUpload: 0` and
`chatQuota: 0` in the authenticated Chat policy). Effective capacity is computed
from the filesystem holding Node data after the protected free-space reserve
and pending Chat and Vault transfers. An explicit positive policy value remains
a lower ceiling. Account and server allowances still apply, and the encrypted
transfer protocol currently supports plaintext files up to 100 GiB.

`admin.storage` is restricted to the Node administrator and reports the configured
limits, effective limits, Chat usage, filesystem capacity and remaining space.
Client discovery and authenticated upload preflight receive the effective file
limit. Upload reservation remains transactional and enforces capacity again;
a displayed value is a snapshot, not a promise that disk space is reserved.
