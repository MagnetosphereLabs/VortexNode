# Vortex Node

Vortex Node is a self-hosted Rust backend for Vortex Chat and Vortex Vault. Chat uses the Vortex fork of Fluxer’s web and desktop interface. Messages, attachments and call media are encrypted and decrypted on participants’ devices. Vault keeps its separate application and encrypted storage format.

The `vortex/integration-20261022` branch is an integration preview. Install a published, matched Node and Chat release; development revisions without `clients.lock.json` deliberately refuse installation. Do not point an unmodified Fluxer client at this backend.

## Server installation

The server installer supports Ubuntu 22.04, 24.04 and 26.04 LTS with systemd. Point your domain at the server first. The interactive setup asks for the domain, account and application choice, then configures HTTPS, services, storage and the media relay.

Choose **Chat** or **Chat and Vault**. The browser client is installed automatically from the release pinned by the Node revision. Desktop clients are installed on users’ computers separately.

For the existing alpha on `main`:

```bash
bash -c 'set -e; f="$(mktemp)"; trap '\''rm -f "$f"'\'' EXIT; curl --proto "=https" --tlsv1.2 -fsSL "https://raw.githubusercontent.com/MagnetosphereLabs/VortexNode/main/install.sh" -o "$f"; sudo bash "$f" install --repo "https://github.com/MagnetosphereLabs/VortexNode"'
```

That command installs the existing alpha, not the Fluxer integration preview. A matched integration release will supply its own pinned installation command.

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

Open the Node’s HTTPS domain for Chat and `/vault` for Vault when enabled. [Vortex Chat](https://github.com/MagnetosphereLabs/VortexChat) contains the shared web/desktop client, Linux installer, release workflows and platform documentation. Native clients ask for the Node address and account credentials.

The Node owner controls registration and invitations, account availability, per-user storage allowances and upload limits through the client’s Node settings. Owning the Node does not automatically make the owner a participant in private conversations.

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
