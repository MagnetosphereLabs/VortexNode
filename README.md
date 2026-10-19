# VortexNode

Building a secure cloud for the Vortex series of applications. This integrates directly with our Vortex Vault software and allows you to self host your own data and file transfers for easy access across devices. Vortex Nodes store and transmit encrypted data, and not even the server provider can read your files or data stored on them. It is simply for encrypted cloud storage and e2e encrypted data transfers. This repo is currently being built and this software is not yet completed.

To install this Alpha build on any Ubuntu server or VPS, simply run:

```bash
bash -c 'set -e; f="$(mktemp)"; trap '\''rm -f "$f"'\'' EXIT; curl --proto "=https" --tlsv1.2 -fsSL "https://raw.githubusercontent.com/MagnetosphereLabs/VortexNode/main/install.sh" -o "$f"; sudo bash "$f" install --repo "https://github.com/MagnetosphereLabs/VortexNode"'
```

Update with:
```bash
sudo /opt/vortex-node/install.sh update
```

Uninstall with:
```bash
sudo /opt/vortex-node/uninstall.sh --delete-data
```
