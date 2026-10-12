# xboard-node

Self-hosted node backend for [Xboard](https://github.com/guimc233/Xboard). Uses the [`mihomo`](https://github.com/MetaCubeX/mihomo) (Clash.Meta) kernel.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocol inbounds: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, Snell, Mieru, Sudoku, ShadowQUIC, TrustTunnel, SOCKS, HTTP, mixed
- Sync: WebSocket push + REST polling dual channel
- User controls: alive-IP tracking, per-user traffic accounting, force-disconnect
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/guimc233/xboard-node:dev
```

### Docker Compose

```bash
git clone -b dev --depth 1 https://github.com/guimc233/Xboard-Node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd / OpenRC)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/guimc233/Xboard-Node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/guimc233/Xboard-Node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1

# Alpine root shell (sudo is normally not installed)
curl -fsSL https://raw.githubusercontent.com/guimc233/Xboard-Node/dev/install.sh | \
  bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

The installer downloads the fork's `dev` Release by default, writes a systemd unit
or OpenRC init script, enables it at boot, waits for `/healthz`, and rolls back binaries
and configuration when health checks fail. OpenRC logs are written to
`/var/log/xboard-node.log`.
Use `--repository owner/name` or `XBOARD_NODE_DOWNLOAD_BASE` to target another release source.

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
