# mihomo kernel backend — design notes

The agent drives exactly one proxy kernel: [mihomo](https://github.com/MetaCubeX/mihomo)
(Clash.Meta). sing-box and Xray are retired.

## Why mihomo runs as a subprocess

sing-box and Xray are embedded as Go libraries because both expose per-instance
handles, so one process can host many nodes.

mihomo does not. Its listener registry, tunnel, route server, statistics manager
and config are **process-global variables** (`listener.PatchInboundListeners`,
`tunnel.Tunnel`, `tunnel/statistic.DefaultManager`, `hub.ApplyConfig`). There is
no per-instance handle, and there is no `SetTracker` hook to observe
connections. Embedding it would therefore limit a process to a single node,
which breaks the agent's machine mode (one process manages every node bound to
the machine).

The backend consequently:

1. writes a `config.yaml` into the node's runtime directory
   (`<config_dir>/node-<id>`),
2. spawns the `mihomo` binary for that node
   (`mihomo -d <dir> -f <dir>/config.yaml`), and
3. drives it through the **external-controller REST API** for accounting and
   connection control.

One node, one mihomo process, one external-controller port.

## Division of responsibility

| Layer | Owner |
| --- | --- |
| Listener shape and all inbound options | Panel (`buildNodeConfig()` → `mihomo.listeners[]`) |
| `rule-providers`, `rules`, `sub-rules`, `sniffer` | Panel |
| Route-profile dispatch (`IN-USER` rules) | Agent |
| `users` list, shaped per `users_shape` | Agent |
| Custom outbounds → mihomo `proxies` | Agent |
| Runtime envelope (controller, secret, log level, geo data) | Agent |
| TLS material (inline PEM) | Agent injects from the certificate manager |

The panel's block is already kernel-native, so the generator copies it and only
adds the parts that depend on live user state.

## External-controller contract

Authentication is `Authorization: Bearer <secret>`.

| Need | Call |
| --- | --- |
| List/account connections | `GET /connections` → `{downloadTotal, uploadTotal, connections:[{id, metadata, upload, download, start, chains, rule, rulePayload}]}` |
| Close one connection | `DELETE /connections/:id` |
| Close all connections | `DELETE /connections` |
| Reload config | `PUT /configs?force=true` with `{"path": "<config.yaml>"}` |
| Version / memory | `GET /version`, `GET /memory` |

`/connections` also has a websocket form; polling is simpler and matches the
agent's existing push interval.

## Per-user attribution

`metadata.inboundUser` (Go field `InUser`) carries the authenticated listener
user, and `metadata.inboundName` (`InName`) carries the listener name. This is
what makes per-user traffic accounting possible:

- every generated user entry **must have a non-empty `username`** — it is
  `omitempty` on vmess/vless and an empty username silently breaks attribution;
- the agent maps `inboundUser` → user id using the identity table
  (`xb:u:<id>` and `xb:u:<id>:rp:<profile>`), and accumulates
  `upload`/`download` deltas per connection id;
- alive source IPs come from `metadata.sourceIP`.

`upload`/`download` in `/connections` are per-connection cumulative counters.

## Capability mapping

| `kernel.Kernel` capability | mihomo |
| --- | --- |
| `BuiltInTrafficStats` | no — polled from the controller |
| `AliveIPTracking` | yes (from connection metadata) |
| `ForceCloseConnection` | yes (`DELETE /connections/:id`) |
| `ForceCloseUser` | yes (iterate connections for the user) |
| `PerUserSpeedLimit` | no — mihomo has no per-user bandwidth limit |
| `DeviceLimit` | no native gate; enforced by the agent from alive-IP state |

User changes require a `PUT /configs` reload: mihomo compares listener configs
and **closes and re-listens** a listener whose `users` changed. That is a
per-listener cycle, not a full restart, but it is not the zero-disruption
hot-swap sing-box provided.

## Operational requirements

- **Binary**: not bundled. Official releases are at
  `https://github.com/MetaCubeX/mihomo/releases/download/<tag>/mihomo-<os>-<arch>[-compatible]-<tag>.gz`
  (Linux = plain gzip, Windows = zip). `install.sh` downloads and installs it.
- **Geo data**: not embedded. `geoip.dat` / `geosite.dat` / `geoip.metadb` /
  `GeoLite2-ASN.mmdb` are downloaded on demand into the mihomo home directory.
  Point `kernel.geo_data_dir` at a writable shared directory.
- **Reload cost**: `PUT /configs` restarts the controller HTTP server, so the
  agent reconnects after every reload.
- **Licence**: mihomo is **GPL-3.0** (GitHub's API incorrectly labels it MIT),
  while the Xboard panel is MIT. Distributing a bundled mihomo binary with the
  agent carries GPL obligations for that distribution; downloading the official
  release at install time keeps the two separate. Review this before shipping a
  prebuilt agent image that embeds the kernel.
