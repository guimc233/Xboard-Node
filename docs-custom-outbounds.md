# Custom Outbounds

## Quick Example

```json
{
  "custom_outbounds": [
    {
      "tag": "warp",
      "protocol": "wireguard",
      "settings": {
        "peers": [{"address": "162.159.195.1"}],
        "private_key": "aMzA..."
      }
    },
    {
      "tag": "us-proxy",
      "protocol": "socks",
      "settings": {"servers": [{"address": "1.2.3.4", "port": 1080}]},
      "proxy_tag": "warp"
    }
  ]
}
```

## Supported Protocols

The panel validates `protocol` against the mihomo type it maps to. Anything not
in this list is rejected before the node starts.

| Panel protocol | mihomo type | Notes |
|----------------|-------------|-------|
| `shadowsocks` | `ss` | `cipher` (or `method`) + `password` |
| `ssr` | `ssr` | |
| `socks` / `socks5` | `socks5` | optional `username` / `password` |
| `http` | `http` | optional `username` / `password` |
| `vmess` | `vmess` | `uuid`, optional `alterId` |
| `vless` | `vless` | `uuid`, optional `flow` |
| `trojan` | `trojan` | `password` |
| `snell` | `snell` | |
| `hysteria` | `hysteria` | |
| `hysteria2` | `hysteria2` | |
| `tuic` | `tuic` | |
| `anytls` | `anytls` | |
| `mieru` | `mieru` | |
| `sudoku` | `sudoku` | |
| `shadowquic` | `shadowquic` | |
| `trusttunnel` | `trusttunnel` | |
| `wireguard` | `wireguard` | |
| `ssh` | `ssh` | |

## Core Fields

| Field | Required | Description |
|-------|----------|-------------|
| `tag` | ✅ | Outbound tag, referenced in routes |
| `protocol` | ✅ | Protocol type |
| `settings` | ✅ | Protocol-specific configuration |
| `proxy_tag` | ❌ | Chain to another outbound (references its tag) |

## Best Practices

- **Prefer** `custom_outbounds`: panel-managed, cross-kernel compatible
- **Use** `kernel.custom_outbound` only: when native fields are needed
