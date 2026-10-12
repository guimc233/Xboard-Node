package model

func OutboundSupportMatrix() map[string]KernelOutboundSupport {
	return map[string]KernelOutboundSupport{
		// mihomo proxy types. The panel's normalized templates only emit
		// shadowsocks/socks5/vless, but raw custom_outbounds may use any type
		// the kernel understands.
		"mihomo": {
			Protocols: []string{
				"shadowsocks",
				"ssr",
				"socks",
				"socks5",
				"http",
				"vmess",
				"vless",
				"trojan",
				"snell",
				"hysteria",
				"hysteria2",
				"tuic",
				"anytls",
				"mieru",
				"sudoku",
				"shadowquic",
				"trusttunnel",
				"wireguard",
				"ssh",
			},
			Features: []string{
				"tag",
				"protocol",
				"settings",
				"proxy_tag",
			},
		},
	}
}

type KernelOutboundSupport struct {
	Protocols []string
	Features  []string
}
