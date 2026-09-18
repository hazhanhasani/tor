# Cloudflare CDN Managed Inbound

Tor Location Manager can replace the old per-location public 3x-ui inbound with one shared CDN-facing inbound.

## Architecture

```text
Client
  |
  | VLESS + WebSocket + TLS
  v
Cloudflare Edge (orange-cloud DNS)
  |
  | HTTPS/WebSocket to origin
  v
3x-ui shared inbound: torloc-cdn
  |
  | route by authenticated client email
  +--> torloc-de-* --> SS2022 Gateway --> Tor DE
  +--> torloc-fr-* --> SS2022 Gateway --> Tor FR
  +--> torloc-nl-* --> SS2022 Gateway --> Tor NL
```

Every enabled Location receives a deterministic, secret-derived VLESS UUID and a unique managed email. One inbound can therefore serve all current and future Tor Locations without consuming one Cloudflare-compatible public port per country.

## 3x-ui certificate reuse

The manager calls:

```text
GET /panel/api/server/getWebCertFiles
```

with the configured Bearer API token. 3x-ui returns only the filesystem paths of its own `webCertFile` and `webKeyFile`. The private key contents never leave the 3x-ui server. Those paths are placed in Xray's inbound TLS `certificates` object.

If the panel has no certificate configured, CDN reconciliation fails closed with a clear error instead of creating a plaintext inbound.

## Transport profile

The managed inbound uses:

- Protocol: VLESS
- Transport: WebSocket
- Security: TLS
- TLS minimum: 1.2
- TLS maximum: 1.3
- ALPN: `http/1.1`
- Optional strict SNI rejection
- Per-location secret-derived UUID
- Random/stored WebSocket path
- Sniffing disabled on the public managed inbound

The generated client link uses the Cloudflare hostname as endpoint, Host and SNI, and advertises a Chrome TLS fingerprint.

## Cloudflare requirements

The DNS record for the configured CDN hostname must be proxied (orange cloud). WebSockets must be enabled. Set Cloudflare SSL/TLS mode to **Full (strict)** so Cloudflare validates the certificate presented by the 3x-ui origin.

Supported HTTPS proxy ports are restricted in the UI and validator to:

```text
443, 2053, 2083, 2087, 2096, 8443
```

The origin port must not collide with the panel listener or Hybrid Tunnel control/WireGuard ports.

## Routing model

The shared inbound tag is:

```text
torloc-cdn
```

For each enabled Location, Xray receives a routing rule matching both:

- `inboundTag = ["torloc-cdn"]`
- `user = ["torloc.<slug>@managed.invalid"]`

and sends the connection to that Location's existing `torloc-<slug>` outbound.

Manual 3x-ui inbound assignments continue to work as separate rules.

## Migration

When Cloudflare mode is enabled and a sync runs:

1. Old managed `torloc-in-*` public inbounds are deleted.
2. One `torloc-cdn` inbound is created.
3. Each enabled Location is inserted as a client in that inbound.
4. Routing rules are rebuilt by client identity.
5. Existing unrelated 3x-ui inbounds, outbounds and routes remain untouched.

Switching back to legacy mode restores the previous per-location managed inbound behavior on the next reconciliation.

## Tunnel integration

When Tor Location Manager runs on a foreign Hybrid Tunnel node, the shared CDN origin port is added to the automatic Port Fabric inventory. This allows the Iran edge to mirror that single origin port through the existing overlay when that topology is used.

## Origin exposure

Cloudflare proxying hides the origin address from normal client configuration, but it does not make an already-known origin IP disappear. For stronger origin protection, restrict the CDN origin port at the server firewall to Cloudflare source ranges or place the origin behind a suitable Cloudflare-origin access design.
