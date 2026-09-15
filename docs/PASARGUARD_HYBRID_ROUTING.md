# PasarGuard + Hybrid Tunnel Routing

Tor Location Manager 1.6 can manage routing for both 3x-ui and PasarGuard.

## PasarGuard API requirements

Create an API key in PasarGuard with at least these permissions:

- `cores.read`
- `cores.update`

Configure the PasarGuard Base URL, API key and target Core ID in **Panel & Network**. The integration reads the target Core with `/api/core/{id}` and updates it with the official Core API. Only outbounds/rules prefixed with `tlm-pg-` are owned by Tor Location Manager.

## Tor routing

A Tor location can select existing PasarGuard inbound tags. The manager injects an SS2022 outbound to the Tor Gateway and a field routing rule for those tags. Existing unrelated Core outbounds and rules are preserved.

## Hybrid tunnel routing

Each hybrid link provides a private Iran overlay IP and foreign overlay IP. Selected panel inbounds use an Xray `freedom` outbound with `sendThrough` set to the Iran overlay IP. The node agent installs source policy routing on the Iran edge:

```text
Xray inbound
  -> freedom(sendThrough=Iran overlay IP)
  -> dedicated policy table
  -> WireGuard (direct or reverse transport)
  -> foreign edge NAT
  -> Internet
```

The policy table contains the tunnel default route plus a blackhole fallback. Traffic using the overlay source therefore does not fall through to the Iran server's ordinary default route if the tunnel disappears.

## Placement requirement

The Xray runtime receiving the managed hybrid route must run on the same Iran edge that owns the tunnel overlay IP. For PasarGuard, do not attach a shared multi-node Core to a hybrid route unless every affected node has the same required overlay path.

## Public endpoint visibility

The design keeps the foreign public IP out of end-user routing/config and prevents accidental default-route fallback for managed traffic. It does not make the two servers' Internet endpoints invisible to their peers, hosting providers, or network operators.
