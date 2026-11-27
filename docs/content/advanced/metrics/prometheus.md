---
title: Prometheus
---

To monitor the WireGuard server, you can use [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/). The container exposes a `/metrics/prometheus` endpoint that can be scraped by Prometheus.

## Enable Prometheus

To enable Prometheus metrics, go to Admin Panel > General and enable Prometheus.

You can optionally set a Bearer Password for the metrics endpoints. This is useful if you want to expose the metrics endpoint to the internet.

## Configure Prometheus

You need to add a scrape config to your Prometheus configuration file. Here is an example:

```yaml
scrape_configs:
    - job_name: 'wg-easy'
      scrape_interval: 30s
      metrics_path: /metrics/prometheus
      static_configs:
          - targets:
                - 'localhost:51821'
      authorization:
          type: Bearer
          credentials: 'SuperSecurePassword'
```

## Multi-interface and routing metrics

Peer metrics include `interface`, `client_id`, and `client_name` labels. Use
`client_id` as the stable identity because names can change. Interface metrics
report desired and applied revisions, observed runtime status, listen port,
compatibility mode, and whether a restart is still required.

Common-routing metrics report the configured group count, enabled and verified
active state, member and prefix counts, all-exits-down state, candidate
priorities, and the number of groups or members depending on each exit client.
Detailed reconciliation errors remain in the authenticated API and application
logs; they are not emitted as unbounded Prometheus labels.

The main metric families are:

- `wg_easy_interface_*`
- `wireguard_*` and `wg_easy_client_*`
- `wg_easy_routing_group_*`
- `wg_easy_exit_client_*`
- `wg_easy_runtime_*`

## Grafana Dashboard

### VPN operations dashboard

[Download the wg-easy VPN operations dashboard](../../assets/grafana/wg-easy-vpn.json).

Import the JSON in **Grafana → Dashboards → New → Import**, then select your
Prometheus data source in the dashboard's **Prometheus** dropdown. It uses only
built-in panels and the Prometheus data source; no additional plugins or
recording rules are required. The dashboard targets Grafana 11 or newer.

Set the Prometheus data source's scrape interval to match your scraper
(`30s` in the example above). Throughput queries use `$__rate_interval`; traffic
volumes use the selected dashboard time range. Allow several scrapes before
expecting rate charts to populate.

The dashboard includes:

- Scrape health, enabled interfaces and clients, recent client handshakes, and
  routing/reconciliation problems.
- Per-client upload/download rates, top traffic consumers over the selected
  period, connectivity history, client inventory, and missing/stale handshakes.
- Routing-group state history, verified activation, all-exits-down conditions,
  and configured member/prefix counts.
- Exit-candidate traffic and connectivity, ordered priorities, and group/member
  dependency counts.
- Interface runtime state, desired/applied revision backlog, restart-required
  flags, compatibility mode, and global reconciliation diagnostics.

**Filter scope:** choose one Job and Instance. Interface and Client ID filter
client panels. Routing group ID filters group health and selects exit candidates;
Interface also limits those exit candidates. Client ID does not filter exit
panels. Global reconciliation and scrape panels remain instance-wide. Names and
IDs appear in legends and tables. Group health spans all its interfaces even
when an Interface filter is selected.

### Interpreting traffic and health

- **Direction:** `wireguard_received_bytes` is peer → server (client upload),
  and `wireguard_sent_bytes` is server → peer (client download). For an exit,
  server → exit typically carries forwarded uploads and exit → server carries
  returning downloads. Exit charts use explicit peer directions.
- **Connectivity:** the exporter calls a peer connected when its handshake is
  less than ten minutes old. This is not an end-to-end probe or the routing
  engine's exit-health timeout. Sleeping clients can show stale handshakes.
  The enabled/recent summary excludes disabled clients; the inventory retains
  the raw handshake observation alongside the enabled flag.
- **Missing handshakes:** the exporter omits handshake metrics when no handshake
  is available. The dashboard lists these peers separately instead of treating
  the missing timestamp as a recent handshake. Recreated interfaces or missing
  runtime data can also cause this state.
- **Traffic totals:** rates and range volumes account for observed counter resets
  before aggregation. They are estimates, not billing counters. Scrape gaps,
  renamed profiles, address/enabled-label changes, and resets between scrapes
  can lose accounting continuity. Adding member and exit traffic counts the
  same forwarded path twice; overview totals are peer-side traffic, not unique
  Internet usage.
- **Group health:** verified active is stronger than merely saved or enabled.
  The all-exits-down metric combines awaiting-exit, blocked, and host-fallback
  runtime states. The dashboard cannot distinguish those policies from these
  metrics alone. Use the authenticated routing-group UI/API for details.
- **Exit counts:** selecting groups filters which exit clients appear, but the
  exported dependency and active-group counts still cover all groups for each
  exit. Primary and backup candidates are included, with shared exits shown
  once. The active-group count reflects runtime state; inspect group verified
  activation separately when desired configuration changes are pending.
- **Missing data:** gaps and “No data” are not converted to healthy zeroes.
  Check the scrape-health panel first. A successful scrape or observed-up
  interface does not verify public UDP reachability.

### Current exporter limits

The exporter does **not** expose client-to-routing-group membership, per-group
selected-exit identity, routing-rule traffic counters, probe latency, packet
loss, or throughput capacity. The dashboard explicitly marks per-group member
traffic as unavailable and shows whole-peer traffic for the selected groups'
exit candidates. It does not attribute a shared exit's bytes to one group.

Adding a membership metric would allow totals for all tunnel traffic of each
group's members, including traffic outside its routed prefixes. Measuring only
traffic actually routed through a group needs dedicated routing-policy counters.

### Community dashboard

For the older, simpler single-interface view, there is also this community dashboard:

[![Grafana Dashboard](https://grafana.com/api/dashboards/21733/images/16863/image)](https://grafana.com/grafana/dashboards/21733-wireguard/)

[21733](https://grafana.com/grafana/dashboards/21733-wireguard/)

/// note | Unofficial

The Grafana dashboard is not official and is not maintained by the `wg-easy` team. If you have any issues with the dashboard, please contact the author of the dashboard.
See [#1299](https://github.com/wg-easy/wg-easy/pull/1299) for more information.

///

The separate `wireguard_peer_endpoint_info` gauge reports an observed endpoint
with stable `interface` and `client_id` labels. Existing traffic and handshake
series retain their label identities. Endpoints include client addresses and
ports, can change during roaming and create additional time series. Keep metrics
authentication enabled and restrict access and retention appropriately.
