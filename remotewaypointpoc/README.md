# Remote-Waypoint POC (agentgateway-programmed ambient waypoint)

This directory contains a proof-of-concept where an **agentgateway** pod acts as
an Istio **ambient waypoint** that **istiod only observes and issues identity
for** — it does **not** configure the waypoint via xDS. The **agentgateway
control plane** programs the waypoint dataplane itself.

It is structured like the reference implementation in
[kubernetes-sigs/wg-ai-gateway PR #56](https://github.com/kubernetes-sigs/wg-ai-gateway/pull/56),
and reuses the same OpenAI-compatible `llm-d-inference-sim` simulator backends.

## What it demonstrates

```
 mesh-client (ambient)          agents-waypoint (agentgateway)        gpt4-backend (sim)
      │                                   │                                  │
      │ curl http://gpt4-backend:8080/v1/chat/completions                    │
      │──────────────►  ztunnel  ─── HBONE mTLS (15008) ──►                  │
      │              (redirects because the Service is                       │
      │               labeled istio.io/use-waypoint)                         │
      │                                   │  terminates as HBONE_WAYPOINT     │
      │                                   │  forwards to original dest ──────►│
      │◄──────────────────────────  HTTP 200 (chat.completion) ──────────────│
```

Ownership split (the whole point of the POC):

| Concern                                   | Owner                         |
| ----------------------------------------- | ----------------------------- |
| Waypoint **identity** (SPIFFE cert)       | **istiod** (CA only)          |
| Waypoint **pod deployment**               | agentgateway deployer         |
| Waypoint **dataplane config** (binds/routes) | agentgateway control plane |
| Client redirection to the waypoint        | ztunnel (from istiod workloadapi) |

istiod **observes** the `agentgateway-remote-waypoint` GatewayClass (to know it
must issue identity and publish the waypoint into the workloadapi) but pushes
**no** agentgateway xDS to it.

## Branches used

| Component     | Repo / branch                                            |
| ------------- | -------------------------------------------------------- |
| Istio         | this repo @ `jaellio/pocindagwwaypoint`                  |
| agentgateway  | `github.com/agentgateway/agentgateway` @ `jaellio/awgwaypoint` (fork/`origin`) |

## Directory structure

| Path                                  | Purpose                                             |
| ------------------------------------- | --------------------------------------------------- |
| [Makefile](Makefile)                  | `make dev-setup` — cluster → istiod → agentgateway → POC → verify |
| [verify.sh](verify.sh)                | Proves ztunnel redirect, waypoint traversal, HBONE_WAYPOINT bind |
| [manifests/00-namespace.yaml](manifests/00-namespace.yaml)         | `agents` namespace (ambient) |
| [manifests/01-gatewayclass.yaml](manifests/01-gatewayclass.yaml)   | `agentgateway-remote-waypoint` GatewayClass |
| [manifests/02-agentgateway-params.yaml](manifests/02-agentgateway-params.yaml) | Waypoint deployment params + CA address |
| [manifests/03-gateway.yaml](manifests/03-gateway.yaml)             | The waypoint Gateway (HBONE :15008) |
| [manifests/04-client.yaml](manifests/04-client.yaml)               | Meshed `mesh-client` curl pod |
| [manifests/05-simulator-backends.yaml](manifests/05-simulator-backends.yaml) | gpt-4 / claude / default simulators + Services |

## Prerequisites

Tools on `PATH`: `docker`, `kind`, [`ctlptl`](https://github.com/tilt-dev/ctlptl),
`kubectl`, `helm`, `go`. Both repos checked out at the branches above.

## Quick start

```bash
cd remotewaypointpoc

# Full end-to-end setup (see individual targets below for what it runs)
make dev-setup \
  ISTIO_DIR=$HOME/go/src/istio.io/istio \
  AGW_DIR=$HOME/go/src/agentgateway
```

`make dev-setup` runs, in order:

1. `kind-cluster` — create a kind cluster + local registry via `ctlptl`.
2. `build-istio` — build & push `pilot`, `proxyv2`, `ztunnel`, `install-cni`
   using the prow kind script with `HUB`/`TAG` (and `HUB_OVERRIDE=1` so the
   script keeps our registry instead of forcing `localhost:5000`).
3. `install-istiod` — `istioctl install` with the **ambient** profile,
   `PILOT_ENABLE_AGENTGATEWAY=true`, `PILOT_ENABLE_AMBIENT_WAYPOINTS=true`, and
   **non-distroless** images (`values.global.variant=""`).
4. `build-agentgateway` — build & push the agentgateway Go controller image.
5. `install-agentgateway` — helm-install the controller and point its deployer
   at the in-cluster registry (`AGW_PROXY_IMAGE_*`).
6. `deploy` — apply everything under `manifests/`.
7. `verify` — run [verify.sh](verify.sh).

Run any step on its own, e.g. `make deploy`, `make test`, `make verify`.

> **Registry note (ctlptl dual address).** Images are **built/pushed** using the
> host address `localhost:39285` and **pulled** by the node using the in-cluster
> address `ctlptl-registry:5000`. The Makefile encodes this as `REG_HOST` vs
> `REG_INCLUSTER`; override `REG_HOST_PORT` if your ctlptl registry uses a
> different host port (`ctlptl get registry`).

> **Non-distroless images.** `values.global.variant=""` selects the default
> (non-`-distroless`) image variant, which is required here.

## Manual test

Send a chat completion from the meshed client (ztunnel redirects it through the
waypoint):

```bash
kubectl exec -n agents deploy/mesh-client -- \
  curl -s -m 12 -w '\nHTTP %{http_code}\n' \
  http://gpt4-backend.agents.svc.cluster.local:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'
```

Expected: an OpenAI `chat.completion` JSON body and `HTTP 200`.

Or just `make test`.

## Verifying traffic goes through ztunnel + the waypoint

`make verify` (or `./verify.sh`) checks four things:

### 1. ztunnel redirects the client to the waypoint

The Service `gpt4-backend` is labeled `istio.io/use-waypoint: agents-waypoint`,
so istiod publishes it into the workloadapi with a waypoint pointer and ztunnel
tunnels client traffic to the waypoint over HBONE:

```bash
kubectl exec -n istio-system ds/ztunnel -- \
  curl -s localhost:15000/config_dump | \
  grep -A6 '"name": "gpt4-backend"'
# → shows a "waypoint" block referencing agents-waypoint
```

### 2. The waypoint bind uses the HBONE_WAYPOINT tunnel protocol

Port-forward the waypoint **dataplane admin** port (localhost:15000 inside the
pod) and dump its live config — this is config the **agentgateway control
plane** pushed, not istiod:

```bash
WP=$(kubectl get pod -n agents -l gateway.networking.k8s.io/gateway-name=agents-waypoint -o name)
kubectl port-forward -n agents "$WP" 15000:15000 &
curl -s localhost:15000/config_dump | grep -i hbone_waypoint
# → the :15008 bind has tunnelProtocol HBONE_WAYPOINT
```

If the bind shows `HBONE_GATEWAY` instead, the waypoint would reject inbound
traffic with `no bind for <ip>:<port>` (that path requires explicit per-address
binds). `HBONE_WAYPOINT` self-terminates and forwards to the original
destination — which is what an ambient waypoint must do.

### 3. The request actually transits the waypoint

Tail the waypoint log while sending a request:

```bash
kubectl logs -n agents -l gateway.networking.k8s.io/gateway-name=agents-waypoint -f
```

Each request produces a line like:

```
request gateway=agents/agents-waypoint listener=mesh route=agents/_waypoint-default \
  endpoint=10.244.0.28:8080 src.addr=10.244.0.17 http.method=POST \
  http.host=gpt4-backend.agents.svc.cluster.local http.path=/v1/chat/completions \
  http.status=200 protocol=http
```

`src.addr` = the client pod, `endpoint` = the simulator pod — proof the hop went
client → waypoint → backend. If the waypoint were bypassed you'd still get 200
but **no** such log line.

### 4. istiod issued the waypoint's identity

```bash
kubectl logs -n agents -l gateway.networking.k8s.io/gateway-name=agents-waypoint | \
  grep 'Successfully fetched certificate'
# → spiffe://cluster.local/ns/agents/sa/agents-waypoint
```

## Optional: off-cluster LLM through the waypoint

Two overlays live under [optional/](optional/). They demonstrate fronting an
**off-cluster** LLM with the waypoint.

### A. httpbun mock — works today, no key

Points a `ServiceEntry` (labelled `istio.io/use-waypoint: agents-waypoint`) at
the public [httpbun](https://httpbun.com) OpenAI-compatible mock, which answers
over plain HTTP. ztunnel redirects egress to `httpbun.com` through the waypoint,
which transparently forwards to the original destination — the **same
transparent mechanism** the in-cluster backends use. No `HTTPRoute` or
`AgentgatewayBackend` is involved.

```
client ──HTTP──► ztunnel ──HBONE──► agents-waypoint ──HTTP──► httpbun.com:80
                                                              /llm/chat/completions
```

```bash
make deploy-httpbun-mock
make test-httpbun-mock     # expect HTTP 200 + a mock chat.completion
```

`test-httpbun-mock` also greps the waypoint log to prove traversal, e.g.:

```
request gateway=agents/agents-waypoint listener=mesh route=agents/_waypoint-default \
  endpoint=httpbun.com:80 http.host=httpbun.com http.path=/llm/chat/completions \
  http.status=200 protocol=http
```

Prerequisite: the kind node needs egress to the public internet.

### B. Credential injection — reference config (not yet wired on this branch)

The realistic agentgateway pattern (from the official
[OpenAI provider guide](https://agentgateway.dev/docs/kubernetes/latest/llm/providers/openai/))
is for the waypoint to **inject a provider API key** and originate TLS toward an
off-cluster LLM, so the client never holds the credential:

```
client ──HTTP (no key)──► ztunnel ──HBONE──► agents-waypoint
                                               │ policies.auth.secretRef
                                               │ → Authorization: Bearer <key>
                                               │ originates TLS
                                               └───────────► api.openai.com:443
```

This requires an `HTTPRoute` → `AgentgatewayBackend` (`ai.provider.openai` +
`policies.auth.secretRef`). **On this POC branch that route does not attach to a
remote waypoint**: HBONE listeners advertise zero route kinds
(`GenerateSupportedKinds` returns `[]` for HBONE), and no `ParentResolver` maps
`Service`/`ServiceEntry` parents to the waypoint, so routes with a `Service` or
`ServiceEntry` `parentRef` report `status.parents: []` and are ignored. Only the
default transparent route (`_waypoint-default`) runs. The overlay
[optional/external-llm-credential-injection.yaml](optional/external-llm-credential-injection.yaml)
is kept as the target configuration for when route attachment lands.

## Notes

- **No ServiceEntry / AgentgatewayBackend / Route is required** for basic
  transparent traffic through the waypoint. The waypoint forwards to the
  original destination service (in-cluster Service or off-cluster ServiceEntry).
  Custom L7 routing to an `AgentgatewayBackend` (model-based routing like
  PR #56, credential injection) is not yet wired for remote waypoints on this
  branch — see "Off-cluster LLM through the waypoint" above.
- The `securityContext: {$patch: delete}` in the AgentgatewayParameters is only
  needed for the dev/Tilt agentgateway image (writable rootfs). Remove it for a
  production image.
