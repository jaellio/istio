#!/usr/bin/env bash
# Verify traffic from the meshed client flows through ztunnel and the waypoint,
# and that the waypoint's inbound bind uses the HBONE_WAYPOINT tunnel protocol.
set -euo pipefail

NS=agents
WP_SELECTOR='gateway.networking.k8s.io/gateway-name=agents-waypoint'
SVC=gpt4-backend.agents.svc.cluster.local:8080

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
info()  { printf '\033[36m== %s ==\033[0m\n' "$1"; }

# -----------------------------------------------------------------------------
info "1. ztunnel: is gpt4-backend bound to the waypoint?"
# ztunnel's workloadapi should show the service with a waypoint pointer.
if kubectl exec -n istio-system ds/ztunnel -- \
     curl -s localhost:15000/config_dump 2>/dev/null \
   | grep -A6 '"name": "gpt4-backend"' | grep -q 'waypoint'; then
  green "   ztunnel has gpt4-backend fronted by a waypoint"
else
  red   "   ztunnel does NOT show gpt4-backend as waypoint-bound"
fi

# -----------------------------------------------------------------------------
info "2. Waypoint dataplane: is the 15008 bind HBONE_WAYPOINT?"
# Port-forward the dataplane admin port (localhost:15000 inside the pod).
WP_POD=$(kubectl get pod -n "$NS" -l "$WP_SELECTOR" -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n "$NS" "pod/$WP_POD" 15000:15000 >/dev/null 2>&1 &
PF_PID=$!
trap 'kill $PF_PID 2>/dev/null || true' EXIT
sleep 2
DUMP=$(curl -s localhost:15000/config_dump || true)
if echo "$DUMP" | grep -iqE 'HBONE_WAYPOINT|"tunnelProtocol": *"?HBONE_WAYPOINT'; then
  green "   waypoint bind tunnelProtocol = HBONE_WAYPOINT"
else
  red   "   HBONE_WAYPOINT not found in dataplane config_dump (showing tunnel/protocol lines):"
  echo "$DUMP" | grep -iE 'tunnel|protocol|bind' | head
fi
kill $PF_PID 2>/dev/null || true
trap - EXIT

# -----------------------------------------------------------------------------
info "3. End-to-end: request from client, count waypoint log lines"
before=$(kubectl logs -n "$NS" -l "$WP_SELECTOR" --tail=-1 2>/dev/null | grep -c 'http.status' || true)
RESP=$(kubectl exec -n "$NS" deploy/mesh-client -- \
  curl -s -m 12 -w '\nHTTP %{http_code}\n' \
  "http://$SVC/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}' 2>&1 || true)
after=$(kubectl logs -n "$NS" -l "$WP_SELECTOR" --tail=-1 2>/dev/null | grep -c 'http.status' || true)

echo "$RESP" | tail -3
if echo "$RESP" | grep -q 'HTTP 200'; then
  green "   client got HTTP 200 from the simulator"
else
  red   "   client did NOT get HTTP 200"
fi
if [ "$((after - before))" -gt 0 ]; then
  green "   waypoint processed the request ($((after - before)) new request log line(s))"
else
  red   "   no new waypoint request log lines — traffic did NOT go through the waypoint"
fi

# -----------------------------------------------------------------------------
info "4. Waypoint identity issued by istiod (SPIFFE)"
kubectl logs -n "$NS" -l "$WP_SELECTOR" --tail=-1 2>/dev/null \
  | grep -m1 'Successfully fetched certificate' \
  && green "   waypoint fetched its workload cert from istiod" \
  || red   "   no cert-fetch log found"
