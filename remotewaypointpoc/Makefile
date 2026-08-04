# Remote-Waypoint POC — dev setup
#
# End-to-end reproduction of the "istiod issues identity, agentgateway programs
# the waypoint" POC. See README.md for the full explanation.
#
# Prereqs on PATH: docker, kind, ctlptl, kubectl, helm, go, and this istio repo
# checked out at branch jaellio/pocindagwwaypoint.
#
# Override these on the command line as needed, e.g.:
#   make dev-setup AGW_DIR=$HOME/go/src/agentgateway
# -----------------------------------------------------------------------------

# --- Repos / branches --------------------------------------------------------
ISTIO_DIR        ?= $(shell git -C .. rev-parse --show-toplevel 2>/dev/null)
ISTIO_BRANCH     ?= jaellio/pocindagwwaypoint
AGW_DIR          ?= $(HOME)/go/src/agentgateway
AGW_REMOTE       ?= origin
AGW_BRANCH       ?= jaellio/awgwaypoint

# --- Registry / images -------------------------------------------------------
# ctlptl provisions a registry reachable from the host at localhost:$(REG_HOST_PORT)
# and from inside the cluster at $(REG_INCLUSTER). Images are BUILT/PUSHED using
# the host address and PULLED by the node using the in-cluster address.
CLUSTER_NAME     ?= kind
REG_NAME         ?= ctlptl-registry
REG_HOST_PORT    ?= 39285
REG_HOST         ?= localhost:$(REG_HOST_PORT)
REG_INCLUSTER    ?= $(REG_NAME):5000

# Istio build HUB/TAG (used by the prow kind script). HUB is the host push
# address; the node pulls the same repo path via $(REG_INCLUSTER).
HUB              ?= $(REG_HOST)
TAG              ?= pocwaypoint
INCLUSTER_HUB    ?= $(REG_INCLUSTER)

# agentgateway controller image
AGW_CTRL_IMAGE   ?= agentgateway-controller
AGW_CTRL_TAG     ?= poc-waypoint
# Dataplane (proxy) image the deployer injects into the waypoint pod. Uses a
# dev tag already present in the ctlptl registry; rebuild/rename as needed.
AGW_PROXY_TAG    ?= v1.0.1-dev

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# -----------------------------------------------------------------------------
# One-shot
# -----------------------------------------------------------------------------
.PHONY: dev-setup
dev-setup: kind-cluster build-istio install-istiod build-agentgateway install-agentgateway deploy verify ## Full setup: cluster -> istiod -> agentgateway -> POC -> verify

.PHONY: clean
clean: ## Delete the kind cluster and registry
	ctlptl delete cluster kind-$(CLUSTER_NAME) || true
	ctlptl delete registry $(REG_NAME) || true

# -----------------------------------------------------------------------------
# Cluster
# -----------------------------------------------------------------------------
.PHONY: kind-cluster
kind-cluster: ## Create a kind cluster + local registry via ctlptl
	ctlptl create registry $(REG_NAME) --port=$(REG_HOST_PORT) || true
	ctlptl create cluster kind --name=kind-$(CLUSTER_NAME) --registry=$(REG_NAME) || true
	kubectl config use-context kind-$(CLUSTER_NAME)

# -----------------------------------------------------------------------------
# Istio (control plane off jaellio/pocindagwwaypoint)
# -----------------------------------------------------------------------------
.PHONY: build-istio
build-istio: ## Build & push istio images (pilot, proxyv2, ztunnel, install-cni) to the registry
	@echo ">> Building istio images from $(ISTIO_DIR) (branch $(ISTIO_BRANCH))"
	@echo ">> HUB=$(HUB) TAG=$(TAG)"
	# HUB_OVERRIDE=1 preserves our HUB instead of the script forcing localhost:5000
	# (see the edit in prow/integ-suite-kind.sh on this branch).
	cd $(ISTIO_DIR) && \
	  HUB=$(HUB) TAG=$(TAG) HUB_OVERRIDE=1 \
	  DOCKER_TARGETS="docker.pilot docker.proxyv2 docker.ztunnel docker.install-cni" \
	  BUILD_WITH_CONTAINER=0 \
	  ./prow/integ-suite-kind.sh --build-only || \
	  ( cd $(ISTIO_DIR) && HUB=$(HUB) TAG=$(TAG) make docker.pilot docker.proxyv2 docker.ztunnel docker.install-cni docker.push )

.PHONY: install-istiod
install-istiod: ## Install istiod (ambient + agentgateway enabled, NON-distroless images)
	cd $(ISTIO_DIR) && go run ./istioctl/cmd/istioctl install -y \
	  --set profile=ambient \
	  --set hub=$(INCLUSTER_HUB) \
	  --set tag=$(TAG) \
	  --set values.global.variant="" \
	  --set values.pilot.env.PILOT_ENABLE_AGENTGATEWAY=true \
	  --set values.pilot.env.PILOT_ENABLE_AMBIENT_WAYPOINTS=true

# -----------------------------------------------------------------------------
# Agentgateway (control plane off jaellio/awgwaypoint)
# -----------------------------------------------------------------------------
.PHONY: agw-checkout
agw-checkout: ## Fetch & checkout the agentgateway POC branch
	cd $(AGW_DIR) && git fetch $(AGW_REMOTE) $(AGW_BRANCH) && git checkout $(AGW_BRANCH)

.PHONY: build-agentgateway
build-agentgateway: ## Build & push the agentgateway controller image (Go control plane)
	cd $(AGW_DIR) && make -C ./controller VERSION=$(AGW_CTRL_TAG) agentgateway-controller
	cp $(AGW_DIR)/controller/_output/pkg/agentgateway/agentgateway-linux-$(shell go env GOARCH) \
	   $(AGW_DIR)/tools/tilt/agentgateway-controller
	printf 'FROM ubuntu:24.04\nRUN useradd -r -U -u 65532 -s /usr/sbin/nologin agentgateway\nRUN chown agentgateway:agentgateway /usr/local/bin\nCOPY --chown=agentgateway:agentgateway agentgateway-controller /usr/local/bin/agentgateway-controller\nUSER 65532\nENTRYPOINT ["/usr/local/bin/agentgateway-controller"]\n' > /tmp/Dockerfile.agwctrl
	docker build -t $(REG_HOST)/$(AGW_CTRL_IMAGE):$(AGW_CTRL_TAG) -f /tmp/Dockerfile.agwctrl $(AGW_DIR)/tools/tilt/
	docker push $(REG_HOST)/$(AGW_CTRL_IMAGE):$(AGW_CTRL_TAG)

.PHONY: install-agentgateway
install-agentgateway: ## Install the agentgateway controller via its helm chart
	helm upgrade --install agentgateway $(AGW_DIR)/controller/install/helm/agentgateway \
	  --namespace default \
	  --set image.registry=$(REG_INCLUSTER) \
	  --set controller.image.repository=$(AGW_CTRL_IMAGE) \
	  --set controller.image.tag=$(AGW_CTRL_TAG) \
	  --set controller.image.pullPolicy=IfNotPresent
	# Point the deployer at the in-cluster registry + dev proxy image.
	# (envconfig prefix is AGW_ — bare PROXY_IMAGE_* are ignored.)
	kubectl set env deployment/agentgateway -n default \
	  AGW_PROXY_IMAGE_REGISTRY=$(REG_INCLUSTER) \
	  AGW_PROXY_IMAGE_REPOSITORY=agentgateway \
	  AGW_PROXY_IMAGE_TAG=$(AGW_PROXY_TAG)
	kubectl rollout status deployment/agentgateway -n default --timeout=120s

# -----------------------------------------------------------------------------
# POC resources
# -----------------------------------------------------------------------------
.PHONY: deploy
deploy: ## Apply all POC manifests (ns, class, params, gateway, client, backends)
	kubectl apply -f manifests/
	kubectl rollout status deployment/agents-waypoint -n agents --timeout=120s || true
	kubectl rollout status deployment/gpt4-backend    -n agents --timeout=120s
	kubectl rollout status deployment/mesh-client      -n agents --timeout=120s

.PHONY: undeploy
undeploy: ## Delete the POC resources
	kubectl delete -f manifests/ --ignore-not-found

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
.PHONY: test
test: ## Send a chat-completion request from the client through the waypoint
	kubectl exec -n agents deploy/mesh-client -- \
	  curl -s -m 12 -w '\nHTTP %{http_code}\n' \
	  http://gpt4-backend.agents.svc.cluster.local:8080/v1/chat/completions \
	  -H 'Content-Type: application/json' \
	  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'

.PHONY: verify
verify: ## Prove traffic traverses ztunnel + waypoint and the bind is HBONE_WAYPOINT
	./verify.sh

# -----------------------------------------------------------------------------
# Optional: off-cluster LLM through the waypoint (httpbun mock, no key)
# -----------------------------------------------------------------------------

.PHONY: deploy-httpbun-mock
deploy-httpbun-mock: ## Front the off-cluster httpbun OpenAI mock with the waypoint (no key)
	kubectl apply -f optional/external-llm-httpbun-mock.yaml

.PHONY: test-httpbun-mock
test-httpbun-mock: ## Send a request to the off-cluster mock through the waypoint
	kubectl exec -n agents deploy/mesh-client -- \
	  curl -s -m 20 -w '\nHTTP %{http_code}\n' \
	  http://httpbun.com/llm/chat/completions \
	  -H 'Content-Type: application/json' \
	  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'
	@echo "Confirm it traversed the waypoint:"
	kubectl logs -n agents deploy/agents-waypoint --tail=30 | grep httpbun | tail -1

.PHONY: undeploy-httpbun-mock
undeploy-httpbun-mock: ## Remove the httpbun mock ServiceEntry
	kubectl delete -f optional/external-llm-httpbun-mock.yaml --ignore-not-found

# -----------------------------------------------------------------------------
# Optional (reference only): external LLM with credential injection.
# NOTE: this requires an HTTPRoute -> AgentgatewayBackend, which is not yet
# wired for remote waypoints on this branch. Kept as a reference config.
# -----------------------------------------------------------------------------
OPENAI_API_KEY ?=

.PHONY: deploy-external-llm
deploy-external-llm: ## (reference) Apply the OpenAI credential-injection overlay (set OPENAI_API_KEY=...)
	@if [ -n "$(OPENAI_API_KEY)" ]; then \
	  kubectl create secret generic openai-secret -n agents \
	    --from-literal=Authorization="Bearer $(OPENAI_API_KEY)" \
	    --dry-run=client -o yaml | kubectl apply -f - ; \
	fi
	kubectl apply -f optional/external-llm-credential-injection.yaml

.PHONY: undeploy-external-llm
undeploy-external-llm: ## Remove the credential-injection overlay
	kubectl delete -f optional/external-llm-credential-injection.yaml --ignore-not-found
