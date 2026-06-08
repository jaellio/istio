// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agentgateway

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayalpha "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pilot/pkg/serviceregistry/ambient"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/util/sets"
)

// WaypointServiceBinding maps a fronted service to the AGW waypoint Gateway that fronts it.
// This is the core data structure for Phase 2 fronted service discovery.
// TODO(jaellio): Why is this relationship 1:1? Shouldn't the key be the gateway that is a waypoint?
// TODO(jaellio): When using a for gateway mapping on the output agw resources wouldn't it make sense
// to have the waypoint gateway as the key instead of the service?
type WaypointServiceBinding struct {
	// ServiceKey is the NamespacedName of the fronted service
	ServiceKey types.NamespacedName
	// WaypointGateway is the NamespacedName of the waypoint Gateway
	WaypointGateway types.NamespacedName
}

func (w WaypointServiceBinding) ResourceName() string {
	return w.ServiceKey.String()
}

func (w WaypointServiceBinding) Equals(other WaypointServiceBinding) bool {
	return w.ServiceKey == other.ServiceKey && w.WaypointGateway == other.WaypointGateway
}

// BuildWaypointServiceBindings creates a collection mapping services to their AGW waypoint gateways.
// For each k8s Service with a use-waypoint label (or inheriting from namespace) pointing to an
// agentgateway-waypoint class Gateway, a WaypointServiceBinding is created.
// TODO(jaellio): why aren't we doing any filtering on the services? Not all services will have the use-waypoint label
// and be bound to a waypoint?
// TODO(jaellio): The use-waypoint label may also exist on a pod. We need to handle this somehow. However, I don't think
// gatewayAPI policies can be attached to pods - the only applicable attachment here is service
func BuildWaypointServiceBindings(
	services krt.Collection[*corev1.Service],
	namespaces krt.Collection[*corev1.Namespace],
	gateways krt.Collection[*gatewayv1.Gateway],
	gatewayClasses krt.Collection[gatewaycommon.GatewayClass],
	opts krt.OptionsBuilder,
) krt.Collection[WaypointServiceBinding] {
	return krt.NewCollection(services, func(ctx krt.HandlerContext, svc *corev1.Service) *WaypointServiceBinding {
		// check if the service or it's namespace has the use-waypoint label
		wpRef := resolveUseWaypoint(ctx, svc.ObjectMeta, namespaces)
		if wpRef == nil {
			return nil
		}

		// Check if the referenced gateway exists
		gw := ptr.Flatten(krt.FetchOne(ctx, gateways, krt.FilterKey(wpRef.ResourceName())))
		if gw == nil {
			return nil
		}

		// Check that the gateway has an AGW waypoint class
		class := gatewaycommon.FetchAgentgatewayClass(ctx, gatewayClasses, gw.Spec.GatewayClassName)
		if class == nil || class.Controller != constants.ManagedAgentgatewayWaypointController {
			return nil
		}

		return &WaypointServiceBinding{
			ServiceKey:      types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name},
			WaypointGateway: types.NamespacedName{Namespace: wpRef.Namespace, Name: wpRef.Name},
		}
	}, opts.WithName("WaypointServiceBindings")...)
}

// resolveUseWaypoint looks up the use-waypoint label on a service or its namespace
// and returns the referenced waypoint gateway, if any.
func resolveUseWaypoint(
	ctx krt.HandlerContext,
	meta metav1.ObjectMeta,
	namespaces krt.Collection[*corev1.Namespace],
) *krt.Named {
	// Check object labels first
	// These labels take precedence over namespace labels
	wp, isNone := ambient.GetUseWaypoint(meta, meta.Namespace)
	if isNone {
		return nil
	}
	if wp != nil {
		return wp
	}

	// Fall back to namespace labels
	ns := ptr.Flatten(krt.FetchOne(ctx, namespaces, krt.FilterKey(meta.Namespace)))
	if ns == nil {
		return nil
	}
	wp, _ = ambient.GetUseWaypoint(ns.ObjectMeta, meta.Namespace)
	return wp
}

// OutboundServiceKey represents a service that a waypoint needs addresses for
// but doesn't directly front.
type OutboundServiceKey struct {
	Namespace string
	Name      string
}

func (o OutboundServiceKey) String() string {
	return fmt.Sprintf("%s/%s", o.Namespace, o.Name)
}

// ComputeOutboundServicesFromHTTPRoutes extracts backend service references from HTTPRoutes
// that are attached to fronted services of a waypoint. Returns services that are NOT in the
// fronted set (i.e., outbound services the waypoint needs to reach but doesn't own).
func ComputeOutboundServicesFromHTTPRoutes(
	ctx krt.HandlerContext,
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	routeIndex krt.Index[types.NamespacedName, *gatewayv1.HTTPRoute],
	frontedServices sets.Set[types.NamespacedName],
) sets.Set[types.NamespacedName] {
	outbound := sets.New[types.NamespacedName]()
	for svc := range frontedServices {
		routes := routeIndex.Fetch(ctx, svc)
		for _, route := range routes {
			for _, rule := range route.Spec.Rules {
				// Extract from backendRefs
				for _, br := range rule.BackendRefs {
					addBackendToOutbound(br.BackendObjectReference, route.Namespace, frontedServices, outbound)
				}
				// Extract from filter mirrors
				for _, filter := range rule.Filters {
					if filter.Type == gatewayv1.HTTPRouteFilterRequestMirror && filter.RequestMirror != nil {
						addBackendToOutbound(filter.RequestMirror.BackendRef, route.Namespace, frontedServices, outbound)
					}
				}
			}
		}
	}
	return outbound
}

// ComputeOutboundServicesFromGRPCRoutes extracts backend service references from GRPCRoutes.
func ComputeOutboundServicesFromGRPCRoutes(
	ctx krt.HandlerContext,
	grpcRouteIndex krt.Index[types.NamespacedName, *gatewayv1.GRPCRoute],
	frontedServices sets.Set[types.NamespacedName],
) sets.Set[types.NamespacedName] {
	outbound := sets.New[types.NamespacedName]()
	for svc := range frontedServices {
		routes := grpcRouteIndex.Fetch(ctx, svc)
		for _, route := range routes {
			for _, rule := range route.Spec.Rules {
				for _, br := range rule.BackendRefs {
					addBackendToOutbound(br.BackendObjectReference, route.Namespace, frontedServices, outbound)
				}
				for _, filter := range rule.Filters {
					if filter.Type == gatewayv1.GRPCRouteFilterRequestMirror && filter.RequestMirror != nil {
						addBackendToOutbound(filter.RequestMirror.BackendRef, route.Namespace, frontedServices, outbound)
					}
				}
			}
		}
	}
	return outbound
}

// ComputeOutboundServicesFromTCPRoutes extracts backend service references from TCPRoutes.
func ComputeOutboundServicesFromTCPRoutes(
	ctx krt.HandlerContext,
	tcpRouteIndex krt.Index[types.NamespacedName, *gatewayalpha.TCPRoute],
	frontedServices sets.Set[types.NamespacedName],
) sets.Set[types.NamespacedName] {
	outbound := sets.New[types.NamespacedName]()
	for svc := range frontedServices {
		routes := tcpRouteIndex.Fetch(ctx, svc)
		for _, route := range routes {
			for _, rule := range route.Spec.Rules {
				for _, br := range rule.BackendRefs {
					addBackendToOutbound(br.BackendObjectReference, route.Namespace, frontedServices, outbound)
				}
			}
		}
	}
	return outbound
}

// ComputeOutboundServicesFromTLSRoutes extracts backend service references from TLSRoutes.
func ComputeOutboundServicesFromTLSRoutes(
	ctx krt.HandlerContext,
	tlsRouteIndex krt.Index[types.NamespacedName, *gatewayv1.TLSRoute],
	frontedServices sets.Set[types.NamespacedName],
) sets.Set[types.NamespacedName] {
	outbound := sets.New[types.NamespacedName]()
	for svc := range frontedServices {
		routes := tlsRouteIndex.Fetch(ctx, svc)
		for _, route := range routes {
			for _, rule := range route.Spec.Rules {
				for _, br := range rule.BackendRefs {
					addBackendToOutbound(br.BackendObjectReference, route.Namespace, frontedServices, outbound)
				}
			}
		}
	}
	return outbound
}

// addBackendToOutbound checks if a backendRef points to a Service not in the fronted set
// and adds it to the outbound set if so.
func addBackendToOutbound(
	ref gatewayv1.BackendObjectReference,
	routeNamespace string,
	frontedServices sets.Set[types.NamespacedName],
	outbound sets.Set[types.NamespacedName],
) {
	refKind := normalizeReference(ref.Group, ref.Kind, gvk.Service)
	if refKind != gvk.Service {
		return
	}
	ns := routeNamespace
	if ref.Namespace != nil {
		ns = string(*ref.Namespace)
	}
	key := types.NamespacedName{Namespace: ns, Name: string(ref.Name)}
	if !frontedServices.Contains(key) {
		outbound.Insert(key)
	}
}

// IndexHTTPRoutesByServiceParentRef builds an index from Service NamespacedName to HTTPRoutes
// that reference that service as a parentRef.
func IndexHTTPRoutesByServiceParentRef(route *gatewayv1.HTTPRoute) []types.NamespacedName {
	return indexRouteByServiceParentRef(route.Namespace, route.Spec.ParentRefs)
}

// IndexGRPCRoutesByServiceParentRef builds an index from Service NamespacedName to GRPCRoutes
// that reference that service as a parentRef.
func IndexGRPCRoutesByServiceParentRef(route *gatewayv1.GRPCRoute) []types.NamespacedName {
	return indexRouteByServiceParentRef(route.Namespace, route.Spec.ParentRefs)
}

// IndexTCPRoutesByServiceParentRef builds an index from Service NamespacedName to TCPRoutes
// that reference that service as a parentRef.
func IndexTCPRoutesByServiceParentRef(route *gatewayalpha.TCPRoute) []types.NamespacedName {
	return indexRouteByServiceParentRef(route.Namespace, route.Spec.ParentRefs)
}

// IndexTLSRoutesByServiceParentRef builds an index from Service NamespacedName to TLSRoutes
// that reference that service as a parentRef.
func IndexTLSRoutesByServiceParentRef(route *gatewayv1.TLSRoute) []types.NamespacedName {
	return indexRouteByServiceParentRef(route.Namespace, route.Spec.ParentRefs)
}

// indexRouteByServiceParentRef extracts Service parentRefs from a route's parentRefs.
func indexRouteByServiceParentRef(routeNamespace string, refs []gatewayv1.ParentReference) []types.NamespacedName {
	var result []types.NamespacedName
	for _, ref := range refs {
		refKind := normalizeReference(ref.Group, ref.Kind, gvk.KubernetesGateway)
		if refKind != gvk.Service {
			continue
		}
		ns := routeNamespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		result = append(result, types.NamespacedName{Namespace: ns, Name: string(ref.Name)})
	}
	return result
}

// FrontedServicesForWaypoint returns the set of service NamespacedNames fronted by a specific waypoint gateway.
func FrontedServicesForWaypoint(
	ctx krt.HandlerContext,
	waypointGateway types.NamespacedName,
	bindingsByWaypoint krt.Index[types.NamespacedName, WaypointServiceBinding],
) sets.Set[types.NamespacedName] {
	bindings := bindingsByWaypoint.Fetch(ctx, waypointGateway)
	result := sets.NewWithLength[types.NamespacedName](len(bindings))
	for _, b := range bindings {
		result.Insert(b.ServiceKey)
	}
	return result
}
