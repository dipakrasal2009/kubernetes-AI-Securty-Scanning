// Package checks contains all security check implementations.
// Stage 1: stubs that compile and satisfy the Check interface.
// Stage 2: real logic replaces each stub.
package checks

import (
	"github.com/yourorg/kubeaudit/pkg/k8sclient"
	"github.com/yourorg/kubeaudit/pkg/models"
	"github.com/yourorg/kubeaudit/pkg/orchestrator"
)

// Ensure all stubs satisfy the orchestrator.Check interface at compile time.
var _ orchestrator.Check = (*ContainerCheck)(nil)
var _ orchestrator.Check = (*ResourceCheck)(nil)
var _ orchestrator.Check = (*NetworkCheck)(nil)
var _ orchestrator.Check = (*RBACCheck)(nil)
var _ orchestrator.Check = (*SecretCheck)(nil)
var _ orchestrator.Check = (*ImageCheck)(nil)

// ContainerCheck will detect: root user, privileged flag, dangerous Linux caps.
type ContainerCheck struct{}
func (c *ContainerCheck) Name() string { return "container-security" }
func (c *ContainerCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// ResourceCheck will detect: missing CPU/memory limits, requests, QoS class.
type ResourceCheck struct{}
func (c *ResourceCheck) Name() string { return "resource-limits" }
func (c *ResourceCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// NetworkCheck will detect: hostNetwork, hostPID, NodePort services.
type NetworkCheck struct{}
func (c *NetworkCheck) Name() string { return "network-exposure" }
func (c *NetworkCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// RBACCheck will detect: wildcard verbs, cluster-admin overuse, default SA.
type RBACCheck struct{}
func (c *RBACCheck) Name() string { return "rbac-misconfig" }
func (c *RBACCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// SecretCheck will detect: secrets in env vars, missing encryption annotations.
type SecretCheck struct{}
func (c *SecretCheck) Name() string { return "secret-exposure" }
func (c *SecretCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// ImageCheck will detect: latest tag, missing digest, always-pull policy.
type ImageCheck struct{}
func (c *ImageCheck) Name() string { return "image-hygiene" }
func (c *ImageCheck) Run(res *k8sclient.ResourceSet) []models.Finding { return nil }

// DefaultChecks returns all built-in checks ready to be registered.
func DefaultChecks() []orchestrator.Check {
	return []orchestrator.Check{
		&ContainerCheck{},
		&ResourceCheck{},
		&NetworkCheck{},
		&RBACCheck{},
		&SecretCheck{},
		&ImageCheck{},
	}
}
