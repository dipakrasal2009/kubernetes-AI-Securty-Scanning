// Package k8sclient provides lightweight Kubernetes resource types and a client
// that reads from the Kubernetes API using only Go stdlib (net/http + encoding/json).
// When you later add k8s.io/client-go, replace the HTTP calls with client-go List()
// calls — the ResourceSet interface and all callers remain unchanged.
package k8sclient

// ── Minimal Kubernetes resource types ────────────────────────────────────────
// These mirror the fields we actually use from the real API objects.
// They are intentionally minimal — add fields as checks need them.

type ObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ── Container / Pod types ─────────────────────────────────────────────────────

type SecurityContext struct {
	RunAsNonRoot           *bool   `json:"runAsNonRoot,omitempty"`
	RunAsUser              *int64  `json:"runAsUser,omitempty"`
	Privileged             *bool   `json:"privileged,omitempty"`
	ReadOnlyRootFilesystem *bool   `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEsc      *bool   `json:"allowPrivilegeEscalation,omitempty"`
	Capabilities           *Capabilities `json:"capabilities,omitempty"`
}

type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

type ResourceRequirements struct {
	Limits   map[string]string `json:"limits,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
}

type EnvVar struct {
	Name      string       `json:"name"`
	Value     string       `json:"value,omitempty"`
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Container struct {
	Name            string               `json:"name"`
	Image           string               `json:"image"`
	SecurityContext *SecurityContext      `json:"securityContext,omitempty"`
	Resources       ResourceRequirements `json:"resources,omitempty"`
	Env             []EnvVar             `json:"env,omitempty"`
}

type PodSpec struct {
	Containers         []Container      `json:"containers"`
	InitContainers     []Container      `json:"initContainers,omitempty"`
	HostNetwork        bool             `json:"hostNetwork,omitempty"`
	HostPID            bool             `json:"hostPID,omitempty"`
	ServiceAccountName string           `json:"serviceAccountName,omitempty"`
	SecurityContext    *PodSecurityCtx  `json:"securityContext,omitempty"`
}

type PodSecurityCtx struct {
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
}

type PodTemplateSpec struct {
	Meta ObjectMeta `json:"metadata,omitempty"`
	Spec PodSpec    `json:"spec"`
}

// ── Workload types ────────────────────────────────────────────────────────────

type DeploymentSpec struct {
	Template PodTemplateSpec `json:"template"`
}

type Deployment struct {
	Meta ObjectMeta     `json:"metadata"`
	Spec DeploymentSpec `json:"spec"`
}

type DeploymentList struct {
	Items []Deployment `json:"items"`
}

type Pod struct {
	Meta ObjectMeta `json:"metadata"`
	Spec PodSpec    `json:"spec"`
}

type PodList struct {
	Items []Pod `json:"items"`
}

// ── Service types ─────────────────────────────────────────────────────────────

type ServicePort struct {
	NodePort int32  `json:"nodePort,omitempty"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

type ServiceSpec struct {
	Type  string        `json:"type,omitempty"`
	Ports []ServicePort `json:"ports,omitempty"`
}

type Service struct {
	Meta ObjectMeta  `json:"metadata"`
	Spec ServiceSpec `json:"spec"`
}

type ServiceList struct {
	Items []Service `json:"items"`
}

// ── RBAC types ────────────────────────────────────────────────────────────────

type PolicyRule struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources,omitempty"`
	APIGroups []string `json:"apiGroups,omitempty"`
}

type ClusterRoleBinding struct {
	Meta     ObjectMeta `json:"metadata"`
	RoleRef  RoleRef    `json:"roleRef"`
	Subjects []Subject  `json:"subjects,omitempty"`
}

type ClusterRoleBindingList struct {
	Items []ClusterRoleBinding `json:"items"`
}

type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// ── ResourceSet is the single value passed to every Check ────────────────────
// Checks read from this — they never call the API themselves.

type ResourceSet struct {
	Deployments         []Deployment
	Pods                []Pod
	Services            []Service
	ClusterRoleBindings []ClusterRoleBinding
}
