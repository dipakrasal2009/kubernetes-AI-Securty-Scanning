package k8sclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yourorg/kubeaudit/pkg/k8sclient/kubeconfig"
)

// Client talks to the Kubernetes API server.
// It holds a pre-configured http.Client and the base URL.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	namespace  string
}

// Config holds everything needed to construct a Client.
type Config struct {
	// KubeconfigPath is the path to the kubeconfig file.
	// If empty, the client tries in-cluster config, then ~/.kube/config.
	KubeconfigPath string

	// Namespace restricts listing to a single namespace.
	// Empty string means all namespaces.
	Namespace string

	// Context selects a named kubeconfig context.
	// Empty string means the current-context in the kubeconfig.
	Context string
}

// NewClient creates a Client from the provided Config.
// It automatically falls back: explicit path → in-cluster → ~/.kube/config.
func NewClient(cfg Config) (*Client, error) {
	// 1. Try in-cluster first (running inside a Pod)
	if cfg.KubeconfigPath == "" {
		if c, err := newInClusterClient(cfg.Namespace); err == nil {
			return c, nil
		}
	}

	// 2. Resolve kubeconfig path
	kubecfgPath := cfg.KubeconfigPath
	if kubecfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot find home directory: %w", err)
		}
		kubecfgPath = filepath.Join(home, ".kube", "config")
	}

	// 3. Parse kubeconfig
	kc, err := kubeconfig.Load(kubecfgPath)
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig %q: %w", kubecfgPath, err)
	}

	contextName := cfg.Context
	if contextName == "" {
		contextName = kc.CurrentContext
	}

	ctx, ok := kc.Contexts[contextName]
	if !ok {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	cluster, ok := kc.Clusters[ctx.Cluster]
	if !ok {
		return nil, fmt.Errorf("cluster %q not found in kubeconfig", ctx.Cluster)
	}

	user, ok := kc.Users[ctx.User]
	if !ok {
		return nil, fmt.Errorf("user %q not found in kubeconfig", ctx.User)
	}

	// 4. Build TLS config
	tlsCfg, err := buildTLS(cluster, user)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	ns := cfg.Namespace
	if ns == "" {
		ns = ctx.Namespace
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    cluster.Server,
		token:      user.Token,
		namespace:  ns,
	}, nil
}

// newInClusterClient creates a Client using the service-account token mounted
// inside a running Pod. Returns an error if not running in-cluster.
func newInClusterClient(namespace string) (*Client, error) {
	const (
		tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		caFile     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
		nsFile     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
		apiBaseURL = "https://kubernetes.default.svc"
	)

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to parse in-cluster CA")
	}

	ns := namespace
	if ns == "" {
		if nsBytes, err := os.ReadFile(nsFile); err == nil {
			ns = string(nsBytes)
		}
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
		baseURL:   apiBaseURL,
		token:     string(tokenBytes),
		namespace: ns,
	}, nil
}

// ── API helpers ───────────────────────────────────────────────────────────────

func (c *Client) get(path string, out interface{}) error {
	url := c.baseURL + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", url, err)
	}
	return nil
}

func (c *Client) namespacePath(resource string) string {
	if c.namespace == "" {
		return fmt.Sprintf("/apis/apps/v1/%s", resource)
	}
	return fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s", c.namespace, resource)
}

func (c *Client) coreNamespacePath(resource string) string {
	if c.namespace == "" {
		return fmt.Sprintf("/api/v1/%s", resource)
	}
	return fmt.Sprintf("/api/v1/namespaces/%s/%s", c.namespace, resource)
}

// ── Public resource fetchers ──────────────────────────────────────────────────

func (c *Client) ListDeployments() ([]Deployment, error) {
	var list DeploymentList
	if err := c.get(c.namespacePath("deployments"), &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *Client) ListPods() ([]Pod, error) {
	var list PodList
	if err := c.get(c.coreNamespacePath("pods"), &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *Client) ListServices() ([]Service, error) {
	var list ServiceList
	if err := c.get(c.coreNamespacePath("services"), &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *Client) ListClusterRoleBindings() ([]ClusterRoleBinding, error) {
	var list ClusterRoleBindingList
	if err := c.get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// FetchAll fetches all resources and returns a ResourceSet.
// Errors from individual resources are collected and returned together
// so partial results are still usable.
func (c *Client) FetchAll() (*ResourceSet, []error) {
	rs := &ResourceSet{}
	var errs []error

	if items, err := c.ListDeployments(); err != nil {
		errs = append(errs, fmt.Errorf("deployments: %w", err))
	} else {
		rs.Deployments = items
	}

	if items, err := c.ListPods(); err != nil {
		errs = append(errs, fmt.Errorf("pods: %w", err))
	} else {
		rs.Pods = items
	}

	if items, err := c.ListServices(); err != nil {
		errs = append(errs, fmt.Errorf("services: %w", err))
	} else {
		rs.Services = items
	}

	if items, err := c.ListClusterRoleBindings(); err != nil {
		errs = append(errs, fmt.Errorf("clusterrolebindings: %w", err))
	} else {
		rs.ClusterRoleBindings = items
	}

	return rs, errs
}

// Namespace returns the namespace this client is scoped to (empty = all).
func (c *Client) Namespace() string { return c.namespace }

// ServerURL returns the API server base URL.
func (c *Client) ServerURL() string { return c.baseURL }

// ── TLS helpers ───────────────────────────────────────────────────────────────

func buildTLS(cluster kubeconfig.ClusterInfo, user kubeconfig.UserInfo) (*tls.Config, error) {
	cfg := &tls.Config{}

	if cluster.InsecureSkipTLSVerify {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}

	// CA cert
	caData, err := resolveData(cluster.CertificateAuthorityData, cluster.CertificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("CA cert: %w", err)
	}
	if len(caData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.RootCAs = pool
	}

	// Client cert+key
	certData, err := resolveData(user.ClientCertificateData, user.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	keyData, err := resolveData(user.ClientKeyData, user.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}
	if len(certData) > 0 && len(keyData) > 0 {
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, fmt.Errorf("parsing client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// resolveData returns PEM bytes from either a base64-encoded inline value
// or a file path, whichever is set.
func resolveData(inlineB64, filePath string) ([]byte, error) {
	if inlineB64 != "" {
		return base64.StdEncoding.DecodeString(inlineB64)
	}
	if filePath != "" {
		return os.ReadFile(filePath)
	}
	return nil, nil
}
