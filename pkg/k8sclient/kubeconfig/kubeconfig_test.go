package kubeconfig_test

import (
	"testing"

	"github.com/yourorg/kubeaudit/pkg/k8sclient/kubeconfig"
)

const sampleKubeconfig = `
apiVersion: v1
kind: Config
current-context: dev-context
clusters:
- name: dev-cluster
  cluster:
    server: https://192.168.1.100:6443
    insecure-skip-tls-verify: true
- name: prod-cluster
  cluster:
    server: https://prod.k8s.example.com:6443
    certificate-authority-data: dGVzdA==
contexts:
- name: dev-context
  context:
    cluster: dev-cluster
    user: dev-user
    namespace: development
- name: prod-context
  context:
    cluster: prod-cluster
    user: prod-user
users:
- name: dev-user
  user:
    token: my-dev-token
- name: prod-user
  user:
    client-certificate-data: Y2VydA==
    client-key-data: a2V5
`

func TestParseCurrentContext(t *testing.T) {
	kc, err := kubeconfig.Parse([]byte(sampleKubeconfig))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if kc.CurrentContext != "dev-context" {
		t.Errorf("CurrentContext = %q, want dev-context", kc.CurrentContext)
	}
}

func TestParseClusters(t *testing.T) {
	kc, err := kubeconfig.Parse([]byte(sampleKubeconfig))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	dev, ok := kc.Clusters["dev-cluster"]
	if !ok {
		t.Fatal("dev-cluster not found")
	}
	if dev.Server != "https://192.168.1.100:6443" {
		t.Errorf("dev-cluster server = %q", dev.Server)
	}
	if !dev.InsecureSkipTLSVerify {
		t.Error("dev-cluster InsecureSkipTLSVerify should be true")
	}

	prod, ok := kc.Clusters["prod-cluster"]
	if !ok {
		t.Fatal("prod-cluster not found")
	}
	if prod.CertificateAuthorityData != "dGVzdA==" {
		t.Errorf("prod-cluster ca-data = %q", prod.CertificateAuthorityData)
	}
}

func TestParseContexts(t *testing.T) {
	kc, err := kubeconfig.Parse([]byte(sampleKubeconfig))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	ctx, ok := kc.Contexts["dev-context"]
	if !ok {
		t.Fatal("dev-context not found")
	}
	if ctx.Cluster != "dev-cluster" {
		t.Errorf("context cluster = %q, want dev-cluster", ctx.Cluster)
	}
	if ctx.Namespace != "development" {
		t.Errorf("context namespace = %q, want development", ctx.Namespace)
	}
}

func TestParseUsers(t *testing.T) {
	kc, err := kubeconfig.Parse([]byte(sampleKubeconfig))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	dev, ok := kc.Users["dev-user"]
	if !ok {
		t.Fatal("dev-user not found")
	}
	if dev.Token != "my-dev-token" {
		t.Errorf("dev-user token = %q, want my-dev-token", dev.Token)
	}

	prod, ok := kc.Users["prod-user"]
	if !ok {
		t.Fatal("prod-user not found")
	}
	if prod.ClientCertificateData != "Y2VydA==" {
		t.Errorf("prod-user cert-data = %q", prod.ClientCertificateData)
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := kubeconfig.Parse([]byte("%invalid: [yaml: {"))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestParseEmpty(t *testing.T) {
	kc, err := kubeconfig.Parse([]byte(""))
	if err != nil {
		t.Fatalf("Parse failed on empty input: %v", err)
	}
	if kc.CurrentContext != "" {
		t.Errorf("expected empty CurrentContext, got %q", kc.CurrentContext)
	}
}
