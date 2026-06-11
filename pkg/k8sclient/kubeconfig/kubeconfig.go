// Package kubeconfig parses ~/.kube/config files using only Go stdlib.
// It implements the subset of the kubeconfig spec that kubeaudit needs.
package kubeconfig

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// KubeConfig represents the top-level kubeconfig file.
type KubeConfig struct {
	CurrentContext string                `yaml:"current-context"`
	Clusters       map[string]ClusterInfo `yaml:"-"`
	Contexts       map[string]ContextInfo `yaml:"-"`
	Users          map[string]UserInfo    `yaml:"-"`
}

type ClusterInfo struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
}

type ContextInfo struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace"`
}

type UserInfo struct {
	ClientCertificate     string `yaml:"client-certificate"`
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKey             string `yaml:"client-key"`
	ClientKeyData         string `yaml:"client-key-data"`
	Token                 string `yaml:"token"`
	TokenFile             string `yaml:"tokenFile"`
}

// raw mirrors the literal YAML structure before we normalise into maps.
type raw struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// Load reads and parses a kubeconfig file from disk.
func Load(path string) (*KubeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading kubeconfig: %w", err)
	}
	return Parse(data)
}

// Parse parses raw YAML bytes into a KubeConfig.
func Parse(data []byte) (*KubeConfig, error) {
	var r raw
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	kc := &KubeConfig{
		CurrentContext: r.CurrentContext,
		Clusters:       make(map[string]ClusterInfo),
		Contexts:       make(map[string]ContextInfo),
		Users:          make(map[string]UserInfo),
	}

	for _, c := range r.Clusters {
		kc.Clusters[c.Name] = ClusterInfo{
			Server:                   c.Cluster.Server,
			CertificateAuthority:     c.Cluster.CertificateAuthority,
			CertificateAuthorityData: c.Cluster.CertificateAuthorityData,
			InsecureSkipTLSVerify:    c.Cluster.InsecureSkipTLSVerify,
		}
	}
	for _, c := range r.Contexts {
		kc.Contexts[c.Name] = ContextInfo{
			Cluster:   c.Context.Cluster,
			User:      c.Context.User,
			Namespace: c.Context.Namespace,
		}
	}
	for _, u := range r.Users {
		kc.Users[u.Name] = UserInfo{
			ClientCertificate:     u.User.ClientCertificate,
			ClientCertificateData: u.User.ClientCertificateData,
			ClientKey:             u.User.ClientKey,
			ClientKeyData:         u.User.ClientKeyData,
			Token:                 u.User.Token,
			TokenFile:             u.User.TokenFile,
		}
	}

	return kc, nil
}

// MarshalJSON implements json.Marshaler so KubeConfig can be logged safely.
func (kc *KubeConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		CurrentContext string   `json:"current_context"`
		Clusters       []string `json:"clusters"`
		Contexts       []string `json:"contexts"`
		Users          []string `json:"users"`
	}{
		CurrentContext: kc.CurrentContext,
		Clusters:       keys(kc.Clusters),
		Contexts:       keys(kc.Contexts),
		Users:          keys(kc.Users),
	})
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
