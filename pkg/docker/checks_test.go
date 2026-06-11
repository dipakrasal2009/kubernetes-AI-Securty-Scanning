package docker_test

import (
	"testing"

	"github.com/yourorg/kubeaudit/pkg/docker"
	"github.com/yourorg/kubeaudit/pkg/models"
)

// ── helpers ────────────────────────────────────────────────────────────────────

func boolPtr(b bool) *bool   { return &b }
func int64Ptr(i int64) *int64 { return &i }

// container builds a minimal ContainerInspect for testing.
// The modify function allows tests to set specific fields.
func container(name string, modify func(*docker.ContainerInspect)) docker.ContainerInspect {
	ci := docker.ContainerInspect{
		ID:   "abc123",
		Name: "/" + name,
		Config: docker.ContainerConfig{
			Image: "nginx:1.25.0",
			User:  "1000",
		},
		HostConfig: docker.HostConfig{
			ReadonlyRootfs: true,
			Memory:         536870912, // 512 MiB
			NanoCPUs:       1000000000, // 1 CPU
			SecurityOpt:    []string{"no-new-privileges:true"},
		},
		State: docker.ContainerState{Running: true},
	}
	if modify != nil {
		modify(&ci)
	}
	return ci
}

func rs(containers ...docker.ContainerInspect) *docker.ResourceSet {
	return &docker.ResourceSet{Containers: containers}
}

func findingIDs(findings []models.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

// ── PrivilegedCheck ────────────────────────────────────────────────────────────

func TestPrivilegedCheck_Flagged(t *testing.T) {
	c := container("nginx", func(ci *docker.ContainerInspect) {
		ci.HostConfig.Privileged = true
	})
	check := &docker.PrivilegedCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "DOCK-001" {
		t.Errorf("expected DOCK-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity")
	}
}

func TestPrivilegedCheck_Clean(t *testing.T) {
	c := container("nginx", func(ci *docker.ContainerInspect) {
		ci.HostConfig.Privileged = false
	})
	check := &docker.PrivilegedCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for non-privileged container")
	}
}

// ── RootUserCheck ─────────────────────────────────────────────────────────────

func TestRootUserCheck_EmptyUser(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.User = ""
	})
	check := &docker.RootUserCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-002" {
		t.Errorf("expected DOCK-002, got %v", findingIDs(findings))
	}
}

func TestRootUserCheck_ExplicitRoot(t *testing.T) {
	for _, user := range []string{"root", "0", "0:0", "root:root"} {
		c := container("app", func(ci *docker.ContainerInspect) {
			ci.Config.User = user
		})
		check := &docker.RootUserCheck{}
		if len(check.Run(rs(c))) != 1 {
			t.Errorf("user %q: expected 1 finding", user)
		}
	}
}

func TestRootUserCheck_NonRoot(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.User = "1000:1000"
	})
	check := &docker.RootUserCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for non-root user")
	}
}

// ── DangerousCapCheck ─────────────────────────────────────────────────────────

func TestDangerousCapCheck_Flagged(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.CapAdd = []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"}
	})
	check := &docker.DangerousCapCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d: %v", len(findings), findingIDs(findings))
	}
}

func TestDangerousCapCheck_SafeCap(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.CapAdd = []string{"CAP_NET_BIND_SERVICE"}
	})
	check := &docker.DangerousCapCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for safe capability")
	}
}

// ── ReadOnlyFSCheck ───────────────────────────────────────────────────────────

func TestReadOnlyFSCheck_Writable(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.ReadonlyRootfs = false
	})
	check := &docker.ReadOnlyFSCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-004" {
		t.Errorf("expected DOCK-004, got %v", findingIDs(findings))
	}
}

func TestReadOnlyFSCheck_ReadOnly(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.ReadonlyRootfs = true
	})
	check := &docker.ReadOnlyFSCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for read-only rootfs")
	}
}

// ── SensitiveMountCheck ───────────────────────────────────────────────────────

func TestSensitiveMountCheck_DockerSocket(t *testing.T) {
	c := container("dind", func(ci *docker.ContainerInspect) {
		ci.Mounts = []docker.MountPoint{
			{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"},
		}
	})
	check := &docker.SensitiveMountCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected 1 CRITICAL finding for docker socket mount, got %v", findings)
	}
}

func TestSensitiveMountCheck_EtcMount(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Mounts = []docker.MountPoint{
			{Type: "bind", Source: "/etc/ssl", Destination: "/etc/ssl"},
		}
	})
	check := &docker.SensitiveMountCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for /etc mount, got %d", len(findings))
	}
}

func TestSensitiveMountCheck_VolumeMount_Ignored(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Mounts = []docker.MountPoint{
			{Type: "volume", Source: "/var/lib/docker/volumes/mydata", Destination: "/data"},
		}
	})
	check := &docker.SensitiveMountCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for named volume mount")
	}
}

// ── NetworkModeCheck ──────────────────────────────────────────────────────────

func TestNetworkModeCheck_HostNetwork(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.NetworkMode = "host"
	})
	check := &docker.NetworkModeCheck{}
	findings := check.Run(rs(c))
	ids := findingIDs(findings)
	found := false
	for _, id := range ids {
		if id == "DOCK-006" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DOCK-006, got %v", ids)
	}
}

func TestNetworkModeCheck_HostPID(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.PidMode = "host"
	})
	check := &docker.NetworkModeCheck{}
	findings := check.Run(rs(c))
	ids := findingIDs(findings)
	found := false
	for _, id := range ids {
		if id == "DOCK-007" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DOCK-007, got %v", ids)
	}
}

// ── ResourceLimitCheck ────────────────────────────────────────────────────────

func TestResourceLimitCheck_NoMemory(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.Memory = 0
		ci.HostConfig.NanoCPUs = 1000000000
	})
	check := &docker.ResourceLimitCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-008" {
		t.Errorf("expected DOCK-008, got %v", findingIDs(findings))
	}
}

func TestResourceLimitCheck_NoCPU(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.Memory = 536870912
		ci.HostConfig.NanoCPUs = 0
	})
	check := &docker.ResourceLimitCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-009" {
		t.Errorf("expected DOCK-009, got %v", findingIDs(findings))
	}
}

// ── EnvSecretCheck ────────────────────────────────────────────────────────────

func TestEnvSecretCheck_Password(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.Env = []string{"DATABASE_PASSWORD=supersecret", "PORT=8080"}
	})
	check := &docker.EnvSecretCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-010" {
		t.Errorf("expected DOCK-010, got %v", findingIDs(findings))
	}
	// Value must be redacted
	if val, ok := findings[0].Details["value"]; ok && val != "[REDACTED]" {
		t.Errorf("secret value not redacted: %s", val)
	}
}

func TestEnvSecretCheck_EmptyValue_Ignored(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.Env = []string{"API_KEY="}
	})
	check := &docker.EnvSecretCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for empty secret value")
	}
}

// ── ImageTagCheck ─────────────────────────────────────────────────────────────

func TestImageTagCheck_Latest(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.Image = "nginx:latest"
	})
	check := &docker.ImageTagCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-011" {
		t.Errorf("expected DOCK-011, got %v", findingIDs(findings))
	}
}

func TestImageTagCheck_NoTag(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.Image = "nginx"
	})
	check := &docker.ImageTagCheck{}
	if len(check.Run(rs(c))) != 1 {
		t.Error("expected 1 finding for untagged image")
	}
}

func TestImageTagCheck_PinnedDigest(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.Config.Image = "nginx@sha256:abc123def456"
	})
	check := &docker.ImageTagCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings for pinned digest")
	}
}

// ── NoNewPrivilegesCheck ──────────────────────────────────────────────────────

func TestNoNewPrivilegesCheck_Missing(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.SecurityOpt = nil
	})
	check := &docker.NoNewPrivilegesCheck{}
	findings := check.Run(rs(c))
	if len(findings) != 1 || findings[0].ID != "DOCK-012" {
		t.Errorf("expected DOCK-012, got %v", findingIDs(findings))
	}
}

func TestNoNewPrivilegesCheck_Set(t *testing.T) {
	c := container("app", func(ci *docker.ContainerInspect) {
		ci.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	})
	check := &docker.NoNewPrivilegesCheck{}
	if len(check.Run(rs(c))) != 0 {
		t.Error("expected 0 findings when no-new-privileges is set")
	}
}
