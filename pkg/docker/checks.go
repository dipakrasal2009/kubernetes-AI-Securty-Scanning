package docker

import (
	"fmt"
	"strings"

	"github.com/yourorg/kubeaudit/pkg/models"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func ref(ci ContainerInspect) models.ResourceRef {
	return models.ResourceRef{Kind: "DockerContainer", Name: ContainerName(ci)}
}

func finding(id, checkName string, sev models.Severity, ci ContainerInspect, msg, rem string, details map[string]string) models.Finding {
	return models.Finding{
		ID:          id,
		CheckName:   checkName,
		Category:    models.CategoryContainer,
		Severity:    sev,
		Resource:    ref(ci),
		Message:     msg,
		Remediation: rem,
		Details:     details,
	}
}

// ── Check interface (local, mirrors orchestrator.Check without importing it) ──

// DockerCheck is the interface all Docker checks implement.
// It mirrors orchestrator.Check but operates on *ResourceSet instead of
// *k8sclient.ResourceSet, keeping the two scan domains cleanly separated.
type DockerCheck interface {
	Name() string
	Run(rs *ResourceSet) []models.Finding
}

// ── 1. Privileged container check ────────────────────────────────────────────

// PrivilegedCheck flags containers running with --privileged.
// A privileged container has full access to the host kernel — equivalent to root on the host.
type PrivilegedCheck struct{}

func (c *PrivilegedCheck) Name() string { return "docker-privileged" }

func (c *PrivilegedCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		if ci.HostConfig.Privileged {
			out = append(out, finding(
				"DOCK-001", c.Name(),
				models.SeverityCritical, ci,
				"Container is running in privileged mode — it has full access to the host kernel.",
				"Remove --privileged. Use specific --cap-add entries only for capabilities actually needed.",
				map[string]string{"privileged": "true"},
			))
		}
	}
	return out
}

// ── 2. Root user check ────────────────────────────────────────────────────────

// RootUserCheck flags containers running as root (UID 0 or unset User).
type RootUserCheck struct{}

func (c *RootUserCheck) Name() string { return "docker-root-user" }

func (c *RootUserCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		user := strings.TrimSpace(ci.Config.User)
		// Empty user or explicit "0" / "root" means the process runs as root.
		if user == "" || user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
			out = append(out, finding(
				"DOCK-002", c.Name(),
				models.SeverityHigh, ci,
				fmt.Sprintf("Container runs as root (user=%q). A container breakout gives root on the host.", user),
				"Add a non-root USER instruction in the Dockerfile, or pass --user <uid>:<gid> at runtime.",
				map[string]string{"user": user},
			))
		}
	}
	return out
}

// ── 3. Dangerous capabilities check ──────────────────────────────────────────

// DangerousCapCheck flags containers that add high-risk Linux capabilities.
type DangerousCapCheck struct{}

func (c *DangerousCapCheck) Name() string { return "docker-dangerous-caps" }

// dangerousCaps is the set of capabilities that commonly enable container escapes
// or significant privilege escalation.
var dangerousCaps = map[string]string{
	"CAP_SYS_ADMIN":   "allows a wide range of privileged kernel operations",
	"CAP_NET_ADMIN":   "allows network interface/routing manipulation",
	"CAP_SYS_PTRACE":  "allows tracing arbitrary processes (container escape vector)",
	"CAP_SYS_MODULE":  "allows loading kernel modules",
	"CAP_DAC_OVERRIDE": "bypasses file permission checks",
	"CAP_SETUID":      "allows switching to any UID including root",
	"CAP_SETGID":      "allows switching to any GID",
	"SYS_ADMIN":       "allows a wide range of privileged kernel operations (without CAP_ prefix)",
	"NET_ADMIN":       "allows network interface/routing manipulation (without CAP_ prefix)",
	"SYS_PTRACE":      "allows tracing arbitrary processes (without CAP_ prefix)",
	"SYS_MODULE":      "allows loading kernel modules (without CAP_ prefix)",
	"DAC_OVERRIDE":    "bypasses file permission checks (without CAP_ prefix)",
	"SETUID":          "allows switching to any UID (without CAP_ prefix)",
	"SETGID":          "allows switching to any GID (without CAP_ prefix)",
}

func (c *DangerousCapCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		for _, cap := range ci.HostConfig.CapAdd {
			upper := strings.ToUpper(cap)
			if reason, bad := dangerousCaps[upper]; bad {
				out = append(out, finding(
					"DOCK-003", c.Name(),
					models.SeverityHigh, ci,
					fmt.Sprintf("Container adds dangerous capability %s: %s.", cap, reason),
					fmt.Sprintf("Remove %s from --cap-add. Use the minimum capabilities required.", cap),
					map[string]string{"capability": cap},
				))
			}
		}
	}
	return out
}

// ── 4. Read-only filesystem check ────────────────────────────────────────────

// ReadOnlyFSCheck flags containers whose root filesystem is writable.
type ReadOnlyFSCheck struct{}

func (c *ReadOnlyFSCheck) Name() string { return "docker-writable-rootfs" }

func (c *ReadOnlyFSCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		if !ci.HostConfig.ReadonlyRootfs {
			out = append(out, finding(
				"DOCK-004", c.Name(),
				models.SeverityMedium, ci,
				"Container root filesystem is writable. An attacker can modify binaries or drop payloads.",
				"Start the container with --read-only. Mount specific writable paths via --tmpfs or named volumes.",
				map[string]string{"read_only_rootfs": "false"},
			))
		}
	}
	return out
}

// ── 5. Sensitive bind-mount check ─────────────────────────────────────────────

// SensitiveMountCheck flags containers that bind-mount sensitive host paths.
type SensitiveMountCheck struct{}

func (c *SensitiveMountCheck) Name() string { return "docker-sensitive-mount" }

// sensitivePaths are host paths whose exposure inside a container is dangerous.
var sensitivePaths = []struct {
	prefix   string
	reason   string
	severity models.Severity
}{
	{"/var/run/docker.sock", "Docker socket — full control over the Docker daemon from inside the container", models.SeverityCritical},
	{"/proc",                "host /proc — leaks process information and allows kernel parameter modification", models.SeverityHigh},
	{"/sys",                 "host /sys — allows kernel and hardware manipulation", models.SeverityHigh},
	{"/etc",                 "host /etc — exposes system config, cron jobs, and credential files", models.SeverityHigh},
	{"/root",                "host root home directory — may contain SSH keys and secrets", models.SeverityHigh},
	{"/home",                "host /home — may contain user credentials and SSH keys", models.SeverityMedium},
	{"/var/log",             "host /var/log — log tampering possible", models.SeverityMedium},
}

func (c *SensitiveMountCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		for _, mount := range ci.Mounts {
			if mount.Type != "bind" {
				continue
			}
			src := mount.Source
			for _, sp := range sensitivePaths {
				if src == sp.prefix || strings.HasPrefix(src, sp.prefix+"/") {
					out = append(out, finding(
						"DOCK-005", c.Name(),
						sp.severity, ci,
						fmt.Sprintf("Container bind-mounts sensitive host path %q: %s.", src, sp.reason),
						fmt.Sprintf("Remove the bind-mount of %q. If the container needs this data, copy it in at build time or use a secrets manager.", src),
						map[string]string{"host_path": src, "container_path": mount.Destination},
					))
					break
				}
			}
		}
	}
	return out
}

// ── 6. Network mode check ─────────────────────────────────────────────────────

// NetworkModeCheck flags containers using --network=host or --pid=host.
type NetworkModeCheck struct{}

func (c *NetworkModeCheck) Name() string { return "docker-host-network" }

func (c *NetworkModeCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		if strings.EqualFold(ci.HostConfig.NetworkMode, "host") {
			out = append(out, finding(
				"DOCK-006", c.Name(),
				models.SeverityHigh, ci,
				"Container uses --network=host, sharing the host network stack. All host ports are directly reachable.",
				"Use a dedicated Docker network (bridge/overlay). Only expose specific ports with -p.",
				map[string]string{"network_mode": ci.HostConfig.NetworkMode},
			))
		}
		if strings.EqualFold(ci.HostConfig.PidMode, "host") {
			out = append(out, finding(
				"DOCK-007", c.Name(),
				models.SeverityHigh, ci,
				"Container uses --pid=host, sharing the host PID namespace. Container processes can see and signal host processes.",
				"Remove --pid=host unless absolutely required for debugging tools.",
				map[string]string{"pid_mode": ci.HostConfig.PidMode},
			))
		}
	}
	return out
}

// ── 7. Resource limits check ──────────────────────────────────────────────────

// ResourceLimitCheck flags containers with no memory or CPU limits (DoS risk).
type ResourceLimitCheck struct{}

func (c *ResourceLimitCheck) Name() string { return "docker-resource-limits" }

func (c *ResourceLimitCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		if ci.HostConfig.Memory == 0 {
			out = append(out, finding(
				"DOCK-008", c.Name(),
				models.SeverityMedium, ci,
				"Container has no memory limit. A runaway process or OOM exploit can exhaust host memory.",
				"Set --memory (e.g. --memory=512m) to bound the container's memory usage.",
				map[string]string{"memory_bytes": "0 (unlimited)"},
			))
		}
		if ci.HostConfig.NanoCPUs == 0 {
			out = append(out, finding(
				"DOCK-009", c.Name(),
				models.SeverityLow, ci,
				"Container has no CPU limit. It can consume all available host CPUs, starving other workloads.",
				"Set --cpus (e.g. --cpus=1.0) to limit CPU usage.",
				map[string]string{"cpus": "0 (unlimited)"},
			))
		}
	}
	return out
}

// ── 8. Secrets-in-environment check ──────────────────────────────────────────

// EnvSecretCheck flags environment variables whose names suggest secret values.
type EnvSecretCheck struct{}

func (c *EnvSecretCheck) Name() string { return "docker-env-secrets" }

// secretKeywords are substrings commonly found in environment variable names
// that hold sensitive values.
var secretKeywords = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN",
	"API_KEY", "APIKEY", "PRIVATE_KEY", "PRIVATEKEY",
	"ACCESS_KEY", "ACCESSKEY", "AUTH_TOKEN", "AUTHTOKEN",
	"DB_PASS", "DATABASE_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD",
	"AWS_SECRET", "REDIS_PASSWORD",
}

func (c *EnvSecretCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		for _, env := range ci.Config.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) < 2 {
				continue
			}
			key := strings.ToUpper(parts[0])
			val := parts[1]
			if val == "" {
				continue
			}
			for _, kw := range secretKeywords {
				if strings.Contains(key, kw) {
					out = append(out, finding(
						"DOCK-010", c.Name(),
						models.SeverityHigh, ci,
						fmt.Sprintf("Environment variable %q looks like a secret and is set to a non-empty value. Secrets in env vars are visible via docker inspect.", parts[0]),
						"Use Docker secrets (docker secret create) or a secrets manager (Vault, AWS Secrets Manager). Never pass credentials via -e.",
						map[string]string{"env_var": parts[0], "value": "[REDACTED]"},
					))
					break
				}
			}
		}
	}
	return out
}

// ── 9. Image tag check ────────────────────────────────────────────────────────

// ImageTagCheck flags containers running from :latest or untagged images.
type ImageTagCheck struct{}

func (c *ImageTagCheck) Name() string { return "docker-image-tag" }

func (c *ImageTagCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		image := ci.Config.Image
		// No tag at all, or explicit :latest
		if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
			out = append(out, finding(
				"DOCK-011", c.Name(),
				models.SeverityMedium, ci,
				fmt.Sprintf("Container image %q uses :latest or has no tag. You cannot guarantee reproducibility or detect unexpected updates.", image),
				"Pin the image to a specific digest: image@sha256:<hash>. Rebuild and redeploy to rotate.",
				map[string]string{"image": image},
			))
		}
	}
	return out
}

// ── 10. No-new-privileges check ───────────────────────────────────────────────

// NoNewPrivilegesCheck flags containers missing the no-new-privileges security option.
type NoNewPrivilegesCheck struct{}

func (c *NoNewPrivilegesCheck) Name() string { return "docker-no-new-privileges" }

func (c *NoNewPrivilegesCheck) Run(rs *ResourceSet) []models.Finding {
	var out []models.Finding
	for _, ci := range rs.Containers {
		hasNoNewPriv := false
		for _, opt := range ci.HostConfig.SecurityOpt {
			if strings.Contains(strings.ToLower(opt), "no-new-privileges") {
				hasNoNewPriv = true
				break
			}
		}
		if !hasNoNewPriv {
			out = append(out, finding(
				"DOCK-012", c.Name(),
				models.SeverityMedium, ci,
				"Container does not set no-new-privileges. Processes inside can gain extra privileges via setuid binaries.",
				"Add --security-opt no-new-privileges:true to the container run command.",
				map[string]string{"security_opt": "no-new-privileges not set"},
			))
		}
	}
	return out
}

// ── AllDockerChecks returns every built-in Docker check ───────────────────────

// AllDockerChecks returns all built-in Docker security checks.
func AllDockerChecks() []DockerCheck {
	return []DockerCheck{
		&PrivilegedCheck{},
		&RootUserCheck{},
		&DangerousCapCheck{},
		&ReadOnlyFSCheck{},
		&SensitiveMountCheck{},
		&NetworkModeCheck{},
		&ResourceLimitCheck{},
		&EnvSecretCheck{},
		&ImageTagCheck{},
		&NoNewPrivilegesCheck{},
	}
}
