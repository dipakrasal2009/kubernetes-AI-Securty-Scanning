// Package docker provides types and a client for inspecting running Docker containers
// using the Docker Engine API over the Unix socket (/var/run/docker.sock).
// No external dependencies — pure stdlib net/http + encoding/json.
package docker

// ContainerSummary is returned by GET /containers/json
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageId"`
	Status  string            `json:"Status"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Ports   []PortBinding     `json:"Ports"`
	Mounts  []MountPoint      `json:"Mounts"`
}

// PortBinding describes a host ↔ container port mapping.
type PortBinding struct {
	IP          string `json:"IP"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort"`
	Type        string `json:"Type"`
}

// MountPoint describes a volume or bind-mount.
type MountPoint struct {
	Type        string `json:"Type"`   // "bind" | "volume" | "tmpfs"
	Source      string `json:"Source"` // host path for bind mounts
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

// ContainerInspect is the full detail returned by GET /containers/{id}/json
type ContainerInspect struct {
	ID              string          `json:"Id"`
	Name            string          `json:"Name"`
	Image           string          `json:"Image"`
	State           ContainerState  `json:"State"`
	HostConfig      HostConfig      `json:"HostConfig"`
	Config          ContainerConfig `json:"Config"`
	Mounts          []MountPoint    `json:"Mounts"`
	NetworkSettings NetworkSettings `json:"NetworkSettings"`
}

// ContainerState reflects the runtime state of the container.
type ContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Paused     bool   `json:"Paused"`
	Restarting bool   `json:"Restarting"`
	Pid        int    `json:"Pid"`
}

// HostConfig reflects security-relevant host-level settings.
type HostConfig struct {
	Privileged      bool            `json:"Privileged"`
	ReadonlyRootfs  bool            `json:"ReadonlyRootfs"`
	NetworkMode     string          `json:"NetworkMode"`
	PidMode         string          `json:"PidMode"`
	UsernsMode      string          `json:"UsernsMode"`
	IpcMode         string          `json:"IpcMode"`
	CapAdd          []string        `json:"CapAdd"`
	CapDrop         []string        `json:"CapDrop"`
	SecurityOpt     []string        `json:"SecurityOpt"`
	PublishAllPorts bool            `json:"PublishAllPorts"`
	PortBindings    map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	} `json:"PortBindings"`
	Binds       []string `json:"Binds"`
	PidsLimit   *int64   `json:"PidsLimit"`
	Memory      int64    `json:"Memory"`
	NanoCPUs    int64    `json:"NanoCPUs"`
	RestartPolicy RestartPolicy `json:"RestartPolicy"`
}

// RestartPolicy controls automatic container restarts.
type RestartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount"`
}

// ContainerConfig holds the image-level configuration.
type ContainerConfig struct {
	User   string            `json:"User"`
	Env    []string          `json:"Env"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

// NetworkSettings holds network configuration.
type NetworkSettings struct {
	Networks map[string]EndpointSettings `json:"Networks"`
}

// EndpointSettings describes a single network endpoint.
type EndpointSettings struct {
	NetworkID string `json:"NetworkID"`
	IPAddress string `json:"IPAddress"`
}

// ImageInspect is returned by GET /images/{id}/json
type ImageInspect struct {
	ID          string            `json:"Id"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Config      *ImageConfig      `json:"Config"`
	RootFS      RootFS            `json:"RootFS"`
}

// ImageConfig holds image-level OCI config.
type ImageConfig struct {
	User   string            `json:"User"`
	Env    []string          `json:"Env"`
	Labels map[string]string `json:"Labels"`
}

// RootFS describes the image layer structure.
type RootFS struct {
	Type   string   `json:"Type"`
	Layers []string `json:"Layers"`
}

// ResourceSet is the Docker equivalent of k8sclient.ResourceSet —
// the single value passed to every Docker check.
type ResourceSet struct {
	Containers []ContainerInspect
	Images     []ImageInspect
}
