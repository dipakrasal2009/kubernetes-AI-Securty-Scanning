package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultSocket is the standard Docker Engine Unix socket path.
	DefaultSocket = "/var/run/docker.sock"
)

// Client communicates with the Docker Engine API over the Unix socket.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a Docker client connected to socketPath.
// Pass an empty string to use DefaultSocket.
func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		socketPath = DefaultSocket
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	c := &Client{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}

	// Ping the daemon to validate connectivity.
	if err := c.ping(); err != nil {
		return nil, fmt.Errorf("cannot connect to Docker daemon at %s: %w", socketPath, err)
	}

	return c, nil
}

// ping calls GET /_ping to verify the Docker daemon is reachable.
func (c *Client) ping() error {
	req, _ := http.NewRequest("GET", "http://localhost/_ping", nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// get performs a GET request against the Docker API and JSON-decodes the response.
// path is a plain unencoded path (e.g. "/containers/json").
// query is a map of query parameters that will be properly encoded.
func (c *Client) get(path string, query url.Values, out interface{}) error {
	rawURL := "http://localhost" + path
	if len(query) > 0 {
		rawURL += "?" + query.Encode()
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// ── Public resource fetchers ──────────────────────────────────────────────────

// ListRunningContainers returns all currently running containers.
func (c *Client) ListRunningContainers() ([]ContainerSummary, error) {
	var containers []ContainerSummary
	// The filters value must be a JSON string, then URL-encoded by url.Values.Encode().
	q := url.Values{}
	q.Set("filters", `{"status":["running"]}`)
	if err := c.get("/containers/json", q, &containers); err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	return containers, nil
}

// InspectContainer returns the full details for a single container by ID or name.
func (c *Client) InspectContainer(id string) (*ContainerInspect, error) {
	var ci ContainerInspect
	if err := c.get("/containers/"+id+"/json", nil, &ci); err != nil {
		return nil, fmt.Errorf("inspecting container %s: %w", id, err)
	}
	return &ci, nil
}

// InspectImage returns the full details for a single image by ID or tag.
func (c *Client) InspectImage(id string) (*ImageInspect, error) {
	var ii ImageInspect
	if err := c.get("/images/"+id+"/json", nil, &ii); err != nil {
		return nil, fmt.Errorf("inspecting image %s: %w", id, err)
	}
	return &ii, nil
}

// FetchAll fetches all running containers, inspects each one, and returns
// a ResourceSet ready for checks. Errors are collected and returned alongside
// partial results so the scan can continue even if one container fails.
func (c *Client) FetchAll() (*ResourceSet, []error) {
	rs := &ResourceSet{}
	var errs []error

	summaries, err := c.ListRunningContainers()
	if err != nil {
		return rs, []error{err}
	}

	imageIDs := make(map[string]struct{})

	for _, s := range summaries {
		ci, err := c.InspectContainer(s.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rs.Containers = append(rs.Containers, *ci)
		imageIDs[s.ImageID] = struct{}{}
	}

	for id := range imageIDs {
		ii, err := c.InspectImage(id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rs.Images = append(rs.Images, *ii)
	}

	return rs, errs
}

// ContainerName returns a clean name (strips the leading slash Docker adds).
func ContainerName(ci ContainerInspect) string {
	name := ci.Name
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}
