package iso

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/kubev2v/migration-planner/internal/api_server/isoserver"
)

type ServerDownloader struct {
	baseServerURL string
	imageSha256   string
	timeout       time.Duration
}

func NewIsoServerDownloader(baseServerURL, imageSha256 string) *ServerDownloader {
	return &ServerDownloader{
		baseServerURL: baseServerURL,
		imageSha256:   imageSha256,
		timeout:       time.Minute,
	}
}

func (i *ServerDownloader) Get(ctx context.Context, dst io.Writer) error {
	client := &http.Client{
		Timeout: i.timeout,
	}

	u, err := url.Parse(i.baseServerURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	u.Path = path.Join(u.Path, isoserver.GetIsoEndpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request for ISO server: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch ISO from server %q: %w", u.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ISO server returned status %d for %q", resp.StatusCode, u.String())
	}

	totalSize := int64(0)
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if n, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			totalSize = n
		}
	}

	return DownloadWithValidation(ctx, resp.Body, dst, i.imageSha256, totalSize)
}

// HealthCheck verifies if the ISO server is available and has the required ISO
func (i *ServerDownloader) HealthCheck(ctx context.Context) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	u, err := url.Parse(i.baseServerURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	u.Path = path.Join(u.Path, isoserver.HealthEndpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ISO server health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ISO server health check returned status %d", resp.StatusCode)
	}

	return nil
}

func (i *ServerDownloader) Type() string {
	return "iso-server"
}
