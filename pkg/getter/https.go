package getter

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"hauler.dev/go/hauler/v2/pkg/content"
)

type Http struct {
	client *http.Client
}

func NewHttp(insecureSkipTLSVerify bool, caFile string) *Http {
	tr, err := content.BuildTransport(insecureSkipTLSVerify, caFile)
	if err != nil {
		return &Http{client: http.DefaultClient}
	}
	return &Http{client: &http.Client{Transport: tr}}
}

// probe issues a single HEAD request and extracts the display name, the OCI
// media type, and the upstream Last-Modified time, so Name, MediaType, and
// Annotations share one parsing path over the same response instead of each
// reimplementing it. Any field the response doesn't support comes back empty.
func (h Http) probe(u *url.URL) (name, mediaType, lastModified string) {
	resp, err := http.Head(u.String())
	if err != nil {
		return "", "", ""
	}
	defer resp.Body.Close()

	unescaped, err := url.PathUnescape(u.String())
	if err != nil {
		unescaped = u.String()
	}
	name = filepath.Base(unescaped)

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if t, _, err := mime.ParseMediaType(ct); err == nil {
			mediaType = t
		}
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			lastModified = t.UTC().Format(time.RFC3339)
		}
	}
	return name, mediaType, lastModified
}

func (h Http) Name(u *url.URL) string {
	name, _, _ := h.probe(u)
	return name
}

// MediaType returns the HEAD response's Content-Type with any parameters
// (e.g. "; charset=...") stripped, falling back to application/octet-stream
// when the HEAD fails, the header is absent, or it fails to parse.
func (h Http) MediaType(u *url.URL) string {
	_, mt, _ := h.probe(u)
	if mt == "" {
		return "application/octet-stream"
	}
	return mt
}

func (h Http) Open(ctx context.Context, u *url.URL) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status fetching %s: %s", u.String(), resp.Status)
	}
	return resp.Body, nil
}

func (h Http) Detect(u *url.URL) bool {
	switch u.Scheme {
	case "http", "https":
		return true
	}
	return false
}

// Annotations returns manifest-level provenance annotations for an HTTP
// source: the source URL, plus the upstream Last-Modified time as
// org.opencontainers.image.created when the server reports one.
//
// The timestamp must never be the fetch time. These annotations land in the
// manifest, whose bytes are digested to form the store's descriptor, so a
// clock-derived value would give the same unchanged file a new digest on every
// sync -- orphaning the previous manifest blob (there is no store gc), and
// defeating AddIndex's byte-identical skip so index.json is rewritten every
// run. Omitting the annotation is preferable to inventing a value.
func (h Http) Annotations(u *url.URL) map[string]string {
	ann := map[string]string{
		ocispec.AnnotationURL: u.String(),
	}
	if _, _, lastModified := h.probe(u); lastModified != "" {
		ann[ocispec.AnnotationCreated] = lastModified
	}
	return ann
}
