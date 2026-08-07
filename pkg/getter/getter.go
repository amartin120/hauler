package getter

import (
	"context"
	"fmt"
	"io"
	"net/url"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"hauler.dev/go/hauler/v2/pkg/content"
	"hauler.dev/go/hauler/v2/pkg/layer"
)

type Client struct {
	Getters map[string]Getter
	Options ClientOptions
}

// ClientOptions provides options for the client
type ClientOptions struct {
	NameOverride          string
	InsecureSkipTLSVerify bool
	CAFile                string
}

var (
	ErrGetterTypeUnknown = errors.New("no getter type found matching reference")
)

type Getter interface {
	Open(context.Context, *url.URL) (io.ReadCloser, error)

	Detect(*url.URL) bool

	Name(*url.URL) string

	// MediaType reports the OCI media type for the content at u, used as the
	// layer's real mediaType instead of a hauler-private constant.
	MediaType(*url.URL) string

	// Annotations reports manifest-level provenance annotations for the
	// content at u (e.g. org.opencontainers.image.url/.created).
	Annotations(*url.URL) map[string]string
}

func NewClient(opts ClientOptions) *Client {
	defaults := map[string]Getter{
		"file":      NewFile(),
		"directory": NewDirectory(),
		"http":      NewHttp(opts.InsecureSkipTLSVerify, opts.CAFile),
	}

	c := &Client{
		Getters: defaults,
		Options: opts,
	}
	return c
}

func (c *Client) LayerFrom(ctx context.Context, source string) (v1.Layer, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, err
	}

	g, err := c.getterFrom(u)
	if err != nil {
		if errors.Is(err, ErrGetterTypeUnknown) {
			return nil, err
		}
		return nil, fmt.Errorf("create getter: %w", err)
	}

	opener := func() (io.ReadCloser, error) {
		return g.Open(ctx, u)
	}

	annotations := make(map[string]string)
	annotations[ocispec.AnnotationTitle] = c.Name(source)

	switch g.(type) {
	case *directory:
		annotations[content.AnnotationUnpack] = "true"
	}

	// Call g.MediaType directly rather than round-tripping through
	// c.MediaType(source): g and u are already resolved above, so going
	// through the Client would just re-parse the URL and re-run getter
	// detection for no benefit.
	l, err := layer.FromOpener(opener,
		layer.WithMediaType(g.MediaType(u)),
		layer.WithAnnotations(annotations))
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (c *Client) ContentFrom(ctx context.Context, source string) (io.ReadCloser, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, fmt.Errorf("parse source %s: %w", source, err)
	}
	g, err := c.getterFrom(u)
	if err != nil {
		if errors.Is(err, ErrGetterTypeUnknown) {
			return nil, err
		}
		return nil, fmt.Errorf("create getter: %w", err)
	}
	return g.Open(ctx, u)
}

func (c *Client) getterFrom(srcUrl *url.URL) (Getter, error) {
	for _, g := range c.Getters {
		if g.Detect(srcUrl) {
			return g, nil
		}
	}
	return nil, errors.Wrapf(ErrGetterTypeUnknown, "source %s", srcUrl.String())
}

func (c *Client) Name(source string) string {
	if c.Options.NameOverride != "" {
		return c.Options.NameOverride
	}
	u, err := url.Parse(source)
	if err != nil {
		return source
	}
	for _, g := range c.Getters {
		if g.Detect(u) {
			return g.Name(u)
		}
	}
	return source
}

// MediaType resolves source's getter and returns its detected OCI media type.
func (c *Client) MediaType(source string) string {
	u, err := url.Parse(source)
	if err != nil {
		return ""
	}
	for _, g := range c.Getters {
		if g.Detect(u) {
			return g.MediaType(u)
		}
	}
	return ""
}

// Annotations resolves source's getter and returns its manifest-level
// provenance annotations.
func (c *Client) Annotations(source string) map[string]string {
	u, err := url.Parse(source)
	if err != nil {
		return nil
	}
	for _, g := range c.Getters {
		if g.Detect(u) {
			return g.Annotations(u)
		}
	}
	return nil
}
