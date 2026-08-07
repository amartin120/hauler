package getter

import (
	"context"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type File struct{}

func NewFile() *File {
	return &File{}
}

func (f File) Name(u *url.URL) string {
	return filepath.Base(f.path(u))
}

func (f File) Open(ctx context.Context, u *url.URL) (io.ReadCloser, error) {
	return os.Open(f.path(u))
}

func (f File) Detect(u *url.URL) bool {
	if len(f.path(u)) == 0 {
		return false
	}

	fi, err := os.Stat(f.path(u))
	if err != nil {
		return false
	}
	return !fi.IsDir()
}

func (f File) path(u *url.URL) string {
	return filepath.Join(u.Host, u.Path)
}

// MediaType detects the OCI media type from the file's extension via Go's
// builtin mime table, falling back to application/octet-stream for an
// unrecognized or missing extension. mime.TypeByExtension can return a
// "; charset=..." parameter, which the manifest's bare mediaType field must
// not carry, so the result is always re-parsed through mime.ParseMediaType.
func (f File) MediaType(u *url.URL) string {
	mt := mime.TypeByExtension(filepath.Ext(f.path(u)))
	if mt == "" {
		return "application/octet-stream"
	}
	t, _, err := mime.ParseMediaType(mt)
	if err != nil || t == "" {
		return "application/octet-stream"
	}
	return t
}

// Annotations returns manifest-level provenance annotations for a local file
// source: the source path always, plus the file's own mtime when os.Stat
// succeeds -- an on-disk mtime is a real, already-available timestamp, unlike
// an HTTP source where the only meaningful time is when hauler fetched it.
func (f File) Annotations(u *url.URL) map[string]string {
	ann := map[string]string{
		ocispec.AnnotationURL: u.String(),
	}
	if fi, err := os.Stat(f.path(u)); err == nil {
		ann[ocispec.AnnotationCreated] = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return ann
}
