package content

import (
	"context"
	"fmt"
	"io"

	ccontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Target represents a content storage target with resolver, fetcher, and pusher capabilities
type Target interface {
	Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error)
	Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error)
	Pusher(ctx context.Context, ref string) (remotes.Pusher, error)
}

// RegistryOptions holds registry configuration
type RegistryOptions struct {
	PlainHTTP bool
	Insecure  bool
	Username  string
	Password  string
}

// ResolveName extracts the reference name from a descriptor's annotations
func ResolveName(desc ocispec.Descriptor) (string, bool) {
	name, ok := desc.Annotations[ocispec.AnnotationRefName]
	return name, ok
}

// IoContentWriter wraps an io.Writer to implement containerd's content.Writer
type IoContentWriter struct {
	writer       io.WriteCloser
	digester     digest.Digester
	status       ccontent.Status
	outputHash   string
	bytesWritten int64
}

// Write writes data to the underlying writer and updates the digest
func (w *IoContentWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)
	if n > 0 {
		w.digester.Hash().Write(p[:n])
		w.bytesWritten += int64(n)
	}
	return n, err
}

// Close closes the writer and verifies the digest if configured.
// Note: This assumes all data has been written via Write() before Close() is called.
// The digest is computed incrementally during Write() calls, not during Close().
// Validation happens before closing to catch digest mismatches before resources are released.
func (w *IoContentWriter) Close() error {
	if w.outputHash != "" {
		computed := w.digester.Digest().String()
		if computed != w.outputHash {
			return fmt.Errorf("digest mismatch: expected %s, got %s", w.outputHash, computed)
		}
	}
	return w.writer.Close()
}

// Digest returns the current digest of written data
func (w *IoContentWriter) Digest() digest.Digest {
	return w.digester.Digest()
}

// Commit validates the digest and size, then finalizes the write
func (w *IoContentWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...ccontent.Opt) error {
	// Validate size matches bytes written
	if size > 0 && size != w.bytesWritten {
		return fmt.Errorf("size mismatch: expected %d bytes, wrote %d bytes", size, w.bytesWritten)
	}

	// Validate digest matches computed digest
	if expected != "" {
		computed := w.digester.Digest()
		if computed != expected {
			return fmt.Errorf("digest mismatch: expected %s, got %s", expected, computed)
		}
	}

	return nil
}

// Status returns the current status
func (w *IoContentWriter) Status() (ccontent.Status, error) {
	return w.status, nil
}

// Truncate is not supported
func (w *IoContentWriter) Truncate(size int64) error {
	return fmt.Errorf("truncate not supported")
}

type writerOption func(*IoContentWriter)

// WithOutputHash configures expected output hash for verification
func WithOutputHash(hash string) writerOption {
	return func(w *IoContentWriter) {
		w.outputHash = hash
	}
}

// NewIoContentWriter creates a new IoContentWriter
func NewIoContentWriter(writer io.WriteCloser, opts ...writerOption) *IoContentWriter {
	w := &IoContentWriter{
		writer:   writer,
		digester: digest.Canonical.Digester(),
		status:   ccontent.Status{},
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// AnnotationUnpack is the annotation key for unpacking
const AnnotationUnpack = "io.containerd.image.unpack"

// nopCloser wraps an io.Writer to implement io.WriteCloser with a no-op Close
type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

// NopWriteCloser returns an io.WriteCloser with a no-op Close method wrapping
// the provided io.Writer.
func NopWriteCloser(w io.Writer) io.WriteCloser {
	return nopCloser{w}
}
