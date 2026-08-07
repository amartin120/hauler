package getter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type directory struct {
	*File
}

func NewDirectory() *directory {
	return &directory{File: NewFile()}
}

func (d directory) Open(ctx context.Context, u *url.URL) (io.ReadCloser, error) {
	tmpfile, err := os.CreateTemp("", "hauler")
	if err != nil {
		return nil, err
	}

	digester := digest.Canonical.Digester()
	zw := gzip.NewWriter(io.MultiWriter(tmpfile, digester.Hash()))

	tarDigester := digest.Canonical.Digester()
	if err := tarDir(d.path(u), d.Name(u), io.MultiWriter(zw, tarDigester.Hash()), false); err != nil {
		zw.Close()
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return nil, err
	}

	if err := zw.Close(); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return nil, err
	}
	if err := tmpfile.Sync(); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return nil, err
	}

	// Close the write handle; re-open as read-only
	tmpName := tmpfile.Name()
	tmpfile.Close()

	fi, err := os.Open(tmpName)
	if err != nil {
		os.Remove(tmpName)
		return nil, err
	}

	return &tempFileReadCloser{File: fi, path: tmpName}, nil
}

func (d directory) Detect(u *url.URL) bool {
	if len(d.path(u)) == 0 {
		return false
	}

	fi, err := os.Stat(d.path(u))
	if err != nil {
		return false
	}
	return fi.IsDir()
}

// MediaType detects the OCI media type from the directory's own path
// extension. Directory names rarely carry a recognized extension, so this
// almost always falls back to application/octet-stream -- harmless, since
// the bundle is tar+gzip bytes regardless of the declared media type, and
// content.AnnotationUnpack (set in Client.LayerFrom) is what actually signals
// "this needs untarring" downstream.
func (d directory) MediaType(u *url.URL) string {
	mt := mime.TypeByExtension(filepath.Ext(d.path(u)))
	if mt == "" {
		return "application/octet-stream"
	}
	t, _, err := mime.ParseMediaType(mt)
	if err != nil || t == "" {
		return "application/octet-stream"
	}
	return t
}

// Annotations returns manifest-level provenance annotations for a directory
// source: the source path always, plus the directory's own mtime when
// os.Stat succeeds, mirroring File.Annotations.
func (d directory) Annotations(u *url.URL) map[string]string {
	ann := map[string]string{
		ocispec.AnnotationURL: u.String(),
	}
	if fi, err := os.Stat(d.path(u)); err == nil {
		ann[ocispec.AnnotationCreated] = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return ann
}

func tarDir(root string, prefix string, w io.Writer, stripTimes bool) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Rename path
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.Join(prefix, name)
		name = filepath.ToSlash(name)

		// Generate header
		var link string
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return errors.Wrap(err, path)
		}
		header.Name = name
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""

		if stripTimes {
			header.ModTime = time.Time{}
			header.AccessTime = time.Time{}
			header.ChangeTime = time.Time{}
		}

		// Write file
		if err := tw.WriteHeader(header); err != nil {
			return errors.Wrap(err, "tar")
		}
		if mode.IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			if _, err := io.Copy(tw, file); err != nil {
				return errors.Wrap(err, path)
			}
		}

		return nil
	}); err != nil {
		return err
	}
	return nil
}

// tempFileReadCloser wraps an *os.File and removes the underlying
// temp file when closed.
type tempFileReadCloser struct {
	*os.File
	path string
}

func (t *tempFileReadCloser) Close() error {
	err := t.File.Close()
	os.Remove(t.path)
	return err
}
