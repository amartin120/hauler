package getter_test

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/getter"
)

// TestFile_MediaType_RecognizedExtension proves File.MediaType resolves a
// ".txt" file to "text/plain" -- guaranteed by Go's builtin mime table
// ($GOROOT/src/mime/type.go), so this assertion holds across OS/CI without
// depending on an OS-provided mime.types file.
func TestFile_MediaType_RecognizedExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f := getter.NewFile()
	u, err := url.Parse("file://" + path)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	if got, want := f.MediaType(u), "text/plain"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestFile_MediaType_UnrecognizedExtension proves File.MediaType falls back
// to application/octet-stream for an extension with no builtin-table entry.
// Deliberately uses ".zzz" rather than ".yaml"/".sh": those are only resolved
// via an OS mime.types file and are not guaranteed empty on every platform/CI.
func TestFile_MediaType_UnrecognizedExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.zzz")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f := getter.NewFile()
	u, err := url.Parse("file://" + path)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	if got, want := f.MediaType(u), "application/octet-stream"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestDirectory_MediaType_FallsBackToOctetStream proves Directory.MediaType
// falls back to application/octet-stream for a directory path, which rarely
// carries a recognized extension -- the bundle is still tar+gzip bytes
// regardless of the declared media type.
func TestDirectory_MediaType_FallsBackToOctetStream(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "mydir")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	d := getter.NewDirectory()
	u, err := url.Parse("directory://" + sub)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	if got, want := d.MediaType(u), "application/octet-stream"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestFile_Annotations_URLAndMtime proves File.Annotations sets the source
// URL and a created timestamp matching the fixture's actual on-disk mtime.
func TestFile_Annotations_URLAndMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wantMtime := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := os.Chtimes(path, wantMtime, wantMtime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	f := getter.NewFile()
	u, err := url.Parse("file://" + path)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	ann := f.Annotations(u)
	if got, want := ann[ocispec.AnnotationURL], u.String(); got != want {
		t.Errorf("annotations[%s] = %q, want %q", ocispec.AnnotationURL, got, want)
	}

	created, ok := ann[ocispec.AnnotationCreated]
	if !ok {
		t.Fatalf("expected %s annotation to be set", ocispec.AnnotationCreated)
	}
	createdTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("annotations[%s] = %q is not RFC3339: %v", ocispec.AnnotationCreated, created, err)
	}
	// Generous tolerance: filesystem mtime resolution varies by platform.
	if diff := createdTime.Sub(wantMtime); diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("annotations[%s] = %v, want close to fixture mtime %v", ocispec.AnnotationCreated, createdTime, wantMtime)
	}
}

// TestClient_Annotations_DelegatesToDetectedGetter proves Client.Annotations
// resolves the right getter for source and returns its Annotations.
func TestClient_Annotations_DelegatesToDetectedGetter(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	c := getter.NewClient(getter.ClientOptions{})

	ann := c.Annotations(fileWithExt)
	u, err := url.Parse(fileWithExt)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	// A bare relative path parses with an empty scheme, so file.Detect must
	// still find it via the file getter and Annotations must still carry the
	// source string as the URL annotation.
	if got, want := ann[ocispec.AnnotationURL], u.String(); got != want {
		t.Errorf("annotations[%s] = %q, want %q", ocispec.AnnotationURL, got, want)
	}
}
