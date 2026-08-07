package getter_test

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/getter"
)

// TestHttp_Open_HonorsContextCancellation proves that Http.Open actually
// wires the ctx argument into the outgoing HTTP request (via
// http.NewRequestWithContext), rather than accepting-but-ignoring it. A
// handler that never writes a response blocks http.Get indefinitely; if Open
// used http.Get instead of a context-aware request, cancelling ctx would
// never unblock the call and this test would hang until killed by the test
// binary's own timeout rather than returning promptly.
func TestHttp_Open_HonorsContextCancellation(t *testing.T) {
	blockCh := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never respond until the test cleans up... simulates a hung/slow
		// server so the only way Open returns early is via ctx cancellation.
		<-blockCh
	}))
	// Cleanup runs LIFO: unblock the handler goroutine first so srv.Close
	// (registered second, run first) doesn't itself hang waiting for the
	// in-flight handler to return.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(blockCh) })

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	h := getter.NewHttp(false, "")

	done := make(chan error, 1)
	go func() {
		_, err := h.Open(ctx, u)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from Open after ctx cancellation, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Open did not return within 5s of ctx cancellation... ctx is not wired into the request")
	}
}

// TestHttp_MediaType_StripsContentTypeParams proves MediaType returns the
// bare mediaType (no "; charset=..." parameter), matching what a manifest's
// mediaType field requires.
func TestHttp_MediaType_StripsContentTypeParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	h := getter.NewHttp()
	if got, want := h.MediaType(u), "text/plain"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestHttp_MediaType_FallbackNoContentTypeHeader proves MediaType falls back
// to application/octet-stream when the server sets no Content-Type header at
// all on the HEAD response.
func TestHttp_MediaType_FallbackNoContentTypeHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately write nothing: no Content-Type header, no body -- Go's
		// http package only sniffs a Content-Type from the first Write call,
		// which never happens here.
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	h := getter.NewHttp()
	if got, want := h.MediaType(u), "application/octet-stream"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestHttp_MediaType_FallbackHeadFails proves MediaType falls back to
// application/octet-stream when the HEAD request itself fails (e.g. nothing
// listening at the target address).
func TestHttp_MediaType_FallbackHeadFails(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:1/unreachable")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	h := getter.NewHttp()
	if got, want := h.MediaType(u), "application/octet-stream"; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}
}

// TestHttp_Annotations_UsesLastModified proves Annotations reports the
// upstream Last-Modified time (normalized to UTC RFC3339) rather than the
// fetch time, and that it also carries the source URL.
func TestHttp_Annotations_UsesLastModified(t *testing.T) {
	const lastModified = "Wed, 21 Oct 2020 07:28:00 GMT"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL + "/file.txt")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	ann := getter.NewHttp().Annotations(u)

	if got, want := ann[ocispec.AnnotationURL], u.String(); got != want {
		t.Errorf("annotations[%s] = %q, want %q", ocispec.AnnotationURL, got, want)
	}
	if got, want := ann[ocispec.AnnotationCreated], "2020-10-21T07:28:00Z"; got != want {
		t.Errorf("annotations[%s] = %q, want %q", ocispec.AnnotationCreated, got, want)
	}
}

// TestHttp_Annotations_OmitsCreatedWithoutLastModified proves that a server
// which reports no Last-Modified yields no created annotation at all. Inventing
// one from the clock is what makes a manifest non-reproducible -- see
// TestHttp_Annotations_Deterministic.
func TestHttp_Annotations_OmitsCreatedWithoutLastModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL + "/file.txt")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	ann := getter.NewHttp().Annotations(u)

	if got, want := ann[ocispec.AnnotationURL], u.String(); got != want {
		t.Errorf("annotations[%s] = %q, want %q", ocispec.AnnotationURL, got, want)
	}
	if created, ok := ann[ocispec.AnnotationCreated]; ok {
		t.Errorf("annotations[%s] = %q, want it absent when the server sends no Last-Modified", ocispec.AnnotationCreated, created)
	}
}

// TestHttp_Annotations_Deterministic is the invariant the other two exist to
// protect: repeated calls for an unchanged resource must produce byte-identical
// annotations. These land in the manifest, whose bytes are digested into the
// store's descriptor, so any clock-derived value would give the same file a new
// digest on every sync -- orphaning the prior manifest blob and defeating
// AddIndex's byte-identical skip. Covers both the Last-Modified and the
// omitted-timestamp paths, since a regression could reappear in either.
func TestHttp_Annotations_Deterministic(t *testing.T) {
	for _, tc := range []struct {
		name         string
		lastModified string
	}{
		{name: "with Last-Modified", lastModified: "Wed, 21 Oct 2020 07:28:00 GMT"},
		{name: "without Last-Modified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.lastModified != "" {
					w.Header().Set("Last-Modified", tc.lastModified)
				}
			}))
			t.Cleanup(srv.Close)

			u, err := url.Parse(srv.URL + "/file.txt")
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}

			h := getter.NewHttp()
			first := h.Annotations(u)
			time.Sleep(1100 * time.Millisecond) // long enough for a clock-derived RFC3339 value to tick
			second := h.Annotations(u)

			if !maps.Equal(first, second) {
				t.Errorf("annotations differ across calls: %v vs %v", first, second)
			}
		})
	}
}
