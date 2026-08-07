package store

// testhelpers_test.go provides shared test helpers for cmd/hauler/cli/store tests.
//
// This file is in-package (package store) so tests can call unexported
// helpers like storeImage, storeFile, rewriteReference, etc.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	golog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	gvtypes "github.com/google/go-containerregistry/pkg/v1/types"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	ociempty "github.com/sigstore/cosign/v3/pkg/oci/empty"
	ocimutate "github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ocistatic "github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"helm.sh/helm/v4/pkg/action"

	"hauler.dev/go/hauler/v2/internal/flags"
	"hauler.dev/go/hauler/v2/pkg/artifacts"
	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// newTestKeyPair generates a fresh ECDSA P-256 key pair and writes the public
// half in the PEM form cosign's --key expects, returning the private key and
// that path. Generated rather than vendored so the tests never depend on a
// fixture whose algorithm cosign might later stop accepting.
func newTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing public key: %v", err)
	}
	return priv, path
}

// writeTestPubKey returns the path to a public key with no signed image behind
// it -- for tests that only need verification to fail closed.
func writeTestPubKey(t *testing.T) string {
	t.Helper()
	_, path := newTestKeyPair(t)
	return path
}

// seedSignedImage pushes a random image and a genuine cosign v2 signature for
// it, returning the image and the path to the public key that verifies it.
//
// The signature is built the way cosign itself builds one -- a simplesigning
// payload naming the image's digest, signed with ECDSA-P256, carried as the
// dev.cosignproject.cosign/signature annotation on a layer of the
// sha256-<hex>.sig manifest -- so cosign.Verifier's library path accepts it
// with IgnoreTlog set. seedCosignV2Artifacts pushes the same tags with random
// content and is its fail-closed counterpart.
func seedSignedImage(t *testing.T, host, repo, tag string, opts ...remote.Option) (gcrv1.Image, string) {
	t.Helper()

	img := seedImage(t, host, repo, tag, opts...)
	hash, err := img.Digest()
	if err != nil {
		t.Fatalf("seedSignedImage digest: %v", err)
	}

	priv, keyPath := newTestKeyPair(t)
	sv, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("seedSignedImage LoadECDSASignerVerifier: %v", err)
	}

	digestRef, err := name.NewDigest(host+"/"+repo+"@"+hash.String(), name.Insecure)
	if err != nil {
		t.Fatalf("seedSignedImage NewDigest: %v", err)
	}
	// The payload binds the signature to this exact digest; cosign rejects a
	// signature whose payload names a different one, which is what makes the
	// pinning assertions meaningful.
	payloadBytes, err := (&payload.Cosign{Image: digestRef}).MarshalJSON()
	if err != nil {
		t.Fatalf("seedSignedImage marshaling payload: %v", err)
	}
	rawSig, err := sv.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		t.Fatalf("seedSignedImage SignMessage: %v", err)
	}

	ociSig, err := ocistatic.NewSignature(payloadBytes, base64.StdEncoding.EncodeToString(rawSig))
	if err != nil {
		t.Fatalf("seedSignedImage ocistatic.NewSignature: %v", err)
	}
	sigs, err := ocimutate.AppendSignatures(ociempty.Signatures(), false, ociSig)
	if err != nil {
		t.Fatalf("seedSignedImage AppendSignatures: %v", err)
	}

	sigRef, err := name.NewTag(host+"/"+repo+":"+strings.ReplaceAll(hash.String(), ":", "-")+".sig", name.Insecure)
	if err != nil {
		t.Fatalf("seedSignedImage NewTag (sig): %v", err)
	}
	if err := remote.Write(sigRef, sigs, opts...); err != nil {
		t.Fatalf("seedSignedImage writing signature: %v", err)
	}
	return img, keyPath
}

// newTestStore creates a fresh store in a temp directory. Fatal on error.
func newTestStore(t *testing.T) *store.Layout {
	t.Helper()
	s, err := store.NewLayout(t.TempDir())
	if err != nil {
		t.Fatalf("newTestStore: %v", err)
	}
	return s
}

// newTestRegistry starts an in-memory OCI registry backed by httptest.
// Returns the host (host:port) and remote.Options that route requests through
// the server's plain-HTTP transport. The server is shut down via t.Cleanup.
//
// Pass the returned remoteOpts to seedImage/seedIndex and to store.AddImage
// calls so that both sides use the same plain-HTTP transport.
func newTestRegistry(t *testing.T) (host string, remoteOpts []remote.Option) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host = strings.TrimPrefix(srv.URL, "http://")
	remoteOpts = []remote.Option{remote.WithTransport(srv.Client().Transport)}
	return host, remoteOpts
}

// pushBlobPlain uploads data as a blob to host/repo via a single monolithic
// POST (?digest=<digest>), bypassing go-containerregistry's own blob-write
// path entirely so a manifest built by hand (pushManifestPlain) can reference
// it without any of go-containerregistry's own types touching the bytes.
// Returns the blob's digest.
func pushBlobPlain(t *testing.T, host, repo string, data []byte) digest.Digest {
	t.Helper()
	dgst := digest.FromBytes(data)
	url := fmt.Sprintf("http://%s/v2/%s/blobs/uploads/?digest=%s", host, repo, dgst.String())
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pushBlobPlain: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pushBlobPlain: Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("pushBlobPlain: unexpected status %d: %s", resp.StatusCode, body)
	}
	return dgst
}

// pushManifestPlain PUTs data (already-serialized manifest bytes) to
// host/repo:tag directly via http.Client -- never remote.Write/mutate, which
// would re-serialize through go-containerregistry's own types and could
// silently normalize away the exact bytes a test is pinning. Returns the
// manifest's digest.
func pushManifestPlain(t *testing.T, host, repo, tag, contentType string, data []byte) digest.Digest {
	t.Helper()
	url := fmt.Sprintf("http://%s/v2/%s/manifests/%s", host, repo, tag)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pushManifestPlain: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(len(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pushManifestPlain: Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("pushManifestPlain: unexpected status %d: %s", resp.StatusCode, body)
	}
	return digest.FromBytes(data)
}

// ociChartManifestAnnotations returns a representative set of manifest-level
// annotations a real Helm-OCI publisher writes (authors, created,
// description, source, title, url, version) -- used by the OCI-passthrough
// tests to prove none of them are dropped by storing the chart as-is.
func ociChartManifestAnnotations(version string) map[string]string {
	return map[string]string{
		ocispec.AnnotationAuthors:     "Test Publisher <test@example.com>",
		ocispec.AnnotationCreated:     "2024-01-01T00:00:00Z",
		ocispec.AnnotationDescription: "A test chart for OCI passthrough",
		ocispec.AnnotationSource:      "https://github.com/example/chart-with-file-dependency-chart",
		ocispec.AnnotationTitle:       "chart-with-file-dependency-chart",
		ocispec.AnnotationURL:         "https://example.com/charts/chart-with-file-dependency-chart",
		ocispec.AnnotationVersion:     version,
	}
}

// seedOCIChartManifest hand-crafts and pushes an upstream-shaped OCI Helm
// chart manifest to host/repo:tag -- manifest-level annotations, no
// layer-level org.opencontainers.image.title, and no top-level "mediaType"
// JSON field (real publishers commonly omit it, relying on the registry's
// Content-Type response header instead, exactly as
// ghcr.io/nginxinc/charts/nginx-ingress does). chartTgz must be real chart
// archive bytes so chrt.Load() can parse a chart out of it later. Returns the
// manifest's raw bytes and digest so a test can assert the store recorded
// them byte-for-byte.
func seedOCIChartManifest(t *testing.T, host, repo, tag string, chartTgz []byte, annotations map[string]string) ([]byte, digest.Digest) {
	t.Helper()

	configData := []byte(`{"name":"` + repo + `","version":"` + tag + `"}`)
	configDigest := pushBlobPlain(t, host, repo, configData)
	layerDigest := pushBlobPlain(t, host, repo, chartTgz)

	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Config: ocispec.Descriptor{
			MediaType: consts.ChartConfigMediaType,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: consts.ChartLayerMediaType,
				Digest:    layerDigest,
				Size:      int64(len(chartTgz)),
			},
		},
		Annotations: annotations,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("seedOCIChartManifest: marshal manifest: %v", err)
	}

	dgst := pushManifestPlain(t, host, repo, tag, ocispec.MediaTypeImageManifest, data)
	return data, dgst
}

// failAfterNManifestGETs wraps an http.Handler and returns a 500 for every GET
// request whose path has the given suffix beyond the first n such requests.
// It simulates a registry that serves a chart puller's first, successful
// fetch (e.g. Helm's own OCI pull during chart.NewChart) but has become
// unreachable by the time a second, independent fetch of the same ref runs
// (e.g. store.Layout.AddImage's own remote.Get) -- used to pin fetchChart's
// OCI-passthrough fallback to the rewrap path.
type failAfterNManifestGETs struct {
	next       http.Handler
	pathSuffix string
	n          int32
	seen       int32
}

func (h *failAfterNManifestGETs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, h.pathSuffix) {
		if atomic.AddInt32(&h.seen, 1) > h.n {
			http.Error(w, "simulated registry failure", http.StatusInternalServerError)
			return
		}
	}
	h.next.ServeHTTP(w, r)
}

// recordingHandler records the path of every request it serves before
// delegating. Concurrent handlers append to the same slice, so every method
// takes mu.
type recordingHandler struct {
	next  http.Handler
	mu    sync.Mutex
	paths []string
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.paths = append(h.paths, r.Method+" "+r.URL.Path)
	h.mu.Unlock()
	h.next.ServeHTTP(w, r)
}

func (h *recordingHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paths = nil
}

func (h *recordingHandler) countContaining(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, p := range h.paths {
		if strings.Contains(p, sub) {
			n++
		}
	}
	return n
}

func (h *recordingHandler) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.paths...)
}

// newRecordingRegistry mirrors newTestRegistry but records request paths, so a
// test can assert how a tag was reached and not just what was stored.
func newRecordingRegistry(t *testing.T) (string, []remote.Option, *recordingHandler) {
	t.Helper()
	rec := &recordingHandler{next: registry.New(registry.Logger(golog.New(io.Discard, "", 0)))}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), []remote.Option{remote.WithTransport(srv.Client().Transport)}, rec
}

// seedImage pushes a random single-platform image to the test registry.
// repo is a bare path like "myorg/myimage"... tag is the image tag string.
// Pass the remoteOpts from newTestRegistry so writes use the correct transport.
func seedImage(t *testing.T, host, repo, tag string, opts ...remote.Option) gcrv1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("seedImage random.Image: %v", err)
	}
	ref, err := name.NewTag(host+"/"+repo+":"+tag, name.Insecure)
	if err != nil {
		t.Fatalf("seedImage name.NewTag: %v", err)
	}
	if err := remote.Write(ref, img, opts...); err != nil {
		t.Fatalf("seedImage remote.Write: %v", err)
	}
	return img
}

// seedIndex pushes a 2-platform image index (linux/amd64 + linux/arm64) to
// the test registry. Pass the remoteOpts from newTestRegistry.
func seedIndex(t *testing.T, host, repo, tag string, opts ...remote.Option) gcrv1.ImageIndex {
	t.Helper()
	amd64Img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("seedIndex random.Image amd64: %v", err)
	}
	arm64Img, err := random.Image(512, 2)
	if err != nil {
		t.Fatalf("seedIndex random.Image arm64: %v", err)
	}
	idx := mutate.AppendManifests(
		empty.Index,
		mutate.IndexAddendum{
			Add: amd64Img,
			Descriptor: gcrv1.Descriptor{
				MediaType: gvtypes.OCIManifestSchema1,
				Platform:  &gcrv1.Platform{OS: "linux", Architecture: "amd64"},
			},
		},
		mutate.IndexAddendum{
			Add: arm64Img,
			Descriptor: gcrv1.Descriptor{
				MediaType: gvtypes.OCIManifestSchema1,
				Platform:  &gcrv1.Platform{OS: "linux", Architecture: "arm64"},
			},
		},
	)
	ref, err := name.NewTag(host+"/"+repo+":"+tag, name.Insecure)
	if err != nil {
		t.Fatalf("seedIndex name.NewTag: %v", err)
	}
	if err := remote.WriteIndex(ref, idx, opts...); err != nil {
		t.Fatalf("seedIndex remote.WriteIndex: %v", err)
	}
	return idx
}

// seedFileInHTTPServer starts an httptest server serving a single file at
// /filename with the given content. Returns the full URL. Server closed via t.Cleanup.
func seedFileInHTTPServer(t *testing.T, filename, content string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+filename, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, content) //nolint:errcheck
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/" + filename
}

// defaultRootOpts returns a StoreRootOpts pointed at storeDir with Retries=1.
// Using Retries=1 avoids the 5-second RetriesInterval sleep in failure tests.
func defaultRootOpts(storeDir string) *flags.StoreRootOpts {
	return &flags.StoreRootOpts{
		StoreDir: storeDir,
		Retries:  1,
	}
}

// defaultCliOpts returns CliRootOpts with log level error, audit level none, and ignore errors false.
// Audit is disabled here rather than pointed at a temp HaulerDir so tests don't write to the
// developer/CI user's real $HOME/.hauler/audit.log.
func defaultCliOpts() *flags.CliRootOpts {
	return &flags.CliRootOpts{
		IgnoreErrors: false,
		LogLevel:     "error",
		AuditLevel:   "none",
	}
}

// newTestContext returns a context with a no-op zerolog logger attached so that
// log.FromContext does not emit to stdout/stderr during tests.
func newTestContext(t *testing.T) context.Context {
	t.Helper()
	zl := zerolog.New(io.Discard)
	return zl.WithContext(context.Background())
}

// newAddChartOpts builds an AddChartOpts for loading a local .tgz chart from
// repoURL (typically a testdata directory path) at the given version string.
func newAddChartOpts(repoURL, version string) *flags.AddChartOpts {
	return &flags.AddChartOpts{
		ChartOpts: &action.ChartPathOptions{
			RepoURL: repoURL,
			Version: version,
		},
	}
}

// assertArtifactInStore walks the store and fails the test if no descriptor
// has an AnnotationRefName containing refSubstring.
func assertArtifactInStore(t *testing.T, s *store.Layout, refSubstring string) {
	t.Helper()
	found := false
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if strings.Contains(desc.Annotations[ocispec.AnnotationRefName], refSubstring) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("assertArtifactInStore walk: %v", err)
	}
	if !found {
		t.Errorf("no artifact with ref containing %q found in store", refSubstring)
	}
}

// assertArtifactNotInStore is assertArtifactInStore's opposite: fails if any
// descriptor's AnnotationRefName contains refSubstring.
func assertArtifactNotInStore(t *testing.T, s *store.Layout, refSubstring string) {
	t.Helper()
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if strings.Contains(desc.Annotations[ocispec.AnnotationRefName], refSubstring) {
			t.Errorf("expected no artifact with ref containing %q, found one in store", refSubstring)
		}
		return nil
	}); err != nil {
		t.Fatalf("assertArtifactNotInStore walk: %v", err)
	}
}

// assertArtifactKindInStore walks the store and fails if no descriptor matches
// refSubstring and kind. No descriptor carries a "kind" annotation anymore, so
// kind here only selects which annotation shape to look for: a real
// image/index's own ref.name still equals refSubstring directly, while a
// sig/att/sbom/referrer's true ref.name is its own derived value -- matched by
// the base image recorded in io.containerd.image.name (the subject pointer)
// plus the derived shape for that artifact kind (.sig/.att/.sbom suffix, or an
// "@digest" ref for a referrer).
func assertArtifactKindInStore(t *testing.T, s *store.Layout, refSubstring, kind string) {
	t.Helper()
	found := false
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		ref := desc.Annotations[ocispec.AnnotationRefName]
		subject := desc.Annotations[consts.ContainerdImageNameKey]
		switch kind {
		case consts.KindAnnotationImage, consts.KindAnnotationIndex:
			if strings.Contains(ref, refSubstring) {
				found = true
			}
		case consts.KindAnnotationSigs:
			if strings.Contains(subject, refSubstring) && strings.HasSuffix(ref, ".sig") {
				found = true
			}
		case consts.KindAnnotationAtts:
			if strings.Contains(subject, refSubstring) && strings.HasSuffix(ref, ".att") {
				found = true
			}
		case consts.KindAnnotationSboms:
			if strings.Contains(subject, refSubstring) && strings.HasSuffix(ref, ".sbom") {
				found = true
			}
		default:
			if strings.HasPrefix(kind, consts.KindAnnotationReferrers) &&
				strings.Contains(subject, refSubstring) && strings.Contains(ref, "@") {
				found = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("assertArtifactKindInStore walk: %v", err)
	}
	if !found {
		t.Errorf("no artifact with ref containing %q and kind %q found in store", refSubstring, kind)
	}
}

// mergeAnnotations returns a new map containing every key/value from each of
// maps, later maps overriding earlier ones on key collision.
func mergeAnnotations(maps ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// seedManifestDescriptor writes m as a real blob into s's store and adds an
// index entry for it under annotations, so artifacts.Classify -- which
// requires decoding real manifest content, not just an annotation -- works
// against it. Unlike seedStoreDescriptor, which fabricates a descriptor with
// no backing blob, this is required whenever a test needs a fixture that
// actually classifies as something (a sig/att/sbom/referrer/chart/file/...).
func seedManifestDescriptor(t *testing.T, s *store.Layout, m ocispec.Manifest, annotations map[string]string) ocispec.Descriptor {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("seedManifestDescriptor: marshal manifest: %v", err)
	}
	dgst := digest.FromBytes(data)
	if err := s.OCI.WriteBlob(context.Background(), dgst, int64(len(data)), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}); err != nil {
		t.Fatalf("seedManifestDescriptor: WriteBlob: %v", err)
	}

	mediaType := string(m.MediaType)
	if mediaType == "" {
		mediaType = ocispec.MediaTypeImageManifest
	}
	desc := ocispec.Descriptor{
		MediaType:   mediaType,
		Digest:      dgst,
		Size:        int64(len(data)),
		Annotations: annotations,
	}
	if err := s.OCI.AddIndex(desc); err != nil {
		t.Fatalf("seedManifestDescriptor: AddIndex: %v", err)
	}
	return desc
}

// seedNoTitleChartManifest writes a chart manifest directly into s's store --
// no live registry involved -- with a config media type that classifies as a
// chart (artifacts.Classify's Rule 4) and a single layer carrying no
// org.opencontainers.image.title annotation, the shape an OCI-passthrough
// chart (fetchChart's registry.IsOCI branch) produces. ref is the chart's
// store reference (e.g. "myorg/mychart:1.0.0").
func seedNoTitleChartManifest(t *testing.T, s *store.Layout, ref string, layerContent []byte) {
	t.Helper()

	configData := []byte(`{}`)
	configDigest := digest.FromBytes(configData)
	if err := s.OCI.WriteBlob(context.Background(), configDigest, int64(len(configData)), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(configData)), nil
	}); err != nil {
		t.Fatalf("seedNoTitleChartManifest: WriteBlob config: %v", err)
	}

	layerDigest := digest.FromBytes(layerContent)
	if err := s.OCI.WriteBlob(context.Background(), layerDigest, int64(len(layerContent)), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerContent)), nil
	}); err != nil {
		t.Fatalf("seedNoTitleChartManifest: WriteBlob layer: %v", err)
	}

	m := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Config: ocispec.Descriptor{
			MediaType: consts.ChartConfigMediaType,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: consts.ChartLayerMediaType,
				Digest:    layerDigest,
				Size:      int64(len(layerContent)),
			},
		},
	}

	seedManifestDescriptor(t, s, m, map[string]string{
		ocispec.AnnotationRefName: ref,
	})
}

// assertArtifactClassifiesAs walks the store, decodes the manifest of the
// first descriptor whose ref.name contains refSubstring, and fails unless
// artifacts.Classify reports want.
func assertArtifactClassifiesAs(t *testing.T, s *store.Layout, refSubstring string, want artifacts.Kind) {
	t.Helper()
	found := false
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if found || !strings.Contains(desc.Annotations[ocispec.AnnotationRefName], refSubstring) {
			return nil
		}
		rc, err := s.Fetch(context.Background(), desc)
		if err != nil {
			t.Fatalf("assertArtifactClassifiesAs: fetch %s: %v", desc.Digest, err)
		}
		defer rc.Close()
		var m ocispec.Manifest
		if err := json.NewDecoder(rc).Decode(&m); err != nil {
			t.Fatalf("assertArtifactClassifiesAs: decode manifest %s: %v", desc.Digest, err)
		}
		if got := artifacts.Classify(desc, &m); got == want {
			found = true
		} else {
			t.Errorf("artifacts.Classify(%s) = %v, want %v", desc.Digest, got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("assertArtifactClassifiesAs walk: %v", err)
	}
	if !found {
		t.Errorf("no artifact with ref containing %q classifying as %v found in store", refSubstring, want)
	}
}

// storedDigest returns the digest of the first indexed descriptor whose ref
// annotation contains refSubstring, or "" if there is none.
func storedDigest(t *testing.T, s *store.Layout, refSubstring string) string {
	t.Helper()
	found := ""
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if found == "" && strings.Contains(desc.Annotations[ocispec.AnnotationRefName], refSubstring) {
			found = desc.Digest.String()
		}
		return nil
	}); err != nil {
		t.Fatalf("storedDigest walk: %v", err)
	}
	return found
}

// fetchStoredManifestBytes walks the store for the descriptor whose
// AnnotationRefName exactly equals ref, fetches it, and returns its raw
// manifest bytes -- used to assert a manifest was stored byte-for-byte, which
// a decoded/re-marshaled comparison would not catch (e.g. Go's encoding/json
// silently reordering fields).
func fetchStoredManifestBytes(t *testing.T, s *store.Layout, ref string) []byte {
	t.Helper()
	var desc ocispec.Descriptor
	found := false
	if err := s.OCI.Walk(func(_ string, d ocispec.Descriptor) error {
		if !found && d.Annotations[ocispec.AnnotationRefName] == ref {
			desc = d
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("fetchStoredManifestBytes walk: %v", err)
	}
	if !found {
		t.Fatalf("no descriptor with ref %q found in store", ref)
	}
	rc, err := s.Fetch(context.Background(), desc)
	if err != nil {
		t.Fatalf("fetchStoredManifestBytes: fetch %s: %v", desc.Digest, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("fetchStoredManifestBytes: read %s: %v", desc.Digest, err)
	}
	return data
}

// lastAuditEntryFlags reads <haulerDir>/audit.log (see pkg/audit.Append /
// resolveDir) and returns the "flags" object of its last JSON line -- only
// populated at audit level "verbose", since audit.Append omits Flags
// otherwise. Fails the test if the file is missing, empty, or malformed.
func lastAuditEntryFlags(t *testing.T, haulerDir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(haulerDir, "audit.log"))
	if err != nil {
		t.Fatalf("reading audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("audit.log has no entries")
	}
	var entry struct {
		Flags map[string]any `json:"flags"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("unmarshaling last audit.log line: %v\nline: %s", err, lines[len(lines)-1])
	}
	return entry.Flags
}

// lastAuditEntryReference reads <haulerDir>/audit.log and returns the
// "reference" field of its last JSON line. Unlike Flags, Reference is written
// at every audit level except "none", so callers need not set "verbose".
func lastAuditEntryReference(t *testing.T, haulerDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(haulerDir, "audit.log"))
	if err != nil {
		t.Fatalf("reading audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("audit.log has no entries")
	}
	var entry struct {
		Reference string `json:"reference"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("unmarshaling last audit.log line: %v\nline: %s", err, lines[len(lines)-1])
	}
	return entry.Reference
}

// storedRefNames returns every org.opencontainers.image.ref.name in the store
// index, for assertions that need an exact match rather than storedDigest's
// substring search.
func storedRefNames(t *testing.T, s *store.Layout) []string {
	t.Helper()
	var refs []string
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if r := desc.Annotations[ocispec.AnnotationRefName]; r != "" {
			refs = append(refs, r)
		}
		return nil
	}); err != nil {
		t.Fatalf("storedRefNames walk: %v", err)
	}
	return refs
}

// countArtifactsInStore returns the number of descriptors in the store index.
func countArtifactsInStore(t *testing.T, s *store.Layout) int {
	t.Helper()
	count := 0
	if err := s.OCI.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("countArtifactsInStore walk: %v", err)
	}
	return count
}

// seedCosignV2Artifacts pushes synthetic cosign v2 signature, attestation, and SBOM
// manifests at the sha256-<hex>.sig / .att / .sbom tags derived from baseImg's digest.
// Pass the remoteOpts from newLocalhostRegistry or newTestRegistry.
func seedCosignV2Artifacts(t *testing.T, host, repo string, baseImg gcrv1.Image, opts ...remote.Option) {
	t.Helper()
	hash, err := baseImg.Digest()
	if err != nil {
		t.Fatalf("seedCosignV2Artifacts: get digest: %v", err)
	}
	tagPrefix := strings.ReplaceAll(hash.String(), ":", "-")
	for _, suffix := range []string{".sig", ".att", ".sbom"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatalf("seedCosignV2Artifacts: random.Image (%s): %v", suffix, err)
		}
		ref, err := name.NewTag(host+"/"+repo+":"+tagPrefix+suffix, name.Insecure)
		if err != nil {
			t.Fatalf("seedCosignV2Artifacts: NewTag (%s): %v", suffix, err)
		}
		if err := remote.Write(ref, img, opts...); err != nil {
			t.Fatalf("seedCosignV2Artifacts: Write (%s): %v", suffix, err)
		}
	}
}

// seedOCI11Referrer pushes a synthetic OCI 1.1 / cosign v3 Sigstore bundle manifest
// whose subject field points at baseImg. The in-process registry auto-registers it in
// the referrers index so remote.Referrers returns it.
// Pass the remoteOpts from newLocalhostRegistry or newTestRegistry.
func seedOCI11Referrer(t *testing.T, host, repo string, baseImg gcrv1.Image, opts ...remote.Option) {
	t.Helper()
	hash, err := baseImg.Digest()
	if err != nil {
		t.Fatalf("seedOCI11Referrer: get digest: %v", err)
	}
	rawManifest, err := baseImg.RawManifest()
	if err != nil {
		t.Fatalf("seedOCI11Referrer: raw manifest: %v", err)
	}
	mt, err := baseImg.MediaType()
	if err != nil {
		t.Fatalf("seedOCI11Referrer: media type: %v", err)
	}
	baseDesc := gcrv1.Descriptor{
		MediaType: mt,
		Digest:    hash,
		Size:      int64(len(rawManifest)),
	}

	bundleJSON := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := static.NewLayer(bundleJSON, gvtypes.MediaType(consts.SigstoreBundleMediaType))
	referrerImg, err := mutate.AppendLayers(empty.Image, bundleLayer)
	if err != nil {
		t.Fatalf("seedOCI11Referrer: AppendLayers: %v", err)
	}
	referrerImg = mutate.MediaType(referrerImg, gvtypes.OCIManifestSchema1)
	referrerImg = mutate.ConfigMediaType(referrerImg, gvtypes.MediaType(consts.OCIEmptyConfigMediaType))
	referrerImg = mutate.Subject(referrerImg, baseDesc).(gcrv1.Image)

	referrerTag, err := name.NewTag(host+"/"+repo+":bundle-referrer", name.Insecure)
	if err != nil {
		t.Fatalf("seedOCI11Referrer: NewTag: %v", err)
	}
	if err := remote.Write(referrerTag, referrerImg, opts...); err != nil {
		t.Fatalf("seedOCI11Referrer: Write: %v", err)
	}
}

// seedStoreDescriptor injects a descriptor with the given annotations directly
// into the store index without requiring a real registry or blob. This is used
// to pre-populate the store for rewriteReference unit tests.
func seedStoreDescriptor(t *testing.T, s *store.Layout, annotations map[string]string) {
	t.Helper()
	desc := ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageManifest,
		Digest:      digest.Digest("sha256:" + strings.Repeat("a", 64)),
		Size:        1,
		Annotations: annotations,
	}
	if err := s.OCI.AddIndex(desc); err != nil {
		t.Fatalf("seedStoreDescriptor: %v", err)
	}
}

// assertAnnotationsInStore walks the store and fails if no descriptor has both
// AnnotationRefName == refName AND ContainerdImageNameKey == containerdName.
func assertAnnotationsInStore(t *testing.T, s *store.Layout, refName, containerdName string) {
	t.Helper()
	found := false
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if desc.Annotations[ocispec.AnnotationRefName] == refName &&
			desc.Annotations[consts.ContainerdImageNameKey] == containerdName {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("assertAnnotationsInStore walk: %v", err)
	}
	if !found {
		t.Errorf("no artifact with AnnotationRefName=%q and ContainerdImageNameKey=%q found in store", refName, containerdName)
	}
}

// assertReferrerInStore walks the store and fails if no descriptor has a kind
// annotation with the KindAnnotationReferrers prefix and a ref containing refSubstring.
func assertReferrerInStore(t *testing.T, s *store.Layout, refSubstring string) {
	t.Helper()
	found := false
	if err := s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		// A referrer's own ref.name is now its digest form (repo@<referrerDigest>),
		// so refSubstring (the base image's tag-form ref) is matched against the
		// subject pointer, io.containerd.image.name, instead.
		if strings.Contains(desc.Annotations[consts.ContainerdImageNameKey], refSubstring) &&
			strings.Contains(desc.Annotations[ocispec.AnnotationRefName], "@") {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("assertReferrerInStore walk: %v", err)
	}
	if !found {
		t.Errorf("no OCI referrer with ref containing %q found in store", refSubstring)
	}
}
