package artifacts_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/artifacts"
	"hauler.dev/go/hauler/v2/pkg/artifacts/file"
)

// TestClassify_FileManifest_RealProductionShape feeds file.NewFile's actual
// Manifest() output -- not a hand-built fixture -- into Classify, proving the
// real production code path (OCI empty config + a real per-source layer
// media type) classifies as KindFile, matching classify.go's rule 6 and
// mappers.go's Files() dispatch.
func TestClassify_FileManifest_RealProductionShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("classify integration content"))
	}))
	t.Cleanup(srv.Close)

	f := file.NewFile(srv.URL + "/somefile.txt")

	gm, err := f.Manifest()
	if err != nil {
		t.Fatalf("Manifest(): %v", err)
	}

	raw, err := json.Marshal(gm)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	desc := ocispec.Descriptor{MediaType: string(gm.MediaType)}
	if got, want := artifacts.Classify(desc, &m), artifacts.KindFile; got != want {
		t.Errorf("Classify() = %v, want %v", got, want)
	}
}
