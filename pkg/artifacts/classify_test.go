package artifacts

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"

	"hauler.dev/go/hauler/v2/pkg/consts"
)

func TestClassify(t *testing.T) {
	baseSubject := &ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Size:      100,
	}

	titled := func(mt string) ocispec.Descriptor {
		return ocispec.Descriptor{
			MediaType:   mt,
			Annotations: map[string]string{ocispec.AnnotationTitle: "some-file.bin"},
		}
	}
	untitled := func(mt string) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt}
	}

	tests := []struct {
		name string
		desc ocispec.Descriptor
		m    *ocispec.Manifest
		want Kind
	}{
		{
			name: "rule1: OCI image index media type",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex},
			m:    nil,
			want: KindIndex,
		},
		{
			name: "rule1: docker manifest list media type",
			desc: ocispec.Descriptor{MediaType: consts.DockerManifestListSchema2},
			m:    nil,
			want: KindIndex,
		},
		{
			name: "rule2: v3 referrer, sig artifactType",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject:      baseSubject,
				ArtifactType: consts.CosignReferrerSigArtifactType,
			},
			want: KindSignature,
		},
		{
			name: "rule2: v3 referrer, in-toto artifactType (real attestation referrer)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject:      baseSubject,
				ArtifactType: ctypes.IntotoPayloadType,
			},
			want: KindAttestation,
		},
		{
			name: "rule2: v3 referrer, new-bundle-format artifactType (attestation bundle)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject:      baseSubject,
				ArtifactType: consts.SigstoreBundleMediaType,
			},
			want: KindAttestation,
		},
		{
			name: "rule2: v3 referrer, sbom artifactType",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject:      baseSubject,
				ArtifactType: consts.CosignReferrerSBOMArtifactType,
			},
			want: KindSBOM,
		},
		{
			name: "rule2: v3 referrer, unrecognized artifactType falls back to generic Referrer",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject:      baseSubject,
				ArtifactType: "application/vnd.example.something.v1+json",
			},
			want: KindReferrer,
		},
		{
			name: "rule2: v3 referrer, no artifactType at all falls back to generic Referrer",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Subject: baseSubject,
			},
			want: KindReferrer,
		},
		{
			name: "rule3: cosign v2 tag-convention signature -- standard image config must NOT win over the cosign layer check",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.DockerConfigJSON},
				Layers: []ocispec.Descriptor{untitled(ctypes.SimpleSigningMediaType)},
			},
			want: KindSignature,
		},
		{
			name: "rule3: cosign v2 tag-convention attestation (DSSE envelope layer)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
				Layers: []ocispec.Descriptor{untitled(ctypes.DssePayloadType)},
			},
			want: KindAttestation,
		},
		{
			name: "rule3: cosign v2 tag-convention SBOM (SPDX layer)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
				Layers: []ocispec.Descriptor{untitled(ctypes.SPDXJSONMediaType)},
			},
			want: KindSBOM,
		},
		{
			name: "rule3: cosign v2 tag-convention SBOM (CycloneDX layer)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
				Layers: []ocispec.Descriptor{untitled(ctypes.CycloneDXJSONMediaType)},
			},
			want: KindSBOM,
		},
		{
			name: "rule4: OCI Helm chart added via `store add image` (no chart-specific metadata beyond standard Helm OCI shape)",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.ChartConfigMediaType},
				Layers: []ocispec.Descriptor{untitled(consts.ChartLayerMediaType)},
			},
			want: KindChart,
		},
		{
			name: "rule5: standard container image, no titled layers",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
				Layers: []ocispec.Descriptor{untitled(consts.OCILayer)},
			},
			want: KindImage,
		},
		{
			name: "rule5: standard container image, docker config media type",
			desc: ocispec.Descriptor{MediaType: consts.DockerManifestSchema2},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.DockerConfigJSON},
				Layers: []ocispec.Descriptor{untitled(consts.DockerLayer)},
			},
			want: KindImage,
		},
		{
			name: "rule5: rke2-binary heuristic -- image config reused for a file, titled layer, no known image layer type",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
				Layers: []ocispec.Descriptor{titled("application/vnd.rke2.binary.layer.v1+gzip")},
			},
			want: KindFile,
		},
		{
			name: "rule6: OCI 1.1 empty config with a titled layer",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.OCIEmptyConfigMediaType},
				Layers: []ocispec.Descriptor{titled("text/plain")},
			},
			want: KindFile,
		},
		{
			name: "rule6: totally empty config field with a titled layer",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Layers: []ocispec.Descriptor{titled("text/plain")},
			},
			want: KindFile,
		},
		{
			name: "rule7: legacy hauler file://",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.FileLocalConfigMediaType},
			},
			want: KindFile,
		},
		{
			name: "rule7: legacy hauler http://",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.FileHttpConfigMediaType},
			},
			want: KindFile,
		},
		{
			name: "rule7: legacy hauler directory:// -- pre-existing resolveCtype bug fix",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: consts.FileDirectoryConfigMediaType},
			},
			want: KindFile,
		},
		{
			name: "rule7.5: unrecognized config media type WITH a titled layer still classifies as File",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: "application/vnd.unknown.config.v1+json"},
				Layers: []ocispec.Descriptor{titled("application/vnd.content.hauler.file.layer.v1")},
			},
			want: KindFile,
		},
		{
			name: "rule8: unrecognized config media type, no titled layers",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m: &ocispec.Manifest{
				Config: ocispec.Descriptor{MediaType: "application/vnd.example.something.v1+json"},
			},
			want: KindUnknown,
		},
		{
			name: "nil manifest with a non-index descriptor is Unknown, not a panic",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest},
			m:    nil,
			want: KindUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.desc, tt.m)
			if got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}
