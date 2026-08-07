package artifacts

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"

	"hauler.dev/go/hauler/v2/pkg/consts"
)

// Kind is the content type of an OCI manifest, derived from the manifest's own
// bytes rather than from which hauler subcommand wrote it.
type Kind string

const (
	KindIndex       Kind = "Index"
	KindChart       Kind = "Chart"
	KindImage       Kind = "Image"
	KindFile        Kind = "File"
	KindSignature   Kind = "Signature"
	KindAttestation Kind = "Attestation"
	KindSBOM        Kind = "SBOM"
	KindReferrer    Kind = "Referrer"
	KindUnknown     Kind = "Unknown"
)

// cosignArtifactTypes maps every manifest-level artifactType a cosign v3
// referrer (subject != nil) is known to write to its Kind. Sourced from the
// vendored github.com/sigstore/cosign/v3@v3.1.2 write paths:
//   - WriteSignaturesExperimentalOCI (pkg/oci/remote/write.go) -> sig artifactType
//   - WriteAttestationsReferrer (pkg/oci/remote/write.go) -> ctypes.IntotoPayloadType
//   - WriteAttestationNewBundleFormat (pkg/oci/remote/write.go) -> bundle.BundleV03MediaType,
//     i.e. consts.SigstoreBundleMediaType (cosign has no signature equivalent of this
//     writer as of v3.1.2 -- VerifyImageSignatures errors "bundle support for image
//     signatures is not yet implemented" when NewBundleFormat is set)
//   - `cosign attach sbom` --oci-experimental (cmd/cosign/cli/attach/sbom.go) -> sbom artifactType
var cosignArtifactTypes = map[string]Kind{
	consts.CosignReferrerSigArtifactType:  KindSignature,
	ctypes.SimpleSigningMediaType:         KindSignature,
	ctypes.IntotoPayloadType:              KindAttestation,
	ctypes.DssePayloadType:                KindAttestation,
	consts.CosignReferrerAttArtifactType:  KindAttestation,
	consts.SigstoreBundleMediaType:        KindAttestation,
	consts.CosignReferrerSBOMArtifactType: KindSBOM,
	ctypes.SPDXMediaType:                  KindSBOM,
	ctypes.SPDXJSONMediaType:              KindSBOM,
	ctypes.CycloneDXXMLMediaType:          KindSBOM,
	ctypes.CycloneDXJSONMediaType:         KindSBOM,
	ctypes.SyftMediaType:                  KindSBOM,
}

// isIndexMediaType reports whether mt names an OCI or Docker manifest list.
func isIndexMediaType(mt string) bool {
	return mt == ocispec.MediaTypeImageIndex || mt == consts.DockerManifestListSchema2
}

// Classify derives an OCI manifest's content type from the manifest bytes
// themselves (desc's own media type, plus m's config/layers/subject), not
// from any hauler-assigned "kind" annotation -- identical bytes classify
// identically regardless of which subcommand wrote them. m is unused (and
// may be nil) when desc.MediaType alone already answers the question, i.e.
// for an index.
//
// Cosign checks (rules 2-3) run before the image check (rule 5) because a
// cosign v2 tag-convention sig/att/sbom manifest carries a perfectly standard
// image config -- without this ordering every legacy signature would
// misclassify as a container image.
func Classify(desc ocispec.Descriptor, m *ocispec.Manifest) Kind {
	// Rule 1: index.
	if isIndexMediaType(desc.MediaType) {
		return KindIndex
	}

	if m == nil {
		return KindUnknown
	}

	// Rule 2: OCI 1.1 referrer (subject present) -- refine by artifactType.
	if m.Subject != nil {
		if kind, ok := cosignArtifactTypes[m.ArtifactType]; ok {
			return kind
		}
		return KindReferrer
	}

	// Rule 3: cosign v2 tag convention (no subject) -- refine by layer media type.
	for _, layer := range m.Layers {
		if kind, ok := cosignArtifactTypes[layer.MediaType]; ok {
			return kind
		}
	}

	// Rule 4: Helm chart.
	if m.Config.MediaType == consts.ChartConfigMediaType {
		return KindChart
	}

	// Rule 5: standard image config, with the rke2-binary carve-out --
	// mirrors internal/mapper.FromManifest's config-media-type switch
	// verbatim: any layer carrying a title annotation means this is a file
	// artifact reusing an image config, not a real container image.
	if m.Config.MediaType == consts.DockerConfigJSON || m.Config.MediaType == ocispec.MediaTypeImageConfig {
		for _, layer := range m.Layers {
			if _, ok := layer.Annotations[ocispec.AnnotationTitle]; ok {
				return KindFile
			}
		}
		return KindImage
	}

	// Rule 6: OCI 1.1 empty config with at least one titled layer -- the generic
	// artifact shape `oras push` and equivalents produce.
	if m.Config.MediaType == consts.OCIEmptyConfigMediaType || m.Config.MediaType == "" {
		for _, layer := range m.Layers {
			if _, ok := layer.Annotations[ocispec.AnnotationTitle]; ok {
				return KindFile
			}
		}
	}

	// Rule 7: legacy hauler file config media types.
	switch m.Config.MediaType {
	case consts.FileLocalConfigMediaType, consts.FileDirectoryConfigMediaType, consts.FileHttpConfigMediaType:
		return KindFile
	}

	// Rule 7.5: last resort before giving up -- a titled layer under any other
	// config type (e.g. a wasm or arbitrary OCI artifact config hauler has no
	// name for) is still a strong enough file signal to act on. Generalizes
	// mapper.go's pre-Classify fallback, which checked title unconditionally
	// once the config media type matched nothing else.
	for _, layer := range m.Layers {
		if _, ok := layer.Annotations[ocispec.AnnotationTitle]; ok {
			return KindFile
		}
	}

	// Rule 8: unrecognized.
	return KindUnknown
}
