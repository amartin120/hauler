package consts

import "fmt"

const (
	// container media types
	OCIManifestSchema1        = "application/vnd.oci.image.manifest.v1+json"
	DockerManifestSchema2     = "application/vnd.docker.distribution.manifest.v2+json"
	DockerManifestListSchema2 = "application/vnd.docker.distribution.manifest.list.v2+json"
	OCIImageIndexSchema       = "application/vnd.oci.image.index.v1+json"
	DockerConfigJSON          = "application/vnd.docker.container.image.v1+json"
	DockerLayer               = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	DockerForeignLayer        = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	DockerUncompressedLayer   = "application/vnd.docker.image.rootfs.diff.tar"
	OCILayer                  = "application/vnd.oci.image.layer.v1.tar+gzip"
	OCIArtifact               = "application/vnd.oci.empty.v1+json"

	// helm chart media types
	ChartConfigMediaType = "application/vnd.cncf.helm.config.v1+json"
	ChartLayerMediaType  = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	ProvLayerMediaType   = "application/vnd.cncf.helm.chart.provenance.v1.prov"

	// file media types
	//
	// FileLayerMediaType and the three File*ConfigMediaType constants below are
	// read-only legacy: a new file artifact never writes them (see
	// pkg/artifacts/file's compute(), which now emits a real per-source layer
	// media type and the fixed OCI empty config). They are retained solely so
	// artifacts.Classify and internal/mapper.Files() can still recognize an
	// old-format manifest on read.
	FileLayerMediaType           = "application/vnd.content.hauler.file.layer.v1"
	FileLocalConfigMediaType     = "application/vnd.content.hauler.file.local.config.v1+json"
	FileDirectoryConfigMediaType = "application/vnd.content.hauler.file.directory.config.v1+json"
	FileHttpConfigMediaType      = "application/vnd.content.hauler.file.http.config.v1+json"

	// FileArtifactType is the manifest-level artifactType a file artifact now
	// writes. Sourced from oras.land/oras-go/v2's exported MediaTypeUnknownArtifact
	// constant (pack.go) -- hardcoded here rather than imported, matching the
	// sourcing-comment convention already used below for the cosign referrer
	// artifactType constants, since oras-go is only an indirect dependency.
	FileArtifactType = "application/vnd.unknown.artifact.v1"

	// wasm media types
	WasmArtifactLayerMediaType = "application/vnd.wasm.content.layer.v1+wasm"
	WasmConfigMediaType        = "application/vnd.wasm.config.v1+json"

	// unknown media types
	UnknownManifest = "application/vnd.hauler.cattle.io.unknown.v1+json"
	UnknownLayer    = "application/vnd.content.hauler.unknown.layer"
	Unknown         = "unknown"

	// vendor prefixes
	OCIVendorPrefix    = "vnd.oci"
	DockerVendorPrefix = "vnd.docker"
	HaulerVendorPrefix = "vnd.hauler"

	// annotation keys
	//
	// ContainerdImageNameKey ("io.containerd.image.name") holds a full ref with
	// registry. On a real image/index descriptor it is that descriptor's own name
	// (registry-prepended). On a sig/att/sbom/referrer descriptor it is instead a
	// deliberate subject pointer: the *base* image's full ref, not the artifact's
	// own ref -- which now lives, uniquely, in org.opencontainers.image.ref.name.
	// This is not a compatibility wart; it is what lets `store info`/`store remove`
	// group a signature under its image without decoding the manifest's `subject`
	// field, and it is exactly the invariant content.saveIndexLocked's sort relies
	// on (registry-stripped ContainerdImageNameKey == ref.name iff the descriptor
	// is a real image/index).
	ContainerdImageNameKey = "io.containerd.image.name"
	// KindAnnotationName and the KindAnnotation* values below are read-only
	// legacy: new stores no longer write a "kind" annotation at all -- content
	// type is derived from manifest bytes at read time (see pkg/artifacts.Classify).
	// They are retained solely so loadIndexLocked can recognize and migrate an
	// old-format index.json's entries on load; consts.NormalizeLegacyKind
	// translates the even-older dev.cosignproject.cosign/... values first.
	KindAnnotationName  = "kind"
	KindAnnotationImage = "dev.hauler/image"
	KindAnnotationIndex = "dev.hauler/imageIndex"
	KindAnnotationSigs  = "dev.hauler/sigs"
	KindAnnotationAtts  = "dev.hauler/atts"
	KindAnnotationSboms = "dev.hauler/sboms"
	// KindAnnotationReferrers was the kind prefix for OCI 1.1 referrer manifests
	// (cosign v3 new-bundle-format) in a legacy store: each referrer's kind had
	// the referrer manifest digest appended (e.g. "dev.hauler/referrers/sha256hex")
	// since the digest was the only thing disambiguating multiple referrers that
	// otherwise all shared the base image's ref.name.
	KindAnnotationReferrers = "dev.hauler/referrers"

	// Sigstore / OCI 1.1 artifact media types used by cosign v3 new-bundle-format.
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	OCIEmptyConfigMediaType = "application/vnd.oci.empty.v1+json"

	// annotations used by all artifacts
	AnnotationTargetStore = "hauler.dev/store"
	AnnotationRetries     = "hauler.dev/retries"

	// annotations used by images
	// Cosign v3's "experimental OCI 1.1" referrer artifactType convention --
	// github.com/sigstore/cosign/v3/internal/pkg/oci/remote.ArtifactType computes
	// these as fmt.Sprintf("application/vnd.dev.cosign.artifact.%s.v1+json", attName)
	// for "sig"/"att"/"sbom"; that helper is unexported, so the three results are
	// hardcoded here. WriteSignaturesExperimentalOCI (pkg/oci/remote/write.go) sets
	// the sig value as a referrer manifest's artifactType; `cosign attach sbom`
	// (cmd/cosign/cli/attach/sbom.go) sets the sbom value the same way.
	CosignReferrerSigArtifactType  = "application/vnd.dev.cosign.artifact.sig.v1+json"
	CosignReferrerAttArtifactType  = "application/vnd.dev.cosign.artifact.att.v1+json"
	CosignReferrerSBOMArtifactType = "application/vnd.dev.cosign.artifact.sbom.v1+json"

	ImageAnnotationKey           = "hauler.dev/key"
	ImageAnnotationPlatform      = "hauler.dev/platform"
	ImageAnnotationRegistry      = "hauler.dev/registry"
	ImageAnnotationTlog          = "hauler.dev/use-tlog-verify"
	ImageAnnotationRewrite       = "hauler.dev/rewrite"
	ImageAnnotationExcludeExtras = "hauler.dev/exclude-extras"
	ImageRefKey                  = "org.opencontainers.image.ref.name"

	// cosign keyless validation options
	ImageAnnotationCertIdentity                 = "hauler.dev/certificate-identity"
	ImageAnnotationCertIdentityRegexp           = "hauler.dev/certificate-identity-regexp"
	ImageAnnotationCertOidcIssuer               = "hauler.dev/certificate-oidc-issuer"
	ImageAnnotationCertOidcIssuerRegexp         = "hauler.dev/certificate-oidc-issuer-regexp"
	ImageAnnotationCertGithubWorkflowRepository = "hauler.dev/certificate-github-workflow-repository"

	// TLS options for verifying the image signature.  If not specified, the default system CA bundle will be used.
	ImageAnnotationCaFile                = "hauler.dev/ca-file"
	ImageAnnotationInsecureSkipTLSVerify = "hauler.dev/insecure-skip-tls-verify"

	// content kinds
	ImagesContentKind = "Images"
	ChartsContentKind = "Charts"
	FilesContentKind  = "Files"
	// DriverContentKind = "Driver"

	// content groups
	ContentGroup    = "content.hauler.cattle.io"
	CollectionGroup = "collection.hauler.cattle.io"

	// environment variables
	HaulerDir             = "HAULER_DIR"
	HaulerTempDir         = "HAULER_TEMP_DIR"
	HaulerStoreDir        = "HAULER_STORE_DIR"
	HaulerIgnoreErrors    = "HAULER_IGNORE_ERRORS"
	HaulerRetries         = "HAULER_RETRIES"
	HaulerConcurrency     = "HAULER_CONCURRENCY"
	HaulerBlobConcurrency = "HAULER_BLOB_CONCURRENCY"
	HaulerLogLevel        = "HAULER_LOG_LEVEL"
	HaulerAuditLevel      = "HAULER_AUDIT_LEVEL"

	CaFile                = "CA_FILE"
	InsecureSkipTLSVerify = "INSECURE_SKIP_TLS_VERIFY"

	// container files and directories
	ImageManifestFile = "manifest.json"
	ImageConfigFile   = "config.json"

	// other constraints
	CarbideRegistry           = "rgcrprod.azurecr.us"
	DefaultNamespace          = "hauler"
	DefaultTag                = "latest"
	DefaultStoreName          = "store"
	DefaultHaulerDirName      = ".hauler"
	DefaultHaulerTempDirName  = "hauler"
	DefaultRegistryRootDir    = "registry"
	DefaultRegistryPort       = 5000
	DefaultFileserverRootDir  = "fileserver"
	DefaultFileserverPort     = 8080
	DefaultFileserverTimeout  = 60
	DefaultHaulerArchiveName  = "haul.tar.zst"
	DefaultHaulerManifestName = "hauler-manifest.yaml"
	DefaultStoreMetadataName  = "store.json"
	DefaultStoreInventoryName = "stores.json"
	DefaultRetries            = 3
	RetriesInterval           = 5
	DefaultConcurrency        = 5
	DefaultBlobConcurrency    = 16
	CustomTimeFormat          = "2006-01-02 15:04:05"
)

var FileExcludePattern = fmt.Sprintf(`^%s/[.\-_]`, DefaultNamespace)
