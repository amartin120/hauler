package mapper

import (
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/artifacts"
	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/content"
)

type Fn func(desc ocispec.Descriptor) (string, error)

// FromManifest returns the appropriate content store for extracting manifest's
// layers to disk, routed by artifacts.Classify's content-derived Kind rather
// than by which subcommand originally wrote the manifest.
func FromManifest(manifest ocispec.Manifest, root string) (content.Target, error) {
	switch artifacts.Classify(ocispec.Descriptor{MediaType: string(manifest.MediaType)}, &manifest) {
	case artifacts.KindChart:
		return NewMapperFileStore(root, Chart())
	case artifacts.KindFile:
		return NewMapperFileStore(root, Files())
	case artifacts.KindImage:
		return NewMapperFileStore(root, Images())
	default:
		return NewMapperFileStore(root, Default())
	}
}

func Images() map[string]Fn {
	m := make(map[string]Fn)

	manifestMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		return consts.ImageManifestFile, nil
	})

	for _, l := range []string{consts.DockerManifestSchema2, consts.DockerManifestListSchema2, consts.OCIManifestSchema1} {
		m[l] = manifestMapperFn
	}

	layerMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		return fmt.Sprintf("%s.tar.gz", desc.Digest.String()), nil
	})

	for _, l := range []string{consts.OCILayer, consts.DockerLayer} {
		m[l] = layerMapperFn
	}

	configMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		return consts.ImageConfigFile, nil
	})

	for _, l := range []string{consts.DockerConfigJSON} {
		m[l] = configMapperFn
	}

	return m
}

func Chart() map[string]Fn {
	m := make(map[string]Fn)

	chartMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		f := "chart.tar.gz"
		if _, ok := desc.Annotations[ocispec.AnnotationTitle]; ok {
			f = desc.Annotations[ocispec.AnnotationTitle]
		}
		return f, nil
	})

	provMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		return "prov.json", nil
	})

	m[consts.ChartLayerMediaType] = chartMapperFn
	m[consts.ProvLayerMediaType] = provMapperFn
	return m
}

// DefaultCatchAll is the sentinel key used in a mapper map to match any media type
// not explicitly registered. Push checks for this key as a fallback.
const DefaultCatchAll = ""

// Default returns a catch-all mapper that extracts any layer blob using its title
// annotation as the filename, falling back to a digest-based name. Used when the
// manifest config media type is not a known hauler type.
func Default() map[string]Fn {
	m := make(map[string]Fn)
	m[DefaultCatchAll] = Fn(func(desc ocispec.Descriptor) (string, error) {
		if title, ok := desc.Annotations[ocispec.AnnotationTitle]; ok {
			return title, nil
		}
		return fmt.Sprintf("%s.bin", desc.Digest.String()), nil
	})
	return m
}

func Files() map[string]Fn {
	m := make(map[string]Fn)

	fileMapperFn := Fn(func(desc ocispec.Descriptor) (string, error) {
		// Use the title annotation to determine the filename
		if title, ok := desc.Annotations[ocispec.AnnotationTitle]; ok {
			return title, nil
		}
		// Fallback to digest-based filename if no title
		return fmt.Sprintf("%s.file", desc.Digest.String()), nil
	})

	// Match the media type that's actually used in the manifest
	// (set by getter.LayerFrom in pkg/getter/getter.go)
	m[consts.FileLayerMediaType] = fileMapperFn
	m[consts.OCILayer] = fileMapperFn                          // Also handle standard OCI layers that have title annotation
	m["application/vnd.oci.image.layer.v1.tar"] = fileMapperFn // And the tar variant

	// Catch-all for OCI artifacts that use custom layer media types (e.g. rke2-binary).
	// Write the blob if it carries an AnnotationTitle... silently discard everything else
	// (config blobs, metadata) by returning an empty filename.
	m[DefaultCatchAll] = Fn(func(desc ocispec.Descriptor) (string, error) {
		if title, ok := desc.Annotations[ocispec.AnnotationTitle]; ok {
			return title, nil
		}
		return "", nil // No title → discard (config blob or unrecognised metadata)
	})

	return m
}
