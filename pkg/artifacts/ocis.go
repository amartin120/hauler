package artifacts

import "github.com/google/go-containerregistry/pkg/v1"

// OCI is what hauler constructs locally -- a file fetched from disk or a URL,
// a chart tarball resolved by Helm -- so it can describe itself as an OCI
// manifest and reach the store through Layout.AddArtifact.
//
// The dividing line it draws is construction, not content type: a container
// image arrives from a registry already as a v1.Image and goes through
// Layout.AddImage instead, so it never needs an adapter. That is why the only
// implementors are file.File and chart.Chart. Deliberately narrower than
// v1.Image, which would force these to synthesize a container image
// ConfigFile they do not have.
//
// Once written, nothing downstream distinguishes them -- artifacts.Classify
// derives content type from the stored manifest's own bytes.
type OCI interface {
	MediaType() string

	Manifest() (*v1.Manifest, error)

	RawConfig() ([]byte, error)

	Layers() ([]v1.Layer, error)
}
