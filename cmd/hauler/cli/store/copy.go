package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/internal/flags"
	"hauler.dev/go/hauler/v2/internal/mapper"
	"hauler.dev/go/hauler/v2/pkg/artifacts"
	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/content"
	"hauler.dev/go/hauler/v2/pkg/log"
	"hauler.dev/go/hauler/v2/pkg/retry"
	"hauler.dev/go/hauler/v2/pkg/store"
)

func CopyCmd(ctx context.Context, o *flags.CopyOpts, s *store.Layout, targetRef string, ro *flags.CliRootOpts) error {
	l := log.FromContext(ctx)

	if o.Username != "" || o.Password != "" {
		return fmt.Errorf("--username/--password have been deprecated, please use 'hauler login'")
	}

	if !s.IndexExists() {
		return fmt.Errorf("store index not found: run 'hauler store add/sync/load' first")
	}

	ignoreErrors := flags.ShouldIgnoreErrors(ro)

	components := strings.SplitN(targetRef, "://", 2)
	switch components[0] {
	case "directory", "dir":
		l.Debugf("identified [directory] target reference of [%s]", components[1])

		// Create destination directory if it doesn't exist
		if err := os.MkdirAll(components[1], 0755); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}

		// For directory targets, extract files and charts (not images, and not
		// cosign sig/att/sbom/referrer artifacts -- registry-only metadata that
		// isn't extractable as a file or chart).
		err := s.Walk(func(reference string, desc ocispec.Descriptor) error {
			// Handle different media types
			switch desc.MediaType {
			case ocispec.MediaTypeImageIndex, consts.DockerManifestListSchema2:
				// Multi-platform index - process each child manifest
				rc, err := s.Fetch(ctx, desc)
				if err != nil {
					l.Warnf("failed to fetch index [%s]: %v", reference, err)
					return nil
				}

				var index ocispec.Index
				if err := json.NewDecoder(rc).Decode(&index); err != nil {
					if cerr := rc.Close(); cerr != nil {
						l.Warnf("failed to close index reader for [%s]: %v", reference, cerr)
					}
					l.Warnf("failed to decode index for [%s]: %v", reference, err)
					return nil
				}

				// Close rc immediately after decoding - we're done reading from it
				if cerr := rc.Close(); cerr != nil {
					l.Warnf("failed to close index reader for [%s]: %v", reference, cerr)
				}

				// Process each manifest in the index
				for _, manifestDesc := range index.Manifests {
					manifestRC, err := s.Fetch(ctx, manifestDesc)
					if err != nil {
						l.Warnf("failed to fetch child manifest: %v", err)
						continue
					}

					var m ocispec.Manifest
					if err := json.NewDecoder(manifestRC).Decode(&m); err != nil {
						manifestRC.Close()
						l.Warnf("failed to decode child manifest: %v", err)
						continue
					}
					manifestRC.Close()

					// Extract only files and charts -- classify from the child's own
					// content, not from which subcommand originally wrote it.
					if k := artifacts.Classify(manifestDesc, &m); k != artifacts.KindChart && k != artifacts.KindFile {
						l.Debugf("skipping non-file/chart child manifest (%s) in index [%s]", k, reference)
						continue
					}

					// Create mapper and extract. reference is the parent index's
					// ref -- there is no more specific per-child ref available,
					// since index children aren't independently indexed.
					mapperStore, err := mapper.FromManifest(m, components[1], reference)
					if err != nil {
						l.Warnf("failed to create mapper for child: %v", err)
						continue
					}

					// Note: We can't call s.Copy with manifestDesc because it's not in the nameMap
					// Instead, we need to manually push through the mapper
					if err := extractManifestContent(ctx, s, manifestDesc, m, mapperStore); err != nil {
						l.Warnf("failed to extract child: %v", err)
						continue
					}

					l.Debugf("extracted child manifest from index [%s]", reference)
				}

			case ocispec.MediaTypeImageManifest, consts.DockerManifestSchema2:
				// Single-platform manifest
				rc, err := s.Fetch(ctx, desc)
				if err != nil {
					l.Warnf("failed to fetch [%s]: %v", reference, err)
					return nil
				}

				var m ocispec.Manifest
				if err := json.NewDecoder(rc).Decode(&m); err != nil {
					rc.Close()
					l.Warnf("failed to decode manifest for [%s]: %v", reference, err)
					return nil
				}

				// Extract only files and charts for directory targets -- classify from
				// the manifest's own content (also catches sig/att/sbom/referrer
				// manifests, which reuse a standard image config and would otherwise
				// slip past a config-media-type-only check).
				if k := artifacts.Classify(desc, &m); k != artifacts.KindChart && k != artifacts.KindFile {
					rc.Close()
					l.Debugf("skipping non-file/chart [%s] (%s) for directory target", reference, k)
					return nil
				}

				// Create a mapper store based on the manifest type
				mapperStore, err := mapper.FromManifest(m, components[1], reference)
				if err != nil {
					rc.Close()
					l.Warnf("failed to create mapper for [%s]: %v", reference, err)
					return nil
				}

				// Copy/extract the content
				_, err = s.Copy(ctx, reference, mapperStore, "")
				if err != nil {
					rc.Close()
					l.Warnf("failed to extract [%s]: %v", reference, err)
					return nil
				}
				rc.Close()

				l.Debugf("extracted [%s] to directory", reference)

			default:
				l.Debugf("skipping unsupported media type [%s] for [%s]", desc.MediaType, reference)
			}

			return nil
		})
		if err != nil {
			return err
		}

	case "registry", "reg", "oci":
		l.Debugf("identified [registry] target reference of [%s]", components[1])
		registryOpts := content.RegistryOptions{
			PlainHTTP: o.PlainHTTP,
			Insecure:  o.Insecure,
		}
		// Shared across every per-artifact RegistryTarget below to keep connections pooled.
		registryClient := content.NewRegistryHTTPClient(components[1], registryOpts)

		var fatalErr error
		err := s.Walk(func(reference string, desc ocispec.Descriptor) error {
			if fatalErr != nil {
				return nil
			}
			baseRef := desc.Annotations[ocispec.AnnotationRefName]
			if baseRef == "" {
				return nil
			} else if regexp.MustCompile(consts.FileExcludePattern).MatchString(baseRef) {
				l.Warnf("skipping file artifact [%s]: invalid filename for registry serve", baseRef)
				return nil
			}
			// --only matches the *subject* an artifact is about: for a real image/index
			// that's its own ref (io.containerd.image.name is always set, defaulting to
			// the registry-qualified form of baseRef), but for a sig/att/sbom/referrer --
			// whose own ref.name is now a derived, per-artifact value like
			// "repo:sha256-<hex>.sig" -- it's the base image recorded in
			// io.containerd.image.name instead. baseRef is always a substring of a real
			// image's io.containerd.image.name, so this preserves every match a filter
			// against baseRef alone used to produce. The fallback to baseRef is the
			// deterministic path for chart and file artifacts: store.Layout.AddArtifact
			// never sets io.containerd.image.name at all -- only writeImage/writeIndex
			// (images, indexes, sigs, atts, sboms, referrers) do.
			onlyMatch := desc.Annotations[consts.ContainerdImageNameKey]
			if onlyMatch == "" {
				onlyMatch = baseRef
			}
			if o.Only != "" && !strings.Contains(onlyMatch, o.Only) {
				l.Debugf("skipping [%s] (not matching --only filter)", baseRef)
				return nil
			}

			// Every descriptor's own ref.name is already its true, unique ref -- sig/att/
			// sbom manifests carry their own cosign tag and referrers their own digest
			// form, so no push-time derivation from a parent image is needed.
			destRef := baseRef

			toRef, err := content.RewriteRefToRegistry(destRef, components[1])
			if err != nil {
				if !ignoreErrors {
					fatalErr = fmt.Errorf("rewriting ref [%s]: %w", baseRef, err)
					return nil
				}
				l.Warnf("failed to rewrite ref [%s]: %v", baseRef, err)
				return nil
			}
			l.Infof("%s", destRef)
			// A fresh target per artifact gives each push its own in-memory status
			// tracker. Containerd's tracker keys blobs by digest only (not repo),
			// so a shared tracker would mark shared blobs as "already exists" after
			// the first image, skipping the per-repository blob link creation that
			// Docker Distribution requires for manifest validation.
			target := content.NewRegistryTarget(components[1], registryOpts, registryClient)
			var pushed ocispec.Descriptor
			if err := retry.Operation(ctx, o.StoreRootOpts, ro, func() error {
				var copyErr error
				pushed, copyErr = s.Copy(ctx, reference, target, toRef)
				return copyErr
			}); err != nil {
				if !ignoreErrors {
					fatalErr = err
				}
				return nil
			}
			l.Infof("%s: digest: %s size: %d", toRef, pushed.Digest, pushed.Size)
			return nil
		})
		if fatalErr != nil {
			return fatalErr
		}
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("detecting protocol from [%s]", targetRef)
	}

	l.Infof("copied artifacts to [%s]", components[1])
	return nil
}

// extractManifestContent extracts a manifest's layers through a mapper target
// This is used for child manifests in indexes that aren't in the store's nameMap
func extractManifestContent(ctx context.Context, s *store.Layout, desc ocispec.Descriptor, m ocispec.Manifest, target content.Target) error {
	// Get a pusher from the target
	pusher, err := target.Pusher(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to get pusher: %w", err)
	}

	// Copy config blob
	if err := copyBlobDescriptor(ctx, s, m.Config, pusher); err != nil {
		return fmt.Errorf("failed to copy config: %w", err)
	}

	// Copy each layer blob
	for _, layer := range m.Layers {
		if err := copyBlobDescriptor(ctx, s, layer, pusher); err != nil {
			return fmt.Errorf("failed to copy layer: %w", err)
		}
	}

	// Copy the manifest itself
	if err := copyBlobDescriptor(ctx, s, desc, pusher); err != nil {
		return fmt.Errorf("failed to copy manifest: %w", err)
	}

	return nil
}

// copyBlobDescriptor copies a single descriptor blob from the store to a pusher
func copyBlobDescriptor(ctx context.Context, s *store.Layout, desc ocispec.Descriptor, pusher remotes.Pusher) (err error) {
	// Fetch the content from the store
	rc, err := s.OCI.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to fetch blob: %w", err)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close reader: %w", closeErr)
		}
	}()

	// Get a writer from the pusher
	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil // content already present on remote
		}
		return fmt.Errorf("failed to push: %w", err)
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close writer: %w", closeErr)
		}
	}()

	// Copy the content
	n, err := io.Copy(writer, rc)
	if err != nil {
		return fmt.Errorf("failed to copy content: %w", err)
	}

	// Commit the written content
	if err := writer.Commit(ctx, n, desc.Digest); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	return nil
}
