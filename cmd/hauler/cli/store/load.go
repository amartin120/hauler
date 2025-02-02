package store

import (
	"context"
	"os"

	"hauler.dev/go/hauler/internal/flags"
	"hauler.dev/go/hauler/pkg/archives"
	"hauler.dev/go/hauler/pkg/consts"
	"hauler.dev/go/hauler/pkg/content"
	"hauler.dev/go/hauler/pkg/log"
	"hauler.dev/go/hauler/pkg/store"
)

// LoadCmd
// TODO: Just use mholt/archiver for now, even though we don't need most of it
func LoadCmd(ctx context.Context, o *flags.LoadOpts, archiveRefs ...string) error {
	l := log.FromContext(ctx)

	storeDir := o.StoreDir

	if storeDir == "" {
		storeDir = os.Getenv(consts.HaulerStoreDir)
	}

	if storeDir == "" {
		storeDir = consts.DefaultStoreName
	}

	for _, archiveRef := range archiveRefs {
		l.Infof("loading content from [%s] to [%s]", archiveRef, storeDir)
		err := unarchiveLayoutTo(ctx, archiveRef, storeDir, o.TempOverride)
		if err != nil {
			return err
		}
	}

	return nil
}

// unarchiveLayoutTo accepts an archived oci layout and extracts the contents to an existing oci layout, preserving the index
func unarchiveLayoutTo(ctx context.Context, archivePath string, dest string, tempOverride string) error {
	l := log.FromContext(ctx)

	if tempOverride == "" {
		tempOverride = os.Getenv(consts.HaulerTempDir)
	}

	tempDir, err := os.MkdirTemp(tempOverride, consts.DefaultHaulerTempDirName)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	l.Debugf("using temporary directory at [%s]", tempDir)

	if err := archives.Unarchive(ctx, archivePath, tempDir); err != nil {
		return err
	}

	s, err := store.NewLayout(tempDir)
	if err != nil {
		return err
	}

	ts, err := content.NewOCI(dest)
	if err != nil {
		return err
	}

	_, err = s.CopyAll(ctx, ts, nil)
	return err
}
