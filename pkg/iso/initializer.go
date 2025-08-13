package iso

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"

	"go.uber.org/zap"
)

type IsoDownloader interface {
	Download(context.Context, io.WriteSeeker) error
}

type IsoInitializer struct {
	downloader IsoDownloader
}

func NewIsoInitializer(downloader IsoDownloader) *IsoInitializer {
	return &IsoInitializer{downloader: downloader}
}

// Initialize always attempts to download a new ISO file.
// If the download fails, the existing ISO file (if any) is kept unchanged.
// If the download succeeds, the new ISO replaces the existing one.
func (i *IsoInitializer) Initialize(ctx context.Context, targetIsoFile string, targetIsoSha256 string) error {
	tempIsoFile, err := os.CreateTemp(path.Dir(targetIsoFile), "iso-image")
	if err != nil {
		return fmt.Errorf("failed to create temporary iso file: %w", err)
	}

	defer func() {
		_ = os.Remove(tempIsoFile.Name())
	}()

	if err := i.downloader.Download(ctx, tempIsoFile); err != nil {
		_ = tempIsoFile.Close()
		return fmt.Errorf("failed to write the image to the temporary iso file: %w", err)
	}
	_ = tempIsoFile.Close()

	if err := i.verifyIso(tempIsoFile.Name(), targetIsoSha256); err != nil {
		return fmt.Errorf("downloaded ISO failed verification: %w", err)
	}

	zap.S().Infof("replacing old ISO %s with new ISO %s", targetIsoFile, tempIsoFile.Name())

	return os.Rename(tempIsoFile.Name(), targetIsoFile)
}

func (i *IsoInitializer) verifyIso(targetIsoFile, targetIsoSha256 string) error {
	if _, err := os.Stat(targetIsoFile); err != nil {
		return err
	}

	// compute sha256
	reader, err := os.Open(targetIsoFile)
	if err != nil {
		return err
	}
	defer reader.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return err
	}

	computedSha256 := fmt.Sprintf("%x", hasher.Sum(nil))

	if targetIsoSha256 != computedSha256 {
		return fmt.Errorf("sha256 sums dont't match. computed %s wanted %s", computedSha256, targetIsoSha256)
	}

	return nil
}
