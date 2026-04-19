package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/kubev2v/migration-planner/internal/auth"
	"github.com/kubev2v/migration-planner/internal/store"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/pkg/image"
	"github.com/kubev2v/migration-planner/pkg/metrics"
	"github.com/kubev2v/migration-planner/pkg/version"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultImageTTL = 30 * time.Minute
)

type ImageSvc struct {
	store         store.Store
	tempImagesDir string
	cleaner       *image.ImageCleaner
	mu            sync.Mutex
}

func NewImageSvc(s store.Store, tempImagesDir string, cleanInterval time.Duration) *ImageSvc {
	cleaner := image.NewImageCleaner(cleanInterval)
	cleaner.Start()

	return &ImageSvc{
		store:         s,
		tempImagesDir: tempImagesDir,
		cleaner:       cleaner,
	}
}

func (i *ImageSvc) GenerateOVA(ctx context.Context, sourceId string) (string, string, error) {
	source, err := i.getSource(ctx, sourceId)
	if err != nil {
		return "", "", err
	}

	b := image.NewImageBuilder(source.ImageInfra.SourceID).WithImageInfra(source.ImageInfra)
	token, err := i.generateAgentToken(ctx, source)
	if err != nil {
		return "", "", err
	}
	b.WithAgentToken(token)

	etag, err := b.Etag()
	if err != nil {
		return "", "", err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	tmpfile := filepath.Join(i.tempImagesDir, fmt.Sprintf("%s.ova", etag))
	if _, err = os.Stat(tmpfile); err == nil {
		return tmpfile, etag, nil
	}

	if !os.IsNotExist(err) {
		return "", "", err
	}

	f, err := os.Create(tmpfile)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = f.Close()
	}()

	if err := b.Generate(f); err != nil {
		_ = os.Remove(tmpfile)
		metrics.IncreaseOvaDownloadsTotalMetric("failed")
		return "", "", err
	}

	metrics.IncreaseOvaDownloadsTotalMetric("successful")
	i.cleaner.Register(tmpfile, defaultImageTTL)

	return tmpfile, etag, nil
}

func (i *ImageSvc) ValidateToken(token string) error {
	parsedToken, err := jwt.Parse(token, i.getSourceKey)
	if err != nil {
		return fmt.Errorf("unauthorized: %v", err)
	}

	return parsedToken.Claims.Valid()
}

func (i *ImageSvc) Validate(ctx context.Context, sourceId string) error {
	if _, err := i.getSource(ctx, sourceId); err != nil {
		return err
	}

	return nil
}

func (i *ImageSvc) UpdateAgentVersion(sourceId string) {
	versionInfo := version.Get()
	if !version.IsValidAgentVersion(versionInfo.AgentVersionName) {
		zap.S().Named("image_service").Warnw("agent version not valid, skipping storage", "source_id", sourceId, "agent_version_name", versionInfo.AgentVersionName, "agent_git_commit", versionInfo.AgentGitCommit)
	} else {
		// Use detached context to ensure version persists even if client disconnects
		persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Use atomic update to prevent race conditions during concurrent downloads
		if err := i.store.ImageInfra().UpdateAgentVersion(persistCtx, sourceId, versionInfo.AgentVersionName); err != nil {
			zap.S().Named("image_service").Warnw("failed to update agent version", "error", err, "source_id", sourceId, "agent_version", versionInfo.AgentVersionName)
		} else {
			zap.S().Named("image_service").Infow("stored agent version", "source_id", sourceId, "agent_version", versionInfo.AgentVersionName)
		}
	}
}

func (i *ImageSvc) Stop() {
	i.cleaner.Stop()
}

func (i *ImageSvc) getSource(ctx context.Context, sourceId string) (*model.Source, error) {
	sourceUUID, err := uuid.Parse(sourceId)
	if err != nil {
		return nil, fmt.Errorf("invalid source ID %q: %w", sourceId, err)
	}
	source, err := i.store.Source().Get(ctx, sourceUUID)
	if err != nil {
		return nil, fmt.Errorf("get source %s: %w", sourceUUID, err)
	}

	return source, nil
}

func (i *ImageSvc) getSourceKey(token *jwt.Token) (interface{}, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("malformed token claims")
	}

	sourceId, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing 'sub' claim")
	}

	source, err := i.getSource(context.TODO(), sourceId)
	if err != nil {
		return nil, fmt.Errorf("invalid source ID")
	}

	return []byte(source.ImageInfra.ImageTokenKey), nil
}

func (i *ImageSvc) generateAgentToken(ctx context.Context, source *model.Source) (string, error) {
	// get the key associated with source orgID to generate agent token
	key, err := i.store.PrivateKey().Get(ctx, source.OrgID)
	if err != nil {
		if !errors.Is(err, store.ErrRecordNotFound) {
			return "", err
		}
		newKey, token, err := auth.GenerateAgentJWTAndKey(source)
		if err != nil {
			return "", err
		}
		if _, err := i.store.PrivateKey().Create(ctx, *newKey); err != nil {
			return "", err
		}
		return token, nil
	}

	token, err := auth.GenerateAgentJWT(key, source)
	if err != nil {
		return "", err
	}

	return token, nil
}
