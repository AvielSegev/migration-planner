package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/kubev2v/migration-planner/internal/config"
	"github.com/kubev2v/migration-planner/internal/store"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/pkg/events"
	"github.com/kubev2v/migration-planner/pkg/log"
	"github.com/spf13/cobra"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"go.uber.org/zap"
)

var backfillCmd = &cobra.Command{
	Use:   "backfill",
	Short: "Backfill existing assessments into Kafka",
	Long:  "Reads all assessments from the database and publishes AssessmentCreated events to Kafka, backfilling historical data.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.InitLog(zap.NewAtomicLevelAt(zap.InfoLevel))
		defer func() { _ = logger.Sync() }()

		undo := zap.ReplaceGlobals(logger)
		defer undo()

		cfg, err := config.New()
		if err != nil {
			zap.S().Fatalw("reading configuration", "error", err)
		}

		zap.S().Info("Initializing data store")
		db, err := store.InitDB(cfg)
		if err != nil {
			zap.S().Fatalw("initializing data store", "error", err)
		}

		s := store.NewStore(db)
		defer func() { _ = s.Close() }()

		ctx := context.Background()

		brokers := strings.Split(cfg.Kafka.Brokers, ",")
		var kafkaOpts []kgo.Opt

		if cfg.Kafka.UseTLS {
			kafkaOpts = append(kafkaOpts, kgo.DialTLSConfig(new(tls.Config)))
		}

		if cfg.Kafka.SASLUsername != "" {
			mechanism := scram.Auth{
				User: cfg.Kafka.SASLUsername,
				Pass: cfg.Kafka.SASLPassword,
			}
			kafkaOpts = append(kafkaOpts, kgo.SASL(mechanism.AsSha512Mechanism()))
		}

		producer, err := events.NewKafkaProducer(brokers, kafkaOpts...)
		if err != nil {
			zap.S().Fatalw("creating kafka producer", "error", err)
		}
		defer producer.Close()

		pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
		defer pingCancel()

		if err := producer.Ping(pingCtx); err != nil {
			zap.S().Fatalw("kafka broker unreachable", "error", err)
		}

		zap.S().Infow("kafka producer connected", "brokers", cfg.Kafka.Brokers)

		return backfillAssessments(ctx, s, producer)
	},
}

func backfillAssessments(ctx context.Context, s store.Store, writer events.Writer) error {
	assessments, err := s.Assessment().List(ctx, nil)
	if err != nil {
		return fmt.Errorf("listing assessments: %w", err)
	}

	zap.S().Infow("found assessments to backfill", "count", len(assessments))

	partnerIDs, err := resolvePartnerIDs(ctx, s, assessments)
	if err != nil {
		return fmt.Errorf("resolving partner IDs: %w", err)
	}

	var success, failed, skipped int
	for _, assessment := range assessments {
		if len(assessment.Snapshots) == 0 {
			zap.S().Warnw("skipping assessment with no snapshots", "id", assessment.ID)
			skipped++
			continue
		}

		payload := events.NewAssessmentCreatedPayload(events.AssessmentData{
			ID:         assessment.ID.String(),
			SnapshotID: assessment.Snapshots[0].ID,
			Inventory:  assessment.Snapshots[0].Inventory,
			Name:       assessment.Name,
			OrgID:      assessment.OrgID,
			Username:   assessment.Username,
			SourceType: assessment.SourceType,
			PartnerID:  partnerIDs[assessment.ID.String()],
			CreatedAt:  assessment.CreatedAt,
			UpdatedAt:  assessment.UpdatedAt,
		})

		ceBytes, err := events.BuildCloudEvent(events.AssessmentCreatedEventType, payload)
		if err != nil {
			zap.S().Errorw("building cloud event", "id", assessment.ID, "error", err)
			failed++
			continue
		}

		if err := writer.Write(ctx, events.GenericTopic, ceBytes); err != nil {
			zap.S().Errorw("publishing event", "id", assessment.ID, "error", err)
			failed++
			continue
		}

		success++
	}

	zap.S().Infow("backfill completed", "total", len(assessments), "success", success, "failed", failed, "skipped", skipped)
	return nil
}

func resolvePartnerIDs(ctx context.Context, s store.Store, assessments model.AssessmentList) (map[string]*string, error) {
	ids := make([]string, len(assessments))
	for i, a := range assessments {
		ids[i] = a.ID.String()
	}

	relsByID, err := s.Authz().ListBulkRelationship(ctx, ids)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*string, len(assessments))
	for _, a := range assessments {
		id := a.ID.String()
		for _, rel := range relsByID[id] {
			if rel.Relation == model.ViewerRelation && rel.Subject.Kind == model.OrgSubject {
				partnerID := rel.Subject.ID
				result[id] = &partnerID
				break
			}
		}
	}
	return result, nil
}
