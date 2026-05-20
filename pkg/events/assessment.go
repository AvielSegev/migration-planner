package events

import (
	"context"
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/pkg/kafka"
	"go.uber.org/zap"
)

// AssessmentEventPayload represents the assessment event payload
type AssessmentEventPayload struct {
	Assessment AssessmentData `json:"assessment"`
	Action     string         `json:"action"`
}

// AssessmentData represents the assessment data in the event
type AssessmentData struct {
	ID         string          `json:"id"`
	SnapshotID uint            `json:"snapshot_id,omitempty"`
	Name       string          `json:"name,omitempty"`
	OrgID      string          `json:"org_id,omitempty"`
	Username   string          `json:"username,omitempty"`
	SourceType string          `json:"source_type,omitempty"`
	PartnerID  *string         `json:"partner_id,omitempty"`
	Location   *string         `json:"location,omitempty"`
	Inventory  json.RawMessage `json:"inventory,omitempty"`
	CreatedAt  time.Time       `json:"created_at,omitempty"`
	UpdatedAt  *time.Time      `json:"updated_at,omitempty"`
	DeletedAt  *time.Time      `json:"deleted_at,omitempty"`
}

// AssessmentEventProducer handles producing assessment events
type AssessmentEventProducer struct {
	producer *kafka.KafkaProducer
}

// NewAssessmentEventProducer creates a new assessment event producer
func NewAssessmentEventProducer(producer *kafka.KafkaProducer) *AssessmentEventProducer {
	return &AssessmentEventProducer{
		producer: producer,
	}
}

// ProduceAssessmentCreatedEvent ProduceAssessmentEvent emits an assessment event
func (p *AssessmentEventProducer) ProduceAssessmentCreatedEvent(
	ctx context.Context,
	assessment *model.Assessment,
	inventory []byte,
) error {

	data := AssessmentData{
		ID:         assessment.ID.String(),
		SnapshotID: assessment.Snapshots[0].ID, // latest snapshot ID (snapshots are ordered by created_at DESC)
		Inventory:  json.RawMessage(inventory),
		Name:       assessment.Name,
		OrgID:      assessment.OrgID,
		Username:   assessment.Username,
		SourceType: assessment.SourceType,
		CreatedAt:  assessment.CreatedAt,
		UpdatedAt:  assessment.UpdatedAt,
	}

	// Create CloudEvent
	event := NewCloudEvent(AssessmentEventType, EventSource)

	payload := AssessmentEventPayload{
		Assessment: data,
		Action:     ActionAssessmentCreated,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, payload); err != nil {
		zap.S().Errorw("failed to set event data", "error", err, "assessment_id", assessment.ID)
		return err
	}

	// Produce to Kafka
	if err := p.producer.Write(ctx, GenericTopic, event); err != nil {
		zap.S().Errorw("failed to produce assessment event", "error", err, "assessment_id", assessment.ID)
		return err
	}

	zap.S().Infow("assessment event produced", "assessment_id", assessment.ID, "event_id", event.ID())
	return nil
}

// ProduceAssessmentDeletedEvent emits an assessment deleted event
func (p *AssessmentEventProducer) ProduceAssessmentDeletedEvent(
	ctx context.Context,
	assessmentID string,
) error {
	now := time.Now()

	data := AssessmentData{
		ID:        assessmentID,
		DeletedAt: &now,
	}

	// Create CloudEvent
	event := NewCloudEvent(AssessmentEventType, EventSource)

	payload := AssessmentEventPayload{
		Assessment: data,
		Action:     ActionAssessmentDeleted,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, payload); err != nil {
		zap.S().Errorw("failed to set event data for delete", "error", err, "assessment_id", assessmentID)
		return err
	}

	// Produce to Kafka
	if err := p.producer.Write(ctx, GenericTopic, event); err != nil {
		zap.S().Errorw("failed to produce assessment deleted event", "error", err, "assessment_id", assessmentID)
		return err
	}

	zap.S().Infow("assessment deleted event produced", "assessment_id", assessmentID, "event_id", event.ID())
	return nil
}
