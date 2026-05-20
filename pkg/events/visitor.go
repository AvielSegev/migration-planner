package events

import (
	"context"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kubev2v/migration-planner/pkg/kafka"
	"go.uber.org/zap"
)

// VisitorEventPayload represents the visitor tracking event payload
type VisitorEventPayload struct {
	Visitor VisitorData `json:"visitor"`
}

// VisitorData represents the visitor data in the event
type VisitorData struct {
	Username  string    `json:"username"`
	OrgID     string    `json:"org_id"`
	Timestamp time.Time `json:"timestamp"`
}

// VisitorEventProducer handles producing visitor tracking events
type VisitorEventProducer struct {
	producer *kafka.KafkaProducer
}

// NewVisitorEventProducer creates a new visitor event producer
func NewVisitorEventProducer(producer *kafka.KafkaProducer) *VisitorEventProducer {
	return &VisitorEventProducer{
		producer: producer,
	}
}

// ProduceVisitorEvent emits a visitor tracking event
func (p *VisitorEventProducer) ProduceVisitorEvent(
	ctx context.Context,
	username string,
	orgID string,
) error {
	data := VisitorData{
		Username:  username,
		OrgID:     orgID,
		Timestamp: time.Now(),
	}

	// Create CloudEvent
	event := NewCloudEvent(VisitorEventType, EventSource)

	payload := VisitorEventPayload{
		Visitor: data,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, payload); err != nil {
		zap.S().Errorw("failed to set visitor event data", "error", err, "username", username)
		return fmt.Errorf("failed to set visitor event data: %w", err)
	}

	// Produce to Kafka
	if err := p.producer.Write(ctx, GenericTopic, event); err != nil {
		zap.S().Errorw("failed to produce visitor event", "error", err, "username", username)
		return fmt.Errorf("failed to produce visitor event: %w", err)
	}

	zap.S().Infow("visitor event produced", "username", username, "org_id", orgID, "event_id", event.ID())
	return nil
}
