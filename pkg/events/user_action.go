package events

import (
	"context"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kubev2v/migration-planner/pkg/kafka"
	"go.uber.org/zap"
)

type UserActionEventPayload struct {
	UserAction UserActionData `json:"user_action"`
}

type UserActionData struct {
	Username     string    `json:"username"`
	AssessmentID *string   `json:"assessment_id,omitempty"`
	SourceID     *string   `json:"source_id,omitempty"`
	PartnerID    *string   `json:"partner_id,omitempty"`
	ActionType   string    `json:"action_type"`
	Timestamp    time.Time `json:"timestamp"`
}

type UserActionEventProducer struct {
	producer *kafka.KafkaProducer
}

func NewUserActionEventProducer(producer *kafka.KafkaProducer) *UserActionEventProducer {
	return &UserActionEventProducer{
		producer: producer,
	}
}

func (p *UserActionEventProducer) ProduceUserActionEvent(
	ctx context.Context,
	data UserActionData,
) error {
	event := NewCloudEvent(UserActionEventType, EventSource)

	payload := UserActionEventPayload{
		UserAction: data,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, payload); err != nil {
		zap.S().Errorw("failed to set user action event data", "error", err, "username", data.Username)
		return fmt.Errorf("failed to set user action event data: %w", err)
	}

	if err := p.producer.Write(ctx, GenericTopic, event); err != nil {
		zap.S().Errorw("failed to produce user action event", "error", err, "username", data.Username)
		return fmt.Errorf("failed to produce user action event: %w", err)
	}

	zap.S().Infow("user action event produced",
		"username", data.Username,
		"action_type", data.ActionType,
		"assessment_id", data.AssessmentID,
		"event_id", event.ID())
	return nil
}
