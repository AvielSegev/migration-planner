package events

import (
	"context"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kubev2v/migration-planner/pkg/kafka"
	"go.uber.org/zap"
)

// PartnerCustomerEventPayload represents the partner-customer relationship event payload
type PartnerCustomerEventPayload struct {
	PartnerCustomer PartnerCustomerData `json:"partner_customer"`
}

// PartnerCustomerData represents the partner-customer relationship data in the event
type PartnerCustomerData struct {
	ID               string     `json:"id"`
	CustomerUsername string     `json:"customer_username"`
	PartnerID        string     `json:"partner_id"`
	RequestStatus    string     `json:"request_status"`
	Location         string     `json:"location"`
	AcceptedAt       *time.Time `json:"accepted_at,omitempty"`
	TerminatedAt     *time.Time `json:"terminated_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// PartnerCustomerEventProducer handles producing partner-customer relationship events
type PartnerCustomerEventProducer struct {
	producer *kafka.KafkaProducer
}

// NewPartnerCustomerEventProducer creates a new partner-customer event producer
func NewPartnerCustomerEventProducer(producer *kafka.KafkaProducer) *PartnerCustomerEventProducer {
	return &PartnerCustomerEventProducer{
		producer: producer,
	}
}

// ProducePartnerCustomerEvent emits a partner-customer relationship event
func (p *PartnerCustomerEventProducer) ProducePartnerCustomerEvent(
	ctx context.Context,
	data PartnerCustomerData,
) error {
	event := NewCloudEvent(PartnerCustomerEventType, EventSource)

	payload := PartnerCustomerEventPayload{
		PartnerCustomer: data,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, payload); err != nil {
		zap.S().Errorw("failed to set partner-customer event data", "error", err, "id", data.ID)
		return fmt.Errorf("failed to set partner-customer event data: %w", err)
	}

	if err := p.producer.Write(ctx, GenericTopic, event); err != nil {
		zap.S().Errorw("failed to produce partner-customer event", "error", err, "id", data.ID)
		return fmt.Errorf("failed to produce partner-customer event: %w", err)
	}

	zap.S().Infow("partner-customer event produced",
		"id", data.ID,
		"customer", data.CustomerUsername,
		"partner_id", data.PartnerID,
		"status", data.RequestStatus,
		"event_id", event.ID())
	return nil
}
