package events

import (
	"context"
	"fmt"

	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/pkg/kafka"
	"go.uber.org/zap"
)

// EventBus defines the interface for publishing events
type EventBus interface {
	Publish(ctx context.Context, event Event) error
}

// Event represents a generic event
type Event interface {
	Type() string
	Validate() error
}

// KafkaEventBus implements EventBus using Kafka as the transport
type KafkaEventBus struct {
	kafkaProducer *kafka.KafkaProducer
}

// NewKafkaEventBus creates a new Kafka-based event bus
func NewKafkaEventBus(kafkaProducer *kafka.KafkaProducer) *KafkaEventBus {
	return &KafkaEventBus{
		kafkaProducer: kafkaProducer,
	}
}

// NoOpEventBus is a no-op implementation of EventBus that logs instead of publishing
// Used when event publishing is disabled or in tests
type NoOpEventBus struct{}

// NewNoOpEventBus creates a new no-op event bus
func NewNoOpEventBus() *NoOpEventBus {
	return &NoOpEventBus{}
}

// Publish logs the event but does not actually publish it
func (b *NoOpEventBus) Publish(ctx context.Context, event Event) error {
	zap.S().Debugw("nil kafka producer, skipping event publication",
		"event_type", event.Type())
	return nil
}

// Publish routes and publishes events based on their type
func (bus *KafkaEventBus) Publish(ctx context.Context, event Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	switch e := event.(type) {
	case *VisitorEvent:
		return NewVisitorEventProducer(bus.kafkaProducer).ProduceVisitorEvent(ctx, e.Username, e.OrgID)
	case *AssessmentCreatedEvent:
		return NewAssessmentEventProducer(bus.kafkaProducer).ProduceAssessmentCreatedEvent(ctx, e.Assessment, e.Inventory)
	case *AssessmentDeletedEvent:
		return NewAssessmentEventProducer(bus.kafkaProducer).ProduceAssessmentDeletedEvent(ctx, e.AssessmentID)
	case *PartnerCustomerEvent:
		return NewPartnerCustomerEventProducer(bus.kafkaProducer).ProducePartnerCustomerEvent(ctx, e.Data)
	case *UserActionEvent:
		return NewUserActionEventProducer(bus.kafkaProducer).ProduceUserActionEvent(ctx, e.Data)
	default:
		return fmt.Errorf("unsupported event type: %T", event)
	}
}

// VisitorEvent represents a visitor tracking event
type VisitorEvent struct {
	Username string
	OrgID    string
}

func (e *VisitorEvent) Type() string {
	return VisitorEventType
}

func (e *VisitorEvent) Validate() error {
	if e.Username == "" {
		return fmt.Errorf("username is required")
	}
	if e.OrgID == "" {
		return fmt.Errorf("org_id is required")
	}
	return nil
}

// NewVisitorEvent creates a new visitor event
func NewVisitorEvent(username, orgID string) *VisitorEvent {
	return &VisitorEvent{
		Username: username,
		OrgID:    orgID,
	}
}

// AssessmentCreatedEvent represents an assessment creation event
type AssessmentCreatedEvent struct {
	Assessment *model.Assessment
	Inventory  []byte
}

func (e *AssessmentCreatedEvent) Type() string {
	return AssessmentEventType
}

func (e *AssessmentCreatedEvent) Validate() error {
	if e.Assessment == nil {
		return fmt.Errorf("assessment is required")
	}
	return nil
}

// NewAssessmentCreatedEvent creates a new assessment created event
func NewAssessmentCreatedEvent(assessment *model.Assessment, inventory []byte) *AssessmentCreatedEvent {
	return &AssessmentCreatedEvent{
		Assessment: assessment,
		Inventory:  inventory,
	}
}

// AssessmentDeletedEvent represents an assessment deletion event
type AssessmentDeletedEvent struct {
	AssessmentID string
}

func (e *AssessmentDeletedEvent) Type() string {
	return AssessmentEventType
}

func (e *AssessmentDeletedEvent) Validate() error {
	if e.AssessmentID == "" {
		return fmt.Errorf("assessment ID is required")
	}
	return nil
}

// NewAssessmentDeletedEvent creates a new assessment deleted event
func NewAssessmentDeletedEvent(assessmentID string) *AssessmentDeletedEvent {
	return &AssessmentDeletedEvent{
		AssessmentID: assessmentID,
	}
}

// PartnerCustomerEvent represents a partner-customer relationship event
type PartnerCustomerEvent struct {
	Data PartnerCustomerData
}

func (e *PartnerCustomerEvent) Type() string {
	return PartnerCustomerEventType
}

func (e *PartnerCustomerEvent) Validate() error {
	if e.Data.ID == "" {
		return fmt.Errorf("id is required")
	}
	if e.Data.CustomerUsername == "" {
		return fmt.Errorf("customer_username is required")
	}
	if e.Data.PartnerID == "" {
		return fmt.Errorf("partner_id is required")
	}
	return nil
}

// NewPartnerCustomerEvent creates a new partner-customer event
func NewPartnerCustomerEvent(data PartnerCustomerData) *PartnerCustomerEvent {
	return &PartnerCustomerEvent{
		Data: data,
	}
}

// UserActionEvent represents a user action event
type UserActionEvent struct {
	Data UserActionData
}

func (e *UserActionEvent) Type() string {
	return UserActionEventType
}

func (e *UserActionEvent) Validate() error {
	if e.Data.Username == "" {
		return fmt.Errorf("username is required")
	}
	if e.Data.ActionType == "" {
		return fmt.Errorf("action_type is required")
	}
	return nil
}

// NewUserActionEvent creates a new user action event
func NewUserActionEvent(data UserActionData) *UserActionEvent {
	return &UserActionEvent{
		Data: data,
	}
}
