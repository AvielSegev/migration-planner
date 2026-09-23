package eventwrap

import (
	"context"

	"github.com/google/uuid"
	api "github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/auth"
	"github.com/kubev2v/migration-planner/internal/service"
	"github.com/kubev2v/migration-planner/internal/service/mappers"
	"github.com/kubev2v/migration-planner/internal/store"
	"github.com/kubev2v/migration-planner/pkg/events"
	"github.com/kubev2v/migration-planner/pkg/events/kafka"
	"github.com/kubev2v/migration-planner/pkg/requestid"
	"go.uber.org/zap"
)

type EventSizerService struct {
	inner  service.SizerServicer
	store  store.Store
	outbox *OutboxService
}

func NewEventSizerService(inner service.SizerServicer, s store.Store) service.SizerServicer {
	return &EventSizerService{inner: inner, store: s, outbox: NewOutboxService(s)}
}

func (e *EventSizerService) CalculateClusterRequirements(
	ctx context.Context,
	assessmentID uuid.UUID,
	req *mappers.ClusterRequirementsRequestForm,
) (*api.ClusterRequirementsResponse, error) {
	result, err := e.inner.CalculateClusterRequirements(ctx, assessmentID, req)
	if err != nil {
		if eventErr := e.writeErrorEvent(ctx, "calculate_requirements"); eventErr != nil {
			zap.S().Warnw("failed to write sizing error event", "error", eventErr, "assessment_id", assessmentID)
		}
		return nil, err
	}

	assessment, err := e.store.Assessment().Get(ctx, assessmentID)
	if err != nil {
		return nil, err
	}

	payload := kafka.NewSizingPayload(assessment.Username, assessmentID.String())
	ceBytes, err := kafka.BuildCloudEvent(kafka.SizingEventType, payload)
	if err != nil {
		return nil, err
	}
	if err := e.outbox.Insert(ctx, events.EventTypeKafka, ceBytes); err != nil {
		return nil, err
	}

	return result, nil
}

func (e *EventSizerService) writeErrorEvent(ctx context.Context, step string) error {
	var actor *kafka.ErrorActor
	if user, ok := auth.UserFromContext(ctx); ok && user.Organization != "" {
		actor = &kafka.ErrorActor{OrgID: user.Organization}
	}
	payload := kafka.NewErrorPayload(
		kafka.SeverityError,
		"sizing.calculate",
		step,
		"Cluster sizing could not be calculated",
		actor,
		requestid.FromContext(ctx),
	)
	data, buildErr := kafka.BuildErrorCloudEvent(payload)
	if buildErr != nil {
		return buildErr
	}
	return e.outbox.Insert(ctx, events.EventTypeKafka, data)
}

func (e *EventSizerService) CalculateStandaloneClusterRequirements(
	ctx context.Context,
	req *mappers.StandaloneClusterRequirementsRequestForm,
) (*mappers.StandaloneClusterRequirementsResponseForm, error) {
	return e.inner.CalculateStandaloneClusterRequirements(ctx, req)
}

func (e *EventSizerService) GetClusterRequirementsInput(ctx context.Context, assessmentID uuid.UUID, clusterID string) (*mappers.ClusterRequirementsInputForm, error) {
	return e.inner.GetClusterRequirementsInput(ctx, assessmentID, clusterID)
}

func (e *EventSizerService) Health(ctx context.Context) error {
	return e.inner.Health(ctx)
}
