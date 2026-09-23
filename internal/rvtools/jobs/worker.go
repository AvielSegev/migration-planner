package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/marcboeker/go-duckdb/v2" // DuckDB driver
	"github.com/riverqueue/river"

	"github.com/kubev2v/migration-planner/internal/store"
	"github.com/kubev2v/migration-planner/internal/store/model"
	"github.com/kubev2v/migration-planner/pkg/duckdb_parser"
	"github.com/kubev2v/migration-planner/pkg/events"
	"github.com/kubev2v/migration-planner/pkg/events/kafka"
	"github.com/kubev2v/migration-planner/pkg/inventory/converters"
	"github.com/kubev2v/migration-planner/pkg/log"
	pkgstore "github.com/kubev2v/migration-planner/pkg/store"
)

type RVToolsWorker struct {
	river.WorkerDefaults[RVToolsJobArgs]
	store     store.Store
	validator duckdb_parser.Validator
}

func NewRVToolsWorker(store store.Store, validator duckdb_parser.Validator) *RVToolsWorker {
	return &RVToolsWorker{
		store:     store,
		validator: validator,
	}
}

// createParser creates a new per-job DuckDB instance and parser.
// The caller is responsible for closing the returned *sql.DB when done.
func (w *RVToolsWorker) createParser() (*duckdb_parser.Parser, *sql.DB, error) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return nil, nil, fmt.Errorf("opening duckdb: %w", err)
	}
	extensionDir := "/tmp/duckdb_extensions"
	if _, err := db.Exec(fmt.Sprintf("SET extension_directory='%s';", extensionDir)); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("setting duckdb extension directory: %w", err)
	}
	qi := pkgstore.NewQueryInterceptor(db)
	parser := duckdb_parser.New(qi, w.validator)
	if err := parser.Init(); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("initializing duckdb schema: %w", err)
	}
	return parser, db, nil
}

func (w *RVToolsWorker) Timeout(_ *river.Job[RVToolsJobArgs]) time.Duration {
	return 10 * time.Minute
}

// failJob logs an error, updates job status to failed, and returns the error.
func (w *RVToolsWorker) failJob(ctx context.Context, logger *log.OperationTracer, jobID int64, orgID, step string, err error, errMsg string) error {
	logger.Error(err).WithString("step", step).Log()
	if updateErr := w.updateJobStatus(ctx, jobID, model.JobStatusFailed, errMsg, nil); updateErr != nil {
		logger.Error(updateErr).WithString("step", "update_failed_status").Log()
	}

	if eventErr := w.writeErrorEvent(ctx, jobID, orgID, step, err); eventErr != nil {
		logger.Error(eventErr).WithString("step", "write_error_event").Log()
	}

	return err
}

func (w *RVToolsWorker) writeErrorEvent(ctx context.Context, jobID int64, orgID, step string, err error) error {
	message := map[string]string{
		"create_parser":     "The inventory parser could not be initialized",
		"ingest_rvtools":    "The inventory file could not be ingested",
		"validate_rvtools":  "The inventory file failed validation",
		"build_inventory":   "The inventory could not be built",
		"marshal_inventory": "The inventory could not be serialized",
		"create_assessment": "The assessment could not be created",
	}[step]
	if message == "" {
		message = "The assessment creation job failed"
	}
	if step == "create_assessment" && errors.Is(err, store.ErrDuplicateKey) {
		message = "An assessment with this name already exists"
	}

	var actor *kafka.ErrorActor
	if orgID != "" {
		actor = &kafka.ErrorActor{OrgID: orgID}
	}
	payload := kafka.NewErrorPayload(
		kafka.SeverityError,
		"assessment.create",
		step,
		message,
		actor,
		strconv.FormatInt(jobID, 10),
	)
	data, err := kafka.BuildErrorCloudEvent(payload)
	if err != nil {
		return fmt.Errorf("building error event: %w", err)
	}
	if err := w.store.Outbox().Insert(ctx, model.OutboxEvent{EventType: events.EventTypeKafka, Payload: data}); err != nil {
		return fmt.Errorf("writing error event to outbox: %w", err)
	}
	return nil
}

// Work processes an RVTools assessment job.
func (w *RVToolsWorker) Work(ctx context.Context, job *river.Job[RVToolsJobArgs]) error {
	logger := log.NewDebugLogger("rvtools_worker").
		WithContext(ctx).
		Operation("process_rvtools_job").
		WithParam("job_id", job.ID).
		WithString("assessment_name", job.Args.Name).
		Build()

	logger.Step("job_started").Log()

	filePath := job.Args.FilePath
	defer func() { _ = os.Remove(filePath) }()

	// Create per-job DuckDB instance for isolation
	parser, duckDB, err := w.createParser()
	if err != nil {
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "create_parser", err, fmt.Sprintf("failed to create DuckDB parser: %v", err))
	}
	defer func() { _ = duckDB.Close() }()

	// Update status to validating before ingestion (which includes OPA validation)
	if err := w.updateJobStatus(ctx, job.ID, model.JobStatusValidating, "", nil); err != nil {
		logger.Error(err).WithString("step", "update_validating_status").Log()
	}

	// Ingest RVTools file using duckdb_parser
	validationResult, err := parser.IngestRvTools(ctx, filePath)
	if err != nil {
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "ingest_rvtools", err, fmt.Sprintf("error ingesting RVTools file: %v", err))
	}

	// Check for validation errors
	if validationResult.HasErrors() {
		validationErr := fmt.Errorf("validation failed: %v", validationResult.Errors)
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "validate_rvtools", validationErr, fmt.Sprintf("RVTools validation failed: %v", validationResult.Errors[0].Message))
	}

	// Log any warnings
	for _, warning := range validationResult.Warnings {
		logger.Step("validation_warning").WithString("code", warning.Code).WithString("message", warning.Message).Log()
	}

	// Update status to parsing
	if err := w.updateJobStatus(ctx, job.ID, model.JobStatusParsing, "", nil); err != nil {
		logger.Error(err).WithString("step", "update_parsing_status").Log()
	}

	// Build inventory from parsed data
	logger.Step("building_inventory").Log()
	inv, err := parser.BuildInventory(ctx, nil)
	if err != nil {
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "build_inventory", err, fmt.Sprintf("error building inventory: %v", err))
	}
	inventory := converters.ToAPI(inv)

	// Marshal inventory to JSON
	inventoryJSON, err := json.Marshal(inventory)
	if err != nil {
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "marshal_inventory", err, fmt.Sprintf("error marshaling inventory: %v", err))
	}

	// Check for cancellation before creating assessment
	if err := ctx.Err(); err != nil {
		logger.Error(err).WithString("step", "pre_create_assessment_cancelled").Log()
		return err
	}

	logger.Step("creating_assessment").Log()

	// Build assessment model
	assessment := model.Assessment{
		ID:         uuid.New(),
		Name:       job.Args.Name,
		OrgID:      job.Args.OrgID,
		Username:   job.Args.Username,
		SourceType: "rvtools",
	}
	if job.Args.FirstName != "" {
		assessment.OwnerFirstName = &job.Args.FirstName
	}
	if job.Args.LastName != "" {
		assessment.OwnerLastName = &job.Args.LastName
	}

	// RVTools assessments don't have subset inventories
	createdAssessment, err := w.store.Assessment().Create(ctx, assessment, inventoryJSON, nil)
	if err != nil {
		var errMsg string
		if errors.Is(err, store.ErrDuplicateKey) {
			errMsg = fmt.Sprintf("assessment with name '%s' already exists", assessment.Name)
		} else {
			errMsg = fmt.Sprintf("failed to create assessment: %v", err)
		}
		return w.failJob(ctx, logger, job.ID, job.Args.OrgID, "create_assessment", err, errMsg)
	}
	w.store.RequestMetricsCacheRefresh()

	updates := store.NewRelationshipBuilder().
		With(model.NewAssessmentResource(assessment.ID.String()), model.OwnerRelation, model.NewUserSubject(job.Args.Username)).
		Build()

	if err := w.store.Authz().WriteRelationships(ctx, updates); err != nil {
		return fmt.Errorf("authz: failed to write owner relation: %w", err)
	}

	// Update job with assessment ID
	if err := w.updateJobStatus(ctx, job.ID, model.JobStatusCompleted, "", &createdAssessment.ID); err != nil {
		logger.Error(err).WithString("step", "update_completed_status").Log()
	}

	cePayload := kafka.NewAssessmentCreatedPayload(kafka.AssessmentData{
		ID:         createdAssessment.ID.String(),
		SnapshotID: createdAssessment.Snapshots[0].ID,
		Inventory:  createdAssessment.Snapshots[0].Inventory,
		Name:       createdAssessment.Name,
		OrgID:      createdAssessment.OrgID,
		Username:   createdAssessment.Username,
		SourceType: createdAssessment.SourceType,
		CreatedAt:  createdAssessment.CreatedAt,
		UpdatedAt:  createdAssessment.UpdatedAt,
	})
	ceBytes, err := kafka.BuildCloudEvent(kafka.AssessmentCreatedEventType, cePayload)
	if err != nil {
		return fmt.Errorf("failed to build outbox event: %w", err)
	}
	if err := w.store.Outbox().Insert(ctx, model.OutboxEvent{EventType: events.EventTypeKafka, Payload: ceBytes}); err != nil {
		return fmt.Errorf("failed to write outbox event: %w", err)
	}

	logger.Success().
		WithUUID("assessment_id", createdAssessment.ID).
		WithString("assessment_name", createdAssessment.Name).
		Log()

	return nil
}

// updateJobStatus updates the job's metadata with the current status using job store.
func (w *RVToolsWorker) updateJobStatus(ctx context.Context, jobID int64, status, errorMsg string, assessmentID *uuid.UUID) error {
	metadata := model.RVToolsJobMetadata{
		Status:       status,
		Error:        errorMsg,
		AssessmentID: assessmentID,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	return w.store.Job().UpdateMetadata(ctx, jobID, metadataJSON)
}
