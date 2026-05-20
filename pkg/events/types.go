package events

const (
	// GenericTopic Topic where all events are produced
	GenericTopic = "assisted.migrations.events"

	// Event types
	AssessmentEventType      = "assisted.migrations.events.assessment"
	VisitorEventType         = "assisted.migrations.events.visitor"
	PartnerCustomerEventType = "assisted.migrations.events.partner_customer"
	UserActionEventType      = "assisted.migrations.events.user_action"

	// Event source
	EventSource = "migration-planner"

	// Assessment events types
	ActionAssessmentCreated = "created"
	ActionAssessmentDeleted = "deleted"

	// User action types
	ActionTypeShareAssessment     = "share"
	ActionTypeUnshareAssessment   = "unshare"
	ActionTypeSizing              = "sizing"
	ActionTypeMigrationComplexity = "migration_complexity"
	ActionTypeDownloadOVA         = "download_ova"
)
