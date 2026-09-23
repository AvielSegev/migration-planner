package kafka

type ErrorEventPayload struct {
	Error ErrorData `json:"error"`
}

type ErrorData struct {
	Severity      string      `json:"severity"`
	Operation     string      `json:"operation"`
	Step          string      `json:"step"`
	Message       string      `json:"message"`
	Actor         *ErrorActor `json:"actor,omitempty"`
	CorrelationID string      `json:"correlation_id,omitempty"`
}

type ErrorActor struct {
	OrgID string `json:"org_id,omitempty"`
}

const (
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

func NewErrorPayload(severity, operation, step, message string, actor *ErrorActor, correlationID string) ErrorEventPayload {
	return ErrorEventPayload{
		Error: ErrorData{
			Severity:      severity,
			Operation:     operation,
			Step:          step,
			Message:       message,
			Actor:         actor,
			CorrelationID: correlationID,
		},
	}
}

func BuildErrorCloudEvent(payload ErrorEventPayload) ([]byte, error) {
	return BuildCloudEvent(ErrorEventType, payload)
}
