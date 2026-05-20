package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
	"time"
)

func NewCloudEvent(eventType, eventSource string) event.Event {
	// Create CloudEvent
	e := cloudevents.NewEvent()
	e.SetID(uuid.New().String())
	e.SetSource(eventSource)
	e.SetType(eventType)
	e.SetTime(time.Now())

	return e
}
