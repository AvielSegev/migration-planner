package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kprom"
	"go.uber.org/zap"
)

type KafkaProducer struct {
	cl *kgo.Client
}

func NewKafkaProducer(brokers []string, opts ...kgo.Opt) (*KafkaProducer, error) {
	clientID, err := os.Hostname()
	if err != nil {
		clientID = fmt.Sprintf("producer-%s", uuid.NewString())
	}

	defaults := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ClientID(clientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.WithHooks(kprom.NewMetrics("kafka_producer")),
	}

	cl, err := kgo.NewClient(append(defaults, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	return &KafkaProducer{cl: cl}, nil
}

func (p *KafkaProducer) Write(ctx context.Context, topic string, e cloudevents.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to marshal cloudevent: %w", err)
	}

	record := &kgo.Record{
		Topic: topic,
		Key:   []byte(e.ID()),
		Value: data,
	}

	results := p.cl.ProduceSync(ctx, record)
	if err := results.FirstErr(); err != nil {
		return fmt.Errorf("failed to produce message: %w", err)
	}

	zap.S().Infow("message pushed to kafka", "topic", record.Topic, "offset", record.Offset, "partition", record.Partition)
	return nil
}

func (p *KafkaProducer) Close(_ context.Context) error {
	p.cl.Close()
	return nil
}
