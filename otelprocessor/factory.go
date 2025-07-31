package otelprocessor

import (
	"context"

	"github.com/cockroachdb/redact/otelprocessor/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

func NewFactory() processor.Factory {
	return processor.NewFactory(
		metadata.Type,
		createDefaultConfig,
		processor.WithLogs(createLogsProcessor, metadata.LogsStability),
	)
}

func createLogsProcessor(ctx context.Context, params processor.Settings, baseCfg component.Config, next consumer.Logs) (processor.Logs, error) {
	cfg := baseCfg.(*Config)
	redactProcessor := newRedactProcessor(ctx, cfg)
	return processorhelper.NewLogs(
		ctx,
		params,
		cfg,
		next,
		redactProcessor.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}),
	)
}
