package otelprocessor

import (
	"context"

	"github.com/cockroachdb/redact"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

type redactProcessor struct {
	config Config
}

func newRedactProcessor(_ context.Context, config *Config) *redactProcessor {
	rp := &redactProcessor{
		config: *config,
	}

	return rp
}

func (rp *redactProcessor) processLogs(_ context.Context, logs plog.Logs) (plog.Logs, error) {
	resourceLogs := logs.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		rp.processResourceLog(resourceLogs.At(i))
	}

	return logs, nil
}

func (rp *redactProcessor) processResourceLog(rl plog.ResourceLogs) {
	for i := 0; i < rl.ScopeLogs().Len(); i++ {
		ils := rl.ScopeLogs().At(i)
		for j := 0; j < ils.LogRecords().Len(); j++ {
			log := ils.LogRecords().At(j)
			rp.processLogBody(log.Body())
		}
	}
}

func (rp *redactProcessor) processLogBody(body pcommon.Value) {
	if body.Type() == pcommon.ValueTypeStr {
		red := redact.RedactableString(body.AsString())
		body.SetStr(string(red.Redact()))
	}
}
