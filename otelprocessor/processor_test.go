package otelprocessor

import (
	"context"
	"testing"

	"github.com/cockroachdb/redact"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
)

type TestConfig struct {
	config *Config
}

func TestLogBody(t *testing.T) {
	inBatch := plog.NewLogs()
	rl := inBatch.ResourceLogs().AppendEmpty()
	ils := rl.ScopeLogs().AppendEmpty()
	library := ils.Scope()
	library.SetName("first-library")

	logEntry := ils.LogRecords().AppendEmpty()

	body := redact.Sprintf("hello %s", "world")
	logEntry.Body().SetStr(string(body))

	ctx := context.Background()
	processor := newRedactProcessor(ctx, &Config{})
	outBatch, err := processor.processLogs(ctx, inBatch)
	assert.NoError(t, err)
	outLogBody := outBatch.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()

	require.Equal(t, string(body.Redact()), outLogBody)
}
