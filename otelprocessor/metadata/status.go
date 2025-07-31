package metadata

import "go.opentelemetry.io/collector/component"

var Type = component.MustNewType("redact")

const LogsStability = component.StabilityLevelAlpha
