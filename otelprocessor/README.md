# Redact Processor

This is a processor made to use with the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), that redacts sensitive information present in log bodies using [cockroachdb/redact](https://github.com/cockroachdb/redact).


## Usage

Follow the [guide to build a custom OpenTelemetry collector](https://opentelemetry.io/docs/collector/custom-collector/) which has this processor included in it.

```yaml
# builder-config.yaml

# ...
processors:
  - gomod:
      github.com/cockroachdb/redact/otelprocessor master
# ...
```

And in the config for the collector:

```yaml
processors:
  redact:

service:
  pipelines:
    logs:
      receivers: [...]
      processors: [redact]
      exporters: [...]
```
