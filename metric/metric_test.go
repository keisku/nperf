package metric

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type testHandler struct {
	*slog.JSONHandler
	t time.Time
}

func (h *testHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Time = h.t
	return h.JSONHandler.Handle(ctx, r)
}

func TestFilterPrinter_Encode(t *testing.T) {
	date := time.Date(2023, 8, 14, 6, 48, 44, 0, time.UTC)
	type fields struct {
		IncludeNames      []string
		ExcludeNames      []string
		IncludeAttributes []string
		ExcludeAttributes []string
	}
	tests := []struct {
		name            string
		fields          fields
		resourceMetrics metricdata.ResourceMetrics
		want            []map[string]interface{}
	}{
		{
			name: "metric attribute filter",
			fields: fields{
				IncludeAttributes: []string{"key:must:have", `domain:.*\.com`},
				ExcludeAttributes: []string{"process_name:.*", `domain:.*`},
			},
			resourceMetrics: metricdata.ResourceMetrics{
				ScopeMetrics: []metricdata.ScopeMetrics{
					{
						Metrics: []metricdata.Metrics{
							{
								Name: "nperf_something_bytes",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example"),
												attribute.String("domain", "test.com"),
											),
										},
									},
								},
							},
							{
								Name: "nperf_something_bytes_suffix",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "prefix_example"),
											),
										},
									},
								},
							},
							{
								Name: "prefix_nperf_something_bytes",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example_suffix"),
											),
										},
									},
								},
							},
							{
								Name: "something_histogram",
								Data: metricdata.Histogram[float64]{
									DataPoints: []metricdata.HistogramDataPoint[float64]{
										{
											Sum:   10,
											Count: 2,
											Attributes: attribute.NewSet(
												attribute.String("pid", "1234"),
											),
										},
										{
											Sum:   12,
											Count: 4,
											Attributes: attribute.NewSet(
												attribute.String("key", "must:have"),
												attribute.String("key", "second:must:have"),
											),
										},
										{
											Sum:   10,
											Count: 2,
											Attributes: attribute.NewSet(
												attribute.String("process_name", "test"),
											),
										},
										{
											Sum:   100,
											Count: 25,
											Attributes: attribute.NewSet(
												attribute.String("domain", "nperf.io"),
											),
										},
									},
								},
							},
						},
					},
				},
			},
			want: []map[string]interface{}{
				{
					"daddr":        "3.233.157.101",
					"domain":       "test.com",
					"level":        slog.LevelInfo.String(),
					"msg":          "nperf_something_bytes",
					"process_name": "example",
					"saddr":        "127.0.0.1",
					"time":         date.Format(time.RFC3339Nano),
					"unit":         "bytes",
					"value":        float64(123),
				},
				{
					"level": slog.LevelInfo.String(),
					"msg":   "something_histogram",
					"pid":   "1234",
					"time":  date.Format(time.RFC3339Nano),
					"unit":  "",
					"value": float64(5),
				},
				{
					"key":   "second:must:have",
					"level": slog.LevelInfo.String(),
					"msg":   "something_histogram",
					"time":  date.Format(time.RFC3339Nano),
					"unit":  "",
					"value": float64(3),
				},
			},
		},
		{
			name: "metric name filter",
			fields: fields{
				IncludeNames: []string{"^nperf_something_bytes$"},
				ExcludeNames: []string{".*"},
			},
			resourceMetrics: metricdata.ResourceMetrics{
				ScopeMetrics: []metricdata.ScopeMetrics{
					{
						Metrics: []metricdata.Metrics{
							{
								Name: "nperf_something_bytes",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example"),
											),
										},
									},
								},
							},
							{
								Name: "nperf_something_bytes_suffix",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example"),
											),
										},
									},
								},
							},
							{
								Name: "prefix_nperf_something_bytes",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example"),
											),
										},
									},
								},
							},
						},
					},
				},
			},
			want: []map[string]interface{}{
				{
					"daddr":        "3.233.157.101",
					"level":        slog.LevelInfo.String(),
					"msg":          "nperf_something_bytes",
					"process_name": "example",
					"saddr":        "127.0.0.1",
					"time":         date.Format(time.RFC3339Nano),
					"unit":         "bytes",
					"value":        float64(123),
				},
			},
		},
		{
			name: "no filter",
			resourceMetrics: metricdata.ResourceMetrics{
				ScopeMetrics: []metricdata.ScopeMetrics{
					{
						Metrics: []metricdata.Metrics{
							{
								Name: "nperf_something_bytes",
								Unit: "bytes",
								Data: metricdata.Gauge[int64]{
									DataPoints: []metricdata.DataPoint[int64]{
										{
											Value: 123,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.101"),
												attribute.String("process_name", "example"),
											),
										},
										{
											Value: 97,
											Attributes: attribute.NewSet(
												attribute.String("saddr", "127.0.0.1"),
												attribute.String("daddr", "3.233.157.102"),
												attribute.String("process_name", "foo"),
											),
										},
									},
								},
							},
						},
					},
				},
			},
			want: []map[string]interface{}{
				{
					"daddr":        "3.233.157.101",
					"level":        slog.LevelInfo.String(),
					"msg":          "nperf_something_bytes",
					"process_name": "example",
					"saddr":        "127.0.0.1",
					"time":         date.Format(time.RFC3339Nano),
					"unit":         "bytes",
					"value":        float64(123),
				},
				{
					"daddr":        "3.233.157.102",
					"level":        slog.LevelInfo.String(),
					"msg":          "nperf_something_bytes",
					"process_name": "foo",
					"saddr":        "127.0.0.1",
					"time":         date.Format(time.RFC3339Nano),
					"unit":         "bytes",
					"value":        float64(97),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewFilterPrinter(
				tt.fields.IncludeNames,
				tt.fields.ExcludeNames,
				tt.fields.IncludeAttributes,
				tt.fields.ExcludeAttributes,
			)
			assert.Nil(t, err)
			var buf bytes.Buffer
			slog.SetDefault(slog.New(&testHandler{
				JSONHandler: slog.NewJSONHandler(&buf, nil),
				t:           date,
			}))
			assert.Nil(t, p.Encode(&tt.resourceMetrics))
			var output []map[string]interface{}
			scanner := bufio.NewScanner(&buf)
			for scanner.Scan() {
				data := make(map[string]interface{})
				assert.Nil(t, json.Unmarshal(scanner.Bytes(), &data))
				output = append(output, data)
			}
			assert.Equal(t, tt.want, output)
		})
	}
}
