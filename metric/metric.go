package metric

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"
)

type Datapoint[N int64 | float64] struct {
	Value      N
	Attributes []attribute.KeyValue
}

func SendDatapoint[N int64 | float64](ch chan<- Datapoint[N], dp Datapoint[N]) {
	select {
	case ch <- dp:
	default:
		slog.Warn("can't send a datapoint")
	}
}

func RegisterFloat64(m metric.Meter, ch chan Datapoint[float64], obs metric.Float64ObservableGauge) error {
	_, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for {
			select {
			case dp := <-ch:
				o.ObserveFloat64(obs, dp.Value, metric.WithAttributes(dp.Attributes...))
			default:
				// To avoid blocking the callback.
				return nil
			}
		}
	}, obs)
	return err
}

func RegisterInt64(m metric.Meter, ch chan Datapoint[int64], obs metric.Int64ObservableGauge) error {
	_, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for {
			select {
			case dp := <-ch:
				o.ObserveInt64(obs, dp.Value, metric.WithAttributes(dp.Attributes...))
			default:
				// To avoid blocking the callback.
				return nil
			}
		}
	}, obs)
	return err
}
