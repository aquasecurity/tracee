package metrics

import (
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type ChannelMetrics[T any] map[string]<-chan T

func (m ChannelMetrics[T]) RegisterChannels() error {
	for name, channel := range m {
		ch := channel // copy the channel to avoid retroactive reference

		gaugeVec := prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "tracee_ebpf",
				Name:      fmt.Sprintf("pipeline_channels_%s", name),
				Help:      fmt.Sprintf("Pipeline channel %s", name),
			},
			func() float64 {
				return float64(len(ch))
			},
		)
		err := prometheus.Register(gaugeVec)
		if err != nil {
			return fmt.Errorf("failed to register channel %s: %w", name, err)
		}
	}

	return nil
}

func (m ChannelMetrics[T]) MarshalJSON() ([]byte, error) {
	type channelMetrics struct {
		ChannelName string `json:"ChannelName"`
		ChannelSize int    `json:"BufferedItems"`
	}

	channels := make([]channelMetrics, 0, len(m))
	for name, channel := range m {
		channels = append(channels, channelMetrics{ChannelName: name, ChannelSize: len(channel)})
	}

	return json.Marshal(channels)
}
