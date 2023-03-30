# Documentation

`tracee-bench` is a promQL based tool to query `tracee` runtime performance metrics.
It can be used to benchmark tracee's event pipeline's (see [here](https://aquasecurity.github.io/tracee/dev/architecture/)) performance on your environment.

## Enabling Prometheus

In order to use prometheus with tracee see [this](https://aquasecurity.github.io/tracee/dev/integrating/prometheus/) documentation.
A simple script for running a prometheus container scraping tracee is available in this repository in `prometheus.sh`.

## Metrics tracked

`tracee-bench` tracks three important stats about tracee's performance in your environment:1
1. Avg rate of events emitted per second
2. Avg rate of events lost per second
3. Overall events lost

Ideal performance of tracee should have a stable throughput of events emitted with minimal event loss. If heavy event loss occurs, consider tuning tracee either through [filtering](https://aquasecurity.github.io/tracee/dev/tracing/event-filtering/) or allocating additional CPU (if running on kubernetes).
