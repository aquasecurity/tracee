# Deploy Grafana Dashboard

Grafana is a visualization tools for exported metrics and logs, most commomly
used alongside prometheus.

Since version 0.7.0, tracee exports useful runtime metrics to prometheus.

These metrics exports are enabled by default in all docker images and can be
enabled using the `--metrics` flag in both [tracee-ebpf] and [tracee-rules].

[tracee-ebpf]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/cmd/tracee-ebpf
[tracee-rules]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/cmd/tracee-rules

By using grafana and the new metrics from tracee, we can deploy a simple
dashboard which tracks your tracee's instance performance and outputs.

## Prequisites

The following tools must be available for use, they can all be installed either
through docker or installed/built on your machine.

- [Tracee](https://github.com/aquasecurity/tracee/)
- [Prometheus](https://prometheus.io/download/)
- [Grafana](https://grafana.com/docs/grafana/latest/getting-started/getting-started)

## Run Tracee with Metrics Enabled

Tracee can be most easily deployed with metrics enabled by default and port
forwarded through the following commands:

```text
$ docker run \
    --name tracee --rm --pid=host \
    --cgroupns=host --privileged \
    -v /tmp/tracee:/tmp/tracee  \
    -v /etc/os-release:/etc/os-release-host:ro \
    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
    -it -p 3366:3366 -p 4466:4466 aquasec/tracee:{{ git.tag }}
```

Of course, the forwarded metrics ports can be changed, but you should note that
some of the later instructions depend on these ports.

If running Tracee locally through built binaries, the metrics address may be
overriden with the `--listen-addr` flag in both tracee-ebpf and tracee-rules.

## Run Prometheus and Configure it to Scrape Tracee

Install prometheus or pull it's docker image. Then create the following
configuration file, call it `prometheus.yml` to scrape Tracee:

```text
# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Tracee.
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'prometheus'

    # Override the global default and scrape targets from this job every 5 seconds.
    scrape_interval: 5s

    #Scrape tracee-ebpf's and tracee-rules's default metrics hosts.
    #If forwarding different ports make sure to change these addresses.
    static_configs:
      - targets: ['localhost:3366', 'localhost:4466']
```

We must then start prometheus with the following command:

```
prometheus --config.file=/path/to/prometheus.yml
```

Or alternatively with docker:

```
docker run -p 9090:9090 -v /path/to/config:/etc/prometheus prom/prometheus
```

Then, try to access prometheus through `http://localhost:9090`. If succesful,
move to the next step, otherwise consult with prometheus documentation.

## Run Grafana to display Tracee's Prometheus Metrics

After succesfuly deploying Tracee and Prometheus we may now run Grafana to
visualize it's metrics.

Install grafana using their instructions and enter the now available grafana
website (by default it's usually through http://localhost:3000).

After entering the website, logging in with username and password `admin` (and
changing your password if you wish), you should see the homepage:

![image](https://user-images.githubusercontent.com/22661609/160572543-771d4a0e-d7d8-46d2-bf51-7c9f64487bf8.png)

Add your data source by hovering the configuration tab (the gear icon),
selecting "Data Sources" and pressing "Add Data Source" at the top left. Create
a Prometheus Data Source and point it's URL to the relevant location (usually
http://localhost:9090)

You may now either create your own Dashboard or import our default dashboard.

## Import Tracee's Default Dashboard

First download our Grafana Dashboard's json [here].

[here]: https://github.com/aquasecurity/tracee/tree/main/deploy/grafana/tracee.json

After adding the data source hover on the plus icon in the sidebar and select
"Import". Press "Upload JSON File" at the top of the page and select the
downloaded json from your file browser. Change the name and Dashboard UID if
you wish and press "Import" to finish. 

Finally you will be redirected to the dashboard 🥳
