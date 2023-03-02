# Detections: Deliver using Falcosidekick

!!! Falcosidekick Tip
    [Falcosidekick] is a useful webhook server that can be configured to
    connect to various "outputs" such as: Slack, Mattermost, Teams, Datadog,
    Prometheus, StatsD, Email, Elasticsearch, Loki, PagerDuty, OpsGenie, and
    many more.

To use Tracee with **Falcosidekick**:

1. Obtain connection credentials to the system you want to integrate with.

    1. Consult the system's documentation and look for how to configure an
       incoming webhook.

2. Start the Falcosidekick container, configured with the obtained output
   credentials:

    1. See the [Falcosidekick Readme] for full documentation.


3. Start Tracee while configuring it to post detections to the Falcosidekick endpoint.

    1. If using Docker, you can use the simple [link] flag to allow the
       containers to communicate
    2. Use the webhook flag to point to the Falcosidekick container's endpoint
    3. Tracee ships with a built-in template for Falcosidekick

!!! Example

    1. Start Falcosidekick configured to post to Slack:
    
        ```text
        docker run --name falcosidekick -p 2801:2801 \
          -e SLACK_WEBHOOKURL=https://hooks.slack.com/services/XXX/YYY/ZZZ \
          falcosecurity/falcosidekick
        ```
    
    2. Start Tracee, linking it to the Falcosidekick container, and configuring it
       to call it on detections:
    
        ```text
        $ docker run \
            --name tracee --rm -it \
            --pid=host --cgroupns=host --privileged \
            -v /etc/os-release:/etc/os-release-host:ro \
            -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
            --link falcosidekick aquasec/tracee:{{ git.tag[1:] }} \
            --webhook-template /tracee/templates/falcosidekick.tmpl \
            --webhook-content-type application/json \
            --webhook http://FALCOSIDEKICK:2801
        ```

!!! Also Important
    1. [Deliver using a Webhook](./webhook.md)
    2. [Deliver using Postee](./postee.md)

[link]: https://docs.docker.com/network/links/
[Falcosidekick Readme]: https://github.com/falcosecurity/falcosidekick
[Falcosidekick]: https://github.com/falcosecurity/falcosidekick
