# Detections: Deliver using a Webhook

In addition, Tracee can notify a web service when a detection is made using a
custom webhook:

```bash
tracee-rules --webhook http://my.webhook/endpoint \
    --webhook-template /path/to/my.tmpl \
    --webhook-content-type application/json
```

!!! Also Important
    1. [Deliver using Postee](./postee.md)
    2. [Deliver using Falcosidekick](./falcosidekick.md)
