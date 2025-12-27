# Test Chain: Netcat Detection Example

Simple 3-level chain for local testing (no K8s required).

## Files

1. `chain_level1_netcat.yaml` - Detects netcat execution
2. `chain_level2_container.yaml` - Detects netcat in containers (MEDIUM)
3. `chain_level3_k8s.yaml` - Alerts on all netcat in containers (HIGH)

## Quick Test

### Terminal 1: Start Tracee
```bash
sudo tracee --detectors yaml-dir=./examples/detectors/yaml --output json \
  --enrichment container \
  --events netcat_privileged_alert
```

### Terminal 2: Trigger Detection
```bash
# Simple: just run nc (triggers level 1 only)
nc localhost 8080

# Better: run nc in container (triggers full chain)
docker run --rm alpine nc localhost 8080
```

### View the Chain
Output will show:
```json
{
  "name": "netcat_privileged_alert",
  "detected_from": {
    "name": "netcat_in_container",
    "parent": {
      "name": "netcat_execution",
      "parent": {
        "name": "sched_process_exec"
      }
    }
  }
}
```

Use `jq` to extract chain:
```bash
sudo tracee ... | jq '.detected_from.name, .detected_from.parent.name, .detected_from.parent.parent.name'
```

