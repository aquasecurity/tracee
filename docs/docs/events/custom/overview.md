# Custom Events

Tracee comes with many built-in events, but you can extend its capabilities by creating custom events tailored to your specific needs.

## Modern Approach: Detectors

**Recommended**: The modern way to create custom threat detections and derived events is using the **EventDetector API**.

**📖 See the [Detector Documentation](../../detectors/index.md) for complete guide and examples.**

Key benefits:
- Type-safe protobuf access
- Rich data extraction helpers
- System state access (process trees, containers, DNS)
- Declarative filtering and auto-enrichment
- Built-in metrics and observability
- No plugin complexity

## Legacy Approach: Signatures (Plugin System)

The older signature system using `.so` plugins is still supported for backward compatibility, but we recommend migrating to detectors.

Refer to the [Go](./golang.md) documentation for instructions on the legacy plugin-based approach.

### Loading Signatures

Once you've created a signature plugin, load it using the `signatures-dir` flag:

```bash
tracee --signatures-dir=/tmp/myevents
```

!!! Tip
    Tracee also uses the custom events to add a few events, if you pass your own directory
    for `signatures-dir` you will not load the tracee [signatures](../builtin/security-events.md),
    to avoid such problems, you can either place your own events under the same directory of the tracee custom events,
    or pass multiple directories for example:
    ```bash
    tracee --signatures-dir=/tmp/myevents --signatures-dir=./dist/signatures
    ```

### Migrating from Signatures to Detectors

The [Detector API Reference](../../detectors/api-reference.md#migration-from-signatures) includes complete migration instructions with:

- Step-by-step migration guide
- Before/after code examples
- Pattern translations
- Migration checklist

---

## Choose Your Approach

| Feature | Detectors (Modern) | Signatures (Legacy) |
|---------|-------------------|---------------------|
| Type Safety | ✅ Compile-time | ❌ Runtime casting |
| Data Access | ✅ Type-safe helpers | ❌ Manual parsing |
| System State | ✅ Full datastore access | ❌ Limited |
| Event Filtering | ✅ Declarative | ❌ Manual in code |
| Auto-Enrichment | ✅ Process ancestry, threat metadata | ❌ Manual |
| Deployment | ✅ Compiled-in | ❌ Separate .so files |
| Testing | ✅ Direct function calls | ❌ Callback mocking |
| Observability | ✅ Built-in metrics | ❌ Manual |
| Documentation | ✅ [Complete guide](../../detectors/index.md) | ✅ [Legacy docs](./golang.md) |

**Recommendation**: Use detectors for all new development. Migrate existing signatures over time.

👈 Please use the side-navigation on the left in order to browse the different topics.
