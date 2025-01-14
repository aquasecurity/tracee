# Performance Considerations

1. **Profiling Tracee for Performance test** - Tracee integrates with Pyroscope and Pprof for continuous profiling. When running Tracee locally for development or testing, use the `--pyroscope --pprof` command-line option.

    ```bash
    sudo ./dist/tracee --pyroscope --pprof
    ```

    This enables profiling data to be sent to a local server. The Tracee repository includes a convenient way to deploy a performance dashboard for analyzing this data. Run the following for more details:

    ```bash
    make -f builder/Makefile.performance help
    ```

2. **Performance Dashboard:** The provided performance dashboard allows visualization of host metrics, CPU flame graphs, and other performance-related data. Follow these steps to deploy locally and see instructions on using the dashboard:

    ```bash
    make -f builder/Makefile.performance dashboard-start
    ```

    ```bash
    make -f builder/Makefile.performance dashboard-stop
    ```

3. **Benchmarking:** Before submitting significant code changes, consider running benchmarks to assess their impact on Tracee's performance. (Details on specific benchmarking tools or scripts used within the Tracee project should be added here. If there are existing benchmarks, provide instructions on how to run them. If not, suggest a methodology).

4. **Common Performance Pitfalls:**

    - **Excessive eBPF Events:** Be mindful of the number and frequency of eBPF events being generated. Overly frequent events can lead to performance overhead. (Provide Tracee-specific examples or best practices to avoid this, such as filtering events effectively or using appropriate sampling rates.)
    - **Inefficient eBPF Programs:** Optimize your eBPF programs for minimal overhead. (Provide Tracee-specific guidance. Are there common patterns to avoid within Tracee's eBPF context?)
    - **Resource Consumption:** Consider the CPU and memory usage of Tracee itself. Avoid unnecessary allocations or computations.

By adhering to these practices, you can contribute to Tracee's performance and help ensure its efficiency. Remember that performance is an ongoing effort, so continuous profiling, benchmarking, and optimization are essential.
