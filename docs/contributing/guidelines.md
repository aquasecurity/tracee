# Style Guide for Contributors

For those willing to contribute to Tracee, this repository has code formatting
guidelines being enforced.

## Contributing to Documentation

Our documentation aims to follow the [Diátaxis documentation framework](https://diataxis.fr/).

To contribute to the documentation:

1. Clone the Tracee GitHub repository.
2. Make changes in the `/docs` directory in the root folder.
3. Remember to edit the index in `mkdocs.yml` if you add or move existing files or directories.
4. Test your changes to the documentation.

### Test Documentation Changes

You can test your changes to the documentation by building and running a docker container.
Prerequisites: Docker installed and running locally.
Build the container image:

```bash
make -f ./builder/Makefile.mkdocs mkdocs-build
```

Serve the container image:

```bash
make -f ./builder/Makefile.mkdocs mkdocs-serve
```

Open `localhost:8000/tracee`

Now you should see the documentation.
Check that everything is like you intent.

And finally Submit a PR about the changes.

## Contributing to Tracee Code

We welcome contributions to Tracee's codebase! Before submitting your changes, please familiarize yourself with these guidelines.
To contribute to the code:

### Before You Commit

Tracee relies on several generated files and has strict formatting requirements. Ensure you run the following commands before committing:

**`NOTE:`** In order to not depend on host's libraries versions, we recommend that you always run make and other project dependencies on a virtual environment so the formatting will be align with Tracee guidelines

1. Man Pages Generation: If you've modified core code or documentation that impacts the man pages, run:

    ```bash
    make -f builder/Makefile.man
    ```

    This regenerates the man pages to reflect your changes.

2. Protocol Buffer Compilation: If your changes involve modifications to protocol buffer (`.proto`) files,run:

    ```bash
    make -f builder/Makefile.man
    ```

    This regenerates the corresponding Go code.

3. Pre-commit checks: Every time you're about to create a pull request, execute:

    **`NOTE:`**  If your host machine dependencies doesn't align with Tracee dependencies, This command have to run on a supported [environment](./building/environment.md)

    ```bash
    make check-pr
    ```

    This command performs essential checks:
    - `check-fmt`: Verifies code formatting adheres to project standards.
    - `check-lint`: Runs linting tools (e.g., `golangci-lint`) to catch potential issues.
    - `check-code`: Performs static code analysis for both Go and C code.
    - `format-pr`: Displays the commits in your PR in a standardized format.

    **Note:** `check-fmt`,`check-lint`,`check-code`,`format-pr` are individual make command combined under `check-pr`. You can run the following command without any vm using Makefile

    - For `check-fmt`:

        ```bash
        make -f builder/Makefile.checkers fmt-check
        ```

    - For `check-code`:

        ```bash
        make -f builder/Makefile.checkers code-check
        ```

4. Fixing Code Formatting: If `check-fmt` reports issues, use:

    ```bash
    make -f builder/Makefile.checkers fmt-fix
    ```

    This automatically formats your Go and C code to meet project standards. Review the changes with `git status -s` before committing.

### Performance Considerations

Performance is a critical aspect of Tracee.

To ensure your contributions maintain optimal performance, follow the guidelines in [Performance Considerations](./performance.md) page.

### Kubernetes Considerations

If your contribution impacts Tracee's behavior within a Kubernetes cluster, follow the guidelines in [Kubernetes Considerations](./kubernetes.md).
