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
Check that everything is as you intended.

And finally Submit a PR about the changes.

## Contributing to Tracee Code

We welcome contributions to Tracee's codebase! Before submitting your changes, please familiarize yourself with these guidelines.
To contribute to the code:

### Before You Commit

Before submitting code changes, ensure you follow these essential steps:

1. **Generated Files**: If you've modified certain types of files, regenerate the corresponding outputs:
   - **Man pages**: Run `make -f builder/Makefile.man` if you changed core code or documentation
   - **Protocol buffers**: Run `make -f builder/Makefile.protoc` if you modified `.proto` files

2. **Code Quality**: Run comprehensive code quality checks:
   ```bash
   make check-pr
   ```

   This verifies formatting, runs linting, performs static analysis, and validates your changes meet project standards.

3. **Development Environment**: For consistent results, use a supported [development environment](./building/environment.md) when running checks.

For detailed information about these tools, troubleshooting, and advanced options, see our comprehensive [Code Quality Guide](checkpatch.md).

### Performance Considerations

Performance is a critical aspect of Tracee.

To ensure your contributions maintain optimal performance, follow the guidelines in [Performance Considerations](./performance.md) page.

### Kubernetes Considerations

If your contribution impacts Tracee's behavior within a Kubernetes cluster, follow the guidelines in [Kubernetes Considerations](./kubernetes.md).
