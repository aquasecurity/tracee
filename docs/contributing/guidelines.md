# Style Guide for Contributors

For those willing to contribute to Tracee, this repository has code formatting
guidelines being enforced.

## Contributing to Documentation

Our documentation aims to follow the [Diátaxis documentation framework](https://diataxis.fr/) which includes:

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

## Contributing to Code

To contribute to the code:

1. Clone the Tracee GitHub repository.
2. Make changes to code.
3. Before committing your changes, run the following command:
    1. Check your PR:

        ```bash
        make check-pr
        ```

        This command will run:
        1. `check-fmt` - Check for formatting changes
        2. `check-lint` - Lint golang code
        3. `check-code` - Static Check Go and C source files
        4. `format-pr` - Show PR commits

    2. Fix Go and C source files formatting

        ```bash
        make fix-fmt
        ```

        After you run the fix, check your git status.

        ```bash
        git status -s
        ```
