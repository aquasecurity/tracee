# Contributing to the documentation

We welcome contributions to the Tracee documentation.

Our documentation aims to follow the [Diátaxis documentation framework](https://diataxis.fr/) which includes:

1. A getting started section -- Installation Guidelines and simple scenarios
2. Tutorials -- End-to-end tutorials that have real-world use cases
3. Reference Material -- How to use Tracee
4. Contribution Guidelines

To contribute to the documentation please

1. Clone the Tracee GitHub repository
2. Make changes in the `./docs` directory in the root folder
3. Remember to edit the index in `mkdocs.yml` in the root folder if you add or move existing files or directories
4. Test your changes to the documentation
5. Submit a PR

## Test Documentation Changes

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


