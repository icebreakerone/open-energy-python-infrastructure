# Documentation

Docs are built using Sphinx, making use of a theme from readthedocs.

## Make targets

`make html` to build docs locally

## Sphinx installation

Using Python 3.8

```
> pip install sphinx sphinx-rtd-theme
```

To pick up the library code when building docs, use `python setup.py develop` to symlink
working directory into the virtual environment's package set.