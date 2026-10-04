"""tf-nag: static Terraform plan checks for AWS Solutions."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tf-nag")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+dev"
