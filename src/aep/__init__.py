"""Autonomous Engineering Platform (AEP) - Phase 1 core."""
from importlib.metadata import PackageNotFoundError, version

# Single canonical version source: installed package metadata (generated
# from pyproject.toml's [project].version at build time) - never a
# second hand-typed literal here, see BUGFIX.md BUG-0024/0.1.1 release.
try:
    __version__ = version("aep-platform")
except PackageNotFoundError:
    __version__ = "0+unknown"
