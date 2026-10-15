"""Prism -- rotating-source-IP proxy infrastructure for authorized red-team work.

The CLI lives in prism.cli; its public helpers are re-exported here so callers
(and the test suite) can do `import prism; prism.build_parser()` /
`prism.ensure_endpoints(...)` / `prism.find_mitmdump()` as before the code moved
into a package.
"""
from prism.cli import *  # noqa: F401,F403 -- re-export the CLI's public API
from prism.cli import build_parser, ensure_endpoints, find_mitmdump, main  # noqa: F401
