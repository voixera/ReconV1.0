"""Allow ``python -m vxrecon`` to run the CLI."""

from __future__ import annotations

import sys

from vxrecon.ui.cli import main

if __name__ == "__main__":
    sys.exit(main())
