"""VXRecon entrypoint shim.

Allows ``python vxrecon.py <args>`` from a source checkout without installing.
Installed users should use the ``vxrecon`` console script instead.
"""

from __future__ import annotations

import sys

from vxrecon.ui.cli import main

if __name__ == "__main__":
    sys.exit(main())
