"""Root-level shim so both of these commands run the full suite::

    python -m unittest test_elfaudit -v
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests.test_elfaudit import ELFAuditFixtureTests  # noqa: E402,F401


if __name__ == "__main__":
    unittest.main(verbosity=2)
