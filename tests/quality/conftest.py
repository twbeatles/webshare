"""Quality suite conftest: expose the live loopback harness fixtures.

Fixtures are imported (not via ``pytest_plugins``, which pytest forbids in
non-top-level conftests) so test modules receive ``live_server`` and
``go_live_server`` parameters directly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_harness import go_live_server, live_server  # noqa: F401
