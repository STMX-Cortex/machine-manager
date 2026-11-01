# SPDX-License-Identifier: Apache-2.0
"""Exercise the real check CLI with stable readings; live sampler coverage stays in test_live."""
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

code = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(code / "core"))
import mmread  # noqa: E402

sys.argv[0] = str(code / "bin" / "mm")
with patch.object(mmread, "check_readings", return_value=([], {}, {})):
    runpy.run_path(sys.argv[0], run_name="__main__")
