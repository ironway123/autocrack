"""Make `autocrack` importable when pytest collects this test from any dir."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
