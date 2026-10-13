#!/usr/bin/env python3
"""Deprecated alias for `pro_fleet_assess.py --transport ssh` (kept so old command lines work)."""
import sys

from pro_fleet_assess import main

if __name__ == "__main__":
    if "--transport" not in sys.argv:
        sys.argv[1:] = ["--transport", "ssh"] + sys.argv[1:]
    main()
