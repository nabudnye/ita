#!/usr/bin/env python3
# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

"""Entrypoint for Sub2API error account reauthorization."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.reauthorize_sub2api_errors import main


if __name__ == "__main__":
    raise SystemExit(main())
