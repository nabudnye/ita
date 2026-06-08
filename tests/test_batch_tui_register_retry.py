# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

import queue

from lib.batch_tui import _run_one
from lib.config import RuntimeConfig
from lib.errors import OAuthFlowError


def test_register_retry_reuses_generated_account(monkeypatch, tmp_path):
    seen_existing_ids = []

    def fake_run_single(cfg, *, progress):
        seen_existing_ids.append(cfg.existing_account_id)
        if not cfg.existing_account_id:
            progress("账号已准备", {"id": 123, "email": "reuse@example.com"})
            raise OAuthFlowError("first attempt failed after account generated", stage="codex_authorize")
        progress("账号已准备", {"id": 123, "email": "reuse@example.com"})
        return {
            "account": {"id": 123, "email": "reuse@example.com"},
            "sub2api": {"remote_id": 999},
        }

    monkeypatch.setattr("lib.batch_tui.run_single", fake_run_single)
    events = queue.Queue()
    cfg = RuntimeConfig(idp_token="tok", sub2api_url="https://sub.example", sub2api_email="admin@example.com", sub2api_password="pw")

    _run_one(1, cfg, tmp_path, events, retries=2)

    assert seen_existing_ids == ["", "123"]
    kinds = []
    while not events.empty():
        kinds.append(events.get()["type"])
    assert kinds[-1] == "success"
