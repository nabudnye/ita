# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

from lib.config import RuntimeConfig
from lib.reauthorize_sub2api_errors import run


def test_reauthorize_dry_run(monkeypatch, tmp_path):
    class FakeProvider:
        def __init__(self, config):
            self.config = config

    class FakeScanner:
        def __init__(self, provider):
            self.provider = provider

        def list_accounts(self, *, group):
            assert group == "5"
            return [
                {"id": 1, "status": "active", "name": "ok@example.com", "credentials": {"email": "ok@example.com"}},
                {"id": 2, "status": "error", "error_message": "Token revoked", "name": "bad@example.com", "credentials": {"email": "bad@example.com"}},
            ]

    monkeypatch.setattr("lib.reauthorize_sub2api_errors.Sub2ApiExportProvider", FakeProvider)
    monkeypatch.setattr("lib.reauthorize_sub2api_errors.Sub2ApiHealthScanner", FakeScanner)

    cfg = RuntimeConfig(
        idp_token="tok",
        sub2api_url="https://sub.example",
        sub2api_email="admin@example.com",
        sub2api_password="pw",
        sub2api_group="5",
        artifact_dir=tmp_path,
    )
    summary = run(cfg, apply=False, progress=None)
    assert summary["status"] == "dry_run"
    assert summary["total"] == 2
    assert summary["detected_error_count"] == 1
    assert summary["error_count"] == 1
    assert summary["planned"][0]["email"] == "bad@example.com"
    assert (tmp_path / "reauth_summary.json").exists()
