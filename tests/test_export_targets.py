# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

import argparse

import pytest

from lib.config import RuntimeConfig
from lib.errors import CpaApiError
from lib.sub2api_export import OAuthExportRecord


def _args(**overrides):
    base = dict(
        idp_base=None,
        idp_token="tok",
        client_id=None,
        channel_id=None,
        domain=None,
        email="",
        given_name="",
        family_name="",
        account_id="",
        codex_client_id=None,
        codex_redirect_uri=None,
        codex_scope=None,
        sub2api_url="https://sub.example",
        sub2api_email="admin@example.com",
        sub2api_password="pw",
        sub2api_group="5",
        model_whitelist=None,
        export_targets=None,
        cpa_url=None,
        cpa_management_key=None,
        cpa_note=None,
        artifact_dir=None,
        timeout=None,
        proxy=None,
        no_proxy=False,
        no_sub2api=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_export_targets_sub2api_default_is_old_behavior(monkeypatch):
    monkeypatch.delenv("EXPORT_TARGETS", raising=False)
    cfg = RuntimeConfig.from_env_and_args(_args())
    assert cfg.selected_export_targets == ("sub2api",)
    assert cfg.export_sub2api is True


def test_export_targets_cpa_only_skips_sub2api(monkeypatch):
    cfg = RuntimeConfig.from_env_and_args(_args(export_targets="cpa", cpa_url="https://cpa.example", cpa_management_key="key"))
    assert cfg.selected_export_targets == ("cpa",)
    assert cfg.export_sub2api is False
    cfg.validate()


def test_export_targets_sub2api_and_cpa(monkeypatch):
    cfg = RuntimeConfig.from_env_and_args(_args(export_targets="sub2api,cpa", cpa_url="https://cpa.example", cpa_management_key="key"))
    assert cfg.selected_export_targets == ("sub2api", "cpa")
    assert cfg.export_sub2api is True
    cfg.validate()


def test_cli_export_dispatch_runs_both_targets(monkeypatch, tmp_path):
    from lib import cli

    calls = []

    class FakeSub2:
        def __init__(self, config, logger=None):
            self.config = config

        def push(self, record):
            calls.append(("sub2api", record.email))
            return {"status": "success", "provider": "sub2api", "remote_id": 99}

    class FakeCpa:
        def __init__(self, config, logger=None):
            self.config = config

        def push(self, record):
            calls.append(("cpa", record.email))
            return {"status": "success", "provider": "cpa", "remote_id": "u@example.com.json"}

    monkeypatch.setattr(cli, "Sub2ApiExportProvider", FakeSub2)
    monkeypatch.setattr(cli, "CpaExportProvider", FakeCpa)
    cfg = RuntimeConfig(
        idp_token="tok",
        sub2api_url="https://sub.example",
        sub2api_email="admin@example.com",
        sub2api_password="pw",
        cpa_url="https://cpa.example",
        cpa_management_key="key",
        export_targets=("sub2api", "cpa"),
        artifact_dir=tmp_path,
    )
    record = OAuthExportRecord(account_id="acct", email="u@example.com", secret={"access_token": "acc", "refresh_token": "ref"})
    exports = cli._export_record(cfg, cli.JsonlLogger(tmp_path / "net.jsonl"), record, progress=None)
    assert calls == [("sub2api", "u@example.com"), ("cpa", "u@example.com")]
    assert set(exports) == {"sub2api", "cpa"}
    assert (tmp_path / "exports.public.json").exists()


def test_cli_export_dispatch_failure_propagates(monkeypatch, tmp_path):
    from lib import cli

    class FakeCpa:
        def __init__(self, config, logger=None):
            pass

        def push(self, record):
            raise CpaApiError("boom", stage="cpa_request")

    monkeypatch.setattr(cli, "CpaExportProvider", FakeCpa)
    cfg = RuntimeConfig(idp_token="tok", cpa_url="https://cpa.example", cpa_management_key="key", export_targets=("cpa",), artifact_dir=tmp_path)
    record = OAuthExportRecord(account_id="acct", email="u@example.com", secret={"access_token": "acc", "refresh_token": "ref"})
    with pytest.raises(CpaApiError):
        cli._export_record(cfg, cli.JsonlLogger(tmp_path / "net.jsonl"), record, progress=None)
