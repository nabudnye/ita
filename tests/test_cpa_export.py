# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

import pytest

from lib.cpa_export import CpaConfig, CpaExportProvider
from lib.errors import ConfigError
from lib.sub2api_export import OAuthExportRecord


def test_cpa_payload_and_push_verifies_auth_file():
    requests = []

    def fake_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer mgmt_secret"
        if method == "POST":
            assert url == "https://cpa.example/v0/management/auth-files?name=u%40example.com.json"
            body = kwargs["json_body"]
            assert body["type"] == "codex"
            assert body["email"] == "u@example.com"
            assert body["account_id"] == "acct_1"
            assert body["access_token"] == "acc"
            assert body["refresh_token"] == "ref"
            assert body["id_token"] == "id"
            assert body["expired"] == "2026-06-08T10:00:00Z"
            assert body["last_refresh"] == "2026-06-08T09:00:00Z"
            assert body["priority"] == 3
            assert body["note"] == "note"
            return {"status": "ok"}
        if method == "GET":
            assert url == "https://cpa.example/v0/management/auth-files"
            return {"files": [{"name": "u@example.com.json", "email": "u@example.com"}]}
        raise AssertionError((method, url))

    provider = CpaExportProvider(CpaConfig(url="https://cpa.example", management_key="mgmt_secret", priority=3, note="note"), request_json=fake_request)
    record = OAuthExportRecord(
        account_id="acct_1",
        email="u@example.com",
        secret={
            "access_token": "acc",
            "refresh_token": "ref",
            "id_token": "id",
            "account_id": "acct_1",
            "expired": "2026-06-08T10:00:00Z",
            "last_refresh": "2026-06-08T09:00:00Z",
        },
    )

    payload = provider.build_auth_payload(record)
    assert payload["priority"] == 3
    assert provider.filename_for(record) == "u@example.com.json"
    result = provider.push(record)

    assert result["provider"] == "cpa"
    assert result["remote_id"] == "u@example.com.json"
    assert result["remote_action"] == "uploaded"
    assert [item[0] for item in requests] == ["POST", "GET"]


def test_cpa_config_requires_url_and_management_key():
    with pytest.raises(ConfigError) as excinfo:
        CpaExportProvider(CpaConfig(url="", management_key=""))
    assert "CPA_URL" in str(excinfo.value)
    assert "CPA_MANAGEMENT_KEY" in str(excinfo.value)
