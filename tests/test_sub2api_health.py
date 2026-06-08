# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

from lib.sub2api_export import Sub2ApiConfig, Sub2ApiExportProvider
from lib.sub2api_health import Sub2ApiHealthScanner, account_email, is_error_account


def test_sub2api_health_scanner_filters_group_and_errors():
    requests = []

    def fake_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        if url.endswith("/auth/login"):
            return {"access_token": "admin_token"}
        if url.endswith("/admin/accounts"):
            assert kwargs["headers"]["Authorization"] == "Bearer admin_token"
            assert kwargs["params"]["group"] == "5"
            return {
                "items": [
                    {"id": 1, "name": "ok@example.com", "status": "active", "credentials": {"email": "ok@example.com"}, "account_groups": [{"group_id": 5}]},
                    {"id": 2, "name": "bad@example.com", "status": "error", "error_message": "Token revoked", "credentials": {"email": "bad@example.com"}, "account_groups": [{"group_id": 5}]},
                ],
                "total": 2,
                "page": 1,
                "page_size": 100,
                "pages": 1,
            }
        raise AssertionError(url)

    provider = Sub2ApiExportProvider(Sub2ApiConfig(url="https://sub.example", email="admin@example.com", password="pw", group="5"), request_json=fake_request)
    summary = Sub2ApiHealthScanner(provider).scan_group(group="5")

    assert summary["total"] == 2
    assert summary["error_count"] == 1
    assert summary["ok_count"] == 1
    assert summary["error_accounts"][0]["email"] == "bad@example.com"
    assert requests[1][2]["params"]["group"] == "5"


def test_error_detection_helpers():
    assert not is_error_account({"status": "active", "credentials": {"email": "ok@example.com"}})
    assert is_error_account({"status": "active", "error_message": "401 invalidated"})
    assert account_email({"name": "n", "credentials": {"email": "cred@example.com"}}) == "cred@example.com"
