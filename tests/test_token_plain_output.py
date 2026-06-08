# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

import json

from lib.codex_oauth import OAuthStart
from lib.idp_client import GeneratedAccount
from lib.sso_http_flow import SSOHttpFlow


class FakeFlow(SSOHttpFlow):
    def prime_sso_session(self, start_url, account):
        return None

    def authorize_codex(self, oauth, account):
        return {
            "type": "codex",
            "email": account.email,
            "account_id": "acct_plain",
            "access_token": "plain_acc",
            "refresh_token": "plain_ref",
            "id_token": "plain_id",
            "expired": "2026-06-08T10:00:00Z",
            "last_refresh": "2026-06-08T09:00:00Z",
        }


def test_sso_flow_writes_plain_private_token_json(tmp_path):
    flow = FakeFlow(artifact_dir=tmp_path)
    account = GeneratedAccount(id=1, email="u@example.com", password="pw")
    oauth = OAuthStart(auth_url="https://example.com", state="s", code_verifier="v", redirect_uri="http://localhost/cb")
    token = flow.run(start_url="https://idp.example/start", oauth=oauth, account=account)
    saved = json.loads((tmp_path / "token.private.json").read_text(encoding="utf-8"))
    assert token["access_token"] == "plain_acc"
    assert saved["access_token"] == "plain_acc"
    assert saved["refresh_token"] == "plain_ref"
    assert saved["id_token"] == "plain_id"
