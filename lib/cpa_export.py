# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

"""CLIProxyAPI (CPA) Codex auth-file export provider."""
from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .config import parse_int
from .errors import ConfigError, CpaApiError
from .logging_utils import JsonlLogger, redact, utc_now_iso
from .sub2api_export import OAuthExportRecord, first_non_empty

RequestJson = Callable[..., Any]


@dataclass(frozen=True)
class CpaConfig:
    url: str
    management_key: str
    priority: int = 1
    note: str = "Idp Team Automation"

    def validate(self) -> None:
        missing = []
        if not self.url:
            missing.append("CPA_URL")
        if not self.management_key:
            missing.append("CPA_MANAGEMENT_KEY")
        if missing:
            raise ConfigError("缺少 CPA 配置：" + ", ".join(missing), stage="cpa_config")


class CpaExportProvider:
    name = "cpa"

    def __init__(self, config: CpaConfig, *, logger: JsonlLogger | None = None, request_json: RequestJson | None = None):
        self.config = config
        self.config.validate()
        self.logger = logger
        self.request_json = request_json or self._request_json

    def _management_base(self, raw_url: str) -> str:
        base = str(raw_url or "").strip().rstrip("/")
        if not base:
            raise ConfigError("缺少 CPA_URL", stage="cpa_config")
        if base.endswith("/v0/management"):
            return base
        if base.endswith("/v0"):
            return f"{base}/management"
        return f"{base}/v0/management"

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config.management_key}"}

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        timeout: float = 20,
    ) -> Any:
        body = None if json_body is None else json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        default_headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0 IdpTeamAutomation/0.1",
        }
        if json_body is not None:
            default_headers["Content-Type"] = "application/json"
        merged_headers = {**default_headers, **(headers or {})}
        if self.logger:
            self.logger.write("cpa_request", {"method": method, "url": url, "headers": merged_headers, "body": json_body})
        req = urllib.request.Request(url, data=body, method=method, headers=merged_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                try:
                    payload = json.loads(text) if text.strip() else {}
                except Exception:
                    payload = {"text": text}
                if self.logger:
                    self.logger.write("cpa_response", {"method": method, "url": url, "status": resp.status, "body": payload})
                return payload
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(text) if text.strip() else {}
            except Exception:
                payload = {}
            if self.logger:
                self.logger.write("cpa_error", {"method": method, "url": url, "status": exc.code, "body": payload or text[:500]})
            message = payload.get("message") or payload.get("detail") or text[:200] or f"HTTP {exc.code}"
            raise CpaApiError(f"CPA request failed: {message}", stage="cpa_request", retryable=exc.code in {408, 409, 425, 429} or exc.code >= 500, data={"status": exc.code, "response": redact(payload)}) from exc
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, socket.timeout, ConnectionResetError) as exc:
            if self.logger:
                self.logger.write("cpa_error", {"method": method, "url": url, "error": str(exc)})
            raise CpaApiError(f"CPA request failed: {exc}", stage="cpa_request", retryable=True) from exc

    def filename_for(self, record: OAuthExportRecord) -> str:
        stem = first_non_empty(record.email, record.account_id, record.secret.get("account_id"), "codex_auth")
        safe = re.sub(r"[^A-Za-z0-9._@+-]+", "_", stem).strip("._-")
        if not safe:
            safe = "codex_auth"
        if not safe.lower().endswith(".json"):
            safe = f"{safe}.json"
        return safe[:180]

    def build_auth_payload(self, record: OAuthExportRecord) -> dict[str, Any]:
        return {
            "type": "codex",
            "email": first_non_empty(record.email, record.metadata.get("email")),
            "account_id": first_non_empty(record.secret.get("account_id"), record.account_id, record.metadata.get("remote_account_id")),
            "access_token": str(record.secret.get("access_token") or ""),
            "refresh_token": str(record.secret.get("refresh_token") or ""),
            "id_token": str(record.secret.get("id_token") or ""),
            "expired": first_non_empty(record.secret.get("expired"), record.metadata.get("expired")),
            "last_refresh": first_non_empty(record.secret.get("last_refresh"), record.metadata.get("last_refresh"), utc_now_iso()),
            "priority": parse_int(self.config.priority, 1, minimum=1),
            "note": str(self.config.note or ""),
        }

    def _auth_files(self, data: Any) -> list[Any]:
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        for key in ("files", "items", "records", "data", "auth_files"):
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = self._auth_files(value)
                if nested:
                    return nested
        return []

    def _file_matches(self, item: Any, *, filename: str, email: str) -> bool:
        wanted_name = str(filename or "").strip().lower()
        wanted_email = str(email or "").strip().lower()
        if isinstance(item, str):
            return item.strip().lower() == wanted_name
        if not isinstance(item, dict):
            return False
        content = item.get("content") if isinstance(item.get("content"), dict) else {}
        auth = item.get("auth") if isinstance(item.get("auth"), dict) else {}
        name = first_non_empty(item.get("name"), item.get("filename"), item.get("file"), item.get("path"))
        item_email = first_non_empty(item.get("email"), content.get("email"), auth.get("email"))
        return bool((name and name.strip().lower() == wanted_name) or (wanted_email and item_email.strip().lower() == wanted_email))

    def verify_uploaded(self, *, filename: str, email: str) -> bool:
        base = self._management_base(self.config.url)
        data = self.request_json("GET", f"{base}/auth-files", headers=self._auth_headers(), timeout=20)
        return any(self._file_matches(item, filename=filename, email=email) for item in self._auth_files(data))

    def push(self, record: OAuthExportRecord) -> dict[str, Any]:
        base = self._management_base(self.config.url)
        filename = self.filename_for(record)
        payload = self.build_auth_payload(record)
        if not first_non_empty(payload.get("access_token"), payload.get("refresh_token")):
            raise CpaApiError("CPA 导出缺少 access_token/refresh_token", stage="cpa_payload")
        upload_url = f"{base}/auth-files?{urllib.parse.urlencode({'name': filename})}"
        uploaded = self.request_json("POST", upload_url, headers=self._auth_headers(), json_body=payload, timeout=20)
        if isinstance(uploaded, dict) and "status" in uploaded:
            status = str(uploaded.get("status") or "").lower()
            if status and status not in {"ok", "success", "0"}:
                raise CpaApiError(str(uploaded.get("message") or uploaded), stage="cpa_response", data={"response": redact(uploaded)})
        if not self.verify_uploaded(filename=filename, email=str(payload.get("email") or "")):
            raise CpaApiError("CPA auth 文件上传后校验失败", stage="cpa_verify", retryable=True, data={"filename": filename, "email": payload.get("email")})
        return {
            "status": "success",
            "provider": self.name,
            "email": record.email,
            "account_id": record.account_id,
            "remote_id": filename,
            "remote_action": "uploaded",
        }
