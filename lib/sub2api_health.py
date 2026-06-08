# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

"""Sub2API account health scanning helpers."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import RuntimeConfig, load_dotenv, parse_int
from .errors import IdpTeamAutomationError, Sub2ApiError
from .logging_utils import redact
from .sub2api_export import Sub2ApiConfig, Sub2ApiExportProvider, first_non_empty


@dataclass(frozen=True)
class AccountHealth:
    id: int
    name: str
    email: str
    status: str
    error: str
    group_ids: list[int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "status": self.status,
            "error": self.error,
            "group_ids": self.group_ids,
        }


def _group_ids(item: dict[str, Any]) -> list[int]:
    ids: list[int] = []
    for rel in item.get("account_groups") or []:
        if not isinstance(rel, dict):
            continue
        raw = rel.get("group_id")
        if raw is None and isinstance(rel.get("group"), dict):
            raw = rel["group"].get("id")
        try:
            gid = int(raw)
        except (TypeError, ValueError):
            continue
        if gid not in ids:
            ids.append(gid)
    for raw in item.get("group_ids") or []:
        try:
            gid = int(raw.get("id") or raw.get("group_id") if isinstance(raw, dict) else raw)
        except (TypeError, ValueError):
            continue
        if gid not in ids:
            ids.append(gid)
    return ids


def _credentials(item: dict[str, Any]) -> dict[str, Any]:
    return item.get("credentials") if isinstance(item.get("credentials"), dict) else {}


def account_email(item: dict[str, Any]) -> str:
    creds = _credentials(item)
    return first_non_empty(creds.get("email"), item.get("email"), item.get("name"))


def status_text(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("status", "state", "credential_status", "health_status", "credentials_state"):
        value = item.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    cred_status = item.get("credentials_status") if isinstance(item.get("credentials_status"), dict) else {}
    for key in ("status", "state", "valid", "is_valid", "healthy"):
        value = cred_status.get(key)
        if value not in (None, ""):
            parts.append(f"credentials_status.{key}={value}")
    return " | ".join(parts) or "-"


def error_message(item: dict[str, Any]) -> str:
    return first_non_empty(item.get("error_message"), item.get("last_error"), item.get("error"))


def is_error_account(item: dict[str, Any]) -> bool:
    if error_message(item):
        return True
    blob = status_text(item).lower()
    bad_markers = ("error", "invalid", "failed", "fail", "inactive", "disabled", "paused", "expired", "unauthorized", "401")
    good_markers = ("active", "ok", "valid", "healthy", "normal", "success")
    if any(marker in blob for marker in bad_markers):
        return True
    return blob != "-" and not any(marker in blob for marker in good_markers)


def to_health(item: dict[str, Any]) -> AccountHealth:
    try:
        account_id = int(item.get("id") or 0)
    except (TypeError, ValueError):
        account_id = 0
    return AccountHealth(
        id=account_id,
        name=str(item.get("name") or ""),
        email=account_email(item),
        status=status_text(item),
        error=error_message(item),
        group_ids=_group_ids(item),
    )


class Sub2ApiHealthScanner:
    def __init__(self, provider: Sub2ApiExportProvider):
        self.provider = provider

    def list_accounts(self, *, group: str, page_size: int = 100) -> list[dict[str, Any]]:
        api_base = self.provider._api_base(self.provider.config.url)
        token = self.provider._login(api_base)
        headers = self.provider._auth_headers(token)
        accounts: list[dict[str, Any]] = []
        page = 1
        page_size = max(1, min(500, int(page_size or 100)))
        while True:
            params = {"page": page, "page_size": page_size}
            if str(group or "").strip():
                params["group"] = str(group).strip()
            data = self.provider.request_json("GET", f"{api_base}/admin/accounts", headers=headers, params=params, timeout=30)
            if isinstance(data, dict):
                items = data.get("items") or data.get("records") or data.get("data") or []
                total = parse_int(data.get("total"), 0, minimum=0)
                pages = parse_int(data.get("pages"), 0, minimum=0)
            elif isinstance(data, list):
                items = data
                total = 0
                pages = 0
            else:
                raise Sub2ApiError(f"Sub2API 账号列表返回格式异常：{type(data).__name__}", stage="sub2api_accounts")
            dict_items = [item for item in items if isinstance(item, dict)]
            accounts.extend(dict_items)
            if pages and page >= pages:
                break
            if total and len(accounts) >= total:
                break
            if len(dict_items) < page_size:
                break
            page += 1
        return accounts

    def scan_group(self, *, group: str, page_size: int = 100) -> dict[str, Any]:
        accounts = self.list_accounts(group=group, page_size=page_size)
        error_accounts = [to_health(item) for item in accounts if is_error_account(item)]
        status_counts: dict[str, int] = {}
        for item in accounts:
            text = status_text(item)
            status_counts[text] = status_counts.get(text, 0) + 1
        return {
            "group": str(group),
            "total": len(accounts),
            "error_count": len(error_accounts),
            "ok_count": len(accounts) - len(error_accounts),
            "status_counts": status_counts,
            "error_accounts": [item.as_dict() for item in error_accounts],
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="检测 Sub2API 指定分组内状态错误的账号")
    parser.add_argument("--group", help="Sub2API 分组 ID；默认读取 SUB2API_GROUP")
    parser.add_argument("--page-size", type=int, default=100, help="分页大小，默认 100")
    parser.add_argument("--json", action="store_true", help="输出 JSON 详情")
    parser.add_argument("--output", help="把 JSON 详情写入指定文件")
    parser.add_argument("--sub2api-url", help="Sub2API base URL")
    parser.add_argument("--sub2api-email", help="Sub2API 管理员邮箱")
    parser.add_argument("--sub2api-password", help="Sub2API 管理员密码")
    return parser


def _provider_from_args(args: argparse.Namespace) -> Sub2ApiExportProvider:
    load_dotenv()
    cfg = RuntimeConfig.from_env_and_args(argparse.Namespace(
        idp_base=None,
        idp_token=None,
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
        sub2api_url=args.sub2api_url,
        sub2api_email=args.sub2api_email,
        sub2api_password=args.sub2api_password,
        sub2api_group=args.group,
        model_whitelist=None,
        artifact_dir=None,
        timeout=None,
        proxy=None,
        no_proxy=False,
        no_sub2api=False,
    ))
    return Sub2ApiExportProvider(Sub2ApiConfig(
        url=cfg.sub2api_url,
        email=cfg.sub2api_email,
        password=cfg.sub2api_password,
        group=args.group or cfg.sub2api_group,
    ))


def print_summary(summary: dict[str, Any]) -> None:
    print("Sub2API 分组账号检测完成")
    print("=" * 40)
    print(f"分组 ID: {summary.get('group')}")
    print(f"账号总数: {summary.get('total')}")
    print(f"正常数量: {summary.get('ok_count')}")
    print(f"错误数量: {summary.get('error_count')}")
    print("状态分布:")
    for status, count in sorted((summary.get("status_counts") or {}).items(), key=lambda kv: str(kv[0])):
        print(f"- {status}: {count}")
    errors = summary.get("error_accounts") if isinstance(summary.get("error_accounts"), list) else []
    if errors:
        print("错误账号:")
        for item in errors:
            print(f"- id={item.get('id')} email={item.get('email') or '-'} status={item.get('status') or '-'} error={(item.get('error') or '-')[:120]}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        provider = _provider_from_args(args)
        group = str(args.group or provider.config.group or "").strip()
        if not group:
            raise Sub2ApiError("缺少分组 ID：请传 --group 或设置 SUB2API_GROUP", stage="sub2api_group")
        summary = Sub2ApiHealthScanner(provider).scan_group(group=group, page_size=args.page_size)
    except IdpTeamAutomationError as exc:
        print(f"检测失败: stage={exc.stage} error={exc}", file=sys.stderr)
        return 1
    safe_summary = redact(summary)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(safe_summary, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    if args.json:
        print(json.dumps(safe_summary, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    else:
        print_summary(safe_summary)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
