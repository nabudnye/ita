# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

"""Reauthorize Sub2API accounts that are in error status."""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from .codex_oauth import generate_oauth_start, public_token_result
from .config import PROJECT_ROOT, RuntimeConfig
from .errors import IdpTeamAutomationError, Sub2ApiError
from .idp_client import GeneratedAccount, IdpClient
from .logging_utils import JsonlLogger, redact, utc_now_iso
from .sso_http_flow import SSOHttpFlow
from .sub2api_export import OAuthExportRecord, Sub2ApiConfig, Sub2ApiExportProvider
from .sub2api_health import Sub2ApiHealthScanner, is_error_account

ProgressFn = Callable[[str, dict[str, Any] | None], None]


def _progress(message: str, data: dict[str, Any] | None = None) -> None:
    suffix = ""
    if data:
        visible = {k: v for k, v in redact(data).items() if v not in ("", None, [], {})}
        if visible:
            suffix = " " + json.dumps(visible, ensure_ascii=False, sort_keys=True, default=str)
    print(f"[{utc_now_iso()}] {message}{suffix}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="检测 Sub2API 指定分组错误账号，并重新授权更新原账号")
    parser.add_argument("--group", help="Sub2API 分组 ID；默认读取 SUB2API_GROUP")
    parser.add_argument("--apply", action="store_true", help="实际执行重新授权和更新；不传则只 dry-run")
    parser.add_argument("--email", help="只处理指定邮箱")
    parser.add_argument("--account-id", help="只处理指定 Sub2API 账号 ID；可用于修复单个账号调度状态")
    parser.add_argument("--limit", type=int, default=0, help="最多处理多少个错误账号；0 表示全部")
    parser.add_argument("--retries", type=int, default=3, help="单账号重新授权最大尝试次数，默认 3")
    parser.add_argument("--artifact-dir", help="输出目录，默认 artifacts/reauth_<timestamp>")
    parser.add_argument("--timeout", help="HTTP timeout 秒数")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy")
    parser.add_argument("--no-proxy", action="store_true", help="禁用 proxy")
    parser.add_argument("--idp-base", help="IDP base URL")
    parser.add_argument("--idp-token", help="IDP 访问码")
    parser.add_argument("--client-id", help="IDP client_id")
    parser.add_argument("--codex-client-id", help="Codex OAuth client_id")
    parser.add_argument("--codex-redirect-uri", help="Codex OAuth redirect_uri")
    parser.add_argument("--codex-scope", help="Codex OAuth scope")
    parser.add_argument("--sub2api-url", help="Sub2API base URL")
    parser.add_argument("--sub2api-email", help="Sub2API 管理员邮箱")
    parser.add_argument("--sub2api-password", help="Sub2API 管理员密码")
    parser.add_argument("--model-whitelist", help="Sub2API model whitelist，多个用逗号")
    return parser


def _cfg_from_args(args: argparse.Namespace) -> RuntimeConfig:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    artifact = args.artifact_dir or str(PROJECT_ROOT / "artifacts" / f"reauth_{timestamp}")
    ns = SimpleNamespace(
        idp_base=args.idp_base,
        idp_token=args.idp_token,
        client_id=args.client_id,
        channel_id=None,
        domain=None,
        email="",
        given_name="",
        family_name="",
        account_id="",
        codex_client_id=args.codex_client_id,
        codex_redirect_uri=args.codex_redirect_uri,
        codex_scope=args.codex_scope,
        sub2api_url=args.sub2api_url,
        sub2api_email=args.sub2api_email,
        sub2api_password=args.sub2api_password,
        sub2api_group=args.group,
        model_whitelist=args.model_whitelist,
        no_sub2api=False,
        artifact_dir=artifact,
        timeout=args.timeout,
        proxy=args.proxy,
        no_proxy=bool(args.no_proxy),
    )
    cfg = RuntimeConfig.from_env_and_args(ns)
    cfg.validate()
    return cfg


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(data), ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _load_idp_account(idp: IdpClient, cfg: RuntimeConfig, email: str, *, progress: ProgressFn | None = _progress) -> GeneratedAccount:
    normalized = str(email or "").strip().lower()
    if not normalized:
        raise Sub2ApiError("错误账号缺少 email，无法匹配 IDP 账号", stage="reauth_match")
    page = 1
    while True:
        me = idp.me(token=cfg.idp_token, page=page, page_size=100, client_id=cfg.idp_client_id)
        items = ((me.get("accounts") or {}).get("items") or []) if isinstance(me, dict) else []
        for item in items:
            if str(item.get("email") or "").strip().lower() == normalized:
                return GeneratedAccount.from_payload(item)
        if not items or len(items) < 100:
            break
        page += 1
    raise Sub2ApiError(f"IDP 账号列表中未找到邮箱：{email}", stage="reauth_match")


def _reauthorize_one(
    *,
    cfg: RuntimeConfig,
    provider: Sub2ApiExportProvider,
    sub2api_account: dict[str, Any],
    artifact_dir: Path,
    progress: ProgressFn | None = _progress,
) -> dict[str, Any]:
    account_id = str(sub2api_account.get("id") or "").strip()
    creds = sub2api_account.get("credentials") if isinstance(sub2api_account.get("credentials"), dict) else {}
    email = str(creds.get("email") or sub2api_account.get("email") or sub2api_account.get("name") or "").strip()
    if not account_id:
        raise Sub2ApiError("Sub2API 错误账号缺少 id", stage="reauth_account")
    logger = JsonlLogger(artifact_dir / "network.jsonl")
    idp = IdpClient(cfg.idp_base, timeout=cfg.timeout, logger=logger)
    if progress:
        progress("匹配 IDP 账号", {"sub2api_id": account_id, "email": email})
    account = _load_idp_account(idp, cfg, email, progress=progress)
    _write_json(artifact_dir / "idp_account.public.json", account.as_public_dict())

    if progress:
        progress("启动 IDP SSO 会话", {"idp_account_id": account.id, "sub2api_id": account_id})
    start_url = idp.start_sso(token=cfg.idp_token, account_id=account.id)
    oauth = generate_oauth_start(redirect_uri=cfg.codex_redirect_uri, client_id=cfg.codex_client_id, scope=cfg.codex_scope)
    flow = SSOHttpFlow(timeout=cfg.timeout, proxy=cfg.proxy, artifact_dir=artifact_dir, logger=logger, user_token=cfg.idp_token)
    token_config = flow.run(start_url=start_url, oauth=oauth, account=account)
    token_public = public_token_result(token_config)
    _write_json(artifact_dir / "token.public.json", token_public)
    (artifact_dir / "token.json").write_text(json.dumps(token_config, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")

    record = OAuthExportRecord(
        account_id=str(token_config.get("account_id") or account.email),
        email=str(token_config.get("email") or account.email),
        secret={
            "access_token": token_config.get("access_token") or "",
            "refresh_token": token_config.get("refresh_token") or "",
            "id_token": token_config.get("id_token") or "",
            "client_id": token_config.get("client_id") or cfg.codex_client_id,
            "expired": token_config.get("expired") or "",
            "account_id": token_config.get("account_id") or "",
            "user_id": token_config.get("user_id") or "",
        },
        metadata={"email": account.email, "source": "sub2api_reauth", "generated_account_id": account.id},
    )
    if progress:
        progress("更新 Sub2API 原账号 credentials", {"sub2api_id": account_id, "email": record.email})
    update_result = provider.update_account_credentials(account_id, record, existing=sub2api_account)
    _write_json(artifact_dir / "sub2api_update.public.json", update_result)
    return {"status": "success", "sub2api_id": account_id, "email": record.email, "idp_account_id": account.id, "update": update_result}


def run(cfg: RuntimeConfig, *, apply: bool, limit: int = 0, retries: int = 3, account_id: str = "", email: str = "", progress: ProgressFn | None = _progress) -> dict[str, Any]:
    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)
    provider = Sub2ApiExportProvider(Sub2ApiConfig(
        url=cfg.sub2api_url,
        email=cfg.sub2api_email,
        password=cfg.sub2api_password,
        group=cfg.sub2api_group,
        model_whitelist=cfg.sub2api_model_whitelist,
        concurrency=cfg.sub2api_concurrency,
        priority=cfg.sub2api_priority,
        rate_multiplier=cfg.sub2api_rate_multiplier,
    ))
    if progress:
        progress("扫描 Sub2API 分组错误账号", {"group": cfg.sub2api_group, "apply": apply})
    scanner = Sub2ApiHealthScanner(provider)
    accounts = scanner.list_accounts(group=cfg.sub2api_group)
    if str(account_id or "").strip():
        wanted = str(account_id).strip()
        error_accounts = [item for item in accounts if str(item.get("id") or "") == wanted]
        if not error_accounts:
            detail = provider.get_account(wanted)
            error_accounts = [detail]
    elif str(email or "").strip():
        wanted_email = str(email).strip().lower()
        error_accounts = []
        for item in accounts:
            creds = item.get("credentials") if isinstance(item.get("credentials"), dict) else {}
            item_email = str(creds.get("email") or item.get("email") or item.get("name") or "").strip().lower()
            if item_email == wanted_email:
                error_accounts.append(item)
    else:
        error_accounts = [item for item in accounts if is_error_account(item)]
    detected_error_count = len(error_accounts)
    if limit and limit > 0:
        error_accounts = error_accounts[:limit]
    dry_items = []
    for item in error_accounts:
        creds = item.get("credentials") if isinstance(item.get("credentials"), dict) else {}
        dry_items.append({"id": item.get("id"), "email": creds.get("email") or item.get("email") or item.get("name"), "status": item.get("status"), "error": item.get("error_message")})
    summary: dict[str, Any] = {
        "status": "dry_run" if not apply else "running",
        "group": cfg.sub2api_group,
        "account_id": str(account_id or ""),
        "email": str(email or ""),
        "total": len(accounts),
        "detected_error_count": detected_error_count,
        "error_count": len(error_accounts),
        "apply": apply,
        "artifact_dir": str(cfg.artifact_dir),
        "planned": dry_items,
        "results": [],
    }
    if not apply:
        _write_json(cfg.artifact_dir / "reauth_summary.json", summary)
        return summary
    max_attempts = max(1, int(retries or 1))
    success = 0
    failed = 0
    for index, item in enumerate(error_accounts, 1):
        item_dir = cfg.artifact_dir / f"account_{int(item.get('id') or 0):06d}"
        last_error = ""
        for attempt in range(1, max_attempts + 1):
            attempt_dir = item_dir / f"attempt_{attempt:02d}"
            try:
                if progress:
                    progress("开始重新授权", {"index": index, "total": len(error_accounts), "sub2api_id": item.get("id"), "attempt": attempt})
                result = _reauthorize_one(cfg=cfg, provider=provider, sub2api_account=item, artifact_dir=attempt_dir, progress=progress)
                summary["results"].append(result)
                success += 1
                last_error = ""
                break
            except IdpTeamAutomationError as exc:
                last_error = str(exc)
                _write_json(attempt_dir / "error.json", {"stage": exc.stage, "error": str(exc), "data": exc.data})
                if progress:
                    progress("重新授权失败", {"sub2api_id": item.get("id"), "attempt": attempt, "stage": exc.stage, "error": str(exc)})
                if attempt < max_attempts:
                    time.sleep(min(5.0, 0.8 * attempt))
        if last_error:
            failed += 1
            summary["results"].append({"status": "failed", "sub2api_id": item.get("id"), "email": (item.get("credentials") or {}).get("email") if isinstance(item.get("credentials"), dict) else "", "error": last_error})
        _write_json(cfg.artifact_dir / "reauth_summary.json", summary)
    summary["status"] = "success" if failed == 0 else "partial_failed"
    summary["success_count"] = success
    summary["failed_count"] = failed
    summary["finished_at"] = utc_now_iso()
    _write_json(cfg.artifact_dir / "reauth_summary.json", summary)
    return summary


def print_summary(summary: dict[str, Any]) -> None:
    print("Sub2API 错误账号重新授权任务完成" if summary.get("apply") else "Sub2API 错误账号重新授权 dry-run")
    print("=" * 40)
    print(f"分组 ID: {summary.get('group')}")
    print(f"分组账号数: {summary.get('total')}")
    print(f"检测到错误账号数: {summary.get('detected_error_count', summary.get('error_count'))}")
    print(f"计划处理错误账号数: {summary.get('error_count')}")
    print(f"执行模式: {'apply' if summary.get('apply') else 'dry-run'}")
    print(f"结果目录: {summary.get('artifact_dir')}")
    if summary.get("apply"):
        print(f"成功数量: {summary.get('success_count', 0)}")
        print(f"失败数量: {summary.get('failed_count', 0)}")
    else:
        print("待处理账号:")
        for item in summary.get("planned", []):
            print(f"- id={item.get('id')} email={item.get('email') or '-'} status={item.get('status') or '-'} error={(item.get('error') or '-')[:120]}")
        print("提示：确认后加 --apply 才会真正重新授权并更新 Sub2API。")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = _cfg_from_args(args)
        if args.group:
            cfg = replace(cfg, sub2api_group=str(args.group))
        summary = run(
            cfg,
            apply=bool(args.apply),
            limit=max(0, int(args.limit or 0)),
            retries=max(1, int(args.retries or 1)),
            account_id=str(args.account_id or ""),
            email=str(args.email or ""),
        )
    except IdpTeamAutomationError as exc:
        print(f"任务失败: stage={exc.stage} error={exc}", file=sys.stderr)
        return 1
    print_summary(redact(summary))
    return 0 if summary.get("status") in {"success", "dry_run"} else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
