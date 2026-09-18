from __future__ import annotations

import re
from typing import Iterable

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


class WarpAssistError(ValueError):
    pass


def normalize_warp_domains(raw: str | Iterable[str]) -> list[str]:
    rows = raw.splitlines() if isinstance(raw, str) else list(raw)
    result: list[str] = []
    seen: set[str] = set()
    for item in rows:
        value = str(item or "").strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if value.startswith("https://") or value.startswith("http://"):
            value = value.split("://", 1)[1].split("/", 1)[0]
        if ":" in value and not value.startswith("["):
            value = value.split(":", 1)[0]
        if value.startswith("*."):
            value = value[2:]
        if not DOMAIN_RE.fullmatch(value):
            raise WarpAssistError(f"دامنه WARP Assist معتبر نیست: {item}")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def xray_domain_rules(domains: Iterable[str]) -> list[str]:
    return [f"domain:{domain}" for domain in normalize_warp_domains(domains)]
