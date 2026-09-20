"""ZSK 双签（double-signature）轮换时序校验（不落库）。

双签轮换中，新旧 ZSK 的签名在过渡期内同时存在于区内，标准流程为：

1. **发布新钥**：把新 ZSK 加入 DNSKEY RRset（暂不用它签名）；
2. **启用新钥签名（启签）**：开始用新 ZSK 生成签名（旧 ZSK 继续签名）；
3. **停用旧钥签名（停签）**：停止用旧 ZSK 生成签名（旧 ZSK 仍保留在
   DNSKEY RRset 中）；
4. **移除旧钥**：把旧 ZSK 从 DNSKEY RRset 中删除。

两个等待阶段必须满足：

- **发布 → 启签**至少等待 ``DNSKEY TTL + 时钟偏差``：保证缓存中不含新钥的
  旧 DNSKEY RRset 全部过期，解析方在见到新钥签名之前一定能取得含新钥的
  DNSKEY RRset；
- **停签 → 移除**至少等待 ``区记录最大 TTL + 时钟偏差``：保证缓存中由旧钥
  生成的签名（随记录缓存）全部过期，解析方不会再用已移除的旧钥验证缓存
  记录。

四个时间点必须严格递增（发布 < 启签 < 停签 < 移除），该约束由请求模型
校验（失败为 HTTP 422）。本模块仅做时序计算，不写入数据库；等待时间不足
时不抛错，而是在结果中以 ``violations`` 按阶段顺序列出（HTTP 200）。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

#: 阶段标识：新钥发布 → 新钥启签
PHASE_PUBLISH_TO_ACTIVATE = "publish_to_activate"
#: 阶段标识：旧钥停签 → 旧钥移除
PHASE_DEACTIVATE_TO_REMOVE = "deactivate_to_remove"


def _as_utc(value: datetime) -> datetime:
    """归一化为 UTC：带时区的做转换，朴素时间戳按 UTC 处理。"""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    """格式化为以 Z 结尾的 UTC ISO 8601 字符串。"""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def check_dnssec_rollover(
    zone: str,
    new_key_published_at: datetime,
    new_key_activated_at: datetime,
    old_key_deactivated_at: datetime,
    old_key_removed_at: datetime,
    dnskey_ttl: int,
    max_zone_ttl: int,
    clock_skew: int,
) -> dict:
    """校验一次 ZSK 双签轮换的两阶段等待时间，返回结果字典；不写库。

    :param zone: 已规范化的区域名；
    :param new_key_published_at: 新 ZSK 发布（加入 DNSKEY RRset）时间；
    :param new_key_activated_at: 新 ZSK 启签时间；
    :param old_key_deactivated_at: 旧 ZSK 停签时间；
    :param old_key_removed_at: 旧 ZSK 移除时间；
    :param dnskey_ttl: DNSKEY RRset 的 TTL（秒）；
    :param max_zone_ttl: 区内记录的最大 TTL（秒）；
    :param clock_skew: 允许的时钟偏差（秒）；
    :return: 校验结果字典（``safe``、按阶段顺序排列的两阶段明细与
        ``violations``）；四个时间点的严格递增约束由请求模型保证。
    """
    published = _as_utc(new_key_published_at)
    activated = _as_utc(new_key_activated_at)
    deactivated = _as_utc(old_key_deactivated_at)
    removed = _as_utc(old_key_removed_at)

    # (阶段标识, 起点, 终点, 要求秒数, 阶段中文名, 要求构成说明)
    specs = [
        (
            PHASE_PUBLISH_TO_ACTIVATE,
            published,
            activated,
            dnskey_ttl + clock_skew,
            "新钥发布到启签",
            f"DNSKEY TTL {dnskey_ttl} 秒 + 时钟偏差 {clock_skew} 秒",
        ),
        (
            PHASE_DEACTIVATE_TO_REMOVE,
            deactivated,
            removed,
            max_zone_ttl + clock_skew,
            "旧钥停签到移除",
            f"区记录最大 TTL {max_zone_ttl} 秒 + 时钟偏差 {clock_skew} 秒",
        ),
    ]

    phases: list[dict] = []
    violations: list[dict] = []
    for phase, start, end, required, label, requirement in specs:
        actual = int((end - start).total_seconds())
        earliest = start + timedelta(seconds=required)
        phases.append(
            {
                "phase": phase,
                "from_at": _format_utc(start),
                "to_at": _format_utc(end),
                "actual_seconds": actual,
                "required_seconds": required,
                "earliest_safe_at": _format_utc(earliest),
            }
        )
        if actual < required:
            violations.append(
                {
                    "phase": phase,
                    "actual_seconds": actual,
                    "required_seconds": required,
                    "shortage_seconds": required - actual,
                    "earliest_safe_at": _format_utc(earliest),
                    "message": (
                        f"{label}仅等待 {actual} 秒，少于要求的 {required} 秒"
                        f"（{requirement}）；该阶段终点最早安全时间为 "
                        f"{_format_utc(earliest)}"
                    ),
                }
            )

    return {
        "zone": zone,
        "safe": not violations,
        "phases": phases,
        "violations": violations,
        "note": (
            "校验结果仅依据请求中的轮换计划即时计算，不写入数据库；"
            "新钥发布到启签至少等待 DNSKEY TTL+时钟偏差，"
            "旧钥停签到移除至少等待区记录最大 TTL+时钟偏差"
        ),
    }
