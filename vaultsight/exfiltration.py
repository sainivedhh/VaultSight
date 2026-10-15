"""Exfiltration and insider-risk detection over data store access logs.

Detects:
1. Bulk Downloads: Single user downloading unusually large number of records/bytes.
2. Off-Hours Access: Access outside standard operating hours (e.g. 23:00 to 05:00 UTC).
3. First-Seen IP: Access originating from a previously unobserved IP for a user.
4. Sudden Volume Spike: User exceeding 3x their standard baseline volume.
5. Privilege-Sensitivity Mismatch: Low-privilege users reading high-sensitivity/restricted data.
"""

from datetime import datetime, time
from enum import Enum
from typing import List, Dict, Optional, Set
from collections import defaultdict
from pydantic import BaseModel


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AccessLogEntry(BaseModel):
    """Synthetic audit access log event."""
    timestamp: datetime
    user_id: str
    user_role: str  # "viewer" | "analyst" | "admin" | "contractor"
    ip_address: str
    target_resource: str
    action: str  # "READ" | "DOWNLOAD" | "DELETE" | "EXPORT"
    bytes_transferred: int = 0
    records_count: int = 1
    resource_sensitivity: str = "LOW"  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"


class InsiderThreatAlert(BaseModel):
    """Detection alert for anomalous access or exfiltration behavior."""
    alert_type: str
    severity: AlertSeverity
    user_id: str
    description: str
    timestamp: datetime
    evidence: dict


class ExfiltrationDetector:
    """Detection engine for exfiltration behavior and insider risks."""

    def __init__(
        self,
        bulk_download_records_threshold: int = 100,
        bulk_download_bytes_threshold: int = 50_000_000,  # 50MB
        off_hours_start: time = time(22, 0),
        off_hours_end: time = time(5, 0),
    ):
        self.bulk_records_threshold = bulk_download_records_threshold
        self.bulk_bytes_threshold = bulk_download_bytes_threshold
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    def analyze_logs(
        self,
        logs: List[AccessLogEntry],
        known_user_ips: Optional[Dict[str, Set[str]]] = None,
        user_baseline_volume: Optional[Dict[str, int]] = None,
    ) -> List[InsiderThreatAlert]:
        alerts: List[InsiderThreatAlert] = []

        # Track history dynamically during log processing
        seen_ips: Dict[str, Set[str]] = defaultdict(set)
        if known_user_ips:
            for u, ips in known_user_ips.items():
                seen_ips[u].update(ips)

        user_hourly_volumes: Dict[str, int] = defaultdict(int)

        # Sort logs chronologically
        sorted_logs = sorted(logs, key=lambda entry: entry.timestamp)

        for log in sorted_logs:
            # 1. Bulk Download / Large Export Detection
            if log.records_count >= self.bulk_records_threshold or log.bytes_transferred >= self.bulk_bytes_threshold:
                alerts.append(
                    InsiderThreatAlert(
                        alert_type="BULK_EXFILTRATION",
                        severity=AlertSeverity.CRITICAL if log.resource_sensitivity in ("CRITICAL", "HIGH") else AlertSeverity.HIGH,
                        user_id=log.user_id,
                        timestamp=log.timestamp,
                        description=(
                            f"Bulk download detected: User '{log.user_id}' requested {log.records_count} records "
                            f"({log.bytes_transferred} bytes) from '{log.target_resource}'."
                        ),
                        evidence={
                            "records_count": log.records_count,
                            "bytes_transferred": log.bytes_transferred,
                            "target": log.target_resource,
                            "action": log.action,
                        }
                    )
                )

            # 2. Off-Hours Access Detection
            log_time = log.timestamp.time()
            is_off_hours = False
            if self.off_hours_start > self.off_hours_end:
                # Spans midnight (e.g. 22:00 to 05:00)
                is_off_hours = (log_time >= self.off_hours_start or log_time <= self.off_hours_end)
            else:
                is_off_hours = (self.off_hours_start <= log_time <= self.off_hours_end)

            if is_off_hours and log.resource_sensitivity in ("CRITICAL", "HIGH"):
                alerts.append(
                    InsiderThreatAlert(
                        alert_type="OFF_HOURS_ACCESS",
                        severity=AlertSeverity.HIGH,
                        user_id=log.user_id,
                        timestamp=log.timestamp,
                        description=(
                            f"Anomalous off-hours access: User '{log.user_id}' accessed high-sensitivity "
                            f"resource '{log.target_resource}' at {log_time.strftime('%H:%M:%S')} UTC."
                        ),
                        evidence={
                            "timestamp": log.timestamp.isoformat(),
                            "resource": log.target_resource,
                            "sensitivity": log.resource_sensitivity,
                        }
                    )
                )

            # 3. First-Seen IP Address Detection
            if log.user_id in seen_ips and log.ip_address not in seen_ips[log.user_id]:
                alerts.append(
                    InsiderThreatAlert(
                        alert_type="FIRST_SEEN_IP",
                        severity=AlertSeverity.MEDIUM,
                        user_id=log.user_id,
                        timestamp=log.timestamp,
                        description=(
                            f"New connection origin: User '{log.user_id}' accessed system from new IP "
                            f"'{log.ip_address}' (previously known: {list(seen_ips[log.user_id])})."
                        ),
                        evidence={
                            "new_ip": log.ip_address,
                            "previous_ips": list(seen_ips[log.user_id]),
                        }
                    )
                )
            # Record IP
            seen_ips[log.user_id].add(log.ip_address)

            # 4. Sudden Volume Spike (e.g. 3x user baseline)
            user_hourly_volumes[log.user_id] += log.records_count
            if user_baseline_volume and log.user_id in user_baseline_volume:
                baseline = user_baseline_volume[log.user_id]
                current_vol = user_hourly_volumes[log.user_id]
                if current_vol >= baseline * 3 and baseline > 10:
                    alerts.append(
                        InsiderThreatAlert(
                            alert_type="SUDDEN_VOLUME_SPIKE",
                            severity=AlertSeverity.HIGH,
                            user_id=log.user_id,
                            timestamp=log.timestamp,
                            description=(
                                f"Volume spike: User '{log.user_id}' accessed {current_vol} records, "
                                f"exceeding 3x normal baseline ({baseline} records)."
                            ),
                            evidence={
                                "baseline": baseline,
                                "accumulated_volume": current_vol,
                            }
                        )
                    )

            # 5. Access to High-Sensitivity Objects by Low-Privilege Users
            if log.user_role in ("viewer", "contractor") and log.resource_sensitivity in ("CRITICAL", "HIGH"):
                alerts.append(
                    InsiderThreatAlert(
                        alert_type="PRIVILEGE_SENSITIVITY_MISMATCH",
                        severity=AlertSeverity.HIGH,
                        user_id=log.user_id,
                        timestamp=log.timestamp,
                        description=(
                            f"Privilege mismatch: User '{log.user_id}' with role '{log.user_role}' "
                            f"accessed restricted {log.resource_sensitivity} object '{log.target_resource}'."
                        ),
                        evidence={
                            "role": log.user_role,
                            "target": log.target_resource,
                            "sensitivity": log.resource_sensitivity,
                        }
                    )
                )

        return alerts
