from datetime import datetime, time

from vaultsight.exfiltration import ExfiltrationDetector, AccessLogEntry, AlertSeverity


def test_bulk_exfiltration_alert():
    detector = ExfiltrationDetector(bulk_download_records_threshold=100)
    
    log = AccessLogEntry(
        timestamp=datetime(2026, 10, 15, 14, 30, 0),
        user_id="contractor_bob",
        user_role="contractor",
        ip_address="192.168.1.50",
        target_resource="s3://customer-db-backups/oct2026.sql",
        action="DOWNLOAD",
        bytes_transferred=60_000_000,
        records_count=5000,
        resource_sensitivity="CRITICAL"
    )

    alerts = detector.analyze_logs([log])
    alert_types = [a.alert_type for a in alerts]
    assert "BULK_EXFILTRATION" in alert_types
    assert "PRIVILEGE_SENSITIVITY_MISMATCH" in alert_types
    assert any(a.severity == AlertSeverity.CRITICAL for a in alerts)


def test_off_hours_and_first_seen_ip_alerts():
    detector = ExfiltrationDetector(
        off_hours_start=time(22, 0),
        off_hours_end=time(5, 0)
    )

    known_ips = {"analyst_alice": {"10.0.0.1"}}

    # Off-hours access (02:15 AM) from an unfamiliar IP
    log = AccessLogEntry(
        timestamp=datetime(2026, 10, 15, 2, 15, 0),
        user_id="analyst_alice",
        user_role="analyst",
        ip_address="203.0.113.88",
        target_resource="sqlite:patients.db/kyc_records",
        action="READ",
        bytes_transferred=4000,
        records_count=10,
        resource_sensitivity="HIGH"
    )

    alerts = detector.analyze_logs([log], known_user_ips=known_ips)
    alert_types = [a.alert_type for a in alerts]
    assert "OFF_HOURS_ACCESS" in alert_types
    assert "FIRST_SEEN_IP" in alert_types


def test_volume_spike_alert():
    detector = ExfiltrationDetector()
    baseline = {"engineer_dan": 50}

    logs = [
        AccessLogEntry(
            timestamp=datetime(2026, 10, 15, 10, i, 0),
            user_id="engineer_dan",
            user_role="analyst",
            ip_address="10.0.0.5",
            target_resource=f"s3://logs/chunk_{i}.txt",
            action="READ",
            records_count=60,
            resource_sensitivity="LOW"
        )
        for i in range(4)  # 4 * 60 = 240 records (over 3x of 50 baseline)
    ]

    alerts = detector.analyze_logs(logs, user_baseline_volume=baseline)
    alert_types = [a.alert_type for a in alerts]
    assert "SUDDEN_VOLUME_SPIKE" in alert_types
