"""The audit trail is only worth having if tampering with it is detectable."""
from __future__ import annotations

import json

import pytest

from netnerd_mcp.audit import AuditError, AuditLog, mask, verify


@pytest.fixture
def log(tmp_path):
    return AuditLog(session_id="s-test", base_dir=tmp_path)


class TestHashChain:
    def test_a_clean_log_verifies(self, log):
        log.event("connect", device="r1", host="10.0.0.1")
        log.event("command", device="r1", cmd="show ip bgp summary", reason="peer down")
        log.event("disconnect", device="r1")

        ok, message = verify(log.jsonl_path)
        assert ok, message
        assert "3 event(s)" in message

    def test_an_edited_line_is_detected(self, log):
        log.event("command", device="r1", cmd="show version", reason="check")
        log.event("command", device="r1", cmd="show ip route", reason="check")

        lines = log.jsonl_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["cmd"] = "show run"  # rewrite history
        lines[0] = json.dumps(tampered)
        log.jsonl_path.write_text("\n".join(lines) + "\n")

        ok, message = verify(log.jsonl_path)
        assert not ok
        assert "line 1" in message

    def test_a_removed_line_is_detected(self, log):
        log.event("command", device="r1", cmd="show version", reason="a")
        log.event("blocked", device="r1", cmd="reload", why="destructive")
        log.event("command", device="r1", cmd="show ip route", reason="b")

        lines = log.jsonl_path.read_text().splitlines()
        del lines[1]  # drop the blocked command
        log.jsonl_path.write_text("\n".join(lines) + "\n")

        ok, message = verify(log.jsonl_path)
        assert not ok

    def test_a_deleted_directory_does_not_brick_the_session(self, log):
        """Log rotation or a cleanup script removing the directory should not
        make every later command fail — the session recreates it and carries on."""
        log.event("command", device="r1", cmd="show version", reason="before")

        import shutil
        shutil.rmtree(log.dir)

        log.event("command", device="r1", cmd="show ip route", reason="after")

        assert log.jsonl_path.exists()
        ok, message = verify(log.jsonl_path)
        assert not ok, "the surviving file starts mid-chain, which verify must notice"
        assert len(log.events()) == 2

    def test_write_failure_raises_rather_than_losing_the_event(self, log):
        log.jsonl_path.parent.chmod(0o500)  # read + execute, no write
        try:
            with pytest.raises(AuditError):
                log.event("command", device="r1", cmd="show version", reason="x")
        finally:
            log.jsonl_path.parent.chmod(0o700)


class TestMasking:
    @pytest.mark.parametrize("line,secret", [
        ("username admin password Sup3rSecret", "Sup3rSecret"),
        ("enable secret 5 $1$abcd$efgh", "$1$abcd$efgh"),
        ("snmp-server community pr1vat3 RO", "pr1vat3"),
        ("ntp authentication-key 1 md5 k3yMaterial", "k3yMaterial"),
        ("key-string 7 070C285F4D06", "070C285F4D06"),
    ])
    def test_secrets_are_redacted(self, line, secret):
        assert secret not in mask(line)
        assert "********" in mask(line)

    def test_ordinary_config_survives_untouched(self):
        line = "ip route 10.0.0.0 255.255.255.0 192.168.1.1"
        assert mask(line) == line


class TestReport:
    def test_report_records_commands_reasons_and_blocks(self, log):
        log.event("connect", device="r1", host="10.0.0.1")
        log.event("command", device="r1", cmd="show ip bgp summary",
                  reason="peer 10.0.0.9 is down", ms=412)
        log.event("blocked", device="r1", cmd="reload", why="destructive command")

        report = log.write_report().read_text()

        assert "show ip bgp summary" in report
        assert "peer 10.0.0.9 is down" in report
        assert "reload" in report and "destructive" in report

    def test_report_masks_secrets(self, log):
        log.event("command", device="r1", cmd="snmp-server community pr1vat3 RO",
                  reason="audit")
        assert "pr1vat3" not in log.write_report().read_text()
