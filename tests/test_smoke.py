"""Smoke-тесты: главные инварианты безопасности горячего пути.

Проверяется не «код запускается», а свойства, нарушение которых означает
дыру в контуре безопасности:

* happy path действительно открывает турникет;
* **ни один** рискованный сценарий не открывает турникет автоматически;
* повтор события не открывает турникет второй раз;
* каждое решение попадает в audit log с причиной;
* биометрия в audit log не утекает.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from poc.audit import AuditLog  # noqa: E402
from poc.policy import DEFAULT_THRESHOLDS  # noqa: E402
from poc.service import AccessService  # noqa: E402

EVENTS = REPO_ROOT / "demo" / "events"

RISKY = ["e-1002", "e-1003", "e-1004", "e-1005", "e-1006", "e-1007"]


def load(event_id: str) -> dict:
    return json.loads((EVENTS / f"{event_id}.json").read_text(encoding="utf-8"))


class BaseCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        path = Path(self._tmp.name) / "audit.jsonl"
        self.service = AccessService(audit=AuditLog(path))

    def tearDown(self) -> None:
        self._tmp.cleanup()


class HappyPath(BaseCase):
    def test_allows_known_employee(self) -> None:
        d = self.service.verify(load("e-1001"))
        self.assertEqual(d.decision, "allow")
        self.assertEqual(d.turnstile_command, "open")
        self.assertEqual(d.employee_id, "emp-4821")
        self.assertFalse(d.requires_human_review)
        self.assertFalse(d.degraded_mode)

    def test_allow_clears_every_threshold(self) -> None:
        d = self.service.verify(load("e-1001"))
        t = DEFAULT_THRESHOLDS
        self.assertGreaterEqual(d.quality["quality_score"], t.quality_min)
        self.assertGreaterEqual(d.quality["liveness_score"], t.liveness_min)
        self.assertGreaterEqual(d.match_score, t.match_allow)
        self.assertGreaterEqual(d.margin_to_second_best, t.margin_min)


class RiskyPathsNeverOpen(BaseCase):
    def test_no_risky_scenario_opens_the_turnstile(self) -> None:
        for event_id in RISKY:
            with self.subTest(event=event_id):
                d = self.service.verify(load(event_id))
                self.assertNotEqual(d.decision, "allow")
                self.assertNotEqual(d.turnstile_command, "open")
                self.assertTrue(d.reasons, "решение обязано нести причину")

    def test_presentation_attack_is_denied_not_softened(self) -> None:
        d = self.service.verify(load("e-1003"))
        self.assertEqual(d.decision, "deny")
        self.assertIn("presentation_attack_suspected", d.reasons)
        self.assertTrue(d.requires_human_review)

    def test_revoked_employee_is_denied_and_escalated(self) -> None:
        d = self.service.verify(load("e-1005"))
        self.assertEqual(d.decision, "deny")
        self.assertIn("access_revoked", d.reasons)
        self.assertTrue(d.requires_human_review, "уволенный на проходной — событие безопасности")

    def test_stale_offline_cache_falls_back_to_guard(self) -> None:
        d = self.service.verify(load("e-1006"))
        self.assertEqual(d.decision, "manual_review")
        self.assertTrue(d.degraded_mode)
        self.assertIn("stale_access_cache", d.reasons)

    def test_ambiguous_candidates_go_to_guard(self) -> None:
        d = self.service.verify(load("e-1004"))
        self.assertEqual(d.decision, "manual_review")
        self.assertIn("ambiguous_candidates", d.reasons)
        self.assertLess(d.margin_to_second_best, DEFAULT_THRESHOLDS.margin_min)

    def test_unreadable_frame_does_not_crash_the_gate(self) -> None:
        broken = load("e-1001") | {"event_id": "e-9999", "frame_uri": "file://demo/frames/absent.png"}
        d = self.service.verify(broken)
        self.assertEqual(d.decision, "manual_review")
        self.assertIn("frame_unreadable", d.reasons)


class Idempotency(BaseCase):
    def test_repeat_event_never_opens_twice(self) -> None:
        first = self.service.verify(load("e-1001"))
        second = self.service.verify(load("e-1001"))
        self.assertEqual(first.decision_id, second.decision_id)
        self.assertEqual(first.turnstile_command, "open")
        self.assertEqual(second.turnstile_command, "noop")
        self.assertIn("duplicate_event", second.reasons)

    def test_idempotency_survives_service_restart(self) -> None:
        first = self.service.verify(load("e-1001"))
        restarted = AccessService(audit=AuditLog(self.service.audit.path))
        again = restarted.verify(load("e-1001"))
        self.assertEqual(first.decision_id, again.decision_id)
        self.assertEqual(again.turnstile_command, "noop")


class AuditTrail(BaseCase):
    def test_every_decision_is_logged_with_a_reason(self) -> None:
        for event_id in ["e-1001", *RISKY]:
            self.service.verify(load(event_id))
        records = self.service.audit.records()
        self.assertEqual(len(records), 7)
        for record in records:
            self.assertTrue(record["decision"]["reasons"])
            self.assertIn("policy_version", record["decision"])

    def test_audit_log_contains_no_biometrics(self) -> None:
        self.service.verify(load("e-1001"))
        blob = json.dumps(self.service.audit.records(), ensure_ascii=False)
        for forbidden in ("embedding", "template", "descriptor", "vector"):
            self.assertNotIn(forbidden, blob.lower())

    def test_manual_review_reaches_the_guard_queue(self) -> None:
        self.service.verify(load("e-1004"))
        queue = self.service.review_queue_path
        self.assertTrue(queue.is_file())
        card = json.loads(queue.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(card["event_id"], "e-1004")
        self.assertIn("ttl_seconds", card["frame_ref"], "ссылка на кадр обязана иметь TTL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
