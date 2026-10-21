"""분석 경험 라이브러리 단위 테스트.

교훈은 **실행 대비가 뒷받침할 때만** 남는다. 비교가 없거나 비교가 사람의
판정과 어긋나면 항목을 만들지 않는다.
"""

from __future__ import annotations

import pytest

from netwatcher.detection.experience import (
    ExperienceError,
    ExperienceService,
    build_candidate,
    check_adoption,
    domain_of,
    format_past_verdicts,
    signature_of,
)

PROBE_COMPARED = {
    "status": "compared",
    "comparable": True,
    "input_hash": "a" * 64,
    "counts": {"added": 0, "removed": 2, "changed": 0, "unchanged": 1},
}
PROBE_NONE = {"status": "skipped", "reasons": [{"code": "trace_unavailable"}]}
PROBE_NOT_COMPARABLE = {
    "status": "compared", "comparable": False,
    "counts": {"added": 0, "removed": 2, "changed": 0, "unchanged": 0},
}
PROBE_NO_CHANGE = {
    "status": "compared", "comparable": True,
    "counts": {"added": 0, "removed": 0, "changed": 0, "unchanged": 3},
}
PROBE_OPPOSITE = {
    "status": "compared", "comparable": True,
    "counts": {"added": 2, "removed": 0, "changed": 0, "unchanged": 0},
}

PROPOSAL = {
    "id": 7, "engine": "port_scan", "params": {"threshold": 80},
    "before": {"threshold": 50}, "probe": PROBE_COMPARED,
}
REVIEW = {
    "event_id": 11, "decision": "expected_backup", "note": "매일 09:00 프린터 스캔",
    "actor": "analyst",
}
EVENT = {"id": 11, "engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"}


class TestSignature:
    """서명과 도메인."""

    def test_same_rule_gives_same_signature(self):
        first = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"})
        second = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"})
        assert first == second

    def test_different_rule_gives_different_signature(self):
        first = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"})
        second = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.stealth.title"})
        assert first != second

    def test_title_text_is_not_part_of_signature(self):
        first = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title"})
        second = signature_of({"engine": "port_scan", "title_key": "engines.port_scan.alerts.scan.title",
                               "title": "포트 스캔 감지"})
        assert first == second

    def test_domain_names_the_engine_family(self):
        assert domain_of("port_scan", "port_scan:rule") == "network_scan"

    def test_domain_refines_with_signature_trait(self):
        assert domain_of("port_scan", "port_scan:printer_scan") == "network_scan:printer"


class TestAdoptionRule:
    """채택 조건."""

    def test_comparison_backed_candidate_is_accepted(self):
        support = check_adoption(proposal=PROPOSAL, review=REVIEW, event=EVENT)
        assert support["counts"]["removed"] == 2

    def test_without_comparison_it_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal={**PROPOSAL, "probe": PROBE_NONE}, review=REVIEW, event=EVENT,
            )
        assert error.value.reason == "no_comparison"

    def test_not_comparable_comparison_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal={**PROPOSAL, "probe": PROBE_NOT_COMPARABLE}, review=REVIEW, event=EVENT,
            )
        assert error.value.reason == "comparison_not_comparable"

    def test_comparison_without_difference_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal={**PROPOSAL, "probe": PROBE_NO_CHANGE}, review=REVIEW, event=EVENT,
            )
        assert error.value.reason == "no_observed_difference"

    def test_review_that_is_not_a_normal_judgement_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal=PROPOSAL, review={**REVIEW, "decision": "investigate"}, event=EVENT,
            )
        assert error.value.reason == "review_not_normal"

    def test_review_of_another_engine_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal=PROPOSAL, review=REVIEW,
                event={**EVENT, "engine": "dns_anomaly"},
            )
        assert error.value.reason == "engine_mismatch"

    def test_opposite_direction_is_refused(self):
        with pytest.raises(ExperienceError) as error:
            check_adoption(
                proposal={**PROPOSAL, "probe": PROBE_OPPOSITE}, review=REVIEW, event=EVENT,
            )
        assert error.value.reason == "direction_mismatch"


class TestCandidate:
    """만들어지는 경험 항목."""

    def test_candidate_carries_evidence_and_references(self):
        candidate = build_candidate(proposal=PROPOSAL, review=REVIEW, event=EVENT)
        assert candidate["engine"] == "port_scan"
        assert candidate["source_proposal_id"] == 7
        assert candidate["source_review_id"] == 11
        assert candidate["evidence"]["probe"]["counts"]["removed"] == 2
        assert candidate["evidence"]["review"]["decision"] == "expected_backup"

    def test_candidate_evidence_is_never_empty(self):
        candidate = build_candidate(proposal=PROPOSAL, review=REVIEW, event=EVENT)
        assert candidate["evidence"] != {}

    def test_confidence_stays_in_range(self):
        candidate = build_candidate(proposal=PROPOSAL, review=REVIEW, event=EVENT)
        assert 0 < candidate["confidence"] <= 1

    def test_candidate_expires(self):
        candidate = build_candidate(proposal=PROPOSAL, review=REVIEW, event=EVENT)
        assert candidate["expires_at"]


class TestPastVerdicts:
    """프롬프트 주입 문장."""

    def test_empty_list_produces_nothing(self):
        assert format_past_verdicts([]) == ""

    def test_rows_become_lines(self):
        text = format_past_verdicts([
            {"domain": "network_scan:printer", "confidence": 0.8, "lesson": "정상",
             "created_at": "2026-10-01 00:00:00+00:00"},
        ])
        assert "PAST VERDICTS" in text
        assert "network_scan:printer" in text
        assert "0.80" in text


class FakeProposalRepo:
    def __init__(self, row):
        self._row = row

    async def get_by_id(self, proposal_id):
        return self._row if self._row and self._row["id"] == proposal_id else None


class FakeEventRepo:
    def __init__(self, row):
        self._row = row

    async def get(self, event_id):
        return self._row if self._row and self._row["id"] == event_id else None


class FakeExperienceRepo:
    def __init__(self, review_id=None):
        self.rows = []
        self._review_id = review_id

    async def insert(self, experience):
        self.rows.append(experience)
        return len(self.rows)

    async def latest_review_id_for_engine(self, engine):
        return self._review_id

    async def list_recent(self, limit=50):
        return self.rows[:limit]

    async def list_by_signature(self, engine, signature, limit=5):
        return [r for r in self.rows if r["engine"] == engine and r["signature"] == signature][:limit]

    async def list_by_signatures(self, signatures, limit_per_signature=5):
        wanted = set(signatures)
        return [r for r in self.rows if (r["engine"], r["signature"]) in wanted]


class FakeReviews:
    def __init__(self, review):
        self._review = review

    async def raw(self, event_id):
        return self._review if self._review and self._review["event_id"] == event_id else None


class TestService:
    """경험 서비스."""

    def _service(self, proposal=PROPOSAL, review=REVIEW, event=EVENT, review_id=11):
        experiences = FakeExperienceRepo(review_id)
        service = ExperienceService(
            proposal_repo=FakeProposalRepo(proposal),
            event_repo=FakeEventRepo(event),
            experience_repo=experiences,
            reviews=FakeReviews(review),
        )
        return service, experiences

    @pytest.mark.asyncio
    async def test_candidate_is_built_from_proposal_and_review(self):
        service, _ = self._service()
        candidate = await service.candidate(7)
        assert candidate["source_proposal_id"] == 7

    @pytest.mark.asyncio
    async def test_missing_proposal_is_reported(self):
        service, _ = self._service(proposal=None)
        with pytest.raises(ExperienceError) as error:
            await service.candidate(7)
        assert error.value.reason == "proposal_missing"

    @pytest.mark.asyncio
    async def test_missing_review_is_reported(self):
        service, _ = self._service(review=None, review_id=None)
        with pytest.raises(ExperienceError) as error:
            await service.candidate(7)
        assert error.value.reason == "review_missing"

    @pytest.mark.asyncio
    async def test_adopt_stores_the_experience(self):
        service, experiences = self._service()
        result = await service.adopt(7, 11, "analyst")
        assert result["id"] == 1
        assert len(experiences.rows) == 1
        assert experiences.rows[0]["source_proposal_id"] == 7

    @pytest.mark.asyncio
    async def test_adopt_refuses_without_comparison(self):
        service, experiences = self._service(proposal={**PROPOSAL, "probe": PROBE_NONE})
        with pytest.raises(ExperienceError):
            await service.adopt(7, 11, "analyst")
        assert experiences.rows == []

    @pytest.mark.asyncio
    async def test_matching_returns_only_the_same_signature(self):
        service, experiences = self._service()
        await service.adopt(7, 11, "analyst")
        signature = experiences.rows[0]["signature"]
        assert await service.matching("port_scan", signature)
        assert await service.matching("dns_anomaly", signature) == []
