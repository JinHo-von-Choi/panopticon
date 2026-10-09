"""데이터 전송은 결과 지문을 보존하며 실행 가능한 pickle을 거절한다."""

from dataclasses import asdict
import json
import pickle
from pathlib import Path

import pytest

from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.result_wire import decode_result, encode_result
from netwatcher.replay.service import compare
from tests.test_replay.test_runner_boundary import source


def test_json_roundtrip_preserves_outcome_and_observation_fingerprints():
    trace = source(100)
    contract = AnalysisContract(engine_params={"threshold": 5})
    original = compare(trace, contract, contract, source_bytes=trace.size_bytes)
    kind, restored = decode_result(encode_result("ok", original), 1024 * 1024)
    assert kind == "ok" and asdict(restored) == asdict(original)
    for key, result in original.results.items():
        assert restored.results[key].fingerprint() == result.fingerprint()


def test_pickle_cannot_execute_at_result_boundary(tmp_path):
    marker = tmp_path / "executed"
    class Malicious:
        def __reduce__(self):
            return Path.write_text, (marker, "executed")
    payload = pickle.dumps(Malicious())
    with pytest.raises(ValueError):
        decode_result(payload, 1024 * 1024)
    assert not marker.exists()


@pytest.mark.parametrize("data", [b'["error",NaN]', b'["ok",{"run_id":0,"run_id":1}]', b'["unknown","message"]', b'[[],"message"]'])
def test_malformed_result_is_refused(data):
    with pytest.raises(ValueError):
        decode_result(data, 1024 * 1024)


def test_result_capacity_and_engine_identity_are_validated():
    trace = source()
    contract = AnalysisContract(engine_params={"threshold": 5})
    payload = encode_result("ok", compare(trace, contract, contract))
    with pytest.raises(ValueError):
        decode_result(payload, len(payload) - 1)
    document = json.loads(payload)
    document[1]["results"]["baseline:port_scan"]["engine"] = "other"
    with pytest.raises(ValueError):
        decode_result(json.dumps(document).encode(), 1024 * 1024)


def test_inconsistent_comparability_and_huge_numbers_are_refused():
    trace = source()
    contract = AnalysisContract(engine_params={"threshold": 5})
    document = json.loads(encode_result("ok", compare(trace, contract, contract)))
    document[1]["non_comparable_reasons"] = [{"code": "missing", "detail": "missing evidence"}]
    with pytest.raises(ValueError):
        decode_result(json.dumps(document).encode(), 1024 * 1024)
    document[1]["non_comparable_reasons"] = []
    document[1]["run_id"] = 2**1000
    with pytest.raises(ValueError):
        decode_result(json.dumps(document).encode(), 1024 * 1024)
