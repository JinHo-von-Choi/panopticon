"""Real PostgreSQL and real offline computation protect approval linkage."""
from unittest.mock import MagicMock
import pytest
from netwatcher import __version__
from netwatcher.detection.proposals import ProposalService, ProposalError
from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.runs import ReplayRunService
from netwatcher.replay.trace import Trace
from netwatcher.storage.repositories import ConfigProposalRepository, ReplayRepository


async def pair(service, proposal_id, threshold=10):
    ids = []
    for label, count in [('normal', 6), ('attack', 20)]:
        import uuid
        trace = Trace(uuid.uuid4().hex, records=[
            {'src_ip': '192.0.2.1', 'dst_ip': '192.0.2.2', 'dst_port': i,
             'bytes': 120, 'ts': i / 100, 'ip_proto': 'tcp'} for i in range(count)],
            engines=('port_scan',), compat_snapshot={
                'input_label': label, 'label_confirmed': True, 'proposal_id': proposal_id})
        run = await service.submit(trace,
            AnalysisContract(build_version=__version__, engine_params={'threshold': 5}),
            AnalysisContract(build_version=__version__, engine_params={'threshold': threshold}))
        await service.wait(run)
        ids.append(run)
    return ids


def setup(db):
    registry, editor = MagicMock(), MagicMock()
    registry.get_engine_schema.return_value = {
        'enabled': (bool, True), 'threshold': {'type': int, 'default': 5, 'min': 1, 'max': 100},
        'window_seconds': {'type': int, 'default': 60, 'min': 1, 'max': 3600}}
    registry.reload_engine.return_value = (True, None, [])
    editor.get_engine_config.return_value = {'enabled': True, 'threshold': 5, 'window_seconds': 60}
    replay = ReplayRunService(ReplayRepository(db))
    repo = ConfigProposalRepository(db)
    service = ProposalService(registry, editor, repo)
    service.require_replay_validation(replay)
    return service, replay, repo, registry, editor


@pytest.mark.asyncio
async def test_approval_requires_pair_and_preserves_linked_evidence(db):
    service, replay, repo, registry, editor = setup(db)
    pid = await service.submit('port_scan', {'threshold': 10})
    with pytest.raises(ProposalError, match='먼저 연결'):
        await service.decide(pid, True)
    registry.reload_engine.assert_not_called()
    normal, attack = await pair(replay, pid)
    validation = await service.attach_validation(pid, normal, attack, 'analyst')
    assert validation['scope'] == 'offline_feature_observations'
    row = await repo.get_by_id(pid)
    assert row['validation_runs']['confirmed_by'] == 'analyst'
    result = await service.decide(pid, True, 'admin')
    assert result.applied
    editor.update_engine_config.assert_called_once_with('port_scan', {'threshold': 10})
    await replay.stop()


@pytest.mark.asyncio
async def test_lost_attack_or_foreign_proposal_cannot_bind(db):
    service, replay, repo, registry, editor = setup(db)
    pid = await service.submit('port_scan', {'threshold': 40})
    normal, attack = await pair(replay, pid, 40)
    with pytest.raises(ProposalError, match='공격'):
        await service.attach_validation(pid, normal, attack, 'analyst')
    other = await service.submit('port_scan', {'threshold': 40})
    with pytest.raises(ProposalError, match='입력 근거'):
        await service.attach_validation(other, normal, attack, 'analyst')
    assert not (await repo.get_by_id(pid))['validation_runs']
    registry.reload_engine.assert_not_called()
    await replay.stop()


@pytest.mark.asyncio
async def test_config_drift_blocks_approval_after_successful_validation(db):
    service, replay, repo, registry, editor = setup(db)
    pid = await service.submit('port_scan', {'threshold': 10})
    normal, attack = await pair(replay, pid)
    await service.attach_validation(pid, normal, attack, 'analyst')
    editor.get_engine_config.return_value['threshold'] = 7
    with pytest.raises(ProposalError, match='설정이 변경'):
        await service.decide(pid, True)
    registry.reload_engine.assert_not_called()
    assert (await repo.get_by_id(pid))['status'] == 'pending'
    await replay.stop()


@pytest.mark.asyncio
async def test_same_release_with_different_implementation_cannot_bind(db):
    service, replay, repo, registry, editor = setup(db)
    pid = await service.submit('port_scan', {'threshold': 10})
    normal, attack = await pair(replay, pid)
    replay.implementation_version = 'different-source-with-same-release'
    with pytest.raises(ProposalError, match='구현 지문'):
        await service.attach_validation(pid, normal, attack, 'analyst')
    assert not (await repo.get_by_id(pid))['validation_runs']
    registry.reload_engine.assert_not_called()
    await replay.stop()
