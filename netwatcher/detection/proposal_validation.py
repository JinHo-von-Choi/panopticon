"""Bind stored, labelled feature comparisons to an immutable proposal snapshot.

This validates offline observations only. Unsupported runtime features remain
blocked rather than being treated as a successful safety test.
"""
from netwatcher import __version__

DEFAULTS = {
    'port_scan': {'threshold': 5},
}


class ValidationError(ValueError):
    pass


async def validate_pair(service, row, normal_id, attack_id):
    engine = row['engine']
    defaults = DEFAULTS.get(engine)
    if not defaults or not row['params'] or set(row['params']) - defaults.keys():
        raise ValidationError('변경한 특징값을 재현할 수 없는 엔진 또는 파라미터입니다')
    if normal_id == attack_id:
        raise ValidationError('정상·공격 실행은 서로 달라야 합니다')
    if set(defaults) - (row.get('before') or {}).keys():
        raise ValidationError('현재 설정에 비교 파라미터가 없습니다. 유효한 현재값을 먼저 확인하세요')
    before = {key: row['before'][key] for key in defaults}
    candidate = {**before, **row['params']}
    contracts = []
    runs = []
    for run_id, label in ((normal_id, 'normal'), (attack_id, 'attack')):
        run = await service.get_diff(run_id)
        if not run or run['status'] != 'completed' or run.get('comparable') is not True:
            raise ValidationError('완료된 비교 가능한 실행만 연결할 수 있습니다')
        context = run.get('comparison_context') or {}
        if (context.get('input_label') != label or context.get('label_confirmed') is not True
                or context.get('proposal_id') != row['id'] or not run.get('input_hash')):
            raise ValidationError('담당자 확인 및 제안에 연결된 입력 근거가 없습니다')
        if context.get('implementation_version') != service.implementation_version:
            raise ValidationError('비교 구현 지문이 현재 실행기와 다릅니다. 다시 재현하세요')
        baseline = context.get('baseline_contract') or {}
        proposed = context.get('candidate_contract') or {}
        if baseline.get('params') != before or proposed.get('params') != candidate:
            raise ValidationError('실행 파라미터가 제안의 변경 전·후와 다릅니다')
        if any(contract.get('versions', {}).get('build') != __version__
               for contract in (baseline, proposed)):
            raise ValidationError('실행 빌드 버전이 현재 버전과 다릅니다')
        if any({result['engine'] for result in run.get(side, [])} != {engine}
               for side in ('baseline', 'candidate')):
            raise ValidationError('실행 대상 엔진이 제안과 다릅니다')
        contracts.append((baseline, proposed))
        runs.append(run)
    if runs[0]['input_hash'] == runs[1]['input_hash']:
        raise ValidationError('정상·공격 입력이 동일합니다. 독립적인 확인 샘플이 필요합니다')
    if contracts[0] != contracts[1]:
        raise ValidationError('정상·공격 실행의 비교 계약이 다릅니다')
    attack = runs[1]
    baseline_count = sum(r['observation_count'] for r in attack['baseline'])
    candidate_count = sum(r['observation_count'] for r in attack['candidate'])
    counts = (attack.get('diff') or {}).get('counts') or {}
    if (baseline_count <= 0 or candidate_count < baseline_count
            or counts.get('removed') != 0 or counts.get('changed') != 0):
        raise ValidationError('공격 양성 대조가 없거나 공격 관측이 사라지거나 변경되었습니다')
    return {'normal_run_id': normal_id, 'attack_run_id': attack_id,
            'build_version': __version__, 'scope': 'offline_feature_observations',
            'normal_input_hash': runs[0]['input_hash'], 'attack_input_hash': attack['input_hash']}
