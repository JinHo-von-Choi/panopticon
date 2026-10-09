"""실제 PostgreSQL에서 감사 필터를 SQL 구문으로 해석하지 않는지 확인한다."""

import pytest

from netwatcher.web.audit_log import AuditLogger


@pytest.mark.asyncio
@pytest.mark.parametrize("user,action", [
    ("' OR 1=1 --", None),
    (None, "' OR 1=1 --"),
    ("' OR 1=1 --", "' OR 1=1 --"),
])
async def test_audit_filter_values_are_bound_and_cannot_select_other_records(db, user, action):
    audit = AuditLogger(db.pool)
    assert await audit.log("parameter-test-admin", "parameter-test-change", "/test")
    assert await audit.query(user=user, action=action) == []
    assert len(await audit.query(user="parameter-test-admin", action="parameter-test-change")) == 1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log") == 1
