"""계정 자격 증명·버전 충돌·마지막 관리자 보호를 실제 DB에서 확인한다."""
import asyncio
import pytest

from netwatcher.storage.user_accounts import UserAccounts,AccountConflict,valid_password

PASSWORD='FixturePassword-2026'


@pytest.mark.asyncio
async def test_account_authentication_returns_no_hash_and_honors_disabled_state(db):
    accounts=UserAccounts(db)
    admin=await accounts.create('Admin',PASSWORD,'admin','setup')
    member=await accounts.create('viewer',PASSWORD,'viewer','admin')
    assert admin['username']=='admin' and member['role']=='viewer'
    assert 'password' not in str(member) and 'password_hash' not in member
    logged=await accounts.authenticate('VIEWER',PASSWORD)
    assert logged['id']==member['id'] and logged['version']==1
    assert await accounts.authenticate('viewer','wrong password') is None
    assert await accounts.authenticate('missing',PASSWORD) is None
    disabled=await accounts.update(member['id'],1,role='viewer',enabled=False,actor='admin')
    assert disabled['version']==2
    assert await accounts.authenticate('viewer',PASSWORD) is None
    stored=await db.pool.fetchval('SELECT password_hash FROM user_accounts WHERE username=$1','viewer')
    assert stored.startswith('$2b$') and PASSWORD not in stored
    listing=await accounts.list()
    assert listing['total']==2 and all('password_hash' not in user for user in listing['users'])


@pytest.mark.asyncio
async def test_first_account_requires_admin_and_names_are_unique(db):
    accounts=UserAccounts(db)
    with pytest.raises(AccountConflict,match='administrator_required'):
        await accounts.create('viewer',PASSWORD,'viewer','setup')
    await accounts.create('Admin',PASSWORD,'admin','setup')
    with pytest.raises(AccountConflict,match='username_exists'):
        await accounts.create('ADMIN',PASSWORD,'viewer','admin')
    assert (await accounts.list())['total']==1


@pytest.mark.asyncio
async def test_last_admin_cannot_be_disabled_or_demoted(db):
    accounts=UserAccounts(db);admin=await accounts.create('admin',PASSWORD,'admin','setup')
    for role,enabled in [('admin',False),('viewer',True),('analyst',True)]:
        with pytest.raises(AccountConflict,match='last_administrator'):
            await accounts.update(admin['id'],1,role=role,enabled=enabled,actor='admin')
    unchanged=await accounts.get(admin['id'])
    assert unchanged['version']==1 and unchanged['enabled'] is True and unchanged['role']=='admin'


@pytest.mark.asyncio
async def test_concurrent_admin_demotions_cannot_remove_both(db):
    accounts=UserAccounts(db)
    one=await accounts.create('one',PASSWORD,'admin','setup')
    two=await accounts.create('two',PASSWORD,'admin','one')
    results=await asyncio.gather(accounts.update(one['id'],1,role='viewer',enabled=True,actor='one'),
        accounts.update(two['id'],1,role='viewer',enabled=True,actor='two'),return_exceptions=True)
    assert sum(isinstance(result,AccountConflict) for result in results)==1
    assert await db.pool.fetchval("SELECT count(*) FROM user_accounts WHERE enabled AND role='admin'")==1


@pytest.mark.asyncio
async def test_password_reset_revokes_account_version_and_conflicts_are_preserved(db):
    accounts=UserAccounts(db);admin=await accounts.create('admin',PASSWORD,'admin','setup')
    next_password='DifferentFixturePassword-2026'
    updated=await accounts.reset_password(admin['id'],1,next_password,'admin')
    assert updated['version']==2
    assert await accounts.authenticate('admin',PASSWORD) is None
    assert (await accounts.authenticate('admin',next_password))['version']==2
    with pytest.raises(AccountConflict,match='version_changed'):
        await accounts.update(admin['id'],1,role='admin',enabled=True,actor='admin')
    with pytest.raises(AccountConflict,match='version_changed_or_missing'):
        await accounts.reset_password(admin['id'],1,PASSWORD,'admin')
    assert (await accounts.authenticate('admin',next_password))['version']==2


@pytest.mark.parametrize('password',['short','x'*73,'가'*25,'a'*11+'\x00'])
def test_password_byte_bounds(password):
    with pytest.raises(ValueError):valid_password(password)


@pytest.mark.asyncio
async def test_role_change_during_password_verification_invalidates_login(db,monkeypatch):
    import netwatcher.storage.user_accounts as module
    accounts=UserAccounts(db);admin=await accounts.create('admin',PASSWORD,'admin','setup')
    user=await accounts.create('member',PASSWORD,'analyst','admin')
    original=module.asyncio.to_thread
    async def changed_during_verify(function,*args,**kwargs):
        verified=await original(function,*args,**kwargs)
        await accounts.update(user['id'],1,role='viewer',enabled=True,actor='admin')
        return verified
    monkeypatch.setattr(module.asyncio,'to_thread',changed_during_verify)
    assert await accounts.authenticate('member',PASSWORD) is None
    assert (await accounts.get(user['id']))['role']=='viewer'


@pytest.mark.asyncio
async def test_non_ascii_confusable_and_invalid_role_are_rejected(db):
    accounts=UserAccounts(db)
    for name in ('K-admin','한글관리자','admin name','admin\x00'):
        with pytest.raises(ValueError,match='Invalid username'):
            await accounts.create(name,PASSWORD,'admin','setup')
    with pytest.raises(ValueError,match='Invalid role'):
        await accounts.create('admin',PASSWORD,'owner','setup')
    assert (await accounts.list())['total']==0


@pytest.mark.asyncio
async def test_capacity_is_enforced_without_mutating_existing_accounts(db):
    accounts=UserAccounts(db)
    await accounts.create('admin',PASSWORD,'admin','setup')
    await db.pool.execute("""INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
        SELECT md5(index::text)::uuid,'user-'||index,password_hash,'viewer','setup'
        FROM user_accounts CROSS JOIN generate_series(1,999) index WHERE username='admin'""")
    with pytest.raises(AccountConflict,match='account_capacity'):
        await accounts.create('overflow',PASSWORD,'viewer','admin')
    assert (await accounts.list())['total']==1000
