"""역할 경계 시험에 쓸 완전한 단일 사용자 인증 객체를 만든다."""

from unittest.mock import patch

import bcrypt

from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


PASSWORD_HASH = bcrypt.hashpw(b'RoleFixturePassword-2026', bcrypt.gensalt(rounds=4)).decode()


def configured_auth(secret: str) -> AuthManager:
    with patch.dict('os.environ', {'NETWATCHER_JWT_SECRET': secret}):
        return AuthManager(Config({'auth': {
            'enabled': True, 'multi_user': False, 'password': PASSWORD_HASH,
            'jwt_secret': secret, 'token_expire_hours': 1,
        }}))
