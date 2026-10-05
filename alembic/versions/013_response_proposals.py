"""response_proposals: 업무 영향을 고려한 최소 대응 제안 (계획서 4장, PR 14).

Revision ID: 013_response_proposals
Revises: 012_response_actions
Create Date: 2026-10-06

    "ResponseProposal 은 근거·가시성 상태·대상 매핑·지원 match 범위·예상 관련
     자산·불확실성·TTL 을 묶는다."

여기서 `unconfirmed` (미확인) 이 핵심이다. 공유 IP·NAT·DHCP 교체 때문에
"이 자산이 저 자산과 통신한다" 는 사실조차 확인되지 않을 수 있다. 그런
범위를 확정된 사실처럼 묶으면 사람이 "业务 영향이 없다" 고 오독한다.

그래서 `uncertainty` 를 컬럼으로 두고, 확정 범위와 미확인 범위를 **분리** 해
보관한다. 좁히지 못한 범위는 넓은 IP 차단으로 대체하지 않는다 — 그 대체는
이 테이블이 존재하는 이유를 무효화한다.
"""

from __future__ import annotations

from alembic import op

revision = "013_response_proposals"
down_revision = "012_response_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS response_proposals (
            id                  BIGSERIAL      PRIMARY KEY,
            event_id            BIGINT,
            engine              VARCHAR(64)     NOT NULL DEFAULT '',
            source_ip           VARCHAR(64),
            -- 1) 근거: 무엇이 이 제안을 만들었는가
            evidence            JSONB          NOT NULL DEFAULT '{}'::jsonb,
            -- 2) 가시성 상태: 관측이 온전한가 (관측 범위 장과 공유)
            visibility_state    VARCHAR(16)    NOT NULL DEFAULT 'unknown',
            visibility_reasons  JSONB          NOT NULL DEFAULT '[]'::jsonb,
            -- 3) 대상 매핑: 주소가 누구인지
            target_mapping      JSONB          NOT NULL DEFAULT '{}'::jsonb,
            -- 4) 지원 match 범위: 백엔드가 실제로 좁힐 수 있는가
            match_scope         JSONB          NOT NULL DEFAULT '{}'::jsonb,
            -- 5) 예상 관련 자산 — 확정된 것과 추정된 것을 분리해 담는다
            expected_assets     JSONB          NOT NULL DEFAULT '[]'::jsonb,
            unconfirmed_assets  JSONB          NOT NULL DEFAULT '[]'::jsonb,
            -- 6) 불확실성
            uncertainty         JSONB          NOT NULL DEFAULT '{}'::jsonb,
            ttl_seconds         INTEGER         NOT NULL,
            status              VARCHAR(16)     NOT NULL DEFAULT 'proposed',
            created_by          VARCHAR(64)     NOT NULL DEFAULT 'rules',
            created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            CONSTRAINT response_proposals_status_check
                CHECK (status IN ('proposed', 'approved', 'rejected', 'expired')),
            CONSTRAINT response_proposals_ttl_check CHECK (ttl_seconds > 0)
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_proposals_src
        ON response_proposals(source_ip, created_at DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_proposals_status
        ON response_proposals(status, created_at DESC)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS response_proposals")
