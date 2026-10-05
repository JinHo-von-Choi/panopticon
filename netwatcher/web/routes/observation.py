"""관측 범위(observation scope) 조회 API (PR 11 / 계획서 3장).

왜 이 API 가 필요한가

    "경보가 없다" 는 두 가지 전혀 다른 상태를 같은 말로 쓴다.

    1. 아무 일도 없었다
    2. 아무것도 관측하지 못했다 (인터페이스 정지, 큐 포화, DB 단절)

    이 엔드포인트는 그 구분을 그대로 노출한다. 관측 상태는 항상
    ``observed / partial / stale / unknown`` 중 하나이며 **이유** 를 함께
    돌려준다. 이유 없는 상태를 만들지 않는다.

이 API 는 읽기 전용이며 viewer 역할이면 충분하다. 관측 상태를 본다는
행위 자체는 판단을 바꾸지 않으므로 승인은 필요 없다.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

from netwatcher.observability.observation import (
    STATE_OBSERVED,
    KernelDropProbe,
    STATE_PARTIAL,
    STATE_STALE,
    STATE_UNKNOWN,
    ObservationService,
)
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.observation")

STATE_ORDER = (STATE_OBSERVED, STATE_PARTIAL, STATE_STALE, STATE_UNKNOWN)


def create_observation_router(
    observation: ObservationService,
    kernel_probe: KernelDropProbe | None = None,
) -> APIRouter:
    """관측 범위 조회 라우터를 만든다.

    Args:
        observation: 관측 서비스를 주입한다.
    """
    router = APIRouter(tags=["observation"])

    @router.get("/observation")
    async def get_observation(
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        """현재 센서의 관측 상태를 반환한다.

        반환값은 다음을 반드시 포함한다.

        - ``state``      : observed / partial / stale / unknown
        - ``reasons``    : 그 상태를 판정한 이유 (비어 있지 않음)
        - ``loss``       : 단계별 손실. 커널 drop 과 앱 drop 은 합산되지 않는다
        - ``unsupported_measurements`` : 이 센서에서 측정할 수 없는 항목
        """
        snapshot = observation.snapshot()

        # reasons 가 비면 판정이 설명되지 않은 것이다. 그 상태를 그대로
        # 노출하지 않고 unknown 으로 낮춘다.
        if not snapshot["reasons"]:
            snapshot["state"] = STATE_UNKNOWN
            snapshot["reasons"] = ["판정 근거가 없어 unknown 으로 남긴다"]

        snapshot["state_order"] = list(STATE_ORDER)
        snapshot["kernel_drop_source"] = _kernel_source(kernel_probe)
        snapshot["interpretation"] = _interpretation(snapshot)
        return snapshot

    return router


def _kernel_source(probe: KernelDropProbe | None) -> dict[str, Any]:
    if probe is None:
        return {
            "available": False,
            "reason": "커널 drop 측정기가 연결되지 않았다",
        }
    return probe.status()


def _interpretation(snapshot: dict[str, Any]) -> dict[str, Any]:
    """사람이 오독하지 않도록 문장을 붙인다.

    계약을 통과했다는 사실과 실제로 무엇이 보장되는지를 구분한다.
    """
    state = snapshot["state"]
    no_traffic = snapshot.get("no_traffic_observed")
    message = {
        STATE_OBSERVED: "관측 창이 온전하다. 이 창 안의 수치는 비교 가능하다.",
        STATE_PARTIAL: "관측 창이 온전하지 않다. 수치를 그대로 신뢰하지 마라.",
        STATE_STALE: "센서가 살아 있는지 확인되지 않는다. 경보 부재를 근거로 쓰지 마라.",
        STATE_UNKNOWN: "관측 범위를 알 수 없다. 무엇이 왜인지 알 수 없다는 뜻이다.",
    }.get(state, state)

    cautions: list[str] = []
    if no_traffic:
        cautions.append(
            "관측된 트래픽이 0 이다. 이것만으로 장애를 선언하지 않는다."
        )
    link = snapshot.get("loss", {}).get("link_loss", {})
    if link.get("status") == STATE_UNKNOWN:
        cautions.append(link.get("reason", "링크 손실은 측정되지 않는다"))

    return {"message": message, "cautions": cautions}
