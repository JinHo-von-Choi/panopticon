"""통합 콘솔의 증거 읽기에도 센서의 파일 검증을 적용한다."""

import asyncio
from uuid import uuid4

from fastapi import HTTPException

from netwatcher.services.sensor_evidence import SensorEvidence, validate_state


class LocalEvidenceReader:
    def __init__(self, repository, writer):
        self.repository = repository
        self.evidence = SensorEvidence(writer)
        self.owner = uuid4()

    async def _recorded_sha(self, event_id):
        if self.evidence.writer is None:
            raise HTTPException(503, "증거 저장소를 사용할 수 없습니다.")
        event = await self.repository.get_by_id(event_id)
        if event is None:
            raise HTTPException(404, "사건을 찾을 수 없습니다.")
        metadata = event.get("metadata") or {}
        pcap = metadata.get("pcap")
        return pcap.get("sha256") if isinstance(pcap, dict) else None

    async def state(self, event_id):
        try:
            async with asyncio.timeout(8):
                recorded_sha = await self._recorded_sha(event_id)
                value = await asyncio.to_thread(self.evidence.state, event_id, self.owner, "local", recorded_sha)
                validate_state(value, event_id)
                return value
        except (OSError, ValueError, TypeError, TimeoutError):
            raise HTTPException(503, "증거 파일을 확인하지 못했습니다.") from None

    async def chunk(self, event_id, file_version, offset):
        try:
            async with asyncio.timeout(8):
                recorded_sha = await self._recorded_sha(event_id)
                return await asyncio.to_thread(self.evidence.chunk,
                    {"event_id": event_id, "file_version": file_version, "offset": offset}, self.owner, recorded_sha)
        except FileNotFoundError:
            raise HTTPException(404, "보관된 증거 파일이 없습니다.") from None
        except ValueError:
            raise HTTPException(409, "증거 파일이 변경됐습니다. 다시 조회하세요.") from None
        except (OSError, TypeError, TimeoutError):
            raise HTTPException(503, "증거 파일을 확인하지 못했습니다.") from None
