"""유한 큐로 콘솔의 실시간 이벤트 구독을 관리한다."""

import asyncio
import json


def publish_message(subscribers, message):
    """느린 구독자에게 누락을 알리고 저장 기록의 재조회를 요청한다."""
    for queue in tuple(subscribers):
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            while not queue.empty():
                queue.get_nowait()
            queue.put_nowait(json.dumps({"type": "stream_gap", "reason": "subscriber_overflow"}))


class EventStream:
    def __init__(self):
        self._ws_subscribers = set()

    def subscribe_ws(self):
        queue = asyncio.Queue(maxsize=100)
        self._ws_subscribers.add(queue)
        return queue

    def unsubscribe_ws(self, queue):
        self._ws_subscribers.discard(queue)

    def publish(self, event):
        message = json.dumps(event, ensure_ascii=False)
        publish_message(self._ws_subscribers, message)
