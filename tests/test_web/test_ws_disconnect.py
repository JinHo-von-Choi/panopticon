"""A real idle WebSocket releases its subscription without waiting for heartbeat."""
import asyncio
import socket
import time
from types import SimpleNamespace
import pytest
import uvicorn
import websockets
from fastapi import FastAPI
from netwatcher.web.routes.events import create_ws_router


@pytest.mark.asyncio
async def test_idle_disconnect_releases_subscription_promptly():
    queues = set()
    def subscribe():
        queue = asyncio.Queue(maxsize=10); queues.add(queue); return queue
    dispatcher = SimpleNamespace(subscribe_ws=subscribe, unsubscribe_ws=queues.discard)
    app = FastAPI(); app.include_router(create_ws_router(dispatcher), prefix='/api')
    listener = socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off', timeout_graceful_shutdown=1))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        for _ in range(100):
            if server.started: break
            await asyncio.sleep(.01)
        async with websockets.connect(f'ws://127.0.0.1:{port}/api/ws/events'):
            assert len(queues) == 1
        started = time.monotonic()
        while queues and time.monotonic() - started < .5:
            await asyncio.sleep(.01)
        assert not queues
        assert time.monotonic() - started < .5
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 2)
        listener.close()


@pytest.mark.asyncio
async def test_outgoing_rate_limit_notifies_client_once(monkeypatch):
    from netwatcher.alerts.stream import EventStream
    import netwatcher.web.routes.events as routes
    import json
    monkeypatch.setattr(routes, '_WS_RATE_LIMIT_MSG_PER_MIN', 2)
    stream = EventStream()
    app = FastAPI()
    app.include_router(create_ws_router(stream), prefix='/api')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off', timeout_graceful_shutdown=1))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.01)
        async with websockets.connect(f'ws://127.0.0.1:{port}/api/ws/events') as client:
            for identifier in range(5):
                stream.publish({'type': 'alert', 'id': identifier})
            assert json.loads(await asyncio.wait_for(client.recv(), 2))['id'] == 0
            assert json.loads(await asyncio.wait_for(client.recv(), 2))['id'] == 1
            assert json.loads(await asyncio.wait_for(client.recv(), 2)) == {'type': 'stream_gap', 'reason': 'websocket_rate_limit'}
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(client.recv(), .2)
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 2)
        listener.close()
