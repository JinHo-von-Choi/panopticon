"""순수 replay 연산의 프로세스·시간·메모리 경계. 운영 서비스는 전달하지 않는다."""
from __future__ import annotations

import asyncio
import math
import multiprocessing
import resource
import time

from netwatcher.replay.service import compare
from netwatcher.replay.result_wire import encode_result, decode_result


class ReplayBudgetError(RuntimeError):
    pass


def _compute(send, trace, baseline, candidate, source_bytes, memory_bytes, timeout, result_bytes):
    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        cpu = max(1, math.ceil(timeout)) + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        outcome = compare(trace, baseline, candidate, source_bytes=source_bytes)
        data = encode_result('ok', outcome)
        if len(data) > result_bytes:
            data = encode_result('budget', 'result_bytes')
        send.send_bytes(data)
    except MemoryError:
        send.send_bytes(encode_result('budget', 'memory'))
    except Exception as error:
        send.send_bytes(encode_result('error', type(error).__name__))
    finally:
        send.close()


class ReplayRunner:
    def __init__(self, timeout=600, memory_bytes=256 * 1024 * 1024, result_bytes=32 * 1024 * 1024):
        self.timeout = max(.001, min(600, float(timeout)))
        self.memory_bytes = max(128 * 1024 * 1024, int(memory_bytes))
        self.result_bytes = max(1024, int(result_bytes))
        self._processes = set()
        self.stopping = False

    def terminate_now(self):
        self.stopping = True
        for process in tuple(self._processes):
            if process.is_alive():
                process.kill()

    async def run(self, trace, baseline, candidate, source_bytes):
        if self.stopping:
            raise ReplayBudgetError('shutdown')
        context = multiprocessing.get_context('spawn')
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=_compute, args=(send, trace, baseline, candidate,
                                   source_bytes, self.memory_bytes, self.timeout, self.result_bytes), daemon=True)
        self._processes.add(process)
        started = False
        try:
            process.start()
            started = True
            send.close()
            deadline = time.monotonic() + self.timeout
            while not receive.poll():
                if time.monotonic() >= deadline:
                    raise ReplayBudgetError('wall_time')
                if not process.is_alive():
                    if process.exitcode is not None and process.exitcode < 0:
                        raise ReplayBudgetError('worker_resource_limit')
                    raise RuntimeError('Replay worker exited without a result')
                await asyncio.sleep(.01)
            remaining = max(.001, deadline - time.monotonic())
            try:
                data = await asyncio.wait_for(asyncio.to_thread(receive.recv_bytes, self.result_bytes), remaining)
            except asyncio.TimeoutError:
                raise ReplayBudgetError('wall_time') from None
            except EOFError:
                raise ReplayBudgetError('worker_resource_limit') from None
            except OSError:
                raise ReplayBudgetError('result_bytes') from None
            try:
                remaining = max(.001, deadline - time.monotonic())
                kind, payload = await asyncio.wait_for(
                    asyncio.to_thread(decode_result, data, self.result_bytes), remaining)
            except asyncio.TimeoutError:
                raise ReplayBudgetError('wall_time') from None
            except (ValueError, TypeError, OverflowError, RecursionError):
                raise ReplayBudgetError('invalid_result') from None
            if kind == 'budget':
                raise ReplayBudgetError(payload)
            if kind != 'ok':
                raise RuntimeError('Replay worker failed: ' + str(payload))
            return payload
        finally:
            send.close()
            if started:
                if process.is_alive():
                    process.kill()
                await asyncio.to_thread(process.join, .25)
                if not process.is_alive():
                    process.close()
            receive.close()
            self._processes.discard(process)
