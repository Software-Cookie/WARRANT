"""Micro-batching: requests arriving within a short window are scored together, which multiplies throughput per
accelerator for a few milliseconds of added latency (Bible §17.3)."""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from typing import Generic, TypeVar

Item = TypeVar("Item")
Result = TypeVar("Result")


class MicroBatcher(Generic[Item, Result]):
    def __init__(self, score_batch: Callable[[Sequence[Item]], list[Result]], window_ms: int, max_batch: int) -> None:
        self._score_batch = score_batch
        self._window = window_ms / 1000.0
        self._max_batch = max_batch
        self._queue: asyncio.Queue[tuple[Item, asyncio.Future[Result]]] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self.batches: list[int] = []

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def submit(self, item: Item) -> Result:
        self.start()
        future: asyncio.Future[Result] = asyncio.get_running_loop().create_future()
        await self._queue.put((item, future))
        return await future

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            first = await self._queue.get()
            batch = [first]
            deadline = loop.time() + self._window
            while len(batch) < self._max_batch:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self._queue.get(), timeout=remaining))
                except asyncio.TimeoutError:
                    break
            self.batches.append(len(batch))
            items = [item for item, _ in batch]
            try:
                results = await asyncio.to_thread(self._score_batch, items)
            except Exception as error:  # noqa: BLE001 - a batch failure fails each caller, never the loop
                for _, future in batch:
                    if not future.done():
                        future.set_exception(error)
                continue
            for (_, future), result in zip(batch, results, strict=True):
                if not future.done():
                    future.set_result(result)
