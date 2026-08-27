"""Bounded local worker execution for independent audit jobs."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Generic, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


@dataclass(frozen=True)
class WorkerResult(Generic[R]):
    job_id: str
    value: R | None
    error: str | None


def run_bounded(jobs: Iterable[tuple[str, T]], worker: Callable[[T], R], *, max_workers: int = 4, max_jobs: int = 1000) -> tuple[WorkerResult[R], ...]:
    """Run local jobs with a bounded worker count and deterministic job ordering."""
    if not 1 <= max_workers <= 16:
        raise ValueError("max_workers must be between 1 and 16")
    pending = list(jobs)
    if len(pending) > max_jobs:
        raise ValueError(f"job count exceeds limit {max_jobs}")
    results: dict[str, WorkerResult[R]] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="configsentinel") as pool:
        futures = {pool.submit(worker, payload): job_id for job_id, payload in pending}
        for future in as_completed(futures):
            job_id = futures[future]
            try:
                results[job_id] = WorkerResult(job_id, future.result(), None)
            except Exception as exc:  # worker boundary converts failures into explicit job results
                results[job_id] = WorkerResult(job_id, None, f"{type(exc).__name__}: {exc}")
    return tuple(results[job_id] for job_id, _ in pending)
