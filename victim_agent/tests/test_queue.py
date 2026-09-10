from __future__ import annotations

import logging

from victim_agent.queue import BoundedRetryQueue


def test_push_and_flush_all_success():
    q = BoundedRetryQueue(maxsize=10)
    q.push({"n": 1})
    q.push({"n": 2})
    sent_items = []
    sent = q.flush(lambda item: sent_items.append(item))
    assert sent == 2
    assert sent_items == [{"n": 1}, {"n": 2}]
    assert len(q) == 0


def test_eviction_when_full_logs_warning(caplog):
    q = BoundedRetryQueue(maxsize=2)
    q.push({"n": 1})
    q.push({"n": 2})
    with caplog.at_level(logging.WARNING):
        q.push({"n": 3})  # evicts {"n": 1}
    assert len(q) == 2
    assert any("discarding oldest" in r.message for r in caplog.records)

    sent_items = []
    q.flush(lambda item: sent_items.append(item))
    assert sent_items == [{"n": 2}, {"n": 3}]


def test_flush_stops_at_first_failure_and_preserves_order():
    q = BoundedRetryQueue(maxsize=10)
    q.push({"n": 1})
    q.push({"n": 2})
    q.push({"n": 3})

    def _send(item: dict) -> None:
        if item["n"] == 2:
            raise RuntimeError("simulated failure")

    sent = q.flush(_send)
    assert sent == 1  # only {"n": 1} succeeded
    assert len(q) == 2  # {"n": 2} and {"n": 3} remain, in order

    sent_items = []
    q.flush(lambda item: sent_items.append(item))
    assert sent_items == [{"n": 2}, {"n": 3}]


def test_flush_on_empty_queue_is_a_noop():
    q = BoundedRetryQueue(maxsize=10)
    sent = q.flush(lambda item: (_ for _ in ()).throw(AssertionError("should not be called")))
    assert sent == 0
