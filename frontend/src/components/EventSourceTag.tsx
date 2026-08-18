import type { EventSource } from "../types";

// Section 19: precise, never-misleading labels.
const LABELS: Record<EventSource, string> = {
  offline_demo: "Offline Dataset Demonstration",
  test_event: "Test Event",
  live: "Live",
};

export function EventSourceTag({ source }: { source: EventSource }) {
  return <span className="badge outline">{LABELS[source] ?? source}</span>;
}
