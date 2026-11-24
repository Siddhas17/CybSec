import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import type { TopNode } from "../types";

type SortKey = "attack-desc" | "attack-asc" | "total-desc" | "ip-asc";
const PAGE_SIZE = 10;

export function DestinationAnalysis() {
  const [destinations, setDestinations] = useState<TopNode[]>([]);
  const [selected, setSelected] = useState<TopNode | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("attack-desc");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Keep the existing top-destinations endpoint and its attack-flow ranking.
      setDestinations(await api.analytics.topDestinations(25));
    } catch {
      setError("Could not load destination aggregates. Check the backend connection and retry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return destinations
      .filter((item) => !query || item.ip.toLowerCase().includes(query))
      .slice()
      .sort((a, b) => {
        if (sort === "attack-asc") return a.attack_flow_count - b.attack_flow_count || a.ip.localeCompare(b.ip);
        if (sort === "total-desc") return b.total_flow_count - a.total_flow_count || a.ip.localeCompare(b.ip);
        if (sort === "ip-asc") return a.ip.localeCompare(b.ip);
        return b.attack_flow_count - a.attack_flow_count || a.ip.localeCompare(b.ip);
      });
  }, [destinations, search, sort]);

  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selectedRank = selected ? destinations.findIndex((item) => item.ip === selected.ip) + 1 : 0;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Destination IP Analysis</h1>
          <div className="page-subtitle">Observed destination addresses ranked by persisted attack-labelled flow count.</div>
        </div>
        <button className="secondary" onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
      </div>

      <div className="notice-banner">
        This is a single-machine environment; these are destination IPs observed in captured traffic, not necessarily
        separate physical victim hosts. There is no live multi-host laboratory in this deployment. An “attack flow”
        is a flow whose canonical input label is not BENIGN, aggregated over persisted source-to-destination graph edges.
        This label-derived count is not a verdict that an IP is malicious or a confirmed victim.
      </div>

      <div className="panel destination-provenance">
        <div><span className="page-subtitle">Data source</span><strong>Persisted Attack Graph destination aggregates</strong></div>
        <div><span className="page-subtitle">Provenance and coverage</span><strong>Dataset and represented time range are not included by this API.</strong></div>
        <div className="page-subtitle">The endpoint returns IP, attack-flow count, and total-flow count only. No timestamp or source-dataset field is available here.</div>
      </div>

      {error && <div className="notice-banner" role="alert">{error} <button className="secondary" onClick={() => void load()}>Retry</button></div>}

      <section className="panel" aria-labelledby="destination-list-title">
        <h2 className="section-title" id="destination-list-title">Observed Destination IPs</h2>
        <div className="destination-controls">
          <label>Search IP address<input type="search" aria-label="Search destination IPs" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} placeholder="Filter by IP" /></label>
          <label>Sort by<select aria-label="Sort destinations" value={sort} onChange={(event) => { setSort(event.target.value as SortKey); setPage(0); }}>
            <option value="attack-desc">Attack flows: highest first</option>
            <option value="attack-asc">Attack flows: lowest first</option>
            <option value="total-desc">Total flows: highest first</option>
            <option value="ip-asc">IP address: A to Z</option>
          </select></label>
        </div>
        {loading ? <div className="empty-state" role="status">Loading destination aggregates…</div> : error ? (
          <div className="empty-state">Destination records are unavailable until the backend responds.</div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">{destinations.length ? "No destination IPs match this search." : "No persisted destination aggregates are available."}</div>
        ) : (
          <>
            <div className="page-subtitle destination-result-note">Showing {pageRows.length} of {filtered.length} returned destinations (top 25 from the API).</div>
            <div className="reports-table-wrap" role="region" aria-label="Destination IP analysis table" tabIndex={0}>
              <table>
                <thead><tr><th>Destination IP</th><th>Attack-labelled flows</th><th>Total flows</th><th>Attack-labelled share</th><th>Details</th></tr></thead>
                <tbody>
                  {pageRows.map((item) => (
                    <tr key={item.ip} className={selected?.ip === item.ip ? "selected-live-edge" : undefined}>
                      <td className="mono">{item.ip}</td>
                      <td>{item.attack_flow_count.toLocaleString()}</td>
                      <td>{item.total_flow_count.toLocaleString()}</td>
                      <td>{item.total_flow_count ? `${((item.attack_flow_count / item.total_flow_count) * 100).toFixed(1)}%` : "Unavailable"}</td>
                      <td><button className="secondary" aria-label={`View details for ${item.ip}`} aria-pressed={selected?.ip === item.ip} onClick={() => setSelected(item)}>View details</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="reports-pagination">
              <span>Page {page + 1} of {Math.max(pageCount, 1)}</span>
              <button className="secondary" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button>
              <button className="secondary" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</button>
            </div>
          </>
        )}
      </section>

      {selected && (
        <section className="panel" aria-labelledby="destination-details-title" aria-live="polite">
          <div className="destination-detail-heading"><h2 className="section-title" id="destination-details-title">Destination details</h2><button className="secondary" onClick={() => setSelected(null)}>Close details</button></div>
          <dl className="report-detail-grid">
            <dt>Destination IP</dt><dd className="mono">{selected.ip}</dd>
            <dt>Rank in returned top 25</dt><dd>{selectedRank || "Unavailable"}</dd>
            <dt>Attack-labelled flows</dt><dd>{selected.attack_flow_count.toLocaleString()}</dd>
            <dt>Total flows</dt><dd>{selected.total_flow_count.toLocaleString()}</dd>
            <dt>Attack-labelled share</dt><dd>{selected.total_flow_count ? `${((selected.attack_flow_count / selected.total_flow_count) * 100).toFixed(1)}%` : "Unavailable"}</dd>
            <dt>Time range / dataset</dt><dd>Unavailable from the destination aggregates API.</dd>
          </dl>
          <div className="page-subtitle">These aggregate counts do not establish maliciousness or physical host identity.</div>
        </section>
      )}
    </>
  );
}
