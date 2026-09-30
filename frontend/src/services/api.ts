import axios, { type AxiosInstance } from "axios";
import type {
  AgentOut,
  AgentLifecycleStatus,
  AttackGraphResponse,
  AttacksByType,
  AutoencoderMetrics,
  DatasetStats,
  EventDetail,
  EventOut,
  HealthStatus,
  HistogramBucket,
  KnnMetrics,
  LiveVsOfflineStats,
  ModelComparison,
  ModelInfo,
  ModelStatus,
  PreventionAction,
  RiskAssessment,
  RiskDistributionBucket,
  SecurityReport,
  SensorHealth,
  Summary,
  TestEventPayload,
  TestEventResult,
  ThreatRow,
  TimelinePoint,
  TopNode,
  TrainingRun,
} from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";
const TOKEN_STORAGE_KEY = "attack_graph_app_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

const client: AxiosInstance = axios.create({ baseURL: API_BASE_URL });

client.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      clearToken();
    }
    return Promise.reject(error);
  },
);

export const api = {
  login: async (username: string, password: string): Promise<string> => {
    const { data } = await client.post<{ access_token: string }>("/auth/login", { username, password });
    setToken(data.access_token);
    return data.access_token;
  },
  me: () => client.get<{ username: string; is_admin: boolean }>("/auth/me").then((r) => r.data),

  health: () => client.get<HealthStatus>("/health").then((r) => r.data),

  listEvents: (params?: { limit?: number; offset?: number; source?: string; traffic_class?: string }) =>
    client.get<EventOut[]>("/events", { params }).then((r) => r.data),
  getEvent: (id: number) => client.get<EventDetail>(`/events/${id}`).then((r) => r.data),

  listThreats: (params?: { limit?: number; offset?: number; min_risk_score?: number }) =>
    client.get<ThreatRow[]>("/threats", { params }).then((r) => r.data),

  listRisks: (params?: { limit?: number; offset?: number; min_risk_score?: number }) =>
    client.get<RiskAssessment[]>("/risks", { params }).then((r) => r.data),

  getAttackGraph: (params?: { limit?: number; min_attack_flow_count?: number; node_ip?: string }) =>
    client.get<AttackGraphResponse>("/attack-graph", { params }).then((r) => r.data),

  createTestEvent: (payload: TestEventPayload) => client.post<TestEventResult>("/test-events", payload).then((r) => r.data),

  triggerIngestion: (params?: { sample_per_category?: number; max_total?: number }) =>
    client.post("/admin/ingest", null, { params }).then((r) => r.data),

  sensor: {
    health: () => client.get<SensorHealth>("/sensor/health").then((r) => r.data),
    start: () => client.post("/sensor/start").then((r) => r.data),
    stop: () => client.post("/sensor/stop").then((r) => r.data),
  },

  // victim_agent (Phase 1) -- admin-only, called with the admin's own
  // browser JWT (a completely separate channel from agent-to-backend
  // machine auth, which never touches the frontend).
  agents: {
    list: () => client.get<AgentOut[]>("/agents").then((r) => r.data),
    updateStatus: (agentId: string, status: AgentLifecycleStatus) =>
      client.patch<AgentOut>(`/agents/${encodeURIComponent(agentId)}/status`, { status }).then((r) => r.data),
  },

  prevention: {
    listActions: (params?: { limit?: number; offset?: number }) =>
      client.get<PreventionAction[]>("/prevention/actions", { params }).then((r) => r.data),
    dryRun: (source_ip: string, reason?: string) =>
      client.post<PreventionAction>("/prevention/dry-run", { source_ip, reason }).then((r) => r.data),
    block: (source_ip: string, reason?: string) =>
      client.post<PreventionAction>("/prevention/block", { source_ip, reason }).then((r) => r.data),
    unblock: (source_ip: string) => client.post<PreventionAction>("/prevention/unblock", { source_ip }).then((r) => r.data),
  },

  analytics: {
    summary: () => client.get<Summary>("/analytics/summary").then((r) => r.data),
    attacksByType: () => client.get<AttacksByType[]>("/analytics/attacks-by-type").then((r) => r.data),
    riskDistribution: () => client.get<RiskDistributionBucket[]>("/analytics/risk-distribution").then((r) => r.data),
    timeline: () => client.get<TimelinePoint[]>("/analytics/timeline").then((r) => r.data),
    topSources: (limit = 10) => client.get<TopNode[]>("/analytics/top-sources", { params: { limit } }).then((r) => r.data),
    topDestinations: (limit = 10) => client.get<TopNode[]>("/analytics/top-destinations", { params: { limit } }).then((r) => r.data),
    anomalyScoreDistribution: () => client.get<HistogramBucket[]>("/analytics/anomaly-score-distribution").then((r) => r.data),
    riskScoreDistribution: () => client.get<HistogramBucket[]>("/analytics/risk-score-distribution").then((r) => r.data),
    modelInfo: () => client.get<ModelInfo>("/analytics/model-info").then((r) => r.data),
  },

  modelEval: {
    autoencoderMetrics: () => client.get<AutoencoderMetrics>("/model-eval/autoencoder/metrics").then((r) => r.data),
    knnMetrics: () => client.get<KnnMetrics>("/model-eval/knn/metrics").then((r) => r.data),
    comparison: () => client.get<ModelComparison>("/model-eval/comparison").then((r) => r.data),
    status: () => client.get<ModelStatus>("/model-eval/status").then((r) => r.data),
    liveVsOffline: () => client.get<LiveVsOfflineStats>("/model-eval/live-vs-offline").then((r) => r.data),
    datasetStats: () => client.get<DatasetStats>("/model-eval/dataset-stats").then((r) => r.data),
    trainingHistory: (component?: string) =>
      client.get<TrainingRun[]>("/model-eval/training-history", { params: component ? { component } : undefined }).then((r) => r.data),
    trainingRunDetail: (id: number) => client.get<TrainingRun>(`/model-eval/training-history/${id}`).then((r) => r.data),
    syncTrainingHistory: () => client.post<TrainingRun[]>("/model-eval/training-history/sync").then((r) => r.data),
  },

  reports: {
    generate: () => client.post<SecurityReport>("/reports/generate").then((r) => r.data),
    list: () => client.get<SecurityReport[]>("/reports").then((r) => r.data),
    get: (id: number) => client.get<SecurityReport>(`/reports/${id}`).then((r) => r.data),
    pdfUrl: (id: number, disposition: "attachment" | "inline" = "attachment") => `/reports/${id}/pdf?disposition=${disposition}`,
    exportCsvUrl: (kind: "events" | "alerts" | "anomalies" | "risk-assessments" | "prevention-actions" | "model-metrics") =>
      `/reports/export/${kind}.csv`,
  },
};

export default client;
