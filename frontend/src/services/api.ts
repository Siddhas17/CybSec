import axios, { type AxiosInstance } from "axios";
import type {
  AttackGraphResponse,
  AttacksByType,
  EventDetail,
  EventOut,
  HealthStatus,
  HistogramBucket,
  ModelInfo,
  RiskAssessment,
  RiskDistributionBucket,
  Summary,
  TestEventPayload,
  TestEventResult,
  ThreatRow,
  TimelinePoint,
  TopNode,
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
};

export default client;
