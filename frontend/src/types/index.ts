// Mirrors backend/app/schemas/*.py. Kept in sync by hand -- no codegen in
// this phase (would be a reasonable follow-up, not required here).

export interface RiskFactor {
  name: string;
  value: number;
  contribution: number;
}

export interface Detection {
  anomaly_score: number;
  reconstruction_error: number;
  is_anomaly: boolean;
  threshold_used: number;
  model_version_id: number;
}

export interface RiskAssessment {
  risk_score: number;
  risk_level: RiskLevel;
  factors: RiskFactor[];
  rules_applied: string[];
  reason: string;
  risk_config_version_id: number;
}

export type RiskLevel = "Very Low" | "Low" | "Moderate" | "High" | "Critical";

export interface GraphContext {
  edge_attack_ratio: number | null;
  edge_attack_flow_count: number | null;
  edge_flow_count: number | null;
  edge_first_seen: string | null;
  edge_last_seen: string | null;
  edge_attack_label_count: number | null;
}

export type EventSource = "offline_demo" | "test_event" | "live";

export interface EventOut {
  id: number;
  event_uid: string;
  timestamp: string;
  source_ip: string;
  source_port: number | null;
  destination_ip: string;
  destination_port: number | null;
  protocol: number | null;
  canonical_attack_label: string | null;
  traffic_class: string | null;
  source: EventSource;
  status: string;
  created_at: string;
}

export interface EventDetail extends EventOut {
  detection: Detection | null;
  risk_assessment: RiskAssessment | null;
  graph_context: GraphContext | null;
}

export interface ThreatRow {
  event_id: number;
  timestamp: string;
  source_ip: string;
  source_port: number | null;
  destination_ip: string;
  destination_port: number | null;
  protocol: number | null;
  canonical_attack_label: string | null;
  anomaly_score: number | null;
  is_anomaly: boolean | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  event_source: EventSource;
}

export interface AttackNode {
  ip: string;
  total_flow_count: number;
  benign_flow_count: number;
  attack_flow_count: number;
  attack_ratio: number;
  in_degree: number;
  out_degree: number;
  degree: number;
}

export interface AttackEdge {
  src_ip: string;
  dst_ip: string;
  flow_count: number;
  benign_flow_count: number;
  attack_flow_count: number;
  attack_ratio: number;
  unique_source_ports: number;
  unique_destination_ports: number;
  protocols_seen: number[];
  first_seen: string | null;
  last_seen: string | null;
  total_forward_bytes: number;
  total_backward_bytes: number;
  attack_labels: string[];
}

export interface AttackGraphResponse {
  nodes: AttackNode[];
  edges: AttackEdge[];
  graph_version: string;
  total_node_count: number;
  total_edge_count: number;
  returned_node_count: number;
  returned_edge_count: number;
  filter_applied: string;
}

export interface Summary {
  total_events: number;
  active_threats: number;
  high_risk_events: number;
  anomaly_count: number;
  benign_count: number;
  last_ingested_at: string | null;
  system_health: string;
}

export interface AttacksByType {
  attack_type: string;
  count: number;
}

export interface RiskDistributionBucket {
  risk_level: RiskLevel;
  count: number;
}

export interface TimelinePoint {
  bucket: string;
  event_count: number;
  attack_count: number;
}

export interface TopNode {
  ip: string;
  attack_flow_count: number;
  total_flow_count: number;
}

export interface ModelInfo {
  preprocessing_version: string;
  autoencoder_version: string;
  autoencoder_threshold: number;
  attack_graph_version: string;
  risk_engine_version: string;
  risk_engine_weights: Record<string, number>;
}

export interface HistogramBucket {
  range_start: number;
  range_end: number;
  count: number;
}

export interface HealthStatus {
  status: string;
  database: string;
  analytical_core: string;
  version: string;
}

export interface SensorHealth {
  collector_status: "stopped" | "starting" | "running" | "error";
  interface: string;
  telemetry_enabled: boolean;
  started_at: string | null;
  last_event_at: string | null;
  packets_received: number;
  packets_dropped: number;
  parse_errors: number;
  events_processed: number;
  events_rejected: number;
  processing_errors: number;
  active_flows: number;
  live_graph_edges: number;
  model_available: boolean;
  last_error: string | null;
}

export interface TestEventPayload {
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol?: number;
  features?: Record<string, number>;
  canonical_attack_label?: string;
}

export interface TestEventResult {
  event_id: number;
  event_uid: string;
  source: string;
  anomaly_score: number;
  is_anomaly: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  factors: RiskFactor[];
  rules_applied: string[];
  reason: string;
  imputed_features: string[];
  graph_context_found: boolean;
}

export interface VictimFlowScoreMessageData {
  agent_id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  timestamp: string;
  risk_score: number;
  risk_level: RiskLevel;
  is_anomaly: boolean;
  graph_context_used: boolean;
}

export interface WebSocketMessage<T = unknown> {
  type: "connected" | "heartbeat" | "new_threat" | "prevention_action" | "victim_flow_score";
  data: T;
}

// Phase 7: controlled lab response. "requested_action"/"actual_action" can
// differ -- e.g. requested "block" but actual "rejected" because the
// target IP failed lab-scope validation before any adapter call was made.
export type RequestedAction = "alert" | "dry_run" | "block" | "unblock";
export type ActualAction = "alerted" | "would_block" | "blocked" | "unblocked" | "rejected" | "failed";

export interface PreventionAction {
  id: number;
  event_id: number | null;
  detection_id: number | null;
  risk_assessment_id: number | null;
  user_id: number | null;
  source_ip: string;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  requested_action: RequestedAction;
  actual_action: ActualAction;
  dry_run: boolean;
  success: boolean;
  reason: string;
  adapter: string;
  target_scope: string | null;
  created_at: string;
}

// Model Evaluation (admin-only). Backend endpoints return free-form dicts
// whose shape depends on `available` -- when false, only `reason` is set.

export interface ConfusionMatrix {
  tp: number | null;
  tn: number | null;
  fp: number | null;
  fn: number | null;
}

export interface ClassDistribution {
  benign_count: number;
  attack_count: number;
  total_count: number;
  benign_pct: number;
  attack_pct: number;
}

export interface AutoencoderMetrics {
  available: boolean;
  reason?: string;
  evaluation_label?: string;
  positive_class_definition?: string;
  threshold?: number;
  threshold_strategy?: string;
  confusion_matrix?: ConfusionMatrix;
  precision?: number;
  recall?: number;
  f1?: number;
  roc_auc?: number;
  pr_auc?: number;
  false_positive_rate?: number;
  mean_reconstruction_error_benign?: number;
  median_reconstruction_error_benign?: number;
  mean_reconstruction_error_attack?: number;
  median_reconstruction_error_attack?: number;
  normal_samples?: number;
  anomalous_samples?: number;
  architecture?: { dims: number[]; activation: string; dropout: number };
  trained_at?: string | null;
  training_seconds?: number;
  train_rows?: number;
  val_rows?: number;
}

export interface KnnMetrics {
  available: boolean;
  reason?: string;
  evaluation_label?: string;
  positive_class_definition?: string;
  k?: number;
  weights?: string;
  confusion_matrix?: ConfusionMatrix;
  accuracy?: number;
  primary_averaging_method?: string;
  note_on_averaging?: string;
  precision_weighted?: number;
  recall_weighted?: number;
  f1_weighted?: number;
  precision_macro?: number;
  recall_macro?: number;
  f1_macro?: number;
  roc_auc?: number;
  pr_auc?: number;
  training_time_seconds?: number;
  inference_time_seconds?: number;
  inference_time_per_sample_ms?: number;
  feature_count?: number;
  train_class_distribution?: ClassDistribution;
  test_class_distribution?: ClassDistribution;
  train_rows?: number;
  test_rows?: number;
  trained_at?: string | null;
}

export interface ModelComparison {
  autoencoder: AutoencoderMetrics;
  knn: KnnMetrics;
  comparability_note: string;
}

export interface ModelValidationCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ModelValidationResult {
  component: string;
  valid: boolean;
  checks: ModelValidationCheck[];
}

export interface ModelStatus {
  autoencoder: ModelValidationResult;
  knn: ModelValidationResult;
}

export interface LiveVsOfflineStats {
  offline: {
    label: string;
    autoencoder: AutoencoderMetrics;
    knn: KnnMetrics;
  };
  live: {
    label: string;
    total_live_events: number;
    detected_anomalies: number;
    alerts: number;
    threats_prevented_or_would_block: number;
    average_risk_score: number | null;
    live_accuracy_note: string;
  };
}

export interface DatasetStats {
  available: boolean;
  reason?: string;
  files_loaded?: string[];
  rows_before_dedup?: number;
  exact_duplicate_rows?: number;
  rows_after_dedup?: number;
  rows_after_inf_nan_handling?: number;
  label_distribution_before?: Record<string, number>;
  label_distribution_after?: Record<string, number>;
  split_sizes?: Record<string, number>;
  split_label_distribution?: Record<string, Record<string, number>>;
  raw_inspection_available?: boolean;
}

export interface SecurityReport {
  id: number;
  title: string;
  generated_by_user_id: number | null;
  generation_status: "complete" | "failed";
  error_message: string | null;
  file_path: string | null;
  file_size_bytes: number | null;
  report_period_start: string | null;
  report_period_end: string | null;
  summary_stats: Record<string, unknown> | null;
  model_version_snapshot: Record<string, unknown> | null;
  created_at: string;
}

// victim_agent (Phase 1): identity/registration/heartbeat only. `online` is
// computed server-side from `last_seen` staleness (AGENT_OFFLINE_THRESHOLD_SECONDS)
// -- never a stored/hardcoded value. `status` is a separate administrative
// lifecycle flag ("active"/"disabled"), not the online/offline indicator.
export interface AgentOut {
  id: number;
  agent_id: string;
  hostname: string;
  ip_address: string | null;
  agent_version: string | null;
  status: string;
  last_seen: string | null;
  created_at: string;
  online: boolean;
}

export interface TrainingRun {
  id: number;
  component: string;
  run_id: string;
  model_version_id: number | null;
  artifact_dir: string;
  content_hash: string;
  trained_at: string | null;
  training_duration_seconds: number | null;
  feature_count: number | null;
  dataset_info: Record<string, unknown>;
  hyperparameters: Record<string, unknown>;
  preprocessing_version: string | null;
  threshold: number | null;
  metrics: Record<string, number | null>;
  confusion_matrix: ConfusionMatrix;
  class_distribution: ClassDistribution | null;
  created_at: string;
}
