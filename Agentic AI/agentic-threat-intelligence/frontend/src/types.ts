export type Source = {
  name: string;
  status: string;
  score?: number;
  detections?: number;
  abuse_confidence?: number;
  malicious?: boolean;
  stats?: Record<string, number>;
  results?: unknown;
  message?: string;
};

export type RagSource = {
  id: string;
  title: string;
  text: string;
  url: string;
  relevance_score?: number;
  why_relevant?: string;
};

export type RiskFactor = {
  label: string;
  score: number;
  weight: number;
  contribution: number;
  reason: string;
};

export type RiskExplanation = {
  summary: string;
  formula: string;
  factors: RiskFactor[];
  threshold_reason: string;
  confidence_reason: string;
  limitations: string[];
  supporting_references?: string[];
  provider_statuses?: Array<{ name: string; status: string; score: number }>;
};

export type VisualAnalysis = {
  mode?: string;
  score?: number;
  summary?: string;
  screenshot_available?: boolean;
  login_form_present?: boolean;
  login_form_suspected?: boolean;
  brands_detected?: string[];
  brand_tokens?: string[];
  suspicious_elements?: string[];
  risky_tld?: boolean;
};

export type AgentStep = {
  agent: string;
  status: string;
  summary: string;
};

export type Investigation = {
  id: string;
  indicator: string;
  indicator_type: string;
  normalized_indicator: string;
  status: string;
  verdict: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
  risk_score: number;
  confidence: number;
  recommended_action: string;
  analyst_decision: string | null;
  evidence: {
    threat_intelligence?: { sources: Source[]; matched_indicators?: string[]; resolved_ips?: string[]; mode: string; score: number };
    visual_analysis?: VisualAnalysis;
    rag_context?: RagSource[];
    risk_explanation?: RiskExplanation;
    page?: { title?: string; screenshot_path?: string; screenshot_included?: boolean; screenshot_source?: string; screenshot_error?: string | null; storage?: { provider: string; status: string; path?: string; container?: string; blob_name?: string; cloud_error?: string } | null };
    file?: { filename: string; size_bytes: number; content_uploaded: boolean };
  };
  agent_trace: AgentStep[];
  created_at: string;
  updated_at: string;
};

export type AuditEvent = {
  id: string;
  investigation_id: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type BlocklistEntry = {
  id: string;
  indicator: string;
  indicator_type: string;
  source_investigation_id: string;
  reason: string;
  status: string;
  enforcement_mode: string;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type SystemStatus = {
  mode: string;
  response_mode: string;
  providers: Record<string, boolean>;
  capabilities: Record<string, boolean>;
  warnings: string[];
};
