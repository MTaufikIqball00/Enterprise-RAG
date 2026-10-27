export interface AuthenticatedPrincipal {
  user_id: string;
  username: string;
  email: string;
  role: string;
  explicit_permissions: string[];
  is_active: boolean;
}

export interface CitationItem {
  document_id: string;
  title: string;
  source_filename: string;
  chunk_id: string;
  page_number?: number | null;
  sheet_name?: string | null;
  row_start?: number | null;
  row_end?: number | null;
  section_label?: string | null;
  excerpt: string;
}

export interface CitationDetail {
  chunk_id: string;
  document_id: string;
  title: string;
  source_filename: string;
  page_number?: number | null;
  sheet_name?: number | string | null;
  row_start?: number | null;
  row_end?: number | null;
  section_label?: string | null;
  text_content: string;
}

export interface ClaimItem {
  statement: string;
  classification: string;
  supporting_chunk_ids: string[];
  calculation_expression?: string | null;
}

export interface GuardrailDecision {
  stage: string;
  decision: string;
  rule_id: string;
  reason: string;
  triggered_patterns: string[];
}

export interface RAGQueryResponse {
  request_id: string;
  session_id: string;
  answer: string;
  overall_classification: string;
  claims: ClaimItem[];
  citations: CitationItem[];
  has_source_conflict: boolean;
  conflict_summary?: string | null;
  guardrail_decisions: GuardrailDecision[];
  metadata: Record<string, unknown>;
}

export interface ChatSessionSummary {
  session_id: string;
  title: string;
  role_snapshot: string;
  created_at: string;
}

export interface ChatMessageHistoryItem {
  message_id: string;
  sender: "user" | "assistant";
  content: string;
  citations: CitationItem[];
  epistemic_classification?: string | null;
  request_id: string;
  created_at: string;
}

export interface DocumentItem {
  document_id: string;
  title: string;
  source_filename: string;
  file_type: string;
  scope: string;
  allowed_roles: string[];
  allowed_users?: string[];
  ingestion_status: string;
  chunk_count: number;
  version: number;
  acl_version?: number;
}

export interface AdminUserItem {
  user_id: string;
  username: string;
  email: string;
  role: string;
  explicit_permissions: string[];
  is_active: boolean;
}

export interface RoleChangeAuditItem {
  id: number;
  actor_user_id: string;
  target_user_id: string;
  previous_role: string;
  new_role: string;
  reason: string;
  created_at: string;
}

export interface AuditLogItem {
  id: number;
  request_id: string;
  timestamp: string;
  user_id?: string | null;
  user_role?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  authz_decision: string;
  guardrail_decisions?: GuardrailDecision[];
  accessed_document_ids: string[];
  retrieval_scores?: number[];
  retrieval_config_version?: string | null;
  llm_provider?: string | null;
  llm_model?: string | null;
  latency_ms?: number | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  pipeline_status: string;
  error_code?: string | null;
  metadata?: Record<string, unknown>;
}

export interface EvaluationCaseResult {
  case_id: string;
  category: string;
  passed: boolean;
  observed_classification: string;
  blocked_by_guardrail: boolean;
  citation_count: number;
  has_source_conflict: boolean;
  faithfulness_score: number;
  citation_precision: number;
  failure_reasons: string[];
  answer_preview: string;
}

export interface EvaluationSuiteSummary {
  total_cases: number;
  passed_cases: number;
  failed_cases: number;
  pass_rate: number;
  average_faithfulness: number;
  average_citation_precision: number;
  results: EvaluationCaseResult[];
}

const API_BASE = "/api/v1";

async function parseApiError(res: Response, fallbackMsg: string): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      return body.detail.map((e: { msg?: string }) => e.msg || JSON.stringify(e)).join("; ");
    }
    return fallbackMsg;
  } catch {
    return `${fallbackMsg} (HTTP ${res.status})`;
  }
}

export async function checkBackendHealth(): Promise<{ status: string; service: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Backend tidak merespons");
  return res.json();
}

export async function loginApi(username: string, password: string) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Autentikasi gagal"));
  }
  return res.json() as Promise<{
    access_token: string;
    user_id: string;
    username: string;
    role: string;
  }>;
}

export async function getMeApi(token: string): Promise<AuthenticatedPrincipal> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Sesi autentikasi tidak valid"));
  }
  return res.json();
}

export async function fetchDocuments(token: string): Promise<DocumentItem[]> {
  const res = await fetch(`${API_BASE}/documents`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal memuat daftar dokumen"));
  }
  return res.json();
}

export async function fetchDocumentDetail(token: string, documentId: string): Promise<DocumentItem> {
  const res = await fetch(`${API_BASE}/documents/${encodeURIComponent(documentId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Akses detail dokumen ditolak"));
  }
  return res.json();
}

export async function uploadDocumentApi(
  token: string,
  title: string,
  scope: string,
  allowedRoles: string,
  allowedUsers: string,
  file: File
): Promise<DocumentItem> {
  const form = new FormData();
  form.append("title", title);
  form.append("scope", scope);
  form.append("allowed_roles", allowedRoles);
  form.append("allowed_users", allowedUsers);
  form.append("file", file);

  const res = await fetch(`${API_BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal mengunggah dokumen"));
  }
  return res.json();
}

export async function deleteDocumentApi(
  token: string,
  documentId: string
): Promise<{ document_id: string; ingestion_status: string }> {
  const res = await fetch(`${API_BASE}/documents/${encodeURIComponent(documentId)}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal menghapus dokumen"));
  }
  return res.json();
}

export async function fetchCitationDetail(token: string, chunkId: string): Promise<CitationDetail> {
  const res = await fetch(`${API_BASE}/citations/${encodeURIComponent(chunkId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Akses bukti sitasi ditolak oleh kebijakan ACL"));
  }
  return res.json();
}

export async function sendChatQuery(
  token: string,
  question: string,
  sessionId?: string,
  useCache: boolean = true
): Promise<RAGQueryResponse> {
  const res = await fetch(`${API_BASE}/chat/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ question, session_id: sessionId, use_cache: useCache }),
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Permintaan ke asisten gagal diproses"));
  }
  return res.json();
}

export async function fetchChatSessions(token: string): Promise<ChatSessionSummary[]> {
  const res = await fetch(`${API_BASE}/chat/sessions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal memuat riwayat sesi percakapan"));
  }
  return res.json();
}

export async function fetchSessionMessages(
  token: string,
  sessionId: string
): Promise<ChatMessageHistoryItem[]> {
  const res = await fetch(`${API_BASE}/chat/sessions/${encodeURIComponent(sessionId)}/messages`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Akses pesan sesi ditolak"));
  }
  return res.json();
}

export async function fetchAdminUsers(token: string): Promise<AdminUserItem[]> {
  const res = await fetch(`${API_BASE}/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal memuat daftar pengguna (Khusus Admin)"));
  }
  return res.json();
}

export async function updateUserRoleApi(
  token: string,
  targetUserId: string,
  newRole: string,
  newPermissions: string[],
  reason: string
) {
  const res = await fetch(`${API_BASE}/admin/users/${encodeURIComponent(targetUserId)}/role`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      new_role: newRole,
      new_permissions: newPermissions,
      reason,
    }),
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Perubahan role ditolak oleh kebijakan keamanan"));
  }
  return res.json();
}

export async function fetchRoleChangeAudits(token: string): Promise<RoleChangeAuditItem[]> {
  const res = await fetch(`${API_BASE}/admin/role-change-audits`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal memuat riwayat audit perubahan role"));
  }
  return res.json();
}

export async function fetchAuditLogs(token: string, limit: number = 100): Promise<AuditLogItem[]> {
  const res = await fetch(`${API_BASE}/admin/audit-logs?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Akses audit log ditolak"));
  }
  return res.json();
}

export async function runEvaluationSuiteApi(token: string): Promise<EvaluationSuiteSummary> {
  const res = await fetch(`${API_BASE}/admin/run-evaluation`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(await parseApiError(res, "Gagal menjalankan evaluation benchmark"));
  }
  return res.json();
}
