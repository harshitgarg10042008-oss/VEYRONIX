/**
 * VEYRONIX Centralized API Client
 * Strongly-typed same-origin API client with timeout, cancellation,
 * timing-safe token management, and structured error handling.
 */

export class ApiError extends Error {
  public status: number;
  public code?: string;
  public detail?: string;
  public requestId?: string;

  constructor(status: number, message: string, detail?: string, code?: string, requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.code = code;
    this.requestId = requestId;
  }
}

export interface HealthResponse {
  status: string;
  version: string;
  storage: string;
  deterministic: boolean;
  device_connections: boolean;
  llm_enabled?: boolean;
  backup_age_hours?: number | null;
  auth_required?: boolean;
  deployment_mode?: string;
  timestamp?: string;
}

export interface VersionResponse {
  api_version: string;
  compatible: boolean;
  deployment_mode: string;
  auth_mode: string;
}

export interface ProjectRecord {
  project_id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface SharedAuditRecord {
  audit_id: string;
  project_id?: string;
  filename: string;
  input_sha256?: string;
  vendor?: string;
  format?: string;
  parser_id?: string;
  parser_version?: string;
  control_pack_version?: string;
  score_state: 'NO_AUDIT' | 'AUDIT_PENDING' | 'AUDIT_FAILED' | 'SCORE_AVAILABLE' | 'SCORE_UNAVAILABLE';
  score?: number | null;
  summary?: any;
  created_by?: string;
  report_json?: any;
  reviews?: any[];
  original_configuration_text?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ArchiveMemberResult {
  filename: string;
  format_detected: string;
  vendor_detected: string;
  status: 'PARSED' | 'PARTIALLY_PARSED' | 'SKIPPED' | 'FAILED';
  score?: number | null;
  findings_count?: number;
  report?: any;
  error?: string;
}

export interface ArchiveAuditResponse {
  total_members: number;
  audited_count: number;
  skipped_count: number;
  failed_count: number;
  members: ArchiveMemberResult[];
}

export interface EmailInspectionResponse {
  score: number;
  verdict: 'LEGITIMATE' | 'SUSPICIOUS' | 'MALICIOUS';
  boundary_notice: string;
  headers: {
    from: string;
    from_domain?: string;
    reply_to: string;
    reply_to_domain?: string;
    return_path: string;
    return_path_domain?: string;
    subject: string;
    authentication_results: string;
  };
  auth_analysis: {
    spf: string;
    dkim: string;
    dmarc: string;
  };
  attachments: Array<{
    filename: string;
    content_type: string;
    dangerous_type: boolean;
  }>;
  finding_counts: {
    pass: number;
    fail: number;
    warn: number;
  };
  findings: Array<{
    check_id: string;
    status: 'PASS' | 'FAIL' | 'WARN';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    rationale: string;
  }>;
}

class ApiClient {
  private baseUrl: string;
  private token: string | null = null;
  private defaultTimeoutMs: number = 30000;

  constructor(baseUrl: string = '') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  public setToken(token: string | null): void {
    this.token = token;
  }

  public getToken(): string | null {
    return this.token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    customTimeoutMs?: number
  ): Promise<T> {
    const timeout = customTimeoutMs ?? this.defaultTimeoutMs;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: options.signal || controller.signal,
      });

      clearTimeout(timeoutId);

      const requestId = response.headers.get('x-request-id') || undefined;

      if (!response.ok) {
        let detail = response.statusText;
        let code: string | undefined;

        try {
          const errorJson = await response.json();
          detail = errorJson.detail || errorJson.message || detail;
          code = errorJson.code || errorJson.error;
        } catch {
          // If response body is not json, detail remains statusText
        }

        throw new ApiError(response.status, `Request to ${endpoint} failed: ${detail}`, detail, code, requestId);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return (await response.json()) as T;
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError(408, `Request timed out after ${timeout}ms`, 'Request timeout', 'TIMEOUT');
      }
      if (err instanceof ApiError) {
        throw err;
      }
      throw new ApiError(0, err.message || 'Network error', err.message, 'NETWORK_ERROR');
    }
  }

  // Diagnostics & Health
  public async getHealth(signal?: AbortSignal): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/health', { method: 'GET', signal });
  }

  public async getVersion(signal?: AbortSignal): Promise<VersionResponse> {
    return this.request<VersionResponse>('/api/version', { method: 'GET', signal });
  }

  // Projects
  public async getProjects(signal?: AbortSignal): Promise<{ total: number; projects: ProjectRecord[] }> {
    return this.request<{ total: number; projects: ProjectRecord[] }>('/api/projects', { method: 'GET', signal });
  }

  public async createProject(
    payload: { project_id: string; name: string; description?: string },
    signal?: AbortSignal
  ): Promise<ProjectRecord> {
    return this.request<ProjectRecord>('/api/projects', {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    });
  }

  // Audits & History
  public async getAudits(
    params?: { project_id?: string; limit?: number; offset?: number },
    signal?: AbortSignal
  ): Promise<{ total: number; audits: SharedAuditRecord[] }> {
    const query = new URLSearchParams();
    if (params?.project_id) query.set('project_id', params.project_id);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));
    const qs = query.toString();
    return this.request<{ total: number; audits: SharedAuditRecord[] }>(
      `/api/audits${qs ? `?${qs}` : ''}`,
      { method: 'GET', signal }
    );
  }

  public async getAudit(auditId: string, signal?: AbortSignal): Promise<SharedAuditRecord> {
    return this.request<SharedAuditRecord>(`/api/audits/${encodeURIComponent(auditId)}`, {
      method: 'GET',
      signal,
    });
  }

  public async saveAudit(payload: Partial<SharedAuditRecord>, signal?: AbortSignal): Promise<SharedAuditRecord> {
    return this.request<SharedAuditRecord>('/api/audits', {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    });
  }

  public async deleteAudit(auditId: string, signal?: AbortSignal): Promise<{ status: string; audit_id: string }> {
    return this.request<{ status: string; audit_id: string }>(`/api/audits/${encodeURIComponent(auditId)}`, {
      method: 'DELETE',
      signal,
    });
  }

  public async deleteAllAudits(projectId?: string, signal?: AbortSignal): Promise<{ status: string; deleted_count: number }> {
    const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<{ status: string; deleted_count: number }>(`/api/audits${query}`, {
      method: 'DELETE',
      signal,
    });
  }

  public async recordReview(
    auditId: string,
    review: { reviewer: string; finding_id: string; disposition: string; justification?: string },
    signal?: AbortSignal
  ): Promise<any> {
    return this.request<any>(`/api/audits/${encodeURIComponent(auditId)}/reviews`, {
      method: 'POST',
      body: JSON.stringify(review),
      signal,
    });
  }

  // Deterministic Audit Execution
  public async runAudit(
    payload: { content?: string; filename?: string; vendor?: string; frameworks?: string[] },
    signal?: AbortSignal
  ): Promise<any> {
    return this.request<any>('/api/audit', {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    });
  }

  // Detection
  public async detectVendor(
    content: string,
    filename?: string,
    signal?: AbortSignal
  ): Promise<{ selected_vendor: string; confidence: number; ambiguous: boolean; reason: string; candidates: any[] }> {
    return this.request<any>('/api/detect', {
      method: 'POST',
      body: JSON.stringify({ content, filename }),
      signal,
    });
  }

  // Safe Archive Audit
  public async auditArchive(
    archiveBase64: string,
    filename: string,
    vendor: string = 'auto',
    signal?: AbortSignal
  ): Promise<ArchiveAuditResponse> {
    return this.request<ArchiveAuditResponse>('/api/audit/archive', {
      method: 'POST',
      body: JSON.stringify({ archive_base64: archiveBase64, filename, vendor }),
      signal,
    });
  }

  // Bounded Email Inspection
  public async inspectEmail(emailRaw: string, signal?: AbortSignal): Promise<EmailInspectionResponse> {
    return this.request<EmailInspectionResponse>('/api/email/inspect', {
      method: 'POST',
      body: JSON.stringify({ email_raw: emailRaw }),
      signal,
    });
  }

  // Control Pack
  public async getControlPack(signal?: AbortSignal): Promise<any> {
    return this.request<any>('/api/control-pack', { method: 'GET', signal });
  }

  // User / Auth
  public async getAuthMe(signal?: AbortSignal): Promise<any> {
    return this.request<any>('/api/auth/me', { method: 'GET', signal });
  }

  // Governance Approval Request
  public async requestApproval(payload: any, signal?: AbortSignal): Promise<any> {
    return this.request<any>('/api/approval/request', {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    });
  }
}

export const apiClient = new ApiClient();
