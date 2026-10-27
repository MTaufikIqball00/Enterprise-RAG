import React, { useEffect, useMemo, useState } from "react";
import {
  AuditLogItem,
  EvaluationSuiteSummary,
  fetchAuditLogs,
  runEvaluationSuiteApi,
} from "../api";
import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  LockIcon,
  SearchIcon,
  ShieldIcon,
} from "./Icons";

interface ObservabilityWorkspaceProps {
  token: string;
  userRole: string;
}

export function ObservabilityWorkspace({
  token,
  userRole,
}: ObservabilityWorkspaceProps) {
  const normalizedRole = userRole.toLowerCase();
  const [subView, setSubView] = useState<"audit" | "evaluation">("audit");
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(true);
  const [auditError, setAuditError] = useState<string>("");

  const [searchQuery, setSearchQuery] = useState<string>("");
  const [decisionFilter, setDecisionFilter] = useState<string>("ALL");
  const [actionFilter, setActionFilter] = useState<string>("ALL");
  const [selectedAuditItem, setSelectedAuditItem] =
    useState<AuditLogItem | null>(null);

  const [evalResult, setEvalResult] = useState<EvaluationSuiteSummary | null>(
    null
  );
  const [runningEval, setRunningEval] = useState<boolean>(false);
  const [evalError, setEvalError] = useState<string>("");
  const [evalCategoryFilter, setEvalCategoryFilter] = useState<string>("ALL");

  const isAdmin = normalizedRole === "admin";

  useEffect(() => {
    if (!isAdmin) {
      setLoadingAudit(false);
      return;
    }
    void loadAuditTrail();
  }, [token, isAdmin]);

  async function loadAuditTrail() {
    setLoadingAudit(true);
    setAuditError("");
    try {
      const logs = await fetchAuditLogs(token, 150);
      setAuditLogs(logs);
    } catch (err: unknown) {
      setAuditError(
        err instanceof Error ? err.message : "Gagal memuat jejak audit."
      );
    } finally {
      setLoadingAudit(false);
    }
  }

  async function handleRunEvaluation() {
    setRunningEval(true);
    setEvalError("");
    try {
      const summary = await runEvaluationSuiteApi(token);
      setEvalResult(summary);
      void loadAuditTrail();
    } catch (err: unknown) {
      setEvalError(
        err instanceof Error
          ? err.message
          : "Gagal menjalankan rangkaian evaluasi RAG."
      );
    } finally {
      setRunningEval(false);
    }
  }

  const uniqueActions = useMemo(() => {
    const actions = new Set<string>();
    auditLogs.forEach((item) => {
      if (item.action) actions.add(item.action);
    });
    return Array.from(actions).sort();
  }, [auditLogs]);

  const filteredLogs = useMemo(() => {
    return auditLogs.filter((item) => {
      const matchesDecision =
        decisionFilter === "ALL" || item.authz_decision === decisionFilter;
      const matchesAction =
        actionFilter === "ALL" || item.action === actionFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q ||
        item.request_id.toLowerCase().includes(q) ||
        (item.user_id || "").toLowerCase().includes(q) ||
        (item.user_role || "").toLowerCase().includes(q) ||
        item.action.toLowerCase().includes(q) ||
        (item.resource_id || "").toLowerCase().includes(q) ||
        item.pipeline_status.toLowerCase().includes(q);
      return matchesDecision && matchesAction && matchesQuery;
    });
  }, [auditLogs, decisionFilter, actionFilter, searchQuery]);

  // Real statistics computed exclusively from actual backend audit logs
  const auditStats = useMemo(() => {
    const total = auditLogs.length;
    const allowed = auditLogs.filter(
      (l) => l.authz_decision === "ALLOW"
    ).length;
    const denied = auditLogs.filter((l) => l.authz_decision === "DENY").length;
    const latencies = auditLogs
      .map((l) => l.latency_ms)
      .filter((v): v is number => typeof v === "number" && v >= 0);
    const avgLatency =
      latencies.length > 0
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : null;
    return { total, allowed, denied, avgLatency };
  }, [auditLogs]);

  const filteredEvalResults = useMemo(() => {
    if (!evalResult) return [];
    if (evalCategoryFilter === "ALL") return evalResult.results;
    if (evalCategoryFilter === "PASSED")
      return evalResult.results.filter((r) => r.passed);
    if (evalCategoryFilter === "FAILED")
      return evalResult.results.filter((r) => !r.passed);
    return evalResult.results;
  }, [evalResult, evalCategoryFilter]);

  if (!isAdmin) {
    return (
      <div
        className="p-10 text-center bg-white rounded-xl border border-dashed border-slate-300 flex flex-col items-center gap-2.5"
        role="region"
        aria-label="Akses Terbatas"
      >
        <div className="w-11 h-11 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center">
          <LockIcon size={24} />
        </div>
        <div className="text-base font-bold text-slate-900">
          Observabilitas & Audit Keamanan Dibatasi (Khusus ADMIN)
        </div>
        <div className="text-xs text-slate-500 max-w-md leading-relaxed">
          Role Anda saat ini adalah{" "}
          <strong className="text-slate-800">
            {normalizedRole.toUpperCase()}
          </strong>
          . Sesuai prinsip Least Privilege, hanya pengguna dengan role{" "}
          <strong>ADMIN</strong> (izin{" "}
          <span className="font-mono">audit:read</span> dan{" "}
          <span className="font-mono">eval:run</span>) yang diizinkan mengakses
          log audit sistem dan mengeksekusi benchmark evaluasi LLM.
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Sub-navigation Switcher */}
      <div className="card px-5 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <button
            type="button"
            className={`btn ${
              subView === "audit" ? "btn-primary" : "btn-secondary"
            }`}
            onClick={() => setSubView("audit")}
          >
            <ActivityIcon size={16} />
            Jejak Audit Keamanan ({auditLogs.length})
          </button>
          <button
            type="button"
            className={`btn ${
              subView === "evaluation" ? "btn-primary" : "btn-secondary"
            }`}
            onClick={() => setSubView("evaluation")}
          >
            <ShieldIcon size={16} />
            Evaluasi RAG & Guardrails (11 Kategori)
          </button>
        </div>

        <div className="text-xs text-slate-500">
          Seluruh metrik dihitung langsung dari respons aktual database &
          pipeline evaluasi backend.
        </div>
      </div>

      {subView === "audit" ? (
        <>
          {/* Real Computed Audit Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="card p-4 flex flex-col gap-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Total Peristiwa Tercatat
              </div>
              <div className="text-2xl font-bold text-slate-900">
                {loadingAudit ? "—" : auditStats.total}
              </div>
              <div className="text-[11px] text-slate-500">
                Memuat hingga 150 aktivitas terbaru dari tabel{" "}
                <span className="font-mono">audit_logs</span>
              </div>
            </div>

            <div className="card p-4 flex flex-col gap-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Keputusan Otorisasi: ALLOW
              </div>
              <div className="text-2xl font-bold text-emerald-600">
                {loadingAudit ? "—" : auditStats.allowed}
              </div>
              <div className="text-[11px] text-slate-500">
                Permintaan yang lolos verifikasi RBAC, ACL dokumen, dan
                guardrails
              </div>
            </div>

            <div className="card p-4 flex flex-col gap-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Keputusan Otorisasi: DENY / Diblokir
              </div>
              <div className="text-2xl font-bold text-red-600">
                {loadingAudit ? "—" : auditStats.denied}
              </div>
              <div className="text-[11px] text-slate-500">
                Percobaan lintas role, prompt injection, SARA, atau kredensial
                ditolak
              </div>
            </div>

            <div className="card p-4 flex flex-col gap-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Rata-rata Latensi Pipeline
              </div>
              <div className="text-2xl font-bold text-slate-900">
                {loadingAudit
                  ? "—"
                  : auditStats.avgLatency !== null
                  ? `${auditStats.avgLatency} ms`
                  : "N/A"}
              </div>
              <div className="text-[11px] text-slate-500">
                Rata-rata waktu eksekusi untuk peristiwa yang memiliki catatan
                latensi
              </div>
            </div>
          </div>

          {auditError && (
            <div className="alert alert-danger" role="alert">
              <AlertTriangleIcon size={18} className="shrink-0" />
              <div>
                <strong>Gagal Memuat Audit Log:</strong> {auditError}
              </div>
            </div>
          )}

          <div className="card">
            <div className="card-header">
              <div>
                <h2 className="card-title">
                  Log Aktivitas & Kepatuhan Keamanan (Redacted Audit Log)
                </h2>
                <p className="card-subtitle">
                  Token, password, dan PII sensitif telah disensor secara
                  otomatis sebelum disimpan ke penyimpanan audit. Klik tombol
                  detail untuk memeriksa metadata lengkap.
                </p>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => void loadAuditTrail()}
                disabled={loadingAudit}
              >
                Segarkan Log
              </button>
            </div>

            <div className="card-body">
              <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                <div className="flex-1 min-w-[240px] max-w-md relative">
                  <label htmlFor="audit-search-input" className="sr-only">
                    Cari log audit
                  </label>
                  <input
                    id="audit-search-input"
                    type="search"
                    className="field-input pl-8"
                    placeholder="Cari Request ID, User ID, Role, Action, atau Status..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                  <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">
                    <SearchIcon size={15} />
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <label htmlFor="audit-decision-filter" className="sr-only">
                    Filter keputusan otorisasi
                  </label>
                  <select
                    id="audit-decision-filter"
                    className="field-select w-auto"
                    value={decisionFilter}
                    onChange={(e) => setDecisionFilter(e.target.value)}
                  >
                    <option value="ALL">Semua Keputusan (ALLOW & DENY)</option>
                    <option value="ALLOW">Hanya ALLOW (Diizinkan)</option>
                    <option value="DENY">Hanya DENY (Ditolak/Diblokir)</option>
                  </select>

                  <label htmlFor="audit-action-filter" className="sr-only">
                    Filter jenis aksi
                  </label>
                  <select
                    id="audit-action-filter"
                    className="field-select w-auto"
                    value={actionFilter}
                    onChange={(e) => setActionFilter(e.target.value)}
                  >
                    <option value="ALL">Semua Jenis Aksi</option>
                    {uniqueActions.map((act) => (
                      <option key={act} value={act}>
                        {act}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {loadingAudit ? (
                <div className="flex flex-col gap-2.5">
                  <div className="skeleton h-11 w-full" />
                  <div className="skeleton h-11 w-full" />
                  <div className="skeleton h-11 w-full" />
                </div>
              ) : filteredLogs.length === 0 ? (
                <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 flex flex-col items-center gap-2">
                  <div className="w-10 h-10 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center">
                    <ActivityIcon size={20} />
                  </div>
                  <div className="text-sm font-bold text-slate-900">
                    Tidak Ada Peristiwa Audit yang Cocok
                  </div>
                  <div className="text-xs text-slate-500">
                    Ubah kata kunci pencarian atau reset filter keputusan di
                    atas untuk melihat seluruh log aktivitas.
                  </div>
                </div>
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Waktu (Lokal)</th>
                        <th>Keputusan</th>
                        <th>Aksi & Resource</th>
                        <th>Pengguna & Role</th>
                        <th>Status Pipeline</th>
                        <th>Dokumen Diakses</th>
                        <th>Latensi</th>
                        <th className="text-right">Inspeksi</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLogs.map((log) => (
                        <tr key={log.id}>
                          <td className="font-mono whitespace-nowrap">
                            {new Date(log.timestamp).toLocaleString("id-ID")}
                          </td>
                          <td>
                            <span
                              className={`badge ${
                                log.authz_decision === "ALLOW"
                                  ? "badge-success"
                                  : "badge-danger"
                              }`}
                            >
                              {log.authz_decision === "ALLOW" ? (
                                <CheckCircleIcon size={12} />
                              ) : (
                                <AlertTriangleIcon size={12} />
                              )}
                              {log.authz_decision}
                            </span>
                          </td>
                          <td>
                            <div className="font-semibold text-slate-900">
                              {log.action}
                            </div>
                            <div className="font-mono text-slate-500 text-[11px]">
                              {log.resource_type}
                              {log.resource_id ? `: ${log.resource_id}` : ""}
                            </div>
                          </td>
                          <td>
                            <div className="font-mono text-slate-800">
                              {log.user_id || "anonymous"}
                            </div>
                            {log.user_role && (
                              <span className="badge badge-neutral mt-0.5">
                                {log.user_role.toUpperCase()}
                              </span>
                            )}
                          </td>
                          <td>
                            <span className="badge badge-info font-mono">
                              {log.pipeline_status}
                            </span>
                            {log.error_code && (
                              <div className="font-mono text-red-600 text-[11px] mt-0.5">
                                {log.error_code}
                              </div>
                            )}
                          </td>
                          <td>
                            {log.accessed_document_ids &&
                            log.accessed_document_ids.length > 0 ? (
                              <span className="badge badge-accent font-mono">
                                {log.accessed_document_ids.length} dokumen
                              </span>
                            ) : (
                              <span className="text-xs text-slate-400">
                                Tidak ada
                              </span>
                            )}
                          </td>
                          <td className="font-mono">
                            {typeof log.latency_ms === "number"
                              ? `${log.latency_ms} ms`
                              : "—"}
                          </td>
                          <td className="text-right">
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => setSelectedAuditItem(log)}
                            >
                              Detail
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      ) : (
        /* Evaluation & Guardrail Benchmark Runner View */
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Benchmark Evaluasi Keamanan, Epistemik & Guardrails (11
                Kategori)
              </h2>
              <p className="card-subtitle">
                Jalankan pengujian otomatis end-to-end terhadap pipeline RAG
                nyata untuk memverifikasi ketahanan terhadap kebocoran lintas
                role, prompt injection, ujaran kebencian SARA vs edukasi,
                deteksi konflik dokumen, dan akurasi sitasi.
              </p>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleRunEvaluation()}
              disabled={runningEval}
            >
              <ShieldIcon size={16} />
              {runningEval
                ? "Menjalankan 11 Skenario Evaluasi..."
                : "Jalankan Evaluation Suite Sekarang"}
            </button>
          </div>

          <div className="card-body flex flex-col gap-5">
            {evalError && (
              <div className="alert alert-danger" role="alert">
                <AlertTriangleIcon size={18} className="shrink-0" />
                <div>
                  <strong>Eksekusi Evaluasi Gagal:</strong> {evalError}
                </div>
              </div>
            )}

            {runningEval && (
              <div className="alert alert-info" role="status">
                <ActivityIcon size={18} className="shrink-0" />
                <div>
                  <strong>Sedang Mengeksekusi Skenario Pengujian...</strong>{" "}
                  Sistem sedang menguji dokumen terindeks di Qdrant, filter
                  RBAC, dan validator sitasi secara langsung. Mohon tunggu
                  beberapa detik.
                </div>
              </div>
            )}

            {!evalResult && !runningEval ? (
              <div className="p-10 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 flex flex-col items-center gap-2.5">
                <div className="w-11 h-11 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center">
                  <ShieldIcon size={24} />
                </div>
                <div className="text-sm font-bold text-slate-900">
                  Belum Ada Eksekusi Benchmark pada Sesi Ini
                </div>
                <div className="text-xs text-slate-500 max-w-md leading-relaxed">
                  Sistem tidak menampilkan angka kelulusan statis atau simulasi.
                  Klik tombol{" "}
                  <strong>Jalankan Evaluation Suite Sekarang</strong> di kanan
                  atas untuk mengeksekusi 11 kasus uji nyata terhadap database
                  dan indeks vektor saat ini.
                </div>
              </div>
            ) : (
              evalResult && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col gap-1">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Tingkat Kelulusan (Pass Rate)
                      </div>
                      <div
                        className={`text-2xl font-bold ${
                          evalResult.pass_rate >= 0.9
                            ? "text-emerald-600"
                            : "text-amber-600"
                        }`}
                      >
                        {(evalResult.pass_rate * 100).toFixed(1)}%
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {evalResult.passed_cases} dari {evalResult.total_cases}{" "}
                        skenario memenuhi seluruh kontrak keamanan & epistemik
                      </div>
                    </div>

                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col gap-1">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Skor Kepatuhan Bukti (Faithfulness)
                      </div>
                      <div className="text-2xl font-bold text-slate-900">
                        {(evalResult.average_faithfulness * 100).toFixed(1)}%
                      </div>
                      <div className="text-[11px] text-slate-500">
                        Proporsi klaim jawaban yang terbukti ditopang langsung
                        oleh potongan dokumen resmi
                      </div>
                    </div>

                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col gap-1">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Presisi Sitasi (Citation Precision)
                      </div>
                      <div className="text-2xl font-bold text-slate-900">
                        {(evalResult.average_citation_precision * 100).toFixed(
                          1
                        )}
                        %
                      </div>
                      <div className="text-[11px] text-slate-500">
                        Ketepatan rujukan chunk dokumen terhadap ekspektasi
                        dokumen sumber
                      </div>
                    </div>

                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col gap-1">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Kasus Uji Gagal
                      </div>
                      <div
                        className={`text-2xl font-bold ${
                          evalResult.failed_cases === 0
                            ? "text-emerald-600"
                            : "text-red-600"
                        }`}
                      >
                        {evalResult.failed_cases}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        Jumlah skenario yang menyimpang dari ekspektasi
                        keamanan/epistemik
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs font-semibold text-slate-900">
                      Rincian Hasil Per Kasus Uji ({filteredEvalResults.length}{" "}
                      ditampilkan)
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        className={`btn btn-sm ${
                          evalCategoryFilter === "ALL"
                            ? "btn-primary"
                            : "btn-secondary"
                        }`}
                        onClick={() => setEvalCategoryFilter("ALL")}
                      >
                        Semua ({evalResult.total_cases})
                      </button>
                      <button
                        type="button"
                        className={`btn btn-sm ${
                          evalCategoryFilter === "PASSED"
                            ? "btn-primary"
                            : "btn-secondary"
                        }`}
                        onClick={() => setEvalCategoryFilter("PASSED")}
                      >
                        Lulus ({evalResult.passed_cases})
                      </button>
                      <button
                        type="button"
                        className={`btn btn-sm ${
                          evalCategoryFilter === "FAILED"
                            ? "btn-primary"
                            : "btn-secondary"
                        }`}
                        onClick={() => setEvalCategoryFilter("FAILED")}
                      >
                        Gagal ({evalResult.failed_cases})
                      </button>
                    </div>
                  </div>

                  <div className="table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>ID Kasus</th>
                          <th>Kategori Pengujian</th>
                          <th>Status</th>
                          <th>Klasifikasi Epistemik</th>
                          <th>Guardrail</th>
                          <th>Sitasi</th>
                          <th>Faithfulness</th>
                          <th>Ringkasan Respons / Alasan</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredEvalResults.map((r) => (
                          <tr key={r.case_id}>
                            <td className="font-mono font-semibold text-slate-900">
                              {r.case_id}
                            </td>
                            <td>
                              <span className="badge badge-neutral font-mono">
                                {r.category}
                              </span>
                            </td>
                            <td>
                              {r.passed ? (
                                <span className="badge badge-success">
                                  <CheckCircleIcon size={12} /> LULUS
                                </span>
                              ) : (
                                <span className="badge badge-danger">
                                  <AlertTriangleIcon size={12} /> GAGAL
                                </span>
                              )}
                            </td>
                            <td>
                              <span className="badge badge-info font-mono">
                                {r.observed_classification}
                              </span>
                            </td>
                            <td>
                              {r.blocked_by_guardrail ? (
                                <span className="badge badge-warning">
                                  Diblokir Guardrail
                                </span>
                              ) : (
                                <span className="text-xs text-slate-400">
                                  Lolos
                                </span>
                              )}
                            </td>
                            <td className="font-mono">{r.citation_count}</td>
                            <td className="font-mono">
                              {(r.faithfulness_score * 100).toFixed(0)}%
                            </td>
                            <td className="max-w-sm">
                              <div className="text-xs text-slate-600 leading-relaxed">
                                {r.answer_preview}
                              </div>
                              {r.failure_reasons &&
                                r.failure_reasons.length > 0 && (
                                  <div className="mt-1 text-xs text-red-600 font-semibold">
                                    Kegagalan: {r.failure_reasons.join(", ")}
                                  </div>
                                )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )
            )}
          </div>
        </div>
      )}

      {/* Audit Log Detail Inspector Modal */}
      {selectedAuditItem && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-detail-modal-title"
        >
          <div className="modal-dialog">
            <div className="modal-header">
              <div>
                <h3 id="audit-detail-modal-title" className="modal-title">
                  Inspeksi Peristiwa Audit #{selectedAuditItem.id}
                </h3>
                <p className="card-subtitle">
                  Request ID:{" "}
                  <span className="font-mono">
                    {selectedAuditItem.request_id}
                  </span>
                </p>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setSelectedAuditItem(null)}
              >
                Tutup
              </button>
            </div>

            <div className="modal-body flex flex-col gap-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                <div>
                  <div className="text-slate-500">Waktu Kejadian</div>
                  <div className="font-mono font-semibold text-slate-900 mt-0.5">
                    {new Date(selectedAuditItem.timestamp).toLocaleString(
                      "id-ID"
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Keputusan Otorisasi</div>
                  <div className="mt-0.5">
                    <span
                      className={`badge ${
                        selectedAuditItem.authz_decision === "ALLOW"
                          ? "badge-success"
                          : "badge-danger"
                      }`}
                    >
                      {selectedAuditItem.authz_decision}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Pengguna & Role</div>
                  <div className="font-mono font-semibold text-slate-900 mt-0.5">
                    {selectedAuditItem.user_id || "anonymous"} (
                    {selectedAuditItem.user_role
                      ? selectedAuditItem.user_role.toUpperCase()
                      : "N/A"}
                    )
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Aksi & Status Pipeline</div>
                  <div className="font-mono font-semibold text-slate-900 mt-0.5">
                    {selectedAuditItem.action} →{" "}
                    {selectedAuditItem.pipeline_status}
                  </div>
                </div>
              </div>

              <div>
                <div className="font-semibold mb-1.5 text-slate-900">
                  ID Dokumen yang Diakses (
                  {selectedAuditItem.accessed_document_ids.length})
                </div>
                {selectedAuditItem.accessed_document_ids.length === 0 ? (
                  <div className="text-slate-400">
                    Tidak ada dokumen yang diakses pada peristiwa ini.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {selectedAuditItem.accessed_document_ids.map((docId) => (
                      <span key={docId} className="badge badge-accent font-mono">
                        {docId}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {selectedAuditItem.guardrail_decisions &&
                selectedAuditItem.guardrail_decisions.length > 0 && (
                  <div>
                    <div className="font-semibold mb-1.5 text-slate-900">
                      Keputusan Guardrails
                    </div>
                    <pre className="font-mono p-3 rounded-lg bg-slate-900 text-slate-100 border border-slate-800 overflow-x-auto m-0">
                      {JSON.stringify(
                        selectedAuditItem.guardrail_decisions,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}

              <div>
                <div className="font-semibold mb-1.5 text-slate-900">
                  Metadata Teredaksi (Redacted Audit Metadata)
                </div>
                <pre className="font-mono p-3 rounded-lg bg-slate-900 text-slate-100 border border-slate-800 overflow-x-auto m-0">
                  {JSON.stringify(selectedAuditItem.metadata || {}, null, 2)}
                </pre>
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setSelectedAuditItem(null)}
              >
                Tutup Inspeksi
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
