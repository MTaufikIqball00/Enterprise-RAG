import React, { useState, useEffect } from "react";
import {
  ChatMessageHistoryItem,
  ChatSessionSummary,
  CitationDetail,
  CitationItem,
  RAGQueryResponse,
  fetchChatSessions,
  fetchCitationDetail,
  fetchSessionMessages,
  sendChatQuery,
} from "../api";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  FileTextIcon,
  LockIcon,
  MessageSquareIcon,
  PlusIcon,
  SendIcon,
  ShieldIcon,
} from "./Icons";

interface ChatWorkspaceProps {
  token: string;
  username: string;
  role: string;
}

const ROLE_STARTER_PROMPTS: Record<string, string[]> = {
  employee: [
    "Apa aturan jam operasional kantor?",
    "Bagaimana kebijakan cuti hari raya keagamaan untuk seluruh agama dan suku?",
  ],
  hr: [
    "Berapa Kuota_Cuti_Hari dan Tunjangan_Kesehatan_IDR untuk Staff_Reguler dan Manajer_HR?",
    "Apa aturan jam operasional kantor pada pedoman umum?",
  ],
  finance: [
    "Berapa total Nilai_Juta_IDR untuk Pendapatan_Kuartal_4_Audit_Internal dan Cadangan_Likuiditas_Treasury_Rahasia?",
    "Sebutkan rincian Pos_Keuangan pada Laporan Keuangan Rahasia Q4!",
  ],
  executive: [
    "Bagaimana kebijakan cuti dan tunjangan kesehatan untuk Manajer_HR?",
    "Apa aturan jam operasional kantor?",
  ],
  admin: [],
};

function renderClassificationBadge(classification?: string | null) {
  if (!classification) return null;
  if (classification === "FAKTA_SUMBER") {
    return (
      <span
        className="badge badge-success"
        title="Didukung langsung oleh kutipan sumber terverifikasi"
      >
        <CheckCircleIcon size={13} /> Fakta Sumber Terverifikasi
      </span>
    );
  }
  if (classification === "PERHITUNGAN_DATA_SUMBER") {
    return (
      <span
        className="badge badge-info"
        title="Dihitung secara deterministik dari angka aktual pada sumber"
      >
        <CheckCircleIcon size={13} /> Perhitungan Data Sumber
      </span>
    );
  }
  if (classification === "INFERENSI_TERBATAS") {
    return (
      <span
        className="badge badge-warning"
        title="Sintesis/inferensi terbatas berdasarkan bukti yang disitasi"
      >
        <AlertTriangleIcon size={13} /> Inferensi Terbatas
      </span>
    );
  }
  return (
    <span
      className="badge badge-neutral"
      title="Bukti tidak ditemukan pada dokumen yang diizinkan untuk role Anda"
    >
      <LockIcon size={13} /> Abstention / Bukti Tidak Cukup
    </span>
  );
}

/**
 * Formats raw extractive audit strings (which contain machine-verifiable tags like
 * [FAKTA_SUMBER], [DocID=... | File=...], and [SYNTHETIC FIXTURE]) into clean,
 * human-friendly enterprise prose while preserving 100% factual accuracy.
 */
function renderReadableAnswerContent(rawContent: string, showRawAudit: boolean) {
  if (showRawAudit) {
    return (
      <div className="whitespace-pre-wrap font-mono text-xs bg-slate-100 p-3 rounded-lg border border-slate-200 text-slate-800 leading-relaxed">
        {rawContent}
      </div>
    );
  }

  const paragraphs = rawContent
    .split(/\n\n+/)
    .map((p) => p.trim())
    .filter(Boolean);

  return (
    <div className="flex flex-col gap-3 text-sm leading-relaxed text-slate-800">
      {paragraphs.map((para, idx) => {
        // Clean machine prefixes that are already shown as UI badges/cards
        let cleaned = para
          .replace(
            /^\[(FAKTA_SUMBER|PERHITUNGAN_DATA_SUMBER|INFERENSI_TERBATAS|INFORMASI_TIDAK_TERSEDIA)\]\s*/i,
            ""
          )
          .replace(/\[DocID=[^\]]+\]/g, "")
          .replace(/\[SYNTHETIC(?:\s+FIXTURE)?\]\s*/gi, "")
          .replace(/\s+:/g, ":")
          .replace(/\s{2,}/g, " ")
          .trim();

        // Check if paragraph contains structured "Berdasarkan <DocTitle>: <Data>"
        const colonIndex = cleaned.indexOf(":");
        if (
          cleaned.toLowerCase().startsWith("berdasarkan ") &&
          colonIndex !== -1 &&
          colonIndex < 120
        ) {
          const sourceIntro = cleaned.slice(0, colonIndex).trim();
          const bodyPart = cleaned.slice(colonIndex + 1).trim();

          // Split multiple matched lines separated by " | "
          const segments = bodyPart
            .split(/\s*\|\s*/)
            .map((s) => s.replace(/^CSV\s+Baris\s+\d+\s*:\s*/i, "").trim())
            .filter(Boolean);

          return (
            <div
              key={idx}
              className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm"
            >
              <div className="text-xs font-semibold text-indigo-700 mb-2">
                {sourceIntro}:
              </div>
              <div className="flex flex-col gap-2">
                {segments.map((seg, sIdx) => {
                  // If segment is semicolon-separated key=value pairs from CSV/Excel, render neatly
                  const pairs = seg.split(/\s*;\s*/).filter(Boolean);
                  const isKeyValueList =
                    pairs.length >= 2 && pairs.every((p) => p.includes("="));

                  if (isKeyValueList) {
                    return (
                      <div
                        key={sIdx}
                        className="grid grid-cols-1 sm:grid-cols-3 gap-2 bg-slate-50 p-2.5 rounded-lg border border-slate-100 text-xs"
                      >
                        {pairs.map((pair, pIdx) => {
                          const eqIdx = pair.indexOf("=");
                          const k = pair
                            .slice(0, eqIdx)
                            .trim()
                            .replace(/_/g, " ");
                          const v = pair
                            .slice(eqIdx + 1)
                            .trim()
                            .replace(/_/g, " ");
                          return (
                            <div key={pIdx} className="flex flex-col">
                              <span className="text-[11px] font-medium text-slate-500">
                                {k}
                              </span>
                              <span className="font-semibold text-slate-900 mt-0.5">
                                {v}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    );
                  }

                  return (
                    <div key={sIdx} className="text-sm text-slate-800">
                      {seg}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        }

        return (
          <p key={idx} className="m-0 whitespace-pre-wrap">
            {cleaned}
          </p>
        );
      })}
    </div>
  );
}

export function ChatWorkspace({ token, username, role }: ChatWorkspaceProps) {
  const normalizedRole = role.toLowerCase();
  const [sessions, setSessions] = useState<ChatSessionSummary[]>([]);
  const [loadingSessions, setLoadingSessions] = useState<boolean>(false);
  const [activeSessionId, setActiveSessionId] = useState<string | undefined>(
    undefined
  );
  const [messages, setMessages] = useState<ChatMessageHistoryItem[]>([]);
  const [latestResponseMeta, setLatestResponseMeta] =
    useState<RAGQueryResponse | null>(null);

  const [question, setQuestion] = useState<string>("");
  const [lastSubmittedQuestion, setLastSubmittedQuestion] =
    useState<string>("");
  const [isSending, setIsSending] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [showRawAuditFormat, setShowRawAuditFormat] = useState<boolean>(false);

  // Citation Provenance Modal state
  const [selectedCitation, setSelectedCitation] =
    useState<CitationDetail | null>(null);
  const [loadingCitation, setLoadingCitation] = useState<boolean>(false);
  const [citationError, setCitationError] = useState<string>("");

  const loadSessions = async () => {
    setLoadingSessions(true);
    try {
      const list = await fetchChatSessions(token);
      setSessions(list);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Gagal memuat riwayat sesi"
      );
    } finally {
      setLoadingSessions(false);
    }
  };

  useEffect(() => {
    void loadSessions();
    setActiveSessionId(undefined);
    setMessages([]);
    setLatestResponseMeta(null);
  }, [token]);

  const handleSelectSession = async (sessionId: string) => {
    setActiveSessionId(sessionId);
    setErrorMsg("");
    setLatestResponseMeta(null);
    try {
      const history = await fetchSessionMessages(token, sessionId);
      setMessages(history);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Gagal memuat pesan sesi"
      );
    }
  };

  const handleNewSession = () => {
    setActiveSessionId(undefined);
    setMessages([]);
    setLatestResponseMeta(null);
    setErrorMsg("");
  };

  const executeQuery = async (queryText: string) => {
    const trimmed = queryText.trim();
    if (!trimmed || isSending) return;
    setIsSending(true);
    setErrorMsg("");
    setLastSubmittedQuestion(trimmed);

    try {
      const res = await sendChatQuery(token, trimmed, activeSessionId, true);
      setLatestResponseMeta(res);
      setActiveSessionId(res.session_id);
      setQuestion("");
      const updatedMessages = await fetchSessionMessages(token, res.session_id);
      setMessages(updatedMessages);
      await loadSessions();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Permintaan gagal diproses"
      );
    } finally {
      setIsSending(false);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void executeQuery(question);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void executeQuery(question);
    }
  };

  const handleInspectCitation = async (chunkId: string) => {
    setLoadingCitation(true);
    setCitationError("");
    setSelectedCitation(null);
    try {
      const detail = await fetchCitationDetail(token, chunkId);
      setSelectedCitation(detail);
    } catch (err: unknown) {
      setCitationError(
        err instanceof Error ? err.message : "Gagal membuka bukti sumber"
      );
    } finally {
      setLoadingCitation(false);
    }
  };

  const starterPrompts = ROLE_STARTER_PROMPTS[normalizedRole] || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 min-h-[calc(100vh-7.5rem)]">
      {/* Left Column: Isolated Conversation History */}
      <aside className="lg:col-span-3 card flex flex-col max-h-[calc(100vh-7.5rem)]">
        <div className="p-3.5 border-b border-slate-200 flex items-center justify-between gap-2 bg-slate-50">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-600">
            Riwayat Sesi Anda
          </span>
          <button
            type="button"
            onClick={handleNewSession}
            className="btn btn-secondary btn-sm"
            aria-label="Mulai sesi percakapan baru"
          >
            <PlusIcon size={14} /> Baru
          </button>
        </div>

        <div className="px-3.5 py-2 border-b border-slate-100 text-[11px] text-slate-500 bg-white">
          Terisolasi ketat untuk{" "}
          <strong className="text-slate-800">{username}</strong> (
          <span className="font-mono font-semibold">
            {normalizedRole.toUpperCase()}
          </span>
          ).
        </div>

        <div className="flex-1 overflow-y-auto p-2.5 flex flex-col gap-1.5">
          {loadingSessions ? (
            <div className="flex flex-col gap-2 p-2">
              <div className="skeleton h-11 w-full" />
              <div className="skeleton h-11 w-full" />
            </div>
          ) : sessions.length === 0 ? (
            <div className="p-4 rounded-lg bg-slate-50 border border-dashed border-slate-200 text-slate-500 text-xs text-center leading-relaxed">
              Belum ada riwayat percakapan. Ajukan pertanyaan untuk memulai sesi
              baru.
            </div>
          ) : (
            sessions.map((s) => {
              const active = activeSessionId === s.session_id;
              return (
                <button
                  key={s.session_id}
                  type="button"
                  onClick={() => void handleSelectSession(s.session_id)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg border transition-colors flex flex-col gap-1 ${
                    active
                      ? "bg-indigo-50 border-indigo-200 text-indigo-900"
                      : "bg-white border-transparent hover:bg-slate-100 text-slate-800"
                  }`}
                >
                  <span className="text-xs font-semibold truncate w-full">
                    {s.title}
                  </span>
                  <span className="text-[11px] text-slate-500">
                    {new Date(s.created_at).toLocaleString("id-ID")}
                  </span>
                </button>
              );
            })
          )}
        </div>
      </aside>

      {/* Right Column: Active AI Workspace */}
      <section
        className="lg:col-span-9 card flex flex-col max-h-[calc(100vh-7.5rem)]"
        aria-label="Area Percakapan Asisten AI"
      >
        {/* Workspace Context Banner */}
        <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-slate-800">
            <ShieldIcon size={16} className="text-indigo-600" />
            <span className="text-xs font-semibold">
              ACL-Verified RAG Pipeline (Pre-Retrieval & Post-Retrieval
              Enforced)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowRawAuditFormat((v) => !v)}
              className="btn btn-secondary btn-sm text-[11px]"
              title="Ubah antara tampilan terstruktur yang bersih atau format tag audit mentah"
            >
              {showRawAuditFormat
                ? "Mode: Tag Audit Mentah"
                : "Mode: Tampilan Bersih"}
            </button>
            <span className="badge badge-info">
              Scope Aktif Role:{" "}
              {normalizedRole === "admin"
                ? "NONE (System Admin)"
                : normalizedRole.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Admin Default Zero-Read Notice */}
        {normalizedRole === "admin" && (
          <div className="alert alert-warning mx-5 mt-4 mb-0">
            <AlertTriangleIcon size={18} className="shrink-0 mt-0.5" />
            <div>
              <strong>Kebijakan Least Privilege Administrator:</strong> Role{" "}
              <code className="font-mono font-semibold">admin</code> hanya
              berwenang mengelola pengguna dan mengaudit log sistem. Secara
              default, <code className="font-mono font-semibold">admin</code>{" "}
              <strong>tidak memiliki akses baca</strong> ke dokumen bisnis mana
              pun kecuali diberikan ACL eksplisit.
            </div>
          </div>
        )}

        {/* Error & Retry Banner */}
        {errorMsg && (
          <div
            className="alert alert-danger mx-5 mt-4 mb-0 items-center justify-between"
            role="alert"
          >
            <div className="flex items-center gap-2">
              <AlertTriangleIcon size={16} className="shrink-0" />
              <span>
                <strong>Permintaan Gagal:</strong> {errorMsg}
              </span>
            </div>
            {lastSubmittedQuestion && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => void executeQuery(lastSubmittedQuestion)}
              >
                Coba Lagi
              </button>
            )}
          </div>
        )}

        {/* Messages Scroll Container */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
          {messages.length === 0 ? (
            <div className="m-auto max-w-xl text-center py-6 px-3">
              <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-indigo-50 text-indigo-600 border border-indigo-100 flex items-center justify-center">
                <MessageSquareIcon size={24} />
              </div>
              <h2 className="text-lg font-bold text-slate-900 mb-2">
                Asisten AI Dokumen Internal Perusahaan
              </h2>
              <p className="text-slate-500 text-xs leading-relaxed mb-5">
                Setiap jawaban diverifikasi terhadap dokumen yang diizinkan
                untuk role{" "}
                <strong className="text-slate-800">
                  {normalizedRole.toUpperCase()}
                </strong>
                . Asisten wajib menyertakan sitasi halaman/sheet/baris dan
                menolak mengarang fakta apabila bukti tidak tersedia.
              </p>

              {starterPrompts.length > 0 && (
                <div className="text-left">
                  <div className="text-[11px] font-semibold text-slate-500 mb-2 uppercase tracking-wider">
                    Contoh Pertanyaan Sesuai Hak Akses Role Anda:
                  </div>
                  <div className="flex flex-col gap-2">
                    {starterPrompts.map((promptText) => (
                      <button
                        key={promptText}
                        type="button"
                        className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-indigo-50/60 hover:border-indigo-300 text-xs text-slate-800 font-medium flex items-center gap-2.5 transition-all"
                        onClick={() => void executeQuery(promptText)}
                      >
                        <SendIcon
                          size={14}
                          className="text-indigo-600 shrink-0"
                        />
                        <span>{promptText}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            messages.map((msg) =>
              msg.sender === "user" ? (
                <div
                  key={msg.message_id}
                  className="self-end max-w-[85%] bg-indigo-600 text-white px-4 py-3 rounded-2xl rounded-br-sm text-sm leading-relaxed shadow-sm"
                >
                  <div className="text-[11px] text-indigo-100 mb-1 font-medium">
                    {username} ({normalizedRole.toUpperCase()})
                  </div>
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                </div>
              ) : (
                <div
                  key={msg.message_id}
                  className="self-start w-full max-w-[92%] bg-slate-50 border border-slate-200 px-5 py-4 rounded-2xl rounded-bl-sm text-slate-900 shadow-sm"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-3 pb-2.5 border-b border-slate-200">
                    <div className="flex flex-wrap items-center gap-2">
                      <strong className="text-xs font-bold text-slate-900">
                        Jawaban Terverifikasi
                      </strong>
                      {renderClassificationBadge(msg.epistemic_classification)}
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">
                      ReqID: {msg.request_id}
                    </span>
                  </div>

                  {/* Main Grounded Answer Content (Formatted cleanly by default, or raw audit tags if toggled) */}
                  {renderReadableAnswerContent(
                    msg.content,
                    showRawAuditFormat
                  )}

                  {/* Verified Citations List */}
                  {msg.citations && msg.citations.length > 0 && (
                    <div className="border-t border-slate-200 pt-3 mt-3.5">
                      <div className="text-xs font-semibold text-slate-700 mb-2.5 flex items-center gap-1.5">
                        <FileTextIcon size={14} className="text-indigo-600" />
                        <span>
                          Bukti Sumber & Sitasi Terotorisasi (
                          {msg.citations.length}) — Klik untuk verifikasi lokasi
                          sumber:
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-2.5">
                        {msg.citations.map((cit: CitationItem) => (
                          <div
                            key={cit.chunk_id}
                            className="bg-white border border-slate-200 border-l-4 border-l-indigo-600 rounded-lg p-3 shadow-sm"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="text-xs font-semibold text-slate-900">
                                {cit.title.replace(
                                  /^\[SYNTHETIC(?:\s+FIXTURE)?\]\s*/i,
                                  ""
                                )}{" "}
                                <span className="text-slate-500 font-normal">
                                  ({cit.source_filename})
                                </span>
                              </div>
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                onClick={() =>
                                  void handleInspectCitation(cit.chunk_id)
                                }
                              >
                                Inspeksi Sumber ({cit.chunk_id})
                              </button>
                            </div>
                            <div className="text-[11px] text-indigo-700 font-medium mt-1">
                              DocID:{" "}
                              <code className="font-mono">
                                {cit.document_id}
                              </code>
                              {cit.page_number
                                ? ` • Halaman ${cit.page_number}`
                                : ""}
                              {cit.sheet_name
                                ? ` • Sheet: ${cit.sheet_name}`
                                : ""}
                              {cit.row_start
                                ? ` • Baris ${cit.row_start}-${cit.row_end}`
                                : ""}
                              {cit.section_label
                                ? ` • Bagian: ${cit.section_label}`
                                : ""}
                            </div>
                            <div className="text-xs text-slate-600 mt-1.5 font-mono bg-slate-50 p-2 rounded border border-slate-100">
                              "
                              {cit.excerpt.replace(
                                /\[SYNTHETIC(?:\s+FIXTURE)?\]\s*/gi,
                                ""
                              )}
                              "
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            )
          )}

          {isSending && (
            <div
              className="self-start bg-slate-50 border border-slate-200 px-4 py-3 rounded-xl text-xs text-slate-600 flex items-center gap-2.5"
              aria-live="polite"
            >
              <span className="w-3.5 h-3.5 rounded-full border-2 border-indigo-600 border-t-transparent animate-spin inline-block" />
              <span>
                Memverifikasi izin RBAC/ACL, memeriksa guardrails, dan
                menelusuri bukti dokumen...
              </span>
            </div>
          )}
        </div>

        {/* Latest Response Guardrails & Conflict Telemetry Bar */}
        {latestResponseMeta && (
          <div className="px-5 py-2 bg-slate-100 border-t border-slate-200 text-xs flex flex-wrap items-center gap-2">
            <span className="text-slate-500 font-medium">
              Guardrail Checks:
            </span>
            {latestResponseMeta.guardrail_decisions.map((gd, i) => (
              <span
                key={`${gd.rule_id}-${i}`}
                className={`badge ${
                  gd.decision === "ALLOW"
                    ? "badge-success"
                    : gd.decision === "REDACT"
                    ? "badge-warning"
                    : "badge-danger"
                }`}
                title={gd.reason}
              >
                {gd.stage}: {gd.decision} ({gd.rule_id})
              </span>
            ))}
            {latestResponseMeta.has_source_conflict && (
              <span className="badge badge-warning">
                <AlertTriangleIcon size={12} /> Konflik Antar-Sumber Terdeteksi
              </span>
            )}
          </div>
        )}

        {/* Multiline Prompt Input Form */}
        <form
          onSubmit={handleFormSubmit}
          className="p-4 border-t border-slate-200 bg-slate-50"
        >
          <label htmlFor="rag-prompt-input" className="field-label mb-1.5">
            Pertanyaan Dokumen Internal
          </label>
          <div className="flex gap-2.5 items-end">
            <textarea
              id="rag-prompt-input"
              className="field-textarea resize-none"
              rows={2}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isSending}
              placeholder="Ketik pertanyaan Anda di sini... (Tekan Enter untuk mengirim, Shift+Enter untuk baris baru)"
            />
            <button
              type="submit"
              className="btn btn-primary h-11 px-4 shrink-0"
              disabled={isSending || !question.trim()}
            >
              <SendIcon size={16} />
              <span>{isSending ? "Memproses..." : "Kirim"}</span>
            </button>
          </div>
          <span className="field-hint block mt-1.5">
            Tekan <strong>Enter</strong> untuk mengirim atau{" "}
            <strong>Shift + Enter</strong> untuk baris baru. Semua input dan
            konteks dokumen diperiksa oleh Guardrails & RBAC.
          </span>
        </form>
      </section>

      {/* Citation Provenance Verification Modal */}
      {(selectedCitation || loadingCitation || citationError) && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="citation-modal-title"
          onClick={() => {
            setSelectedCitation(null);
            setCitationError("");
          }}
        >
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 id="citation-modal-title" className="modal-title">
                  Verifikasi Bukti Sumber & Provenance
                </h3>
                <p className="card-subtitle">
                  Diverifikasi langsung melalui endpoint{" "}
                  <code className="font-mono">
                    GET /api/v1/citations/&#123;chunk_id&#125;
                  </code>
                </p>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  setSelectedCitation(null);
                  setCitationError("");
                }}
              >
                Tutup
              </button>
            </div>

            <div className="modal-body flex flex-col gap-3">
              {loadingCitation && (
                <div className="p-6 text-center text-xs text-slate-600">
                  Memverifikasi ACL dokumen induk dan memuat teks sumber...
                </div>
              )}

              {citationError && (
                <div className="alert alert-danger">
                  <AlertTriangleIcon size={16} />
                  <div>
                    <strong>Akses Ditolak / Gagal:</strong> {citationError}
                  </div>
                </div>
              )}

              {selectedCitation && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 bg-slate-50 p-3.5 rounded-lg border border-slate-200 text-xs">
                    <div>
                      <span className="text-slate-500">Judul Dokumen:</span>{" "}
                      <strong className="text-slate-900">
                        {selectedCitation.title}
                      </strong>
                    </div>
                    <div>
                      <span className="text-slate-500">Nama File:</span>{" "}
                      <code className="font-mono text-slate-800">
                        {selectedCitation.source_filename}
                      </code>
                    </div>
                    <div>
                      <span className="text-slate-500">Document ID:</span>{" "}
                      <code className="font-mono text-slate-800">
                        {selectedCitation.document_id}
                      </code>
                    </div>
                    <div>
                      <span className="text-slate-500">Chunk ID:</span>{" "}
                      <code className="font-mono text-slate-800">
                        {selectedCitation.chunk_id}
                      </code>
                    </div>
                    {selectedCitation.page_number && (
                      <div>
                        <span className="text-slate-500">Nomor Halaman:</span>{" "}
                        <strong className="text-slate-900">
                          Halaman {selectedCitation.page_number}
                        </strong>
                      </div>
                    )}
                    {selectedCitation.sheet_name && (
                      <div>
                        <span className="text-slate-500">Nama Sheet:</span>{" "}
                        <strong className="text-slate-900">
                          {selectedCitation.sheet_name}
                        </strong>
                      </div>
                    )}
                    {selectedCitation.row_start && (
                      <div>
                        <span className="text-slate-500">Rentang Baris:</span>{" "}
                        <strong className="text-slate-900">
                          Baris {selectedCitation.row_start} s/d{" "}
                          {selectedCitation.row_end}
                        </strong>
                      </div>
                    )}
                    {selectedCitation.section_label && (
                      <div>
                        <span className="text-slate-500">Bagian:</span>{" "}
                        <strong className="text-slate-900">
                          {selectedCitation.section_label}
                        </strong>
                      </div>
                    )}
                  </div>

                  <div>
                    <span className="field-label mb-1.5">
                      Isi Potongan Dokumen Sumber (Chunk Text):
                    </span>
                    <pre className="bg-slate-900 text-slate-100 p-3.5 rounded-lg border border-slate-800 whitespace-pre-wrap font-mono text-xs m-0 leading-relaxed">
                      {selectedCitation.text_content}
                    </pre>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
