import React, { useState, useEffect, useMemo } from "react";
import {
  DocumentItem,
  deleteDocumentApi,
  fetchDocumentDetail,
  fetchDocuments,
  uploadDocumentApi,
} from "../api";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  LockIcon,
  SearchIcon,
  TrashIcon,
  UploadCloudIcon,
} from "./Icons";

interface DocumentsWorkspaceProps {
  token: string;
  role: string;
}

const ALLOWED_EXTENSIONS = ["pdf", "docx", "xlsx", "csv"];
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

export function DocumentsWorkspace({ token, role }: DocumentsWorkspaceProps) {
  const normalizedRole = role.toLowerCase();
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [successMsg, setSuccessMsg] = useState<string>("");

  // Search, Filter, and Sort states
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [scopeFilter, setScopeFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"title" | "chunks" | "version">("title");

  // Upload Form states
  const [docTitle, setDocTitle] = useState<string>("");
  const [docScope, setDocScope] = useState<string>(
    normalizedRole === "finance"
      ? "finance"
      : normalizedRole === "hr"
      ? "hr"
      : "general"
  );
  const [selectedRoles, setSelectedRoles] = useState<string[]>(
    normalizedRole === "finance"
      ? ["finance"]
      : normalizedRole === "hr"
      ? ["hr", "executive"]
      : ["employee", "hr", "finance", "executive"]
  );
  const [allowedUsersInput, setAllowedUsersInput] = useState<string>("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);

  // Document Detail & Delete Confirmation Modals
  const [inspectedDoc, setInspectedDoc] = useState<DocumentItem | null>(null);
  const [docToDelete, setDocToDelete] = useState<DocumentItem | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  const loadDocs = async () => {
    setLoading(true);
    setErrorMsg("");
    try {
      const list = await fetchDocuments(token);
      setDocuments(list);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Gagal memuat daftar dokumen"
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDocs();
  }, [token]);

  const filteredDocuments = useMemo(() => {
    return documents
      .filter((d) => {
        const matchesSearch =
          d.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          d.source_filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
          d.document_id.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesScope = scopeFilter === "all" || d.scope === scopeFilter;
        const matchesType =
          typeFilter === "all" || d.file_type.toLowerCase() === typeFilter;
        return matchesSearch && matchesScope && matchesType;
      })
      .sort((a, b) => {
        if (sortBy === "chunks") return b.chunk_count - a.chunk_count;
        if (sortBy === "version") return b.version - a.version;
        return a.title.localeCompare(b.title);
      });
  }, [documents, searchQuery, scopeFilter, typeFilter, sortBy]);

  const toggleAllowedRole = (targetRole: string) => {
    setSelectedRoles((prev) =>
      prev.includes(targetRole)
        ? prev.filter((r) => r !== targetRole)
        : [...prev, targetRole]
    );
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setErrorMsg("");
    const file = e.target.files?.[0] || null;
    if (!file) {
      setSelectedFile(null);
      return;
    }
    const ext = file.name.split(".").pop()?.toLowerCase() || "";
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      setErrorMsg(
        `Format file '.${ext}' tidak didukung. Harap pilih file .pdf, .docx, .xlsx, atau .csv.`
      );
      e.target.value = "";
      setSelectedFile(null);
      return;
    }
    if (file.size === 0) {
      setErrorMsg("File kosong (0 byte) tidak dapat diunggah.");
      e.target.value = "";
      setSelectedFile(null);
      return;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setErrorMsg("Ukuran file melebihi batas maksimum 10 MB.");
      e.target.value = "";
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
    if (!docTitle.trim()) {
      setDocTitle(file.name.replace(/\.[^/.]+$/, ""));
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    setSuccessMsg("");

    if (!docTitle.trim()) {
      setErrorMsg("Judul dokumen wajib diisi.");
      return;
    }
    if (selectedRoles.length === 0) {
      setErrorMsg(
        "Pilih minimal satu role yang diizinkan pada Document-Level ACL."
      );
      return;
    }
    if (!selectedFile) {
      setErrorMsg(
        "Pilih file dokumen (.pdf, .docx, .xlsx, .csv) terlebih dahulu."
      );
      return;
    }

    setIsUploading(true);
    try {
      const created = await uploadDocumentApi(
        token,
        docTitle.trim(),
        docScope,
        selectedRoles.join(","),
        allowedUsersInput.trim(),
        selectedFile
      );
      setSuccessMsg(
        `Dokumen "${created.title}" (${created.document_id}) berhasil diparsing dan diindeks menjadi ${created.chunk_count} chunk.`
      );
      setDocTitle("");
      setSelectedFile(null);
      await loadDocs();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Gagal mengunggah dokumen"
      );
    } finally {
      setIsUploading(false);
    }
  };

  const handleInspectDocument = async (docId: string) => {
    setErrorMsg("");
    try {
      const detail = await fetchDocumentDetail(token, docId);
      setInspectedDoc(detail);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Akses detail dokumen ditolak"
      );
    }
  };

  const handleConfirmDelete = async () => {
    if (!docToDelete) return;
    setIsDeleting(true);
    setErrorMsg("");
    setSuccessMsg("");
    try {
      await deleteDocumentApi(token, docToDelete.document_id);
      setSuccessMsg(
        `Dokumen "${docToDelete.title}" (${docToDelete.document_id}) telah dihapus secara konsisten dari database dan vector index.`
      );
      setDocToDelete(null);
      await loadDocs();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Penghapusan dokumen ditolak"
      );
      setDocToDelete(null);
    } finally {
      setIsDeleting(false);
    }
  };

  const canRoleUploadByPolicy =
    normalizedRole === "hr" ||
    normalizedRole === "finance" ||
    normalizedRole === "executive";

  return (
    <div className="flex flex-col gap-5">
      {errorMsg && (
        <div
          className="alert alert-danger items-center justify-between"
          role="alert"
        >
          <div className="flex items-center gap-2">
            <AlertTriangleIcon size={18} className="shrink-0" />
            <span>
              <strong>Peringatan / Penolakan:</strong> {errorMsg}
            </span>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setErrorMsg("")}
          >
            ✕
          </button>
        </div>
      )}

      {successMsg && (
        <div
          className="alert alert-success items-center justify-between"
          role="status"
        >
          <div className="flex items-center gap-2">
            <CheckCircleIcon size={18} className="shrink-0" />
            <span>
              <strong>Berhasil:</strong> {successMsg}
            </span>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setSuccessMsg("")}
          >
            ✕
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Left Card: Authorized Document Library */}
        <section
          className="xl:col-span-7 card"
          aria-label="Daftar Dokumen Terotorisasi"
        >
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Katalog Dokumen Terotorisasi ({filteredDocuments.length})
              </h2>
              <p className="card-subtitle">
                Menampilkan hanya dokumen yang lolos pemeriksaan Document-Level
                ACL untuk role{" "}
                <strong className="text-slate-800">
                  {normalizedRole.toUpperCase()}
                </strong>
                .
              </p>
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => void loadDocs()}
              disabled={loading}
            >
              Segarkan
            </button>
          </div>

          <div className="card-body">
            {/* Search, Filter & Sort Controls */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 mb-4">
              <div className="relative">
                <input
                  type="search"
                  className="field-input pl-8"
                  placeholder="Cari judul / nama file..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  aria-label="Cari dokumen"
                />
                <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">
                  <SearchIcon size={15} />
                </span>
              </div>
              <select
                className="field-select"
                value={scopeFilter}
                onChange={(e) => setScopeFilter(e.target.value)}
                aria-label="Filter berdasarkan scope"
              >
                <option value="all">Semua Scope</option>
                <option value="general">Scope: general</option>
                <option value="hr">Scope: hr</option>
                <option value="finance">Scope: finance</option>
                <option value="executive">Scope: executive</option>
              </select>
              <select
                className="field-select"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                aria-label="Filter berdasarkan format file"
              >
                <option value="all">Semua Format</option>
                <option value="pdf">PDF</option>
                <option value="docx">DOCX</option>
                <option value="xlsx">XLSX</option>
                <option value="csv">CSV</option>
              </select>
              <select
                className="field-select"
                value={sortBy}
                onChange={(e) =>
                  setSortBy(e.target.value as "title" | "chunks" | "version")
                }
                aria-label="Urutkan dokumen"
              >
                <option value="title">Urut: Judul (A-Z)</option>
                <option value="chunks">Urut: Jumlah Chunk</option>
                <option value="version">Urut: Versi</option>
              </select>
            </div>

            {loading ? (
              <div className="flex flex-col gap-2.5">
                <div className="skeleton h-12 w-full" />
                <div className="skeleton h-12 w-full" />
                <div className="skeleton h-12 w-full" />
              </div>
            ) : filteredDocuments.length === 0 ? (
              <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 flex flex-col items-center">
                <div className="w-11 h-11 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center mb-2.5">
                  <LockIcon size={22} />
                </div>
                <h3 className="text-sm font-bold text-slate-900 mb-1">
                  Tidak Ada Dokumen yang Ditampilkan
                </h3>
                <p className="text-xs text-slate-500 max-w-md leading-relaxed">
                  {normalizedRole === "admin"
                    ? "Sesuai prinsip Least Privilege, Administrator sistem tidak memiliki akses baca ke dokumen bisnis."
                    : "Belum ada dokumen yang sesuai filter atau diizinkan untuk role Anda."}
                </p>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Dokumen & Sumber</th>
                      <th>Scope & ACL Roles</th>
                      <th>Status Indexing</th>
                      <th>Chunks</th>
                      <th className="text-right">Aksi</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDocuments.map((doc) => (
                      <tr key={doc.document_id}>
                        <td>
                          <div className="font-semibold text-slate-900">
                            {doc.title}
                          </div>
                          <div className="text-[11px] text-slate-500 mt-0.5">
                            <code className="font-mono">
                              {doc.source_filename}
                            </code>{" "}
                            •{" "}
                            <span className="uppercase font-semibold">
                              {doc.file_type}
                            </span>{" "}
                            • v{doc.version}
                          </div>
                        </td>
                        <td>
                          <div className="mb-1">
                            <span className="badge badge-info">
                              Scope: {doc.scope}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-600">
                            Roles:{" "}
                            <code className="font-mono">
                              {doc.allowed_roles.join(", ")}
                            </code>
                          </div>
                        </td>
                        <td>
                          {doc.ingestion_status === "INDEXED" ? (
                            <span className="badge badge-success">
                              <CheckCircleIcon size={12} /> INDEXED
                            </span>
                          ) : doc.ingestion_status === "FAILED" ? (
                            <span className="badge badge-danger">
                              <AlertTriangleIcon size={12} /> FAILED
                            </span>
                          ) : (
                            <span className="badge badge-warning">
                              {doc.ingestion_status}
                            </span>
                          )}
                        </td>
                        <td>
                          <strong className="font-mono text-slate-900">
                            {doc.chunk_count}
                          </strong>
                        </td>
                        <td className="text-right">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() =>
                                void handleInspectDocument(doc.document_id)
                              }
                            >
                              Detail
                            </button>
                            {canRoleUploadByPolicy && (
                              <button
                                type="button"
                                className="btn btn-danger btn-sm"
                                onClick={() => setDocToDelete(doc)}
                                aria-label={`Hapus dokumen ${doc.title}`}
                              >
                                <TrashIcon size={14} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        {/* Right Card: Ingestion & Document-Level ACL Upload */}
        <section
          className="xl:col-span-5 card"
          aria-label="Formulir Unggah Dokumen Ber-ACL"
        >
          <div className="card-header">
            <div>
              <h2 className="card-title">
                Ingestion Dokumen & Konfigurasi ACL
              </h2>
              <p className="card-subtitle">
                Mendukung format <strong>PDF, DOCX, XLSX, CSV</strong> (maks. 10
                MB) dengan idempotency SHA-256.
              </p>
            </div>
            <span className="text-indigo-600">
              <UploadCloudIcon size={22} />
            </span>
          </div>

          <div className="card-body flex flex-col gap-4">
            {!canRoleUploadByPolicy && (
              <div className="alert alert-warning">
                <AlertTriangleIcon size={18} className="shrink-0 mt-0.5" />
                <div>
                  <strong>
                    Informasi Hak Unggah Role ({normalizedRole.toUpperCase()}):
                  </strong>{" "}
                  Berdasarkan matriks RBAC backend, role{" "}
                  <code className="font-mono font-semibold">
                    {normalizedRole}
                  </code>{" "}
                  tidak memiliki izin mengunggah dokumen. Jika Anda mencoba
                  mengirim form di bawah, backend akan menolak dengan{" "}
                  <code className="font-mono">HTTP 403 Forbidden</code> dan
                  mencatatnya ke Audit Log.
                </div>
              </div>
            )}

            <form
              onSubmit={handleUploadSubmit}
              className="flex flex-col gap-4"
            >
              <div className="field-group">
                <label htmlFor="doc-title-input" className="field-label">
                  Judul Dokumen Resmi
                </label>
                <input
                  id="doc-title-input"
                  className="field-input"
                  value={docTitle}
                  onChange={(e) => setDocTitle(e.target.value)}
                  placeholder="Contoh: Laporan Anggaran Kuartal 1 2026"
                  required
                />
              </div>

              <div className="field-group">
                <label htmlFor="doc-scope-select" className="field-label">
                  Scope Domain Dokumen
                </label>
                <select
                  id="doc-scope-select"
                  className="field-select"
                  value={docScope}
                  onChange={(e) => setDocScope(e.target.value)}
                >
                  <option value="general">
                    general (Dokumen Umum Perusahaan)
                  </option>
                  <option value="hr">hr (Dokumen Sumber Daya Manusia)</option>
                  <option value="finance">
                    finance (Dokumen Keuangan & Treasury)
                  </option>
                  <option value="executive">
                    executive (Dokumen Direksi & Strategis)
                  </option>
                </select>
                <span className="field-hint">
                  Pengunggah wajib memiliki izin unggah pada scope yang dipilih.
                </span>
              </div>

              <div className="field-group">
                <span className="field-label">
                  Document-Level ACL — Role yang Diizinkan Membaca:
                </span>
                <div className="grid grid-cols-2 gap-2 bg-slate-50 p-3 rounded-lg border border-slate-200">
                  {(["employee", "hr", "finance", "executive"] as const).map(
                    (rName) => (
                      <label
                        key={rName}
                        className="flex items-center gap-2 cursor-pointer text-xs text-slate-800"
                      >
                        <input
                          type="checkbox"
                          className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                          checked={selectedRoles.includes(rName)}
                          onChange={() => toggleAllowedRole(rName)}
                        />
                        <span>
                          Role: <strong>{rName.toUpperCase()}</strong>
                        </span>
                      </label>
                    )
                  )}
                </div>
                <span className="field-hint">
                  Role <code className="font-mono">admin</code> secara otomatis
                  dikecualikan dari daftar baca dokumen bisnis.
                </span>
              </div>

              <div className="field-group">
                <label htmlFor="doc-allowed-users" className="field-label">
                  Allowed User IDs Tambahan (Opsional, pisahkan koma)
                </label>
                <input
                  id="doc-allowed-users"
                  className="field-input"
                  value={allowedUsersInput}
                  onChange={(e) => setAllowedUsersInput(e.target.value)}
                  placeholder="Contoh: usr-fin-1, usr-exec-1"
                />
              </div>

              <div className="field-group">
                <label htmlFor="doc-file-input" className="field-label">
                  Pilih File Dokumen (.pdf, .docx, .xlsx, .csv)
                </label>
                <input
                  id="doc-file-input"
                  type="file"
                  className="field-input text-xs file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
                  accept=".pdf,.docx,.xlsx,.csv"
                  onChange={handleFileChange}
                  required
                />
                {selectedFile && (
                  <span className="text-xs font-medium text-emerald-700">
                    File terpilih: <strong>{selectedFile.name}</strong> (
                    {(selectedFile.size / 1024).toFixed(1)} KB)
                  </span>
                )}
              </div>

              <button
                type="submit"
                className="btn btn-primary btn-lg w-full"
                disabled={isUploading}
              >
                <UploadCloudIcon size={16} />
                <span>
                  {isUploading
                    ? "Memvalidasi, Parsing & Mengindeks..."
                    : "Unggah & Indeks Dokumen"}
                </span>
              </button>
            </form>
          </div>
        </section>
      </div>

      {/* Document Detail Modal */}
      {inspectedDoc && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          onClick={() => setInspectedDoc(null)}
        >
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">
                  Metadata & Kebijakan Akses Dokumen
                </h3>
                <p className="card-subtitle">
                  Diverifikasi melalui endpoint{" "}
                  <code className="font-mono">
                    GET /api/v1/documents/{inspectedDoc.document_id}
                  </code>
                </p>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setInspectedDoc(null)}
              >
                Tutup
              </button>
            </div>
            <div className="modal-body grid grid-cols-1 gap-2.5 text-xs">
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Document ID:</span>
                <code className="font-mono font-semibold text-slate-900">
                  {inspectedDoc.document_id}
                </code>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Judul:</span>
                <strong className="text-slate-900">{inspectedDoc.title}</strong>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Nama File Sumber:</span>
                <span className="font-mono text-slate-800">
                  {inspectedDoc.source_filename} (
                  {inspectedDoc.file_type.toUpperCase()})
                </span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Scope:</span>
                <span className="badge badge-info">{inspectedDoc.scope}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Allowed Roles (ACL):</span>
                <code className="font-mono text-slate-800">
                  {inspectedDoc.allowed_roles.join(", ")}
                </code>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100">
                <span className="text-slate-500">Status Ingestion:</span>
                <span className="badge badge-success">
                  {inspectedDoc.ingestion_status}
                </span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-500">
                  Jumlah Potongan Teks (Chunks):
                </span>
                <strong className="font-mono text-slate-900">
                  {inspectedDoc.chunk_count}
                </strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {docToDelete && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          onClick={() => !isDeleting && setDocToDelete(null)}
        >
          <div
            className="modal-dialog max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h3 className="modal-title text-red-700">
                Konfirmasi Penghapusan Dokumen
              </h3>
            </div>
            <div className="modal-body text-xs text-slate-600 leading-relaxed">
              Apakah Anda yakin ingin menghapus dokumen{" "}
              <strong className="text-slate-900">"{docToDelete.title}"</strong>{" "}
              (
              <code className="font-mono text-slate-800">
                {docToDelete.document_id}
              </code>
              )? Tindakan ini akan menghapus seluruh chunk dari database
              relasional dan vector index Qdrant secara permanen.
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={isDeleting}
                onClick={() => setDocToDelete(null)}
              >
                Batal
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={isDeleting}
                onClick={() => void handleConfirmDelete()}
              >
                <TrashIcon size={14} />
                <span>{isDeleting ? "Menghapus..." : "Ya, Hapus Dokumen"}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
