import React, { useEffect, useState } from "react";
import {
  AuthenticatedPrincipal,
  checkBackendHealth,
  getMeApi,
  loginApi,
} from "./api";
import { AdminUsersWorkspace } from "./components/AdminUsersWorkspace";
import { ChatWorkspace } from "./components/ChatWorkspace";
import { DocumentsWorkspace } from "./components/DocumentsWorkspace";
import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  FileTextIcon,
  LockIcon,
  MenuIcon,
  MessageSquareIcon,
  ShieldIcon,
  UsersIcon,
} from "./components/Icons";
import { ObservabilityWorkspace } from "./components/ObservabilityWorkspace";

type WorkspaceSection = "chat" | "documents" | "admin_users" | "observability";

const SEEDED_ACCOUNTS = [
  {
    username: "budi.employee",
    password: "EmpPass#2026!",
    role: "EMPLOYEE",
    scopeSummary: "Dokumen GENERAL",
  },
  {
    username: "siti.hr",
    password: "HrPass#2026!",
    role: "HR",
    scopeSummary: "Dokumen HR & GENERAL",
  },
  {
    username: "andi.finance",
    password: "FinPass#2026!",
    role: "FINANCE",
    scopeSummary: "Dokumen FINANCE & GENERAL",
  },
  {
    username: "dian.exec",
    password: "ExecPass#2026!",
    role: "EXECUTIVE",
    scopeSummary: "Dokumen EXECUTIVE & Lintas Divisi",
  },
  {
    username: "rudi.admin",
    password: "AdmPass#2026!",
    role: "ADMIN",
    scopeSummary: "Manajemen RBAC, Audit & Evaluasi",
  },
];

const SESSION_TOKEN_KEY = "enterprise_rag_jwt_token";

export default function App() {
  const [token, setToken] = useState<string>(() => {
    try {
      return sessionStorage.getItem(SESSION_TOKEN_KEY) || "";
    } catch {
      return "";
    }
  });
  const [principal, setPrincipal] = useState<AuthenticatedPrincipal | null>(
    null
  );
  const [verifyingSession, setVerifyingSession] = useState<boolean>(false);

  // Login form state
  const [username, setUsername] = useState<string>("budi.employee");
  const [password, setPassword] = useState<string>("EmpPass#2026!");
  const [loginLoading, setLoginLoading] = useState<boolean>(false);
  const [loginError, setLoginError] = useState<string>("");

  // Navigation & UI state
  const [activeSection, setActiveSection] = useState<WorkspaceSection>("chat");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState<boolean>(false);
  const [profileModalOpen, setProfileModalOpen] = useState<boolean>(false);

  // Live backend health check
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  useEffect(() => {
    void verifyHealth();
  }, []);

  useEffect(() => {
    if (!token) {
      setPrincipal(null);
      return;
    }
    void loadPrincipalProfile(token);
  }, [token]);

  async function verifyHealth() {
    try {
      const res = await checkBackendHealth();
      setBackendOnline(res.status === "ok");
    } catch {
      setBackendOnline(false);
    }
  }

  async function loadPrincipalProfile(jwtToken: string) {
    setVerifyingSession(true);
    try {
      const me = await getMeApi(jwtToken);
      setPrincipal(me);
      setBackendOnline(true);
    } catch {
      handleLogout();
    } finally {
      setVerifyingSession(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setLoginError("");
    setLoginLoading(true);
    try {
      const res = await loginApi(username.trim(), password);
      try {
        sessionStorage.setItem(SESSION_TOKEN_KEY, res.access_token);
      } catch {
        // Ignore storage errors
      }
      setToken(res.access_token);
      const me = await getMeApi(res.access_token);
      setPrincipal(me);
      setBackendOnline(true);
    } catch (err: unknown) {
      setLoginError(
        err instanceof Error
          ? err.message
          : "Gagal melakukan autentikasi ke server."
      );
      void verifyHealth();
    } finally {
      setLoginLoading(false);
    }
  }

  function handleLogout() {
    try {
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    } catch {
      // Ignore
    }
    setToken("");
    setPrincipal(null);
    setActiveSection("chat");
    setProfileModalOpen(false);
    setMobileSidebarOpen(false);
  }

  function selectDemoAccount(accUsername: string, accPassword: string) {
    setUsername(accUsername);
    setPassword(accPassword);
    setLoginError("");
  }

  function navigateTo(section: WorkspaceSection) {
    setActiveSection(section);
    setMobileSidebarOpen(false);
  }

  const sectionMetadata: Record<
    WorkspaceSection,
    { title: string; subtitle: string }
  > = {
    chat: {
      title: "Asisten AI Dokumen Terverifikasi",
      subtitle:
        "Tanya jawab berbasis bukti dokumen resmi dengan perlindungan RBAC dan Guardrails",
    },
    documents: {
      title: "Repositori Dokumen & Kebijakan ACL",
      subtitle:
        "Daftar sumber pengetahuan terindeks beserta cakupan otorisasi role (Deny-by-Default)",
    },
    admin_users: {
      title: "Manajemen Identitas & Kebijakan RBAC",
      subtitle:
        "Administrasi hak akses pengguna, izin eksplisit, dan jejak audit perubahan role",
    },
    observability: {
      title: "Observabilitas Audit & Evaluasi RAG",
      subtitle:
        "Pemantauan log aktivitas teredaksi dan benchmark 11 kategori keamanan & epistemik",
    },
  };

  if (verifyingSession && !principal) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 bg-slate-900">
        <div className="card p-8 max-w-md w-full text-center">
          <div className="skeleton h-6 w-3/5 mx-auto mb-3" />
          <div className="skeleton h-4 w-4/5 mx-auto" />
          <p className="mt-4 text-xs text-slate-500">
            Memverifikasi sesi keamanan dan izin RBAC Anda...
          </p>
        </div>
      </div>
    );
  }

  if (!token || !principal) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 sm:p-6 bg-gradient-to-br from-slate-950 via-slate-900 to-indigo-950">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 bg-white rounded-2xl overflow-hidden shadow-2xl border border-slate-200">
          {/* Left Hero / Architecture Assurance Column */}
          <div className="lg:col-span-6 p-8 sm:p-10 bg-gradient-to-b from-slate-900 to-slate-950 text-slate-50 flex flex-col justify-between gap-8">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-indigo-500/20 border border-indigo-400/35 text-xs font-semibold text-indigo-200 mb-5">
                <ShieldIcon size={14} />
                Zero-Trust Enterprise RAG Workspace
              </div>

              <h2 className="text-2xl font-bold tracking-tight text-white leading-snug">
                Asisten AI Perusahaan dengan Isolasi Hak Akses & Bukti Terukur
              </h2>
              <p className="mt-3 text-sm text-slate-300 leading-relaxed">
                Dirancang untuk menjawab pertanyaan bisnis secara akurat hanya
                dari dokumen resmi (PDF, DOCX, XLSX, CSV) yang diizinkan bagi
                role Anda—tanpa kebocoran lintas divisi dan tanpa klaim tanpa
                bukti.
              </p>

              <div className="mt-7 flex flex-col gap-4">
                <div className="flex items-start gap-3.5">
                  <div className="w-9 h-9 rounded-lg bg-indigo-500/20 border border-indigo-400/35 flex items-center justify-center text-indigo-300 shrink-0">
                    <LockIcon size={18} />
                  </div>
                  <div>
                    <strong className="block text-sm font-semibold text-slate-100">
                      Pre & Post-Retrieval RBAC Filtering
                    </strong>
                    <span className="text-xs text-slate-400 leading-relaxed">
                      Otorisasi Deny-by-Default diverifikasi sebelum pencarian
                      vektor Qdrant dan divalidasi ulang sebelum konteks dikirim
                      ke model.
                    </span>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <div className="w-9 h-9 rounded-lg bg-indigo-500/20 border border-indigo-400/35 flex items-center justify-center text-indigo-300 shrink-0">
                    <CheckCircleIcon size={18} />
                  </div>
                  <div>
                    <strong className="block text-sm font-semibold text-slate-100">
                      Validasi Sitasi & Deteksi Konflik Dokumen Otomatis
                    </strong>
                    <span className="text-xs text-slate-400 leading-relaxed">
                      Setiap klaim wajib merujuk pada potongan dokumen asli
                      beserta nomor halaman, baris tabel, atau bagian dokumen.
                    </span>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <div className="w-9 h-9 rounded-lg bg-indigo-500/20 border border-indigo-400/35 flex items-center justify-center text-indigo-300 shrink-0">
                    <ActivityIcon size={18} />
                  </div>
                  <div>
                    <strong className="block text-sm font-semibold text-slate-100">
                      Multi-Stage Guardrails & Redacted Audit Log
                    </strong>
                    <span className="text-xs text-slate-400 leading-relaxed">
                      Perlindungan terhadap Prompt Injection, kebocoran
                      kredensial/PII, serta pencatatan jejak audit teredaksi.
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-5 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <span>Status API Backend:</span>
              <span
                className={`inline-flex items-center gap-2 font-semibold ${
                  backendOnline === true
                    ? "text-emerald-400"
                    : backendOnline === false
                    ? "text-red-400"
                    : "text-slate-300"
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    backendOnline === true
                      ? "bg-emerald-400"
                      : backendOnline === false
                      ? "bg-red-400"
                      : "bg-slate-400"
                  }`}
                />
                {backendOnline === true
                  ? "Terhubung (/api/v1/health OK)"
                  : backendOnline === false
                  ? "Backend Offline (Jalankan start_enterprise_rag.bat)"
                  : "Memeriksa Koneksi..."}
              </span>
            </div>
          </div>

          {/* Right Form Column */}
          <div className="lg:col-span-6 p-8 sm:p-10 flex flex-col justify-center gap-5 bg-white">
            <div>
              <h1 className="text-xl font-bold text-slate-900">
                Masuk ke Ruang Kerja
              </h1>
              <p className="mt-1 text-xs text-slate-500">
                Gunakan kredensial perusahaan Anda untuk mengakses asisten dan
                dokumen sesuai hak akses role.
              </p>
            </div>

            {loginError && (
              <div className="alert alert-danger" role="alert">
                <AlertTriangleIcon size={18} />
                <div>
                  <strong>Gagal Masuk:</strong> {loginError}
                </div>
              </div>
            )}

            <form onSubmit={handleLogin} className="flex flex-col gap-4">
              <div className="field-group">
                <label htmlFor="login-username" className="field-label">
                  Username Pengguna
                </label>
                <input
                  id="login-username"
                  type="text"
                  className="field-input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Masukkan username (mis. admin1)"
                  autoComplete="username"
                  required
                />
              </div>

              <div className="field-group">
                <label htmlFor="login-password" className="field-label">
                  Kata Sandi (Password)
                </label>
                <input
                  id="login-password"
                  type="password"
                  className="field-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Masukkan kata sandi"
                  autoComplete="current-password"
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary btn-lg w-full mt-1"
                disabled={loginLoading}
              >
                <LockIcon size={16} />
                {loginLoading
                  ? "Memverifikasi Identitas & RBAC..."
                  : "Masuk dengan Aman"}
              </button>
            </form>

            {/* Quick Role Selector for Local Seeded Accounts */}
            <div className="pt-4 border-t border-slate-200">
              <div className="text-xs font-semibold text-slate-600 mb-2.5">
                Pilih Cepat Akun Pengujian Lokal (Seeded RBAC Roles):
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {SEEDED_ACCOUNTS.map((acc) => {
                  const selected = username === acc.username;
                  return (
                    <button
                      key={acc.username}
                      type="button"
                      onClick={() => selectDemoAccount(acc.username, acc.password)}
                      className={`text-left px-3 py-2 rounded-lg border transition-all ${
                        selected
                          ? "border-indigo-600 bg-indigo-50/70 ring-1 ring-indigo-600/20"
                          : "border-slate-200 bg-slate-50 hover:bg-slate-100 hover:border-slate-300"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-mono font-bold text-xs text-slate-900">
                          {acc.username}
                        </span>
                        <span className="badge badge-accent text-[10px] px-1.5 py-0">
                          {acc.role}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5 truncate">
                        {acc.scopeSummary}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const isAdmin = principal.role.toLowerCase() === "admin";
  const currentMeta = sectionMetadata[activeSection];

  return (
    <div className="min-h-screen flex bg-slate-50">
      {/* Mobile Sidebar Overlay */}
      {mobileSidebarOpen && (
        <div
          onClick={() => setMobileSidebarOpen(false)}
          className="fixed inset-0 bg-slate-900/50 z-30 lg:hidden"
          aria-hidden="true"
        />
      )}

      {/* Left Enterprise Navigation Sidebar */}
      <aside
        className={`w-[264px] bg-slate-900 text-slate-100 flex flex-col shrink-0 border-r border-slate-800 fixed lg:sticky top-0 inset-y-0 left-0 h-screen z-40 transition-transform duration-200 ${
          mobileSidebarOpen
            ? "translate-x-0"
            : "-translate-x-full lg:translate-x-0"
        }`}
        aria-label="Navigasi Utama"
      >
        <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-indigo-500 to-indigo-700 flex items-center justify-center text-white shadow-sm shrink-0">
            <ShieldIcon size={20} />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-50 tracking-tight m-0">
              Enterprise RAG
            </h1>
            <p className="text-[11px] text-slate-400 mt-0.5 mb-0">
              RBAC • Guardrails • Audit
            </p>
          </div>
        </div>

        <nav className="flex-1 p-3 overflow-y-auto flex flex-col gap-5">
          {/* Group 1: Workspace */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2.5 pb-1.5">
              Workspace
            </div>
            <button
              type="button"
              onClick={() => navigateTo("chat")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                activeSection === "chat"
                  ? "bg-indigo-600 text-white font-semibold shadow-sm"
                  : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <MessageSquareIcon size={18} />
              <span>Asisten AI (Chat)</span>
            </button>
          </div>

          {/* Group 2: Knowledge */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2.5 pb-1.5">
              Knowledge Base
            </div>
            <button
              type="button"
              onClick={() => navigateTo("documents")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                activeSection === "documents"
                  ? "bg-indigo-600 text-white font-semibold shadow-sm"
                  : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <FileTextIcon size={18} />
              <span>Dokumen & ACL</span>
            </button>
          </div>

          {/* Group 3: Administration */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2.5 pb-1.5">
              Administration
            </div>
            <button
              type="button"
              onClick={() => navigateTo("admin_users")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                activeSection === "admin_users"
                  ? "bg-indigo-600 text-white font-semibold shadow-sm"
                  : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <UsersIcon size={18} />
              <span className="flex-1">Pengguna & RBAC</span>
              {!isAdmin && (
                <span
                  title="Hanya untuk role ADMIN"
                  className="opacity-60 inline-flex"
                >
                  <LockIcon size={13} />
                </span>
              )}
            </button>
          </div>

          {/* Group 4: Observability */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2.5 pb-1.5">
              Observability
            </div>
            <button
              type="button"
              onClick={() => navigateTo("observability")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                activeSection === "observability"
                  ? "bg-indigo-600 text-white font-semibold shadow-sm"
                  : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <ActivityIcon size={18} />
              <span className="flex-1">Audit & Evaluasi</span>
              {!isAdmin && (
                <span
                  title="Hanya untuk role ADMIN"
                  className="opacity-60 inline-flex"
                >
                  <LockIcon size={13} />
                </span>
              )}
            </button>
          </div>

          {/* Group 5: Settings & Identity Profile */}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2.5 pb-1.5">
              Identitas & Kebijakan
            </div>
            <button
              type="button"
              onClick={() => {
                setProfileModalOpen(true);
                setMobileSidebarOpen(false);
              }}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors text-left"
            >
              <ShieldIcon size={18} />
              <span>Profil & Izin Saya</span>
            </button>
          </div>
        </nav>

        <div className="p-3.5 border-t border-slate-800 bg-slate-950/50">
          <div className="flex items-center justify-between gap-2">
            <div className="flex flex-col min-w-0">
              <span className="text-xs font-semibold text-slate-100 truncate">
                {principal.username}
              </span>
              <span className="text-[11px] text-slate-400 truncate">
                Role: {principal.role} • {principal.user_id}
              </span>
            </div>
            <button
              type="button"
              className="btn btn-sm bg-slate-800 text-slate-100 border border-slate-700 hover:bg-slate-700"
              onClick={handleLogout}
            >
              Keluar
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 bg-white border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-20">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              className="btn btn-ghost btn-sm lg:hidden"
              onClick={() => setMobileSidebarOpen((v) => !v)}
              aria-label="Buka menu navigasi"
            >
              <MenuIcon size={20} />
            </button>
            <div className="min-w-0">
              <h2 className="text-sm sm:text-base font-semibold text-slate-900 truncate m-0">
                {currentMeta.title}
              </h2>
              <p className="text-xs text-slate-500 truncate mt-0.5 mb-0 hidden sm:block">
                {currentMeta.subtitle}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <span
              className={`badge ${
                backendOnline === false ? "badge-danger" : "badge-success"
              }`}
              title="Status koneksi langsung ke endpoint /api/v1/health"
            >
              <CheckCircleIcon size={12} />
              <span className="hidden sm:inline">
                {backendOnline === false ? "API Terputus" : "Sistem Aktif"}
              </span>
            </span>

            <button
              type="button"
              className="badge badge-accent cursor-pointer hover:bg-indigo-100 transition-colors"
              onClick={() => setProfileModalOpen(true)}
              title="Klik untuk melihat detail hak akses RBAC Anda"
            >
              <ShieldIcon size={12} />
              Role: {principal.role}
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 max-w-[1440px] w-full mx-auto">
          {activeSection === "chat" && (
            <ChatWorkspace
              token={token}
              role={principal.role}
              username={principal.username}
            />
          )}

          {activeSection === "documents" && (
            <DocumentsWorkspace token={token} role={principal.role} />
          )}

          {activeSection === "admin_users" && (
            <AdminUsersWorkspace
              token={token}
              currentUserId={principal.user_id}
              userRole={principal.role}
            />
          )}

          {activeSection === "observability" && (
            <ObservabilityWorkspace token={token} userRole={principal.role} />
          )}
        </main>
      </div>

      {/* Profile & RBAC Permissions Inspector Modal */}
      {profileModalOpen && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="profile-modal-title"
        >
          <div className="modal-dialog">
            <div className="modal-header">
              <div>
                <h3 id="profile-modal-title" className="modal-title">
                  Profil Identitas & Kontrak Hak Akses (RBAC)
                </h3>
                <p className="card-subtitle">
                  Data terverifikasi langsung dari endpoint{" "}
                  <span className="font-mono">GET /api/v1/auth/me</span>
                </p>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setProfileModalOpen(false)}
              >
                Tutup
              </button>
            </div>

            <div className="modal-body flex flex-col gap-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                <div>
                  <div className="text-slate-500">Username</div>
                  <div className="font-bold text-slate-900 mt-0.5">
                    {principal.username}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">User ID</div>
                  <div className="font-mono font-semibold text-slate-900 mt-0.5">
                    {principal.user_id}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Email Perusahaan</div>
                  <div className="text-slate-800 mt-0.5">{principal.email}</div>
                </div>
                <div>
                  <div className="text-slate-500">Role Otorisasi Aktif</div>
                  <div className="mt-0.5">
                    <span className="badge badge-accent">{principal.role}</span>
                  </div>
                </div>
              </div>

              <div>
                <div className="font-semibold mb-1.5 text-slate-900">
                  Izin Eksplisit Tambahan (Explicit Permissions)
                </div>
                {principal.explicit_permissions &&
                principal.explicit_permissions.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {principal.explicit_permissions.map((p) => (
                      <span key={p} className="badge badge-info font-mono">
                        {p}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="text-slate-500">
                    Tidak ada izin eksplisit tambahan; mengikuti kebijakan dasar
                    role <strong>{principal.role}</strong>.
                  </div>
                )}
              </div>

              <div className="alert alert-info">
                <ShieldIcon size={18} />
                <div>
                  <strong>Prinsip Keamanan Deny-by-Default:</strong> Sistem
                  memfilter seluruh pencarian dokumen di Qdrant menggunakan role{" "}
                  <span className="font-mono">{principal.role}</span> dan User
                  ID <span className="font-mono">{principal.user_id}</span>.
                  Dokumen di luar cakupan ACL Anda tidak pernah dimuat ke dalam
                  konteks model LLM.
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleLogout}
              >
                Keluar & Ganti Akun Role
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setProfileModalOpen(false)}
              >
                Selesai
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
