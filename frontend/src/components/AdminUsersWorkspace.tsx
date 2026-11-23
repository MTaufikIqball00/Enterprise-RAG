import React, { useEffect, useMemo, useState } from "react";
import {
  AdminUserItem,
  RoleChangeAuditItem,
  createAdminUserApi,
  fetchAdminUsers,
  fetchRoleChangeAudits,
  updateUserRoleApi,
  updateUserStatusApi,
} from "../api";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  LockIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  UsersIcon,
} from "./Icons";

interface AdminUsersWorkspaceProps {
  token: string;
  currentUserId: string;
  userRole: string;
  explicitPermissions?: string[];
}

const AVAILABLE_ROLES = [
  {
    value: "employee",
    label: "EMPLOYEE",
    desc: "Akses dokumen cakupan GENERAL yang diizinkan secara eksplisit di ACL.",
  },
  {
    value: "hr",
    label: "HR",
    desc: "Akses dokumen cakupan HR & GENERAL sesuai daftar ACL dokumen.",
  },
  {
    value: "finance",
    label: "FINANCE",
    desc: "Akses dokumen cakupan FINANCE & GENERAL sesuai daftar ACL dokumen.",
  },
  {
    value: "executive",
    label: "EXECUTIVE",
    desc: "Akses dokumen cakupan EXECUTIVE & laporan lintas departemen yang diizinkan di ACL.",
  },
  {
    value: "admin",
    label: "ADMIN",
    desc: "Manajemen pengguna, kebijakan RBAC, audit log, dan evaluasi sistem.",
  },
];

const EXPLICIT_PERMISSIONS_CATALOG = [
  { id: "doc:upload", label: "Unggah Dokumen Scope Terotorisasi (doc:upload)" },
  { id: "doc:delete", label: "Hapus & Kelola Dokumen Scope Terotorisasi (doc:delete)" },
  { id: "policy:manage", label: "Kelola Pengguna, Role & Kebijakan (policy:manage)" },
  { id: "audit:read", label: "Baca Audit Log Teredaksi (audit:read)" },
  { id: "eval:run", label: "Jalankan Suite Evaluasi 11 Kategori (eval:run)" },
  { id: "upload:general", label: "Unggah Khusus Scope General (upload:general)" },
  { id: "upload:hr", label: "Unggah Khusus Scope HR (upload:hr)" },
  { id: "upload:finance", label: "Unggah Khusus Scope Finance (upload:finance)" },
  { id: "upload:executive", label: "Unggah Khusus Scope Executive (upload:executive)" },
  { id: "read_scope:hr", label: "Akses Baca Scope HR (read_scope:hr)" },
  { id: "read_scope:finance", label: "Akses Baca Scope Finance (read_scope:finance)" },
  { id: "read_scope:executive", label: "Akses Baca Scope Executive (read_scope:executive)" },
];

export function AdminUsersWorkspace({
  token,
  currentUserId,
  userRole,
  explicitPermissions = [],
}: AdminUsersWorkspaceProps) {
  const normalizedRole = userRole.toLowerCase();
  const [users, setUsers] = useState<AdminUserItem[]>([]);
  const [roleAudits, setRoleAudits] = useState<RoleChangeAuditItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [successMsg, setSuccessMsg] = useState<string>("");

  const [searchQuery, setSearchQuery] = useState<string>("");
  const [roleFilter, setRoleFilter] = useState<string>("ALL");

  // Modal state for editing a user's role & permissions
  const [editingUser, setEditingUser] = useState<AdminUserItem | null>(null);
  const [selectedRole, setSelectedRole] = useState<string>("employee");
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  const [auditReason, setAuditReason] = useState<string>("");
  const [confirmStep, setConfirmStep] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [modalError, setModalError] = useState<string>("");

  // Modal state for creating a new user
  const [createModalOpen, setCreateModalOpen] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>("");
  const [newEmail, setNewEmail] = useState<string>("");
  const [newPassword, setNewPassword] = useState<string>("");
  const [newRole, setNewRole] = useState<string>("employee");
  const [newPermissions, setNewPermissions] = useState<string[]>([]);
  const [creatingUser, setCreatingUser] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string>("");

  const isAdmin =
    normalizedRole === "admin" || explicitPermissions.includes("policy:manage");

  useEffect(() => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    void loadAdminData();
  }, [token, isAdmin]);

  async function loadAdminData() {
    setLoading(true);
    setErrorMsg("");
    try {
      const [usersData, auditsData] = await Promise.all([
        fetchAdminUsers(token),
        fetchRoleChangeAudits(token),
      ]);
      setUsers(usersData);
      setRoleAudits(auditsData);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : "Gagal memuat data pengguna dan riwayat kebijakan RBAC."
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setCreateError("");
    if (newUsername.trim().length < 3) {
      setCreateError("Username minimal 3 karakter.");
      return;
    }
    if (!newEmail.includes("@")) {
      setCreateError("Alamat email tidak valid.");
      return;
    }
    if (newPassword.length < 8) {
      setCreateError("Kata sandi minimal 8 karakter.");
      return;
    }
    setCreatingUser(true);
    try {
      const created = await createAdminUserApi(token, {
        username: newUsername.trim(),
        email: newEmail.trim(),
        password: newPassword,
        role: newRole,
        explicit_permissions: newPermissions,
      });
      setSuccessMsg(
        `Pengguna baru "${created.username}" (${created.role.toUpperCase()}) berhasil dibuat dan dicatat ke Audit Log.`
      );
      setCreateModalOpen(false);
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      setNewRole("employee");
      setNewPermissions([]);
      await loadAdminData();
    } catch (err: unknown) {
      setCreateError(
        err instanceof Error ? err.message : "Gagal membuat pengguna baru."
      );
    } finally {
      setCreatingUser(false);
    }
  }

  async function handleToggleUserStatus(user: AdminUserItem) {
    const nextActive = !user.is_active;
    const actionLabel = nextActive ? "mengaktifkan kembali" : "menonaktifkan";
    const reason = window.prompt(
      `Masukkan alasan audit (min. 5 karakter) untuk ${actionLabel} akun "${user.username}":`,
      nextActive
        ? "Aktivasi kembali akun berdasarkan persetujuan keamanan"
        : "Penonaktifan sementara akun berdasarkan kebijakan kepatuhan"
    );
    if (!reason) return;
    if (reason.trim().length < 5) {
      setErrorMsg("Alasan audit perubahan status minimal 5 karakter.");
      return;
    }
    setErrorMsg("");
    setSuccessMsg("");
    try {
      await updateUserStatusApi(token, user.user_id, nextActive, reason.trim());
      setSuccessMsg(
        `Status akun "${user.username}" berhasil diubah menjadi ${
          nextActive ? "AKTIF" : "NONAKTIF"
        } dan tercatat di Audit Log.`
      );
      await loadAdminData();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : "Gagal memperbarui status akun pengguna."
      );
    }
  }

  function openEditModal(user: AdminUserItem) {
    setEditingUser(user);
    setSelectedRole(user.role.toLowerCase());
    setSelectedPermissions(user.explicit_permissions || []);
    setAuditReason("");
    setConfirmStep(false);
    setModalError("");
    setSuccessMsg("");
  }

  function togglePermission(permId: string) {
    setSelectedPermissions((prev) =>
      prev.includes(permId)
        ? prev.filter((p) => p !== permId)
        : [...prev, permId]
    );
  }

  async function handleSaveRoleChange(e: React.FormEvent) {
    e.preventDefault();
    if (!editingUser) return;
    setModalError("");

    if (auditReason.trim().length < 5) {
      setModalError(
        "Alasan audit wajib diisi minimal 5 karakter untuk kepatuhan jejak audit."
      );
      return;
    }

    if (!confirmStep) {
      setConfirmStep(true);
      return;
    }

    setSubmitting(true);
    try {
      await updateUserRoleApi(
        token,
        editingUser.user_id,
        selectedRole,
        selectedPermissions,
        auditReason.trim()
      );
      setSuccessMsg(
        `Kebijakan akses untuk pengguna "${
          editingUser.username
        }" berhasil diperbarui menjadi ${selectedRole.toUpperCase()} dan tercatat di Audit Log.`
      );
      setEditingUser(null);
      await loadAdminData();
    } catch (err: unknown) {
      setModalError(
        err instanceof Error
          ? err.message
          : "Gagal memperbarui role pengguna."
      );
      setConfirmStep(false);
    } finally {
      setSubmitting(false);
    }
  }

  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      const matchesRole =
        roleFilter === "ALL" || u.role.toLowerCase() === roleFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q ||
        u.username.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.user_id.toLowerCase().includes(q);
      return matchesRole && matchesQuery;
    });
  }, [users, roleFilter, searchQuery]);

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
          Akses Administrasi RBAC Dibatasi (Deny-by-Default)
        </div>
        <div className="text-xs text-slate-500 max-w-md leading-relaxed">
          Anda saat ini masuk dengan role{" "}
          <strong className="text-slate-800">
            {normalizedRole.toUpperCase()}
          </strong>
          . Halaman manajemen identitas, perubahan role, dan kebijakan akses
          hanya diizinkan untuk pengguna dengan role <strong>ADMIN</strong>.
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Top Policy Summary Banner */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Manajemen Pengguna & Kebijakan Akses (RBAC)
            </h2>
            <p className="card-subtitle">
              Kelola otorisasi pengguna dengan prinsip Deny-by-Default dan Least
              Privilege. Setiap perubahan role wajib menyertakan alasan audit
              yang dicatat secara permanen.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setCreateError("");
                setCreateModalOpen(true);
              }}
            >
              <PlusIcon size={14} /> Tambah Pengguna
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => void loadAdminData()}
              disabled={loading}
            >
              Muat Ulang Data
            </button>
          </div>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
            {AVAILABLE_ROLES.map((r) => {
              const count = users.filter(
                (u) => u.role.toLowerCase() === r.value
              ).length;
              return (
                <div
                  key={r.value}
                  className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col gap-2"
                >
                  <div className="flex justify-between items-center">
                    <span className="badge badge-accent">{r.label}</span>
                    <span className="text-xl font-bold text-slate-900">
                      {loading ? "—" : count}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 leading-relaxed">
                    {r.desc}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="alert alert-danger" role="alert">
          <AlertTriangleIcon size={18} className="shrink-0" />
          <div>
            <strong>Gagal Memuat Data Administrasi:</strong> {errorMsg}
          </div>
        </div>
      )}

      {successMsg && (
        <div className="alert alert-success" role="status">
          <CheckCircleIcon size={18} className="shrink-0" />
          <div>{successMsg}</div>
        </div>
      )}

      {/* User Directory Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">Direktori Identitas Pengguna Aktif</h3>
            <p className="card-subtitle">
              Menampilkan {filteredUsers.length} dari {users.length} akun
              terdaftar di database identitas.
            </p>
          </div>
        </div>
        <div className="card-body">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex-1 min-w-[240px] max-w-md relative">
              <label htmlFor="admin-user-search" className="sr-only">
                Cari pengguna
              </label>
              <input
                id="admin-user-search"
                type="search"
                className="field-input pl-8"
                placeholder="Cari berdasarkan username, email, atau ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">
                <SearchIcon size={15} />
              </span>
            </div>

            <div className="flex items-center gap-2">
              <label htmlFor="admin-role-filter" className="sr-only">
                Filter Role
              </label>
              <select
                id="admin-role-filter"
                className="field-select w-auto"
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
              >
                <option value="ALL">Semua Role</option>
                {AVAILABLE_ROLES.map((r) => (
                  <option key={r.value} value={r.value}>
                    Role: {r.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {loading ? (
            <div className="flex flex-col gap-2.5" aria-busy="true">
              <div className="skeleton h-11 w-full" />
              <div className="skeleton h-11 w-full" />
              <div className="skeleton h-11 w-full" />
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 flex flex-col items-center gap-2">
              <div className="w-10 h-10 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center">
                <UsersIcon size={20} />
              </div>
              <div className="text-sm font-bold text-slate-900">
                Tidak Ada Pengguna yang Cocok
              </div>
              <div className="text-xs text-slate-500">
                Coba ubah kata kunci pencarian atau reset filter role di atas.
              </div>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Pengguna & Email</th>
                    <th>User ID</th>
                    <th>Role Saat Ini</th>
                    <th>Izin Eksplisit (Permissions)</th>
                    <th>Status Akun</th>
                    <th className="text-right">Tindakan</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((u) => {
                    const isSelf = u.user_id === currentUserId;
                    const uRoleUpper = u.role.toUpperCase();
                    return (
                      <tr key={u.user_id}>
                        <td>
                          <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                            <span>{u.username}</span>
                            {isSelf && (
                              <span className="badge badge-info">
                                Sesi Anda
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-slate-500">
                            {u.email}
                          </div>
                        </td>
                        <td>
                          <span className="font-mono text-xs">{u.user_id}</span>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              uRoleUpper === "ADMIN"
                                ? "badge-warning"
                                : uRoleUpper === "EXECUTIVE"
                                ? "badge-info"
                                : "badge-accent"
                            }`}
                          >
                            <ShieldIcon size={12} />
                            {uRoleUpper}
                          </span>
                        </td>
                        <td>
                          {u.explicit_permissions &&
                          u.explicit_permissions.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {u.explicit_permissions.map((perm) => (
                                <span
                                  key={perm}
                                  className="badge badge-neutral font-mono"
                                >
                                  {perm}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs text-slate-400">
                              Default sesuai Role
                            </span>
                          )}
                        </td>
                        <td>
                          {u.is_active ? (
                            <span className="badge badge-success">
                              <CheckCircleIcon size={12} /> Aktif
                            </span>
                          ) : (
                            <span className="badge badge-danger">Nonaktif</span>
                          )}
                        </td>
                        <td className="text-right">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => openEditModal(u)}
                              disabled={isSelf}
                              title={
                                isSelf
                                  ? "Kebijakan Anti-Self-Escalation melarang Admin mengubah role miliknya sendiri."
                                  : `Ubah role dan izin untuk ${u.username}`
                              }
                            >
                              {isSelf
                                ? "Terkunci (Akun Sendiri)"
                                : "Ubah Role & Izin"}
                            </button>
                            {!isSelf && (
                              <button
                                type="button"
                                className={`btn btn-sm ${
                                  u.is_active ? "btn-danger" : "btn-primary"
                                }`}
                                onClick={() => void handleToggleUserStatus(u)}
                                title={
                                  u.is_active
                                    ? `Nonaktifkan akun ${u.username}`
                                    : `Aktifkan kembali akun ${u.username}`
                                }
                              >
                                {u.is_active ? "Nonaktifkan" : "Aktifkan"}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Immutable Role Change Audit Log Table */}
      <div className="card">
        <div className="card-header">
          <div>
            <h3 className="card-title">
              Riwayat Audit Perubahan Role (Immutable Policy Log)
            </h3>
            <p className="card-subtitle">
              Setiap modifikasi hak akses pengguna dicatat secara permanen untuk
              kebutuhan kepatuhan keamanan dan forensik internal.
            </p>
          </div>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="skeleton h-24 w-full" />
          ) : roleAudits.length === 0 ? (
            <div className="p-5 text-center text-slate-500 text-xs">
              Belum ada riwayat perubahan role yang tercatat pada sistem.
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID Audit</th>
                    <th>Waktu Perubahan (Lokal)</th>
                    <th>Target Pengguna</th>
                    <th>Perubahan Role</th>
                    <th>Diubah Oleh (Actor ID)</th>
                    <th>Alasan Kepatuhan Audit</th>
                  </tr>
                </thead>
                <tbody>
                  {roleAudits.map((item) => (
                    <tr key={item.id}>
                      <td className="font-mono">#{item.id}</td>
                      <td className="font-mono whitespace-nowrap">
                        {new Date(item.created_at).toLocaleString("id-ID")}
                      </td>
                      <td className="font-mono">{item.target_user_id}</td>
                      <td>
                        <div className="flex items-center gap-1.5">
                          <span className="badge badge-neutral">
                            {item.previous_role.toUpperCase()}
                          </span>
                          <span aria-hidden="true">→</span>
                          <span className="badge badge-accent">
                            {item.new_role.toUpperCase()}
                          </span>
                        </div>
                      </td>
                      <td className="font-mono">{item.actor_user_id}</td>
                      <td className="text-slate-900 font-medium">
                        {item.reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Create User Modal */}
      {createModalOpen && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-create-user-title"
        >
          <div className="modal-dialog">
            <div className="modal-header">
              <div>
                <h3 id="modal-create-user-title" className="modal-title">
                  Tambah Identitas Pengguna Baru
                </h3>
                <p className="card-subtitle">
                  POST <span className="font-mono">/api/v1/admin/users</span> —
                  Password di-hash dengan PBKDF2-HMAC-SHA256
                </p>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setCreateModalOpen(false)}
                disabled={creatingUser}
              >
                Tutup
              </button>
            </div>
            <form onSubmit={handleCreateUser}>
              <div className="modal-body flex flex-col gap-3.5">
                {createError && (
                  <div className="alert alert-danger" role="alert">
                    <AlertTriangleIcon size={16} className="shrink-0" />
                    <div>{createError}</div>
                  </div>
                )}
                <div className="field-group">
                  <label htmlFor="create-username" className="field-label">
                    Username
                  </label>
                  <input
                    id="create-username"
                    className="field-input"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Contoh: rina.auditor"
                    required
                    disabled={creatingUser}
                  />
                </div>
                <div className="field-group">
                  <label htmlFor="create-email" className="field-label">
                    Email Perusahaan
                  </label>
                  <input
                    id="create-email"
                    type="email"
                    className="field-input"
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="rina@perusahaan.co.id"
                    required
                    disabled={creatingUser}
                  />
                </div>
                <div className="field-group">
                  <label htmlFor="create-password" className="field-label">
                    Kata Sandi Awal (min. 8 karakter)
                  </label>
                  <input
                    id="create-password"
                    type="password"
                    className="field-input"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Minimal 8 karakter"
                    required
                    disabled={creatingUser}
                  />
                </div>
                <div className="field-group">
                  <label htmlFor="create-role" className="field-label">
                    Role Dasar
                  </label>
                  <select
                    id="create-role"
                    className="field-select"
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    disabled={creatingUser}
                  >
                    {AVAILABLE_ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label} — {r.desc}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field-group">
                  <span className="field-label">Izin Eksplisit Opsional</span>
                  <div className="grid grid-cols-1 gap-1.5 max-h-40 overflow-y-auto p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                    {EXPLICIT_PERMISSIONS_CATALOG.map((perm) => (
                      <label
                        key={perm.id}
                        className="flex items-center gap-2 text-xs text-slate-800 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          className="rounded border-slate-300 text-indigo-600"
                          checked={newPermissions.includes(perm.id)}
                          onChange={() =>
                            setNewPermissions((prev) =>
                              prev.includes(perm.id)
                                ? prev.filter((p) => p !== perm.id)
                                : [...prev, perm.id]
                            )
                          }
                          disabled={creatingUser}
                        />
                        <span>{perm.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setCreateModalOpen(false)}
                  disabled={creatingUser}
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={creatingUser}
                >
                  {creatingUser ? "Menyimpan..." : "Buat Pengguna"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Role & Permissions Modal */}
      {editingUser && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-edit-role-title"
        >
          <div className="modal-dialog">
            <div className="modal-header">
              <div>
                <h3 id="modal-edit-role-title" className="modal-title">
                  Perbarui Kebijakan Role: {editingUser.username}
                </h3>
                <p className="card-subtitle">
                  User ID:{" "}
                  <span className="font-mono">{editingUser.user_id}</span> •{" "}
                  {editingUser.email}
                </p>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setEditingUser(null)}
                disabled={submitting}
              >
                Tutup
              </button>
            </div>

            <form onSubmit={handleSaveRoleChange}>
              <div className="modal-body flex flex-col gap-4">
                {modalError && (
                  <div className="alert alert-danger" role="alert">
                    <AlertTriangleIcon size={16} className="shrink-0" />
                    <div>{modalError}</div>
                  </div>
                )}

                <div className="field-group">
                  <label htmlFor="select-new-role" className="field-label">
                    Pilih Role Baru
                  </label>
                  <select
                    id="select-new-role"
                    className="field-select"
                    value={selectedRole}
                    onChange={(e) => {
                      setSelectedRole(e.target.value);
                      setConfirmStep(false);
                    }}
                    disabled={submitting}
                  >
                    {AVAILABLE_ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label} — {r.desc}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="field-group">
                  <span className="field-label">
                    Izin Eksplisit Tambahan (Explicit Permissions)
                  </span>
                  <span className="field-hint">
                    Pilih izin spesifik jika pengguna memerlukan kapabilitas
                    operasional tambahan di luar role dasar.
                  </span>
                  <div className="grid grid-cols-1 gap-2 mt-1 p-3 rounded-lg bg-slate-50 border border-slate-200">
                    {EXPLICIT_PERMISSIONS_CATALOG.map((perm) => (
                      <label
                        key={perm.id}
                        className="flex items-center gap-2 text-xs text-slate-800 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                          checked={selectedPermissions.includes(perm.id)}
                          onChange={() => {
                            togglePermission(perm.id);
                            setConfirmStep(false);
                          }}
                          disabled={submitting}
                        />
                        <span>{perm.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="field-group">
                  <label htmlFor="audit-reason-input" className="field-label">
                    Alasan Kepatuhan Audit (Wajib, min. 5 karakter)
                  </label>
                  <textarea
                    id="audit-reason-input"
                    className="field-textarea"
                    rows={3}
                    placeholder="Contoh: Mutasi divisi ke departemen HR berdasarkan tiket persetujuan #HR-2026-09..."
                    value={auditReason}
                    onChange={(e) => {
                      setAuditReason(e.target.value);
                      setConfirmStep(false);
                    }}
                    disabled={submitting}
                    required
                  />
                </div>

                {confirmStep && (
                  <div className="alert alert-warning" role="alert">
                    <AlertTriangleIcon size={18} className="shrink-0" />
                    <div>
                      <strong>Konfirmasi Perubahan Hak Akses:</strong> Anda akan
                      mengubah role <strong>{editingUser.username}</strong> dari{" "}
                      <span className="font-mono font-semibold">
                        {editingUser.role.toUpperCase()}
                      </span>{" "}
                      menjadi{" "}
                      <span className="font-mono font-semibold">
                        {selectedRole.toUpperCase()}
                      </span>
                      . Klik tombol <strong>Ya, Terapkan & Catat Audit</strong>{" "}
                      di bawah untuk menyelesaikan.
                    </div>
                  </div>
                )}
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setEditingUser(null)}
                  disabled={submitting}
                >
                  Batal
                </button>
                <button
                  type="submit"
                  className={confirmStep ? "btn btn-danger" : "btn btn-primary"}
                  disabled={submitting}
                >
                  {submitting
                    ? "Menyimpan Kebijakan..."
                    : confirmStep
                    ? "Ya, Terapkan & Catat Audit"
                    : "Tinjau & Simpan Perubahan"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
