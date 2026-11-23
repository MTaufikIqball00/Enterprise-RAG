# Dokumen Arsitektur Sistem — Enterprise RAG (Native Rust Architecture)

## 1. Stack Teknologi Terverifikasi

Sistem Enterprise RAG dibangun sepenuhnya di atas backend **Rust native (Axum + Tokio + SQLx)** dan frontend **React 18 + TypeScript + Tailwind CSS (Vite)** tanpa ketergantungan runtime Python.

| Komponen | Teknologi Terpilih | Crate / Versi Utama | Alasan Teknis & Keamanan |
| :--- | :--- | :--- | :--- |
| **Backend API** | Rust Axum + Tokio + Tower | `axum 0.7`, `tokio 1.40`, `tower-http 0.6` | *Memory-safe*, latensi sub-millisecond, allowlist CORS ketat, ekstraktor autentikasi JWT terpusat, dan *fixed-window rate limiting*. |
| **OpenAPI / Swagger** | `utoipa` | `utoipa 5` | Menghasilkan spesifikasi OpenAPI 3.1 dinamis di `/api-docs/openapi.json` dan antarmuka interaktif Swagger UI di `/docs`. |
| **Relational, FTS5 & Audit DB** | SQLite + SQLx | `sqlx 0.8` (`sqlite`) | Mengaktifkan `PRAGMA foreign_keys = ON` dan `WAL` journal mode untuk konkurensi baca-tulis aman dan integritas referensial. |
| **Hybrid Vector & Lexical Retrieval** | SQLite Persistent Embeddings + SQLite FTS5 (BM25) + Reciprocal Rank Fusion (RRF) + Opsional Qdrant REST | `blake2 0.10`, SQLite FTS5, `reqwest 0.12` | Menggabungkan skor semantik vektor (Blake2b 256d / OpenAI / Gemini) dengan BM25 leksikal melalui RRF (`k=60`) dengan *Pre-Retrieval* & *Post-Retrieval ACL Filtering*. |
| **Bounded Isolated Cache** | `moka` Async Cache | `moka 0.12` | Cache terisolasi per `(user_id, role, explicit_permissions, acl_versions, history_fingerprint, query)` dengan batas kapasitas maksimum (`CACHE_MAX_CAPACITY`) dan TTL (`CACHE_TTL_SECS`). |
| **Document Parsers** | `lopdf`, `zip` + `quick-xml`, `calamine`, `csv` | `lopdf 0.34`, `quick-xml 0.36`, `calamine 0.37`, `csv 1.3` | Ekstraksi deterministik per halaman (PDF), heading & tabel terstruktur `<w:tbl>` (DOCX), sheet/baris (XLSX/CSV), plus *boundary-aware chunking* yang mempertahankan header kolom. |
| **Multi-Provider LLM & Embedding** | Trait `LLMProvider` & `EmbeddingProvider` | `async-trait`, `reqwest 0.12` | Default offline deterministik (`local_grounded` & `local_deterministic`) untuk pengujian 100% *reproducible*, serta konektor HTTP terstruktur untuk **OpenAI** dan **Gemini** via `.env`. |
| **Frontend** | React + TypeScript + Tailwind CSS | React `18.3`, Vite `5.4`, Tailwind `3.4` | Workspace terpadu untuk Chat multi-turn ber-sitasi, Repositori Dokumen & Edit ACL, Manajemen User CRUD & RBAC, serta Observabilitas Audit & Evaluasi 11 Kategori. |

---

## 2. Komponen Inti Arsitektur Keamanan & RAG

1. **Autentikasi JWT HS256, Revokasi Logout (`jti`), & Rate Limiting (`src/security/auth.rs`, `src/api/rate_limit.rs`):**
   - Password di-hash menggunakan `PBKDF2-HMAC-SHA256` (200.000 iterasi) dengan perbandingan *constant-time* (`subtle`).
   - Startup guard di `Settings::validate()` menolak boot pada environment non-development jika `JWT_SECRET_KEY` masih placeholder atau `< 32` byte.
   - `POST /api/v1/auth/logout` mencabut `jti` token ke tabel `revoked_tokens`, sehingga token yang sudah logout langsung ditolak (`401 Unauthorized`).
   - Endpoint `/auth/login` dan `/chat/query` dilindungi *rate limiter* berbasis jendela waktu dengan respons `429 Too Many Requests` + header `Retry-After`.
2. **Authorization Engine Berbasis RBAC, Explicit Permissions & Document ACL (`src/security/rbac.rs`):**
   - Prinsip **Deny-by-Default** dan **Separation of Duties**: role `admin` mengelola pengguna, RBAC, audit, dan evaluasi, namun secara default memiliki **0 akses baca** ke dokumen bisnis.
   - Mendukung izin eksplisit granular yang tersinkronisasi antara backend dan UI: `doc:upload`, `doc:delete`, `policy:manage`, `audit:read`, `eval:run`, `upload:<scope>`, `read_scope:<scope>`, `read_doc:<id>`, `manage_doc:<id>`.
   - Penghapusan dokumen (`DELETE /api/v1/documents/:id`) dan pengeditan ACL (`PATCH /api/v1/documents/:id/acl`) dibatasi ketat kepada pemilik dokumen (`owner_user_id`) atau pemegang izin eksplisit yang tepat, bukan seluruh pengguna di scope yang sama.
   - Perlindungan *Anti-Self-Escalation* dan *Anti-Self-Deactivation* mencegah Admin mengubah role atau status akun miliknya sendiri.
3. **Document Ingestion, DOCX Table Extraction & Smart Chunking (`src/ingestion/`):**
   - Validasi ekstensi, batas ukuran, *magic bytes* (`%PDF-`, `PK\x03\x04`), serta idempotency `SHA-256`.
   - Parser DOCX mengekstrak heading (`Event::Start` & `Event::Empty` pada `<w:pStyle>`) serta tabel `<w:tbl>/<w:tr>/<w:tc>` ke format `Kolom=Nilai` terstruktur sehingga data tabel DOCX dapat disitasi dan dihitung secara deterministik.
   - Chunker memotong pada batas baris/kalimat/kata (tidak memotong di tengah kata/angka) dan menyertakan kembali header kolom pada setiap chunk lanjutan CSV/XLSX/DOCX.
4. **Hybrid Retrieval (FTS5 BM25 + Persistent Vectors + RRF) & Two-Stage ACL (`src/rag/vector_store.rs`):**
   - Embedding disimpan persisten di tabel `document_chunk_embeddings` dan teks diindeks ke virtual table `document_chunks_fts` (FTS5) — plus dukungan opsional server Qdrant eksternal via `QDRANT_URL`.
   - *Tahap 1 (Pre-Retrieval):* Baik pencarian vektor maupun kueri FTS5 BM25 hanya memproses dokumen berstatus `INDEXED` yang lolos verifikasi ACL principal.
   - *Tahap 2 (Post-Retrieval Re-Verification):* Kandidat hasil fusi RRF diverifikasi ulang terhadap tabel `documents` dan `document_chunks` di SQLite sebelum masuk ke konteks LLM.
5. **Multi-Turn Context, Strict CitationValidator & Multi-Stage Guardrails (`src/rag/service.rs`, `src/guardrails/engine.rs`):**
   - Konteks percakapan terbaru dari `chat_messages` pada `session_id` terisolasi digunakan untuk memperkaya pertanyaan lanjutan (*follow-up*), sekaligus dimasukkan ke sidik jari kunci cache.
   - Cache-hit tetap menyimpan pasangan pesan pengguna dan asisten ke tabel `chat_messages` agar riwayat percakapan di UI selalu konsisten.
   - Hasil `Err` dari `CitationValidator::validate_citations_and_claims` ditegakkan keras: klaim tak terverifikasi ditolak (`CIT-001`), dialihkan ke pesan abstention seragam, dan dicatat ke `audit_logs`.
   - Kalkulasi aritmatika melewati `GuardrailsEngine::validate_tool_execution("safe_arithmetic_aggregator", false)` (`TOOL-PASS`).
6. **Redacted Audit Trail & 11-Category Evaluation Suite (`src/audit/logger.rs`, `src/evaluation/runner.rs`):**
   - Seluruh log audit otomatis menyensor hash PBKDF2, Bearer JWT (`eyJ...`), OpenAI key (`sk-...`), Gemini key (`AIza...`), dan Private Key.
   - Suite evaluasi otomatis menguji 11 kategori kritis keamanan dan akurasi RAG secara end-to-end dengan target kelulusan `100%`.
