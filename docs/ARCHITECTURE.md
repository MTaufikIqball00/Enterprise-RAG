# Dokumen Arsitektur Sistem — Enterprise RAG (Tahap 2)

## 1. Keputusan Stack Teknologi Terkonfirmasi
Berdasarkan hasil pemeriksaan dependency (`pip list`) pada `Python 3.10.0` dan `Node.js v24.15.0` serta konfirmasi pengguna:

| Komponen | Teknologi Terpilih | Versi Terverifikasi | Alasan Teknis & Keamanan |
| :--- | :--- | :--- | :--- |
| **Backend API** | FastAPI + Uvicorn | `0.141.1` / `0.52.0` | Validasi input ketat berbasis Pydantic v2, dependency injection untuk RBAC per-endpoint. |
| **Relational & Audit DB** | SQLite + SQLAlchemy 2.0 + Alembic | `2.0.49` / `1.18.4` | Berjalan tanpa ketergantungan Docker daemon, mendukung transaksi ACID dan foreign key (`PRAGMA foreign_keys=ON`). |
| **Vector Database** | Qdrant Local Persistence (`qdrant-client`) | `1.20.0` | Mendukung *Pre-Retrieval Payload Filtering* (`allowed_roles`, `allowed_users`, `scope`, `ingestion_status`) secara native di mode lokal maupun server. |
| **Orchestration Pipeline** | Custom Security-First RAG Pipeline | `0.1.0` | Menghindari *black-box prompt/retrieval* sehingga *pre-retrieval filter* dan *post-retrieval DB ACL re-verification* dapat diaudit baris demi baris. |
| **Document Parsers** | `pypdf`, `python-docx`, `openpyxl`, `csv`/`pandas` | `6.21.2`, `1.2.0`, `3.1.5`, `2.3.3` | Ekstraksi teks deterministik beserta pelacakan halaman (PDF), bagian/paragraf (DOCX), dan nama sheet + baris (XLSX/CSV). |
| **LLM & Embedding** | Multi-Provider Abstraction (`local_deterministic` / `local_grounded` + OpenAI / Gemini API) | `0.1.0` | Memastikan pengujian otomatis berjalan 100% deterministik tanpa membocorkan data ke cloud, sekaligus siap dihubungkan ke API LLM via `.env`. |
| **Frontend** | React (Vite + TypeScript) | Node `v24.15.0` | Antarmuka terpisah untuk Chat ber-sitasi, Manajemen Dokumen ber-ACL, Audit Log Viewer, dan Evaluation Runner. |

---

## 2. Rancangan 16 Komponen Arsitektur
1. **Frontend (React + TypeScript):** Menyediakan antarmuka login/switch user uji, manajemen dokumen (upload + set ACL), chat asisten AI dengan panel bukti sitasi & klasifikasi epistemik, serta panel Audit & Evaluasi (khusus role yang berwenang).
2. **Backend API & Autentikasi:** Endpoint REST FastAPI dengan autentikasi Bearer JWT (`PyJWT==2.13.0`) dan password hashing PBKDF2-HMAC-SHA256 (`cryptography==49.0.0` / `hashlib`).
3. **Authorization Service Berbasis RBAC & Document ACL:** *Deny-by-default* engine yang mengevaluasi `(user.role, user.user_id, user.is_active)` terhadap matriks izin operasi dan ACL tiap dokumen (`allowed_roles`, `allowed_users`, `scope`).
4. **Document Ingestion Pipeline:** Validasi ekstensi, ukuran maksimum, magic bytes/struktur file, perhitungan hash `SHA-256` untuk idempotency, penyimpanan terisolasi, dan pencatatan status (`PENDING` -> `PROCESSING` -> `INDEXED` / `FAILED` / `DELETED`).
5. **Parser PDF, DOCX, XLSX, dan CSV:**
   - **PDF (`pypdf`):** Ekstraksi per halaman (`page_number`). Menolak file PDF kosong/scan gambar tanpa teks dengan status yang jujur karena OCR binary tidak diaktifkan.
   - **DOCX (`python-docx`):** Ekstraksi paragraf dan tabel dengan `section_label`.
   - **XLSX (`openpyxl`) & CSV (`csv`):** Mempertahankan `sheet_name`, nama kolom header, tipe nilai, serta rentang `row_start`–`row_end`.
6. **Text Cleaning, Chunking, Metadata Extraction, dan Indexing:** Pembersihan karakter kontrol, deteksi dini pola *indirect prompt injection* pada teks dokumen, dan pemotongan chunk dengan ukuran (`CHUNK_SIZE_CHARS`) dan overlap (`CHUNK_OVERLAP_CHARS`) terkonfigurasi.
7. **Embedding Model Abstraction:** Antarmuka `EmbeddingProvider` dengan implementasi `LocalDeterministicEmbeddingProvider` (berbasis *signed feature hashing* kata & karakter n-gram ter-normalisasi L2 yang mendukung kemiripan kosinus kata/parafrase bahasa Indonesia & Inggris) serta konektor OpenAI/Gemini opsional.
8. **Vector Database (`QdrantVectorManager`):** Menyimpan vektor embedding beserta payload wajib: `document_id`, `chunk_id`, `scope`, `allowed_roles`, `allowed_users`, `acl_version`, dan `ingestion_status`.
9. **Retrieval & Two-Stage Permission Filtering:**
   - *Tahap 1 (Pre-Retrieval):* Filter Qdrant wajib mencocokkan `ingestion_status == "INDEXED"` dan (`allowed_roles` mengandung `user.role` ATAU `allowed_users` mengandung `user.user_id`), serta melarang role `admin` mengambil dokumen bisnis kecuali diizinkan eksplisit di `allowed_users`.
   - *Tahap 2 (Post-Retrieval Re-Verification):* Setiap kandidat chunk dari Qdrant diperiksa ulang terhadap tabel `documents` dan `document_chunks` di SQLite untuk memastikan ACL belum dicabut dan dokumen belum dihapus sebelum dikirim ke LLM.
10. **LLM Provider Abstraction:** Mengisolasi konteks dokumen di dalam tag `<untrusted_document_context>` dengan instruksi sistem ketat yang melarang eksekusi instruksi dari dalam dokumen.
11. **Input Guardrails & Output Validation:** Memeriksa prompt injection, upaya lintas-role, serangan/pelecehan SARA (dengan analisis konteks agar diskusi kebijakan HR/demografi yang sah tidak terkena *false positive*), serta memvalidasi output agar tidak membocorkan system prompt atau secret.
12. **Citation & Evidence Validation:** Memverifikasi bahwa setiap klaim faktual dan perhitungan angka ditautkan ke `chunk_id` dan `document_id` yang benar-benar ada di himpunan `VerifiedChunkContext`.
13. **Audit Logging:** Mencatat setiap request, keputusan authz, keputusan guardrail, ID dokumen yang diakses, skor retrieval, latensi, dan perubahan role tanpa menyimpan password, token, atau isi mentah dokumen sensitif.
14. **Evaluation Pipeline & Monitoring:** Menjalankan test suite evaluasi terstruktur (termasuk faithfulness, citation accuracy, cross-role block rate, prompt injection block rate, dan false refusal rate).
15. **Relational Database (`SQLite`):** Menyimpan tabel `users`, `role_change_audits`, `documents`, `document_chunks`, `chat_sessions`, `chat_messages`, dan `audit_logs`.
16. **Synchronous/Background Task Handling:** Eksekusi ingestion dan evaluasi dengan pelacakan status transaksional yang aman.
