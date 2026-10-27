# Dokumentasi Guardrails, Audit, dan Evaluasi RAG (Tahap 6 & 7)

## 1. Aturan Guardrails Berlapis (`GuardrailsEngine`)
Implementasi kode: [`GuardrailsEngine`](file:///c:/Users/taufi/Documents/Projects/Enterprise%20RAG/backend/app/guardrails/engine.py#L72-L246).

| Rule ID | Stage | Kebijakan & Alasan Pemblokiran | Penanganan False Positive / False Negative | Mekanisme Pengujian |
| :--- | :---: | :--- | :--- | :--- |
| **INP-001** | `INPUT` | Memblokir *Prompt Injection*, upaya membocorkan *system prompt* / API key, serta upaya *role spoofing* ("anggap role saya finance"). | Hanya memicu blokir jika frasa perintah pembajakan instruksi atau klaim perubahan role eksplisit terdeteksi. Pertanyaan normal tentang prosedur otorisasi tetap diizinkan. | `test_input_guardrails_block_prompt_injection_role_spoofing_and_sql` di `tests/test_stage6_guardrails.py` |
| **INP-002** | `INPUT` | Memblokir upaya injeksi SQL destruktif (`DROP TABLE`, `UNION SELECT password_hash`) atau eksekusi command shell (`rm -rf`, `powershell -enc`). | Menggunakan pencocokan sintaks perintah eksekusi sistem/database. | `test_input_guardrails_block_prompt_injection_role_spoofing_and_sql` & `TC-07` di `tests/test_stage7_audit_evaluation.py` |
| **INP-003** & **INP-003-CTX-ALLOW** | `INPUT` | **Contextual SARA Policy:** Memblokir permintaan yang mengandung pelecehan, penghinaan, atau diskriminasi berbasis SARA (`INP-003`), namun **MENGIZINKAN** diskusi perusahaan/HR yang sah yang menyebut kelompok agama, suku, gender, atau disabilitas (`INP-003-CTX-ALLOW`). | *Mitigasi False Positive:* Penyebutan istilah identitas (`agama`, `suku`, `muslim`, `kristen`, `gender`, `disabilitas`) **tidak** langsung diblokir kecuali berpasangan dengan intensi serangan/pelecehan/diskriminasi. *Catatan False Negative:* Serangan implisit menggunakan bahasa sandi/metafora baru di luar pola leksikal perlu diperbarui secara berkala. | `test_contextual_sara_blocks_harassment_but_allows_legitimate_policy_discussion` di `tests/test_stage6_guardrails.py` & `TC-11` |
| **RET-001** | `RETRIEVAL` | **Indirect Prompt Injection Mitigation:** Menetralkan baris instruksi berbahaya di dalam teks dokumen tidak tepercaya menjadi `[REDACTED_UNTRUSTED_DOCUMENT_INSTRUCTION]` sebelum dikirim ke LLM, sambil mempertahankan baris data faktual lainnya. | Hanya baris yang mengandung pola pembajakan instruksi yang diredaksi; baris tabel/fakta di sekitarnya tetap utuh. | `test_retrieval_indirect_prompt_injection_sanitization_and_tool_guardrail` di `tests/test_stage6_guardrails.py` |
| **TOOL-001** & **TOOL-002** | `TOOL_EXECUTION` | Melarang keras eksekusi tool, SQL, atau URL yang dipicu dari isi dokumen tidak tepercaya (`source_is_document=True`). | Daftar putih (*allowlist*) ketat. | `test_retrieval_indirect_prompt_injection_sanitization_and_tool_guardrail` |
| **OUT-001** | `OUTPUT` | Memvalidasi respons sebelum dikirim ke klien agar tidak pernah membocorkan hash password (`pbkdf2_sha256$...`), API key (`sk-...`), atau penanda internal sistem. | Mengganti output yang bocor dengan `UNIFORM_SAFE_REFUSAL_MESSAGE`. | `test_output_guardrail_blocks_secret_and_hash_leaks` di `tests/test_stage6_guardrails.py` |

---

## 2. Pencegahan Existence Oracle pada Pesan Penolakan
- Apabila pengguna dengan role `employee` atau `admin` menanyakan isi dokumen `finance`, sistem **tidak** pernah menjawab *"Dokumen `synthetic_finance_q4.xlsx` bersifat rahasia untuk role Anda"*.
- Sebaliknya, karena chunk dokumen tersebut sudah disaring pada **Pre-Retrieval Filter** dan **Post-Retrieval Re-Verification**, sistem mengembalikan pesan seragam:
  > *"Informasi tidak ditemukan atau bukti pada dokumen yang dapat Anda akses tidak cukup untuk menjawab pertanyaan ini."*

---

## 3. Baseline, Threshold, dan Metrik Evaluasi (`RAGEvaluationRunner`)
Implementasi kode: [`RAGEvaluationRunner`](file:///c:/Users/taufi/Documents/Projects/Enterprise%20RAG/backend/app/evaluation/runner.py#L44-L148).

Metrik yang dihitung secara deterministik dan diverifikasi dengan *ground-truth assertion*:
1. **Faithfulness / Groundedness Score (Threshold = `1.00`):** Proporsi klaim faktual (`FAKTA_SUMBER`, `PERHITUNGAN_DATA_SUMBER`, `INFERENSI_TERBATAS`) yang memiliki referensi `supporting_chunk_ids` valid dari dokumen terotorisasi.
2. **Citation Precision (Threshold = `1.00`):** Proporsi sitasi yang merujuk pada `document_id`, `chunk_id`, halaman/sheet/baris, dan kutipan teks yang benar-benar ada pada sumber.
3. **Cross-Role Isolation Rate (Threshold = `1.00`):** `100%` pengujian lintas role wajib menghasilkan `0` kebocoran angka/kata kunci terlarang dan `0` sitasi ke dokumen terlarang.
4. **Benchmark Pass Rate across 11 Categories:** Diuji secara otomatis pada [`test_full_11_category_evaluation_dataset_suite`](file:///c:/Users/taufi/Documents/Projects/Enterprise%20RAG/tests/test_stage7_audit_evaluation.py#L106-L326).
