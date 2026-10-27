use regex::{Regex, RegexBuilder};
use std::sync::LazyLock;

use crate::core::enums::{GuardrailDecisionType, GuardrailStage};
use crate::schemas::architecture::{GuardrailDecision, VerifiedChunkContext};

pub const UNIFORM_SAFE_REFUSAL_MESSAGE: &str =
    "Permintaan tidak dapat diproses karena melanggar kebijakan keamanan atau berada di luar cakupan penggunaan asisten internal perusahaan yang diizinkan.";

pub const UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE: &str =
    "Informasi tidak ditemukan atau bukti pada dokumen yang dapat Anda akses tidak cukup untuk menjawab pertanyaan ini.";

struct PatternEntry {
    name: &'static str,
    regex: Regex,
}

static INPUT_INJECTION_PATTERNS: LazyLock<Vec<PatternEntry>> = LazyLock::new(|| {
    vec![
        PatternEntry {
            name: "ignore_instructions_en",
            regex: RegexBuilder::new(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
        PatternEntry {
            name: "ignore_instructions_id",
            regex: RegexBuilder::new(r"abaikan\s+(semua\s+)?(instruksi|aturan)\s+(sebelumnya|sistem)")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
        PatternEntry {
            name: "system_prompt_leak",
            regex: RegexBuilder::new(
                r"(reveal|show|print|tampilkan|bocorkan)\s+(your\s+)?(system\s+prompt|instruksi\s+sistem|api\s*key|secret\s*key|jwt_secret)",
            )
            .case_insensitive(true)
            .build()
            .unwrap(),
        },
        PatternEntry {
            name: "role_spoofing_id",
            regex: RegexBuilder::new(
                r"(anggap|berpura-puralah|ubah)\s+(saya|role\s+saya)\s+(adalah|menjadi)\s+(finance|executive|admin|hr|direktur)",
            )
            .case_insensitive(true)
            .build()
            .unwrap(),
        },
        PatternEntry {
            name: "role_spoofing_en",
            regex: RegexBuilder::new(
                r"(pretend|assume|act\s+as\s+if)\s+(i\s+am|my\s+role\s+is)\s+(finance|executive|admin|hr)",
            )
            .case_insensitive(true)
            .build()
            .unwrap(),
        },
        PatternEntry {
            name: "acl_bypass",
            regex: RegexBuilder::new(r"(bypass|matikan|lewati)\s+(rbac|acl|otorisasi|permission\s+filter)")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
    ]
});

static DANGEROUS_EXECUTION_PATTERNS: LazyLock<Vec<PatternEntry>> = LazyLock::new(|| {
    vec![
        PatternEntry {
            name: "sql_drop_delete",
            regex: RegexBuilder::new(r"\b(DROP\s+TABLE|DELETE\s+FROM\s+users|UNION\s+SELECT\s+password_hash)\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
        PatternEntry {
            name: "shell_exec",
            regex: RegexBuilder::new(r"\b(rm\s+-rf|powershell\s+-enc|cmd\.exe\s+/c|os\.system\(|subprocess\.Popen)\b")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
    ]
});

static IDENTITY_GROUP_TERMS: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(
        r"\b(suku|agama|ras|etnis|antar\s*golongan|sara|muslim|kristen|katolik|hindu|buddha|konghucu|tionghoa|jawa|sunda|papua|batak|dayak|melayu|perempuan|wanita|pria|gender|disabilitas)\b",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});

static HARASSMENT_OR_ATTACK_INTENT: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(
        r"\b(bodoh|malas|rendahan|sampah|hina|usir|pecat\s+semua|larang\s+melamar|tidak\s+pantas\s+bekerja|lebih\s+rendah|penjahat|parasit|diskriminasi\s+terhadap|serang|benci|musnahkan)\b",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});

static UNTRUSTED_DOC_DANGEROUS_LINES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        RegexBuilder::new(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions.*")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"abaikan\s+(semua\s+)?instruksi\s+(sebelumnya|sistem).*")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"system\s*prompt\s*override.*")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"grant\s+admin\s+access.*")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"execute\s+(sql|shell|bash|cmd|tool).*")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>")
            .case_insensitive(true)
            .build()
            .unwrap(),
    ]
});

static OUTPUT_LEAK_PATTERNS: LazyLock<Vec<PatternEntry>> = LazyLock::new(|| {
    vec![
        PatternEntry {
            name: "pbkdf2_hash_leak",
            regex: RegexBuilder::new(r"pbkdf2_sha256\$\d+\$[a-f0-9]+\$[a-f0-9]+")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
        PatternEntry {
            name: "openai_key_leak",
            regex: Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        },
        PatternEntry {
            name: "jwt_secret_leak",
            regex: RegexBuilder::new(r"JWT_SECRET_KEY\s*=\s*['\x22]?[A-Za-z0-9_\-]{16,}")
                .case_insensitive(true)
                .build()
                .unwrap(),
        },
        PatternEntry {
            name: "internal_system_marker",
            regex: Regex::new(r"\[INTERNAL_SYSTEM_PROMPT_CONFIDENTIAL_MARKER\]").unwrap(),
        },
    ]
});

pub struct GuardrailsEngine;

impl GuardrailsEngine {
    pub fn check_input(user_query: &str) -> GuardrailDecision {
        let text = user_query.trim();
        if text.is_empty() {
            return GuardrailDecision {
                stage: GuardrailStage::Input,
                decision: GuardrailDecisionType::Block,
                rule_id: "INP-000".to_string(),
                reason: "Pertanyaan tidak boleh kosong.".to_string(),
                triggered_patterns: vec!["empty_query".to_string()],
            };
        }

        // 1. Check prompt injection & role spoofing
        let triggered_inj: Vec<String> = INPUT_INJECTION_PATTERNS
            .iter()
            .filter(|p| p.regex.is_match(text))
            .map(|p| p.name.to_string())
            .collect();

        if !triggered_inj.is_empty() {
            return GuardrailDecision {
                stage: GuardrailStage::Input,
                decision: GuardrailDecisionType::Block,
                rule_id: "INP-001".to_string(),
                reason: "Terdeteksi upaya prompt injection, ekstraksi konfigurasi sistem, atau manipulasi role/otorisasi.".to_string(),
                triggered_patterns: triggered_inj,
            };
        }

        // 2. Check dangerous command / SQL execution
        let triggered_exec: Vec<String> = DANGEROUS_EXECUTION_PATTERNS
            .iter()
            .filter(|p| p.regex.is_match(text))
            .map(|p| p.name.to_string())
            .collect();

        if !triggered_exec.is_empty() {
            return GuardrailDecision {
                stage: GuardrailStage::Input,
                decision: GuardrailDecisionType::Block,
                rule_id: "INP-002".to_string(),
                reason: "Terdeteksi instruksi eksekusi kode/SQL berbahaya di luar cakupan asisten.".to_string(),
                triggered_patterns: triggered_exec,
            };
        }

        // 3. Contextual SARA evaluation
        let has_identity = IDENTITY_GROUP_TERMS.is_match(text);
        let has_attack = HARASSMENT_OR_ATTACK_INTENT.is_match(text);

        if has_identity && has_attack {
            return GuardrailDecision {
                stage: GuardrailStage::Input,
                decision: GuardrailDecisionType::Block,
                rule_id: "INP-003".to_string(),
                reason: "Diblokir oleh kebijakan konten: permintaan mengandung pelecehan, ujaran kebencian, atau serangan berbasis SARA.".to_string(),
                triggered_patterns: vec!["sara_harassment_intent".to_string()],
            };
        }

        if has_identity && !has_attack {
            return GuardrailDecision {
                stage: GuardrailStage::Input,
                decision: GuardrailDecisionType::Allow,
                rule_id: "INP-003-CTX-ALLOW".to_string(),
                reason: "Penyebutan kelompok identitas dalam konteks kebijakan/diskusi sah diizinkan.".to_string(),
                triggered_patterns: vec![],
            };
        }

        GuardrailDecision {
            stage: GuardrailStage::Input,
            decision: GuardrailDecisionType::Allow,
            rule_id: "INP-PASS".to_string(),
            reason: "Input lolos pemeriksaan keamanan.".to_string(),
            triggered_patterns: vec![],
        }
    }

    pub fn sanitize_retrieved_chunks(
        verified_chunks: Vec<VerifiedChunkContext>,
    ) -> (Vec<VerifiedChunkContext>, GuardrailDecision) {
        let mut sanitized_list = Vec::new();
        let mut redacted_chunk_ids = Vec::new();

        for chunk in verified_chunks {
            let mut clean_lines = Vec::new();
            let mut modified = false;

            for line in chunk.text_content.lines() {
                if UNTRUSTED_DOC_DANGEROUS_LINES.iter().any(|p| p.is_match(line)) {
                    modified = true;
                    clean_lines.push("[REDACTED_UNTRUSTED_DOCUMENT_INSTRUCTION]");
                } else {
                    clean_lines.push(line);
                }
            }

            if modified {
                redacted_chunk_ids.push(chunk.chunk_id.clone());
                sanitized_list.push(VerifiedChunkContext {
                    chunk_id: chunk.chunk_id,
                    document_id: chunk.document_id,
                    text_content: clean_lines.join("\n"),
                    relevance_score: chunk.relevance_score,
                    provenance: chunk.provenance,
                    acl_verified_at: chunk.acl_verified_at,
                });
            } else {
                sanitized_list.push(chunk);
            }
        }

        if !redacted_chunk_ids.is_empty() {
            (
                sanitized_list,
                GuardrailDecision {
                    stage: GuardrailStage::Retrieval,
                    decision: GuardrailDecisionType::Redact,
                    rule_id: "RET-001".to_string(),
                    reason: "Instruksi mencurigakan di dalam dokumen tidak tepercaya telah dinetralkan (indirect prompt injection mitigation).".to_string(),
                    triggered_patterns: redacted_chunk_ids,
                },
            )
        } else {
            (
                sanitized_list,
                GuardrailDecision {
                    stage: GuardrailStage::Retrieval,
                    decision: GuardrailDecisionType::Allow,
                    rule_id: "RET-PASS".to_string(),
                    reason: "Konteks dokumen terverifikasi aman.".to_string(),
                    triggered_patterns: vec![],
                },
            )
        }
    }

    pub fn validate_tool_execution(tool_name: &str, source_is_document: bool) -> GuardrailDecision {
        if source_is_document {
            return GuardrailDecision {
                stage: GuardrailStage::ToolExecution,
                decision: GuardrailDecisionType::Block,
                rule_id: "TOOL-001".to_string(),
                reason: "Dilarang mengeksekusi tool call, SQL, atau URL yang berasal dari isi dokumen tidak tepercaya.".to_string(),
                triggered_patterns: vec![tool_name.to_string()],
            };
        }
        if tool_name != "safe_arithmetic_Aggregator" {
            return GuardrailDecision {
                stage: GuardrailStage::ToolExecution,
                decision: GuardrailDecisionType::Block,
                rule_id: "TOOL-002".to_string(),
                reason: format!("Tool '{}' tidak terdaftar dalam daftar putih keamanan.", tool_name),
                triggered_patterns: vec![tool_name.to_string()],
            };
        }
        GuardrailDecision {
            stage: GuardrailStage::ToolExecution,
            decision: GuardrailDecisionType::Allow,
            rule_id: "TOOL-PASS".to_string(),
            reason: "Eksekusi kalkulasi internal terverifikasi aman.".to_string(),
            triggered_patterns: vec![],
        }
    }

    pub fn validate_output(generated_text: &str) -> (String, GuardrailDecision) {
        let triggered: Vec<String> = OUTPUT_LEAK_PATTERNS
            .iter()
            .filter(|p| p.regex.is_match(generated_text))
            .map(|p| p.name.to_string())
            .collect();

        if !triggered.is_empty() {
            (
                UNIFORM_SAFE_REFUSAL_MESSAGE.to_string(),
                GuardrailDecision {
                    stage: GuardrailStage::Output,
                    decision: GuardrailDecisionType::Block,
                    rule_id: "OUT-001".to_string(),
                    reason: "Output diblokir karena terdeteksi pola sensitif (kredensial/hash/system prompt).".to_string(),
                    triggered_patterns: triggered,
                },
            )
        } else {
            (
                generated_text.to_string(),
                GuardrailDecision {
                    stage: GuardrailStage::Output,
                    decision: GuardrailDecisionType::Allow,
                    rule_id: "OUT-PASS".to_string(),
                    reason: "Output lolos validasi keamanan.".to_string(),
                    triggered_patterns: vec![],
                },
            )
        }
    }
}
