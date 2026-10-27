use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use regex::Regex;

pub static SEMANTIC_SYNONYM_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("gaji", "kompensasi_upah_salary");
    m.insert("upah", "kompensasi_upah_salary");
    m.insert("salary", "kompensasi_upah_salary");
    m.insert("payroll", "kompensasi_upah_salary");
    m.insert("laba", "keuntungan_profit_revenue");
    m.insert("keuntungan", "keuntungan_profit_revenue");
    m.insert("profit", "keuntungan_profit_revenue");
    m.insert("pendapatan", "keuntungan_profit_revenue");
    m.insert("revenue", "keuntungan_profit_revenue");
    m.insert("anggaran", "budget_keuangan_finance");
    m.insert("budget", "budget_keuangan_finance");
    m.insert("cuti", "izin_libur_leave");
    m.insert("leave", "izin_libur_leave");
    m.insert("karyawan", "pegawai_staf_employee");
    m.insert("pegawai", "pegawai_staf_employee");
    m.insert("employee", "pegawai_staf_employee");
    m
});

pub static BOILERPLATE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "string", "integer", "float", "boolean", "sheet", "kolom",
        "header", "baris", "csv", "synthetic", "fixture", "rows", "page", "part",
        "apa", "apakah", "berapa", "bagaimana", "yang", "dan", "untuk", "pada", "di", "dari",
    ]
    .into_iter()
    .collect()
});

static COMPOUND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9_]+").unwrap());
static SUB_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());

pub struct LocalDeterministicEmbeddingProvider {
    pub dimension: usize,
    pub model_name: String,
}

impl LocalDeterministicEmbeddingProvider {
    pub fn new(dimension: usize, model_name: &str) -> Self {
        Self {
            dimension,
            model_name: model_name.to_string(),
        }
    }

    fn extract_features(&self, text: &str) -> Vec<(String, f32)> {
        let lowered = text.to_lowercase();

        let compound_tokens: Vec<String> = COMPOUND_RE
            .find_iter(&lowered)
            .map(|m| m.as_str().to_string())
            .filter(|t| !BOILERPLATE.contains(t.as_str()))
            .collect();

        let sub_tokens: Vec<String> = SUB_RE
            .find_iter(&lowered)
            .map(|m| m.as_str().to_string())
            .filter(|t| !BOILERPLATE.contains(t.as_str()) && t.len() >= 2)
            .collect();

        let mut features: Vec<(String, f32)> = Vec::new();

        for tok in &compound_tokens {
            if tok.contains('_') {
                features.push((format!("cw:{}", tok), 3.0));
            }
        }

        for (idx, tok) in sub_tokens.iter().enumerate() {
            features.push((format!("w:{}", tok), 2.5));
            if let Some(canonical) = SEMANTIC_SYNONYM_MAP.get(tok.as_str()) {
                features.push((format!("c:{}", canonical), 3.5));
            }
            if idx + 1 < sub_tokens.len() {
                features.push((format!("bg:{}_{}", tok, sub_tokens[idx + 1]), 1.2));
            }
            if tok.len() >= 4 && tok.len() <= 10 {
                let chars: Vec<char> = tok.chars().collect();
                for i in 0..=(chars.len() - 4) {
                    let quad: String = chars[i..i + 4].iter().collect();
                    features.push((format!("cg:{}", quad), 0.3));
                }
            }
        }

        features
    }

    pub fn embed_single(&self, text: &str) -> Vec<f32> {
        let mut vec = vec![0.0f32; self.dimension];
        let features = self.extract_features(text);
        if features.is_empty() {
            vec[0] = 1.0;
            return vec;
        }

        for (feat, weight) in features {
            let mut hasher = Blake2bVar::new(8).expect("valid blake2b digest size");
            hasher.update(feat.as_bytes());
            let mut digest = [0u8; 8];
            hasher.finalize_variable(&mut digest).expect("digest size matches");

            let bucket_raw = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
            let bucket = (bucket_raw as usize) % self.dimension;
            let sign = if (digest[4] & 1) == 0 { 1.0f32 } else { -1.0f32 };
            vec[bucket] += sign * weight;
        }

        let sum_sq: f32 = vec.iter().map(|v| v * v).sum();
        let norm = sum_sq.sqrt();
        if norm > 1e-9 {
            for v in &mut vec {
                *v /= norm;
            }
        } else {
            vec[0] = 1.0;
        }
        vec
    }

    pub fn embed_texts(&self, texts: &[String]) -> Vec<Vec<f32>> {
        texts.iter().map(|t| self.embed_single(t)).collect()
    }

    pub fn embed_query(&self, query: &str) -> Vec<f32> {
        self.embed_single(query)
    }
}
