use async_trait::async_trait;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use tracing::warn;

use crate::core::config::Settings;

pub static SEMANTIC_SYNONYM_MAP: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
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
        "string",
        "integer",
        "float",
        "boolean",
        "sheet",
        "kolom",
        "header",
        "baris",
        "csv",
        "synthetic",
        "fixture",
        "rows",
        "page",
        "part",
        "apa",
        "apakah",
        "berapa",
        "bagaimana",
        "yang",
        "dan",
        "untuk",
        "pada",
        "di",
        "dari",
    ]
    .into_iter()
    .collect()
});

static COMPOUND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9_]+").unwrap());
static SUB_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());

#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    fn provider_name(&self) -> &str;
    fn model_name(&self) -> &str;
    fn dimension(&self) -> usize;
    async fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, anyhow::Error>;
    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, anyhow::Error>;
}

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
            hasher
                .finalize_variable(&mut digest)
                .expect("digest size matches");

            let bucket_raw = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
            let bucket = (bucket_raw as usize) % self.dimension;
            let sign = if (digest[4] & 1) == 0 {
                1.0f32
            } else {
                -1.0f32
            };
            vec[bucket] += sign * weight;
        }

        l2_normalize(vec)
    }

    pub fn embed_texts_sync(&self, texts: &[String]) -> Vec<Vec<f32>> {
        texts.iter().map(|t| self.embed_single(t)).collect()
    }
}

fn l2_normalize(mut vec: Vec<f32>) -> Vec<f32> {
    let sum_sq: f32 = vec.iter().map(|v| v * v).sum();
    let norm = sum_sq.sqrt();
    if norm > 1e-9 {
        for v in &mut vec {
            *v /= norm;
        }
    } else if !vec.is_empty() {
        vec[0] = 1.0;
    }
    vec
}

#[async_trait]
impl EmbeddingProvider for LocalDeterministicEmbeddingProvider {
    fn provider_name(&self) -> &str {
        "local_deterministic"
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    async fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, anyhow::Error> {
        Ok(self.embed_texts_sync(texts))
    }

    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, anyhow::Error> {
        Ok(self.embed_single(query))
    }
}

// ============================================================================
// OpenAI HTTP Embedding Provider
// ============================================================================

pub struct OpenAIEmbeddingProvider {
    client: reqwest::Client,
    api_key: String,
    model_name: String,
    dimension: usize,
}

#[derive(Serialize)]
struct OpenAIEmbedRequest<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Deserialize)]
struct OpenAIEmbedResponse {
    data: Vec<OpenAIEmbedData>,
}

#[derive(Deserialize)]
struct OpenAIEmbedData {
    embedding: Vec<f32>,
}

impl OpenAIEmbeddingProvider {
    pub fn new(api_key: String, model_name: String, dimension: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            client,
            api_key,
            model_name,
            dimension,
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAIEmbeddingProvider {
    fn provider_name(&self) -> &str {
        "openai"
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    async fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, anyhow::Error> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        let resp = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(&self.api_key)
            .json(&OpenAIEmbedRequest {
                model: &self.model_name,
                input: texts,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<OpenAIEmbedResponse>()
            .await?;

        Ok(resp
            .data
            .into_iter()
            .map(|d| l2_normalize(d.embedding))
            .collect())
    }

    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, anyhow::Error> {
        let mut res = self.embed_texts(&[query.to_string()]).await?;
        res.pop()
            .ok_or_else(|| anyhow::anyhow!("OpenAI embeddings returned empty vector"))
    }
}

// ============================================================================
// Gemini HTTP Embedding Provider
// ============================================================================

pub struct GeminiEmbeddingProvider {
    client: reqwest::Client,
    api_key: String,
    model_name: String,
    dimension: usize,
}

#[derive(Deserialize)]
struct GeminiEmbedResponse {
    embedding: GeminiEmbeddingValues,
}

#[derive(Deserialize)]
struct GeminiEmbeddingValues {
    values: Vec<f32>,
}

impl GeminiEmbeddingProvider {
    pub fn new(api_key: String, model_name: String, dimension: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            client,
            api_key,
            model_name,
            dimension,
        }
    }

    async fn embed_one(&self, text: &str) -> Result<Vec<f32>, anyhow::Error> {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:embedContent?key={}",
            self.model_name, self.api_key
        );
        let body = serde_json::json!({
            "content": {
                "parts": [{ "text": text }]
            }
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<GeminiEmbedResponse>()
            .await?;

        Ok(l2_normalize(resp.embedding.values))
    }
}

#[async_trait]
impl EmbeddingProvider for GeminiEmbeddingProvider {
    fn provider_name(&self) -> &str {
        "gemini"
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    async fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, anyhow::Error> {
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            results.push(self.embed_one(text).await?);
        }
        Ok(results)
    }

    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, anyhow::Error> {
        self.embed_one(query).await
    }
}

pub fn build_embedding_provider(settings: &Settings) -> Arc<dyn EmbeddingProvider> {
    match settings.embedding_provider.to_lowercase().as_str() {
        "openai" if !settings.openai_api_key.trim().is_empty() => {
            let model = if settings.embedding_model_name.starts_with("local-") {
                "text-embedding-3-small".to_string()
            } else {
                settings.embedding_model_name.clone()
            };
            Arc::new(OpenAIEmbeddingProvider::new(
                settings.openai_api_key.clone(),
                model,
                settings.embedding_dimension,
            ))
        }
        "gemini" if !settings.gemini_api_key.trim().is_empty() => {
            let model = if settings.embedding_model_name.starts_with("local-") {
                "text-embedding-004".to_string()
            } else {
                settings.embedding_model_name.clone()
            };
            Arc::new(GeminiEmbeddingProvider::new(
                settings.gemini_api_key.clone(),
                model,
                settings.embedding_dimension,
            ))
        }
        other => {
            if other != "local_deterministic" {
                warn!(
                    "EMBEDDING_PROVIDER='{}' membutuhkan API key yang valid; fallback aman ke 'local_deterministic'.",
                    other
                );
            }
            Arc::new(LocalDeterministicEmbeddingProvider::new(
                settings.embedding_dimension,
                &settings.embedding_model_name,
            ))
        }
    }
}
