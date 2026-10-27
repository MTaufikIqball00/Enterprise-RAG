use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Employee,
    Hr,
    Finance,
    Executive,
    Admin,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Employee => "employee",
            UserRole::Hr => "hr",
            UserRole::Finance => "finance",
            UserRole::Executive => "executive",
            UserRole::Admin => "admin",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "employee" => Some(UserRole::Employee),
            "hr" => Some(UserRole::Hr),
            "finance" => Some(UserRole::Finance),
            "executive" => Some(UserRole::Executive),
            "admin" => Some(UserRole::Admin),
            _ => None,
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentScope {
    General,
    Hr,
    Finance,
    Executive,
}

impl DocumentScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocumentScope::General => "general",
            DocumentScope::Hr => "hr",
            DocumentScope::Finance => "finance",
            DocumentScope::Executive => "executive",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "general" => Some(DocumentScope::General),
            "hr" => Some(DocumentScope::Hr),
            "finance" => Some(DocumentScope::Finance),
            "executive" => Some(DocumentScope::Executive),
            _ => None,
        }
    }
}

impl std::fmt::Display for DocumentScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedFileType {
    Pdf,
    Docx,
    Xlsx,
    Csv,
}

impl SupportedFileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SupportedFileType::Pdf => "pdf",
            SupportedFileType::Docx => "docx",
            SupportedFileType::Xlsx => "xlsx",
            SupportedFileType::Csv => "csv",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pdf" => Some(SupportedFileType::Pdf),
            "docx" => Some(SupportedFileType::Docx),
            "xlsx" => Some(SupportedFileType::Xlsx),
            "csv" => Some(SupportedFileType::Csv),
            _ => None,
        }
    }
}

impl std::fmt::Display for SupportedFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IngestionStatus {
    Processing,
    Indexed,
    Failed,
    Deleted,
}

impl IngestionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            IngestionStatus::Processing => "PROCESSING",
            IngestionStatus::Indexed => "INDEXED",
            IngestionStatus::Failed => "FAILED",
            IngestionStatus::Deleted => "DELETED",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "PROCESSING" => Some(IngestionStatus::Processing),
            "INDEXED" => Some(IngestionStatus::Indexed),
            "FAILED" => Some(IngestionStatus::Failed),
            "DELETED" => Some(IngestionStatus::Deleted),
            _ => None,
        }
    }
}

impl std::fmt::Display for IngestionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StatementClassification {
    #[serde(rename = "FAKTA_SUMBER")]
    SourceFact,
    #[serde(rename = "PERHITUNGAN_DATA_SUMBER")]
    ComputedFromSource,
    #[serde(rename = "INFERENSI_TERBATAS")]
    PermittedInference,
    #[serde(rename = "INFORMASI_TIDAK_TERSEDIA")]
    InsufficientEvidence,
}

impl StatementClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatementClassification::SourceFact => "FAKTA_SUMBER",
            StatementClassification::ComputedFromSource => "PERHITUNGAN_DATA_SUMBER",
            StatementClassification::PermittedInference => "INFERENSI_TERBATAS",
            StatementClassification::InsufficientEvidence => "INFORMASI_TIDAK_TERSEDIA",
        }
    }
}

impl std::fmt::Display for StatementClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardrailStage {
    Input,
    Retrieval,
    ToolExecution,
    Output,
}

impl GuardrailStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardrailStage::Input => "INPUT",
            GuardrailStage::Retrieval => "RETRIEVAL",
            GuardrailStage::ToolExecution => "TOOL_EXECUTION",
            GuardrailStage::Output => "OUTPUT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardrailDecisionType {
    Allow,
    Block,
    Redact,
}

impl GuardrailDecisionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GuardrailDecisionType::Allow => "ALLOW",
            GuardrailDecisionType::Block => "BLOCK",
            GuardrailDecisionType::Redact => "REDACT",
        }
    }
}
