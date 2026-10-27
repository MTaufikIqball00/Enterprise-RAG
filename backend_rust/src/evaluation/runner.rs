use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::core::enums::{GuardrailDecisionType, StatementClassification};
use crate::rag::service::EnterpriseRAGService;
use crate::schemas::architecture::AuthenticatedPrincipal;

#[derive(Debug, Clone)]
pub struct EvaluationTestCase {
    pub case_id: String,
    pub category: String,
    pub description: String,
    pub principal: AuthenticatedPrincipal,
    pub question: String,
    pub expected_classification: StatementClassification,
    pub expected_blocked_by_guardrail: bool,
    pub expected_substrings_in_answer: Vec<String>,
    pub forbidden_substrings_in_answer: Vec<String>,
    pub require_valid_citation: bool,
    pub expect_source_conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationCaseResult {
    pub case_id: String,
    pub category: String,
    pub passed: bool,
    pub observed_classification: String,
    pub blocked_by_guardrail: bool,
    pub citation_count: usize,
    pub has_source_conflict: bool,
    pub faithfulness_score: f64,
    pub citation_precision: f64,
    pub failure_reasons: Vec<String>,
    pub answer_preview: String,
}

pub struct RAGEvaluationRunner {
    pub rag_service: Arc<EnterpriseRAGService>,
}

impl RAGEvaluationRunner {
    pub fn new(rag_service: Arc<EnterpriseRAGService>) -> Self {
        Self { rag_service }
    }

    pub async fn run_case(&self, pool: &SqlitePool, case: &EvaluationTestCase) -> EvaluationCaseResult {
        let resp = match self
            .rag_service
            .query(pool, &case.principal, &case.question, None, false)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return EvaluationCaseResult {
                    case_id: case.case_id.clone(),
                    category: case.category.clone(),
                    passed: false,
                    observed_classification: "ERROR".to_string(),
                    blocked_by_guardrail: false,
                    citation_count: 0,
                    has_source_conflict: false,
                    faithfulness_score: 0.0,
                    citation_precision: 0.0,
                    failure_reasons: vec![format!("Query execution failed: {}", e)],
                    answer_preview: String::new(),
                };
            }
        };

        let mut failures = Vec::new();
        let was_blocked = resp.guardrail_decisions.iter().any(|g| g.decision == GuardrailDecisionType::Block);

        if was_blocked != case.expected_blocked_by_guardrail {
            failures.push(format!(
                "Expected blocked={}, observed blocked={}",
                case.expected_blocked_by_guardrail, was_blocked
            ));
        }

        if resp.overall_classification != case.expected_classification {
            failures.push(format!(
                "Expected classification={}, observed={}",
                case.expected_classification.as_str(),
                resp.overall_classification.as_str()
            ));
        }

        let lower_ans = resp.answer.to_lowercase();
        for req_sub in &case.expected_substrings_in_answer {
            if !lower_ans.contains(&req_sub.to_lowercase()) {
                failures.push(format!("Missing expected substring: '{}'", req_sub));
            }
        }

        for forb_sub in &case.forbidden_substrings_in_answer {
            if lower_ans.contains(&forb_sub.to_lowercase()) {
                failures.push(format!("CRITICAL LEAKAGE: Forbidden substring found in answer: '{}'", forb_sub));
            }
        }

        if case.require_valid_citation && resp.citations.is_empty() {
            failures.push("Expected at least 1 valid citation, but got 0".to_string());
        }
        if !case.require_valid_citation && !resp.citations.is_empty() {
            failures.push(format!("Expected 0 citations for refusal/no-evidence, got {}", resp.citations.len()));
        }

        if case.expect_source_conflict != resp.has_source_conflict {
            failures.push(format!(
                "Expected has_source_conflict={}, observed={}",
                case.expect_source_conflict, resp.has_source_conflict
            ));
        }

        let citation_precision = if !resp.citations.is_empty() {
            let valid = resp.citations.iter().filter(|c| !c.document_id.is_empty() && !c.chunk_id.is_empty() && !c.excerpt.is_empty()).count();
            valid as f64 / resp.citations.len() as f64
        } else if !case.require_valid_citation {
            1.0
        } else {
            0.0
        };

        let factual_claims: Vec<_> = resp.claims.iter().filter(|cl| {
            matches!(
                cl.classification,
                StatementClassification::SourceFact
                    | StatementClassification::ComputedFromSource
                    | StatementClassification::PermittedInference
            )
        }).collect();

        let faithfulness = if !factual_claims.is_empty() {
            let grounded = factual_claims.iter().filter(|cl| !cl.supporting_chunk_ids.is_empty()).count();
            grounded as f64 / factual_claims.len() as f64
        } else if !case.require_valid_citation {
            1.0
        } else {
            0.0
        };

        let preview: String = resp.answer.chars().take(240).collect();

        EvaluationCaseResult {
            case_id: case.case_id.clone(),
            category: case.category.clone(),
            passed: failures.is_empty(),
            observed_classification: resp.overall_classification.as_str().to_string(),
            blocked_by_guardrail: was_blocked,
            citation_count: resp.citations.len(),
            has_source_conflict: resp.has_source_conflict,
            faithfulness_score: (faithfulness * 10000.0).round() / 10000.0,
            citation_precision: (citation_precision * 10000.0).round() / 10000.0,
            failure_reasons: failures,
            answer_preview: preview,
        }
    }

    pub async fn run_suite(&self, pool: &SqlitePool, cases: &[EvaluationTestCase]) -> serde_json::Value {
        let mut results = Vec::new();
        for case in cases {
            let res = self.run_case(pool, case).await;
            results.push(res);
        }

        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let pass_rate = if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 };

        let avg_faithfulness: f64 = if total > 0 {
            results.iter().map(|r| r.faithfulness_score).sum::<f64>() / total as f64
        } else {
            0.0
        };

        let avg_precision: f64 = if total > 0 {
            results.iter().map(|r| r.citation_precision).sum::<f64>() / total as f64
        } else {
            0.0
        };

        serde_json::json!({
            "summary": {
                "total_cases": total,
                "passed_cases": passed,
                "failed_cases": total - passed,
                "pass_rate_percent": (pass_rate * 100.0).round() / 100.0,
                "average_faithfulness": (avg_faithfulness * 10000.0).round() / 10000.0,
                "average_citation_precision": (avg_precision * 10000.0).round() / 10000.0,
            },
            "cases": results,
        })
    }
}
