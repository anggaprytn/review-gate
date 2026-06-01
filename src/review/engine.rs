use crate::{
    error::Result,
    gitlab::context::MergeRequestContext,
    llm::types::{LlmReviewResponse, LlmRunMetadata},
    review::{
        formatter::{format_malformed_review_markdown, format_review_markdown},
        parser::parse_review_analysis,
        prompt::build_review_prompt,
        types::ReviewAnalysis,
    },
};
use std::future::Future;

#[derive(Debug, Clone)]
pub struct ReviewPreview {
    pub markdown: String,
    pub metadata: LlmRunMetadata,
    pub prompt_token_estimate: u64,
    pub parsed: bool,
    pub analysis: Option<ReviewAnalysis>,
}

pub fn build_sanitized_review_prompt(context: &MergeRequestContext) -> String {
    build_review_prompt(&context.metadata, &context.anchored_diff)
}

pub async fn review_prompt_with_llm<F, Fut>(prompt: String, call_llm: F) -> Result<ReviewPreview>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<LlmReviewResponse>>,
{
    let prompt_token_estimate = estimate_prompt_tokens(&prompt);
    let llm_response = call_llm(prompt).await?;

    let (markdown, parsed, analysis) = match parse_review_analysis(&llm_response.text) {
        Ok(analysis) => (format_review_markdown(&analysis), true, Some(analysis)),
        Err(err) => (
            format_malformed_review_markdown(&llm_response.text, &err),
            false,
            None,
        ),
    };

    Ok(ReviewPreview {
        markdown,
        metadata: llm_response.metadata,
        prompt_token_estimate,
        parsed,
        analysis,
    })
}

pub fn estimate_prompt_tokens(prompt: &str) -> u64 {
    prompt.chars().count().div_ceil(4) as u64
}

#[cfg(test)]
mod tests {
    use super::{estimate_prompt_tokens, review_prompt_with_llm};
    use crate::llm::types::{LlmReviewResponse, LlmRunMetadata};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn preview_calls_llm_through_mockable_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_in_closure = Arc::clone(&called);

        let preview =
            review_prompt_with_llm("review prompt".to_string(), move |prompt| async move {
                called_in_closure.store(true, Ordering::SeqCst);
                assert_eq!(prompt, "review prompt");
                Ok(LlmReviewResponse {
                    text: r#"{
                    "summary": "No material risks.",
                    "overall_risk": "low",
                    "findings": [],
                    "test_coverage_note": null,
                    "privacy_note": null
                }"#
                    .to_string(),
                    metadata: LlmRunMetadata {
                        prompt_eval_count: Some(3),
                        eval_count: Some(9),
                        ..LlmRunMetadata::default()
                    },
                })
            })
            .await
            .unwrap();

        assert!(called.load(Ordering::SeqCst));
        assert!(preview.parsed);
        assert!(preview.markdown.contains("No material risks."));
        assert_eq!(preview.metadata.eval_count, Some(9));
    }

    #[test]
    fn estimates_prompt_tokens_without_external_tokenizer() {
        assert_eq!(estimate_prompt_tokens("12345678"), 2);
        assert_eq!(estimate_prompt_tokens("12345"), 2);
    }
}
