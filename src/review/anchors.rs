use crate::{gitlab::types::MergeRequestDiff, redaction::redact_secrets};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AnchorLineKind {
    Added,
    Removed,
    Context,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewLineAnchor {
    pub anchor_id: String,
    pub file_path: String,
    pub old_path: String,
    pub new_path: String,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
    pub kind: AnchorLineKind,
    pub content_preview: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnchoredDiffContext {
    pub anchors: Vec<ReviewLineAnchor>,
    pub prompt_text: String,
    pub total_anchors: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AnchorBuilder {
    anchors: Vec<ReviewLineAnchor>,
    prompt_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HunkHeader {
    old_start: u32,
    new_start: u32,
}

impl AnchorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_diff(&mut self, diff: &MergeRequestDiff) {
        if diff.diff.trim().is_empty() {
            return;
        }

        let mut file_lines = Vec::new();
        let mut old_line = 0;
        let mut new_line = 0;
        let mut in_hunk = false;

        for line in diff.diff.lines() {
            if let Some(header) = parse_hunk_header(line) {
                old_line = header.old_start;
                new_line = header.new_start;
                in_hunk = true;
                continue;
            }

            if !in_hunk || line.starts_with("\\ No newline at end of file") {
                continue;
            }

            if let Some(content) = line.strip_prefix('+') {
                let anchor =
                    self.next_anchor(diff, None, Some(new_line), AnchorLineKind::Added, content);
                new_line += 1;
                file_lines.push(anchor_prompt_line(&anchor));
                self.anchors.push(anchor);
            } else if let Some(content) = line.strip_prefix('-') {
                let anchor =
                    self.next_anchor(diff, Some(old_line), None, AnchorLineKind::Removed, content);
                old_line += 1;
                file_lines.push(anchor_prompt_line(&anchor));
                self.anchors.push(anchor);
            } else if let Some(content) = line.strip_prefix(' ') {
                let anchor = self.next_anchor(
                    diff,
                    Some(old_line),
                    Some(new_line),
                    AnchorLineKind::Context,
                    content,
                );
                old_line += 1;
                new_line += 1;
                file_lines.push(anchor_prompt_line(&anchor));
                self.anchors.push(anchor);
            }
        }

        if file_lines.is_empty() {
            return;
        }

        if !self.prompt_text.is_empty() {
            self.prompt_text.push('\n');
        }
        self.prompt_text.push_str("File: ");
        self.prompt_text.push_str(&diff.new_path);
        if diff.renamed_file && diff.old_path != diff.new_path {
            self.prompt_text.push_str(" (renamed from ");
            self.prompt_text.push_str(&diff.old_path);
            self.prompt_text.push(')');
        }
        self.prompt_text.push_str("\n\n");
        self.prompt_text.push_str(&file_lines.join("\n"));
        self.prompt_text.push('\n');
    }

    pub fn finish(self, truncated: bool) -> AnchoredDiffContext {
        let total_anchors = self.anchors.len();
        AnchoredDiffContext {
            anchors: self.anchors,
            prompt_text: self.prompt_text,
            total_anchors,
            truncated,
        }
    }

    fn next_anchor(
        &self,
        diff: &MergeRequestDiff,
        old_line: Option<u32>,
        new_line: Option<u32>,
        kind: AnchorLineKind,
        content: &str,
    ) -> ReviewLineAnchor {
        ReviewLineAnchor {
            anchor_id: format!("A{:04}", self.anchors.len() + 1),
            file_path: anchor_file_path(diff, old_line, new_line).to_string(),
            old_path: diff.old_path.clone(),
            new_path: diff.new_path.clone(),
            old_line,
            new_line,
            kind,
            content_preview: sanitized_preview(content),
        }
    }
}

impl AnchoredDiffContext {
    pub fn anchor_map(&self) -> HashMap<&str, &ReviewLineAnchor> {
        self.anchors
            .iter()
            .map(|anchor| (anchor.anchor_id.as_str(), anchor))
            .collect()
    }

    pub fn get(&self, anchor_id: &str) -> Option<&ReviewLineAnchor> {
        let requested = anchor_id.trim();
        self.anchors
            .iter()
            .find(|anchor| anchor.anchor_id == requested)
    }
}

impl AnchorLineKind {
    pub fn display_lower(self) -> &'static str {
        match self {
            AnchorLineKind::Added => "added",
            AnchorLineKind::Removed => "removed",
            AnchorLineKind::Context => "context",
        }
    }
}

fn anchor_file_path(diff: &MergeRequestDiff, old_line: Option<u32>, new_line: Option<u32>) -> &str {
    if new_line.is_some() || old_line.is_none() {
        &diff.new_path
    } else {
        &diff.old_path
    }
}

fn anchor_prompt_line(anchor: &ReviewLineAnchor) -> String {
    format!(
        "[{}] new_line={} old_line={} kind={:<7} | {}",
        anchor.anchor_id,
        optional_line(anchor.new_line),
        optional_line(anchor.old_line),
        anchor.kind.display_lower(),
        anchor.content_preview
    )
}

fn optional_line(line: Option<u32>) -> String {
    line.map(|line| line.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn sanitized_preview(content: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 160;
    redact_secrets(content)
        .replace('\t', "    ")
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(MAX_PREVIEW_CHARS)
        .collect()
}

fn parse_hunk_header(line: &str) -> Option<HunkHeader> {
    let after_open = line.strip_prefix("@@")?;
    let end = after_open.find("@@")?;
    let header = &after_open[..end];
    let mut old_start = None;
    let mut new_start = None;

    for token in header.split_whitespace() {
        if token.starts_with('-') {
            old_start = parse_hunk_range_start(token, '-');
        } else if token.starts_with('+') {
            new_start = parse_hunk_range_start(token, '+');
        }
    }

    Some(HunkHeader {
        old_start: old_start?,
        new_start: new_start?,
    })
}

fn parse_hunk_range_start(token: &str, prefix: char) -> Option<u32> {
    let range = token.strip_prefix(prefix)?;
    let start = range.split_once(',').map_or(range, |(start, _)| start);
    start.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{AnchorBuilder, AnchorLineKind};
    use crate::gitlab::types::MergeRequestDiff;

    #[test]
    fn generates_anchors_for_added_removed_and_context_lines() {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff(
            "src/a.rs",
            "@@ -7,2 +8,3 @@\n context\n-removed\n+added",
        ));
        let anchored = builder.finish(false);

        assert_eq!(anchored.total_anchors, 3);
        assert_eq!(anchored.anchors[0].anchor_id, "A0001");
        assert_eq!(anchored.anchors[0].kind, AnchorLineKind::Context);
        assert_eq!(anchored.anchors[0].old_line, Some(7));
        assert_eq!(anchored.anchors[0].new_line, Some(8));
        assert_eq!(anchored.anchors[1].kind, AnchorLineKind::Removed);
        assert_eq!(anchored.anchors[1].old_line, Some(8));
        assert_eq!(anchored.anchors[1].new_line, None);
        assert_eq!(anchored.anchors[2].kind, AnchorLineKind::Added);
        assert_eq!(anchored.anchors[2].old_line, None);
        assert_eq!(anchored.anchors[2].new_line, Some(9));
    }

    #[test]
    fn prompt_text_uses_file_headings_and_anchor_lines() {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff(
            "src/paymentClient.ts",
            "@@ -8,1 +10,2 @@\n export async function chargeUser() {\n+Authorization: Bearer abc.def",
        ));
        let anchored = builder.finish(true);

        assert!(anchored.truncated);
        assert!(anchored.prompt_text.contains("File: src/paymentClient.ts"));
        assert!(anchored
            .prompt_text
            .contains("[A0001] new_line=10 old_line=8 kind=context"));
        assert!(anchored
            .prompt_text
            .contains("[A0002] new_line=11 old_line=- kind=added"));
        assert!(anchored.prompt_text.contains("[REDACTED_TOKEN]"));
    }

    #[test]
    fn anchor_ids_map_back_to_positions() {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff("src/a.rs", "@@ -0,0 +1 @@\n+new"));
        let anchored = builder.finish(false);

        let anchor = anchored.get("A0001").unwrap();
        assert_eq!(anchor.file_path, "src/a.rs");
        assert_eq!(anchor.new_line, Some(1));
    }

    fn diff(path: &str, body: &str) -> MergeRequestDiff {
        MergeRequestDiff {
            old_path: path.to_string(),
            new_path: path.to_string(),
            diff: body.to_string(),
            new_file: false,
            renamed_file: false,
            deleted_file: false,
            generated_file: None,
            collapsed: None,
            too_large: None,
        }
    }
}
