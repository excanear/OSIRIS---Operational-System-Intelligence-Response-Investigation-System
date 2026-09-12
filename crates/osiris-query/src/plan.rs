use crate::ast::Ast;
use crate::fields::is_known_field;
use crate::parser::{parse, ParseError};

/// §19.2's default row cap for a non-export `EventQueryPlan`.
pub const DEFAULT_EVENT_LIMIT: usize = 500;
/// The hard ceiling even in `export: true` streaming mode — this phase has
/// no real streaming (matches `osiris-storage::Storage::query`'s own
/// documented "Vec instead of QueryResultStream" simplification), so an
/// unbounded export would just be an unbounded in-memory `Vec`.
pub const MAX_EVENT_LIMIT: usize = 5000;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CompileError {
    #[error("OQL syntax error: {0}")]
    Syntax(ParseError),
    #[error("unknown field: {0}")]
    UnknownField(String),
}

impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        CompileError::Syntax(e)
    }
}

/// The analyst-facing, backend-agnostic query surface (ARCHITECTURE.md
/// §12.3), additive to and independent of `osiris-storage`'s four existing
/// typed plans (`QueryPlan`, `AlertQueryPlan`, `RelationshipQueryPlan`,
/// `RiskQueryPlan`), which this type never touches or replaces.
#[derive(Debug, Clone, Default)]
pub struct EventQueryPlan {
    pub filter: Option<Ast>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: usize,
    pub export: bool,
}

impl EventQueryPlan {
    pub fn new() -> Self {
        Self {
            limit: DEFAULT_EVENT_LIMIT,
            ..Default::default()
        }
    }

    /// Parses `oql`, validates every field it references against
    /// `fields::is_known_field`, and stores the resulting AST as this
    /// plan's filter. `since`/`until`/`limit`/`export` are set separately
    /// (mirroring how `osiris-storage::QueryPlan` keeps `since`/`until` as
    /// plain fields never expressed inside a filter language) — a caller
    /// composes both, e.g. `EventQueryPlan::with_filter(q)?.since(...)`.
    pub fn with_filter(oql: &str) -> Result<Self, CompileError> {
        let ast = parse(oql)?;
        Self::validate_fields(&ast)?;
        Ok(Self {
            filter: Some(ast),
            ..Self::new()
        })
    }

    fn validate_fields(ast: &Ast) -> Result<(), CompileError> {
        match ast {
            Ast::And(l, r) | Ast::Or(l, r) => {
                Self::validate_fields(l)?;
                Self::validate_fields(r)
            }
            Ast::Not(inner) => Self::validate_fields(inner),
            Ast::Compare { field, .. } => {
                if is_known_field(field) {
                    Ok(())
                } else {
                    Err(CompileError::UnknownField(format!(
                        "'{}' is not a queryable field (see osiris_query::known_fields())",
                        field
                    )))
                }
            }
        }
    }

    /// The row cap actually enforced by a `Storage::query_events`
    /// implementation — never the caller's raw `limit` unclamped (§19.2).
    pub fn effective_limit(&self) -> usize {
        let ceiling = if self.export { MAX_EVENT_LIMIT } else { DEFAULT_EVENT_LIMIT };
        self.limit.min(ceiling)
    }
}

#[cfg(test)]
mod tests {
    use super::{CompileError, EventQueryPlan, DEFAULT_EVENT_LIMIT, MAX_EVENT_LIMIT};

    #[test]
    fn new_plan_defaults_to_default_limit_no_filter_not_export() {
        let plan = EventQueryPlan::new();
        assert_eq!(plan.limit, DEFAULT_EVENT_LIMIT);
        assert!(plan.filter.is_none());
        assert!(!plan.export);
        assert!(plan.since.is_none());
        assert!(plan.until.is_none());
    }

    #[test]
    fn with_filter_compiles_a_valid_oql_string() {
        let plan = EventQueryPlan::with_filter("event_type = \"PROCESS_EXEC\"").unwrap();
        assert!(plan.filter.is_some());
    }

    #[test]
    fn with_filter_rejects_an_unknown_field() {
        let err = EventQueryPlan::with_filter("bogus_field = 1").unwrap_err();
        match err {
            CompileError::UnknownField(msg) => assert!(msg.contains("bogus_field")),
            other => panic!("expected UnknownField, got {:?}", other),
        }
    }

    #[test]
    fn with_filter_rejects_an_unknown_field_nested_inside_and_or_not() {
        let err = EventQueryPlan::with_filter(
            "event_type = \"PROCESS_EXEC\" AND (NOT bogus_field = 1 OR user.uid = 0)",
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::UnknownField(_)));
    }

    #[test]
    fn with_filter_propagates_a_syntax_error() {
        let err = EventQueryPlan::with_filter("event_type =").unwrap_err();
        assert!(matches!(err, CompileError::Syntax(_)));
    }

    #[test]
    fn effective_limit_clamps_to_default_when_not_export() {
        let mut plan = EventQueryPlan::new();
        plan.limit = DEFAULT_EVENT_LIMIT * 10;
        assert_eq!(plan.effective_limit(), DEFAULT_EVENT_LIMIT);
    }

    #[test]
    fn effective_limit_clamps_to_the_hard_ceiling_even_in_export_mode() {
        let mut plan = EventQueryPlan::new();
        plan.limit = MAX_EVENT_LIMIT * 10;
        plan.export = true;
        assert_eq!(plan.effective_limit(), MAX_EVENT_LIMIT);
    }

    #[test]
    fn effective_limit_in_export_mode_allows_more_than_the_default_cap() {
        let mut plan = EventQueryPlan::new();
        plan.limit = DEFAULT_EVENT_LIMIT + 1;
        plan.export = true;
        assert_eq!(plan.effective_limit(), DEFAULT_EVENT_LIMIT + 1);
    }
}
