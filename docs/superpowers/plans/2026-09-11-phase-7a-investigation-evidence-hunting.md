# Phase 7a — Investigation/Evidence/Hunting Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OQL querying (`osiris-query`), the Investigation Engine (`osiris-investigate`), and the Evidence/Incident Engine (`osiris-evidence`) to OSIRIS, wire them into `osiris-api` and `osiris-cli`, and refactor the five existing ad-hoc `*_story` handlers onto the new Investigation Engine — all additive to Phase 0-6 code.

**Architecture:** Three new library crates under `crates/` (workspace `members = ["crates/*", ...]` already picks them up, no root `Cargo.toml` edit needed). `osiris-query` is a pure engine crate (depends only on `osiris-schema`, like `osiris-detect`/`osiris-correlate`) providing an OQL lexer/parser/AST and an `EventQueryPlan` type; `osiris-storage`'s `Storage` trait gains a `query_events` method using that type, implemented in `osiris-storage-sqlite` by extending the existing hand-rolled SQL-builder in `sqlite_storage.rs` (indexed-column pushdown for the same 8 columns `QueryPlan` already covers, in-memory residual filtering via `serde_json::Value` field-path lookup for every other schema field — a documented MVP limitation, not full SQL pushdown). `osiris-investigate` composes `Storage::query_events`/`query_relationships`/`query_alerts` into the 8 `*_story` operations and `reconstruct_incident`, plus a bounded Entity Graph v2 subgraph. `osiris-evidence` is its own small SQLite-backed control-plane store (own `.db` file, matching ARCHITECTURE.md §10.3's telemetry/control-plane split), independent of `osiris-storage`, with `osiris-audit`'s `AuditLog` wired in for status-transition audit entries.

**Tech Stack:** Rust (edition 2021, stable toolchain, matching `rust-toolchain.toml`), `rusqlite` (bundled) for the new Evidence/Incident store, `serde`/`serde_json` for wire types and residual-filter field-path evaluation, `thiserror` for error types, `axum` for the new/changed API routes, `clap`+`reqwest` for the new CLI subcommand (this crate is a thin HTTP client — see `osiris-cli/src/main.rs`), `tempfile` in tests.

**Spec:** `docs/superpowers/specs/2026-09-11-phase-7a-investigation-evidence-hunting-design.md`, which implements `ARCHITECTURE.md` §9.4, §11.3-11.4, §12 (12.1-12.7), §19.2, §29 Phase 7 scope line.

## Global Constraints

1. **Response Engine is out of scope.** No `osiris-response` crate, no `ResponseAction` type, anywhere in this plan (spec "Explicitly out of scope").
2. **ClickHouse is out of scope.** `osiris-storage-sqlite` is the only backend `query_events` is implemented for; `EventQueryPlan` stays backend-agnostic data so a later ClickHouse crate can implement `query_events` too, but building it is not this plan's work.
3. **The four existing typed storage plans are untouched.** `QueryPlan`, `AlertQueryPlan`, `RelationshipQueryPlan`, `RiskQueryPlan` in `crates/osiris-storage/src/plan.rs` keep every field and method exactly as they are today. `EventQueryPlan` (new, in `osiris-query`) is a fifth, additive plan type.
4. **The 5 existing story endpoints are behaviorally unchanged.** `/api/v1/files/story`, `/api/v1/network/story`, `/api/v1/identity/story`, `/api/v1/systemd/story`, `/api/v1/containers/story` keep their routes, query parameters, and JSON response shapes exactly as today; only their internal implementation moves into `osiris-investigate`.
5. **`osiris-query` has no OSIRIS-internal dependency except `osiris-schema`** — same independence rule `tools/check-dep-graph.sh` already enforces for `osiris-schema` itself, extended here by convention (not yet by the script; the dep-graph task in Part 5 adds the script rule) so `osiris-query` stays usable by anything without dragging in storage.
6. **`osiris-evidence` never depends on `osiris-storage`.** Evidence/Incident are control-plane records (§10.3), stored in their own SQLite file via their own trait, mirroring how `osiris-audit`'s `FileAuditLog` is independent of `osiris-storage`.
7. **No update/delete path for `Evidence` exists anywhere** — not in `EvidenceStore`, not in the API. Correcting a record is always `insert` with `supersedes: Some(old_id)`.
8. **Every `Incident` status transition writes to `osiris-audit` before the transition is persisted**; if the audit write fails, the transition fails and nothing is persisted.
9. **`EventQueryPlan` enforces a row cap (`DEFAULT_EVENT_LIMIT = 500`, hard ceiling `MAX_EVENT_LIMIT = 5000`)** unless the caller sets `export: true`, matching §19.2's "every query plan has an enforced cap unless export mode."
10. **New crates need no root `Cargo.toml` edit** — `members = ["crates/*", ...]` already covers any new `crates/<name>` directory.

---

## Part 1 — `osiris-query`: OQL parser + `EventQueryPlan`

### Task 1: Crate skeleton + AST

**Files:**
- Create: `crates/osiris-query/Cargo.toml`
- Create: `crates/osiris-query/src/lib.rs`
- Create: `crates/osiris-query/src/ast.rs`
- Test: `crates/osiris-query/src/ast.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: nothing (first task in the crate).
- Produces: `pub enum Ast`, `pub enum Op`, `pub enum Value` — consumed by the parser (Task 3) and the plan compiler (Task 5).

- [ ] **Step 1: Create the crate manifest**

```toml
# crates/osiris-query/Cargo.toml
[package]
name = "osiris-query"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
osiris-schema = { path = "../osiris-schema" }

[dev-dependencies]
uuid = { workspace = true }
```

- [ ] **Step 2: Write the failing test for `Value` equality/shape**

```rust
// crates/osiris-query/src/ast.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_variants_compare_by_content() {
        assert_eq!(Value::Str("a".to_string()), Value::Str("a".to_string()));
        assert_ne!(Value::Str("a".to_string()), Value::Num(1.0));
        assert_eq!(
            Value::List(vec![Value::Num(1.0), Value::Num(2.0)]),
            Value::List(vec![Value::Num(1.0), Value::Num(2.0)])
        );
    }

    #[test]
    fn ast_compare_node_holds_field_op_value() {
        let node = Ast::Compare {
            field: "user.uid".to_string(),
            op: Op::Eq,
            value: Value::Num(0.0),
        };
        match node {
            Ast::Compare { field, op, value } => {
                assert_eq!(field, "user.uid");
                assert_eq!(op, Op::Eq);
                assert_eq!(value, Value::Num(0.0));
            }
            _ => panic!("expected Compare"),
        }
    }
}
```

- [ ] **Step 2b: Run test to verify it fails**

Run: `cargo test -p osiris-query ast:: -- --nocapture`
Expected: FAIL with "cannot find type `Ast` / `Op` / `Value` in this scope" (nothing defined yet).

- [ ] **Step 3: Implement the AST types**

```rust
// crates/osiris-query/src/ast.rs (add above the tests module)

/// OQL's operator set, exactly ARCHITECTURE.md §12.3's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    StartsWith,
    EndsWith,
    In,
}

/// A parsed OQL literal. Numbers are `f64` so integer and (theoretical
/// future) fractional literals share one representation; every current
/// numeric schema field is an integer, so comparisons truncate/compare
/// exactly for the values this phase's fields actually produce.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Num(f64),
    List(Vec<Value>),
}

/// The OQL abstract syntax tree: field-comparison leaves combined by
/// `AND`/`OR`/`NOT` per ARCHITECTURE.md §12.3.
#[derive(Debug, Clone, PartialEq)]
pub enum Ast {
    And(Box<Ast>, Box<Ast>),
    Or(Box<Ast>, Box<Ast>),
    Not(Box<Ast>),
    Compare { field: String, op: Op, value: Value },
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query ast:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire the module into `lib.rs`**

```rust
// crates/osiris-query/src/lib.rs
pub mod ast;

pub use ast::{Ast, Op, Value};
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-query/Cargo.toml crates/osiris-query/src/lib.rs crates/osiris-query/src/ast.rs
git commit -m "feat(query): osiris-query crate skeleton and OQL AST types"
```

### Task 2: Lexer

**Files:**
- Create: `crates/osiris-query/src/lexer.rs`
- Test: `crates/osiris-query/src/lexer.rs` (inline)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub enum Token`, `pub struct Lexer`, `pub fn Lexer::tokenize(input: &str) -> Result<Vec<Token>, LexError>`, `pub struct LexError { pub position: usize, pub message: String }` — consumed by the parser (Task 3).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-query/src/lexer.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_a_simple_equality_comparison() {
        let tokens = Lexer::tokenize("event_type = \"PROCESS_EXEC\"").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("event_type".to_string()),
                Token::Op(crate::ast::Op::Eq),
                Token::Str("PROCESS_EXEC".to_string()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tokenizes_and_or_not_and_parens() {
        let tokens = Lexer::tokenize("NOT (a = 1 AND b = 2) OR c = 3").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Not,
                Token::LParen,
                Token::Ident("a".to_string()),
                Token::Op(crate::ast::Op::Eq),
                Token::Num(1.0),
                Token::And,
                Token::Ident("b".to_string()),
                Token::Op(crate::ast::Op::Eq),
                Token::Num(2.0),
                Token::RParen,
                Token::Or,
                Token::Ident("c".to_string()),
                Token::Op(crate::ast::Op::Eq),
                Token::Num(3.0),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tokenizes_every_multi_char_operator() {
        let tokens = Lexer::tokenize("a != 1 AND b >= 2 AND c <= 3 AND d > 4 AND e < 5").unwrap();
        let ops: Vec<_> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Op(op) => Some(*op),
                _ => None,
            })
            .collect();
        assert_eq!(
            ops,
            vec![
                crate::ast::Op::Ne,
                crate::ast::Op::Ge,
                crate::ast::Op::Le,
                crate::ast::Op::Gt,
                crate::ast::Op::Lt,
            ]
        );
    }

    #[test]
    fn tokenizes_keyword_operators_and_in_list() {
        let tokens =
            Lexer::tokenize("a CONTAINS \"x\" AND b STARTS_WITH \"y\" AND c ENDS_WITH \"z\" AND d IN (1, 2, 3)")
                .unwrap();
        let ops: Vec<_> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Op(op) => Some(*op),
                _ => None,
            })
            .collect();
        assert_eq!(
            ops,
            vec![
                crate::ast::Op::Contains,
                crate::ast::Op::StartsWith,
                crate::ast::Op::EndsWith,
                crate::ast::Op::In,
            ]
        );
        assert!(tokens.contains(&Token::Comma));
    }

    #[test]
    fn reports_position_of_an_unterminated_string() {
        let err = Lexer::tokenize("a = \"unterminated").unwrap_err();
        assert_eq!(err.position, 4);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-query lexer:: -- --nocapture`
Expected: FAIL with "cannot find type `Lexer` / `Token` in this scope"

- [ ] **Step 3: Implement the lexer**

```rust
// crates/osiris-query/src/lexer.rs (add above the tests module)
use crate::ast::Op;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Str(String),
    Num(f64),
    Op(Op),
    And,
    Or,
    Not,
    In,
    LParen,
    RParen,
    Comma,
    Eof,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("OQL lex error at position {position}: {message}")]
pub struct LexError {
    pub position: usize,
    pub message: String,
}

pub struct Lexer;

impl Lexer {
    pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;
        let mut tokens = Vec::new();

        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() {
                i += 1;
                continue;
            }
            match c {
                '(' => {
                    tokens.push(Token::LParen);
                    i += 1;
                }
                ')' => {
                    tokens.push(Token::RParen);
                    i += 1;
                }
                ',' => {
                    tokens.push(Token::Comma);
                    i += 1;
                }
                '=' => {
                    tokens.push(Token::Op(Op::Eq));
                    i += 1;
                }
                '!' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push(Token::Op(Op::Ne));
                    i += 2;
                }
                '>' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push(Token::Op(Op::Ge));
                    i += 2;
                }
                '>' => {
                    tokens.push(Token::Op(Op::Gt));
                    i += 1;
                }
                '<' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push(Token::Op(Op::Le));
                    i += 2;
                }
                '<' => {
                    tokens.push(Token::Op(Op::Lt));
                    i += 1;
                }
                '"' => {
                    let start = i;
                    i += 1;
                    let mut s = String::new();
                    let mut closed = false;
                    while i < chars.len() {
                        if chars[i] == '"' {
                            closed = true;
                            i += 1;
                            break;
                        }
                        s.push(chars[i]);
                        i += 1;
                    }
                    if !closed {
                        return Err(LexError {
                            position: start,
                            message: "unterminated string literal".to_string(),
                        });
                    }
                    tokens.push(Token::Str(s));
                }
                c if c.is_ascii_digit() || (c == '-' && chars.get(i + 1).is_some_and(|n| n.is_ascii_digit())) => {
                    let start = i;
                    i += 1;
                    while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                        i += 1;
                    }
                    let text: String = chars[start..i].iter().collect();
                    let n: f64 = text.parse().map_err(|_| LexError {
                        position: start,
                        message: format!("invalid number literal '{}'", text),
                    })?;
                    tokens.push(Token::Num(n));
                }
                c if c.is_alphabetic() || c == '_' => {
                    let start = i;
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                        i += 1;
                    }
                    let word: String = chars[start..i].iter().collect();
                    tokens.push(match word.as_str() {
                        "AND" => Token::And,
                        "OR" => Token::Or,
                        "NOT" => Token::Not,
                        "IN" => Token::In,
                        "CONTAINS" => Token::Op(Op::Contains),
                        "STARTS_WITH" => Token::Op(Op::StartsWith),
                        "ENDS_WITH" => Token::Op(Op::EndsWith),
                        _ => Token::Ident(word),
                    });
                }
                other => {
                    return Err(LexError {
                        position: i,
                        message: format!("unexpected character '{}'", other),
                    });
                }
            }
        }

        tokens.push(Token::Eof);
        Ok(tokens)
    }
}
```

Note: the `IN` keyword yields `Token::In`, not `Token::Op(Op::In)`, since `IN (1, 2, 3)` is syntactically a list, not a scalar comparison — the parser (Task 3) converts a recognized `IN` production into `Op::In` on the `Ast::Compare` node it builds.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query lexer:: -- --nocapture`
Expected: PASS (5 tests)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-query/src/lib.rs (append)
pub mod lexer;
pub use lexer::{LexError, Lexer, Token};
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-query/src/lexer.rs crates/osiris-query/src/lib.rs
git commit -m "feat(query): OQL lexer"
```

### Task 3: Recursive-descent parser

**Files:**
- Create: `crates/osiris-query/src/parser.rs`
- Test: `crates/osiris-query/src/parser.rs` (inline)

**Interfaces:**
- Consumes: `Token`/`Lexer` (Task 2), `Ast`/`Op`/`Value` (Task 1).
- Produces: `pub fn parse(input: &str) -> Result<Ast, ParseError>`, `pub struct ParseError { pub position: usize, pub message: String }` — consumed by the plan compiler (Task 5) and the API/CLI error-handling tasks (Tasks 20, 22).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-query/src/parser.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Op, Value};

    #[test]
    fn parses_a_single_comparison() {
        let ast = parse("event_type = \"PROCESS_EXEC\"").unwrap();
        assert_eq!(
            ast,
            Ast::Compare {
                field: "event_type".to_string(),
                op: Op::Eq,
                value: Value::Str("PROCESS_EXEC".to_string()),
            }
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // a OR b AND c  ==  a OR (b AND c)
        let ast = parse("a = 1 OR b = 2 AND c = 3").unwrap();
        match ast {
            Ast::Or(left, right) => {
                assert_eq!(*left, Ast::Compare { field: "a".into(), op: Op::Eq, value: Value::Num(1.0) });
                match *right {
                    Ast::And(l, r) => {
                        assert_eq!(*l, Ast::Compare { field: "b".into(), op: Op::Eq, value: Value::Num(2.0) });
                        assert_eq!(*r, Ast::Compare { field: "c".into(), op: Op::Eq, value: Value::Num(3.0) });
                    }
                    _ => panic!("expected And on the right of Or"),
                }
            }
            _ => panic!("expected Or at the top"),
        }
    }

    #[test]
    fn parentheses_override_precedence() {
        // (a OR b) AND c
        let ast = parse("(a = 1 OR b = 2) AND c = 3").unwrap();
        match ast {
            Ast::And(left, right) => {
                assert!(matches!(*left, Ast::Or(_, _)));
                assert_eq!(*right, Ast::Compare { field: "c".into(), op: Op::Eq, value: Value::Num(3.0) });
            }
            _ => panic!("expected And at the top"),
        }
    }

    #[test]
    fn not_applies_to_the_immediately_following_term() {
        let ast = parse("NOT a = 1 AND b = 2").unwrap();
        match ast {
            Ast::And(left, right) => {
                assert!(matches!(*left, Ast::Not(_)));
                assert_eq!(*right, Ast::Compare { field: "b".into(), op: Op::Eq, value: Value::Num(2.0) });
            }
            _ => panic!("expected And at the top"),
        }
    }

    #[test]
    fn parses_an_in_list() {
        let ast = parse("event_type IN (\"A\", \"B\", \"C\")").unwrap();
        assert_eq!(
            ast,
            Ast::Compare {
                field: "event_type".to_string(),
                op: Op::In,
                value: Value::List(vec![
                    Value::Str("A".to_string()),
                    Value::Str("B".to_string()),
                    Value::Str("C".to_string()),
                ]),
            }
        );
    }

    #[test]
    fn reports_position_on_a_dangling_operator() {
        let err = parse("a =").unwrap_err();
        assert!(err.message.contains("expected"));
    }

    #[test]
    fn reports_an_unclosed_paren() {
        let err = parse("(a = 1 AND b = 2").unwrap_err();
        assert!(err.message.contains(')'));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-query parser:: -- --nocapture`
Expected: FAIL with "cannot find function `parse` in this scope"

- [ ] **Step 3: Implement the parser**

```rust
// crates/osiris-query/src/parser.rs (add above the tests module)
use crate::ast::{Ast, Op, Value};
use crate::lexer::{LexError, Lexer, Token};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("OQL parse error at token {position}: {message}")]
pub struct ParseError {
    pub position: usize,
    pub message: String,
}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError {
            position: e.position,
            message: e.message,
        }
    }
}

pub fn parse(input: &str) -> Result<Ast, ParseError> {
    let tokens = Lexer::tokenize(input)?;
    let mut p = Parser { tokens, pos: 0 };
    let ast = p.parse_or()?;
    p.expect_eof()?;
    Ok(ast)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn err(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            position: self.pos,
            message: message.into(),
        }
    }

    fn expect_eof(&self) -> Result<(), ParseError> {
        if *self.peek() == Token::Eof {
            Ok(())
        } else {
            Err(self.err(format!("expected end of query, found {:?}", self.peek())))
        }
    }

    // or := and (OR and)*
    fn parse_or(&mut self) -> Result<Ast, ParseError> {
        let mut left = self.parse_and()?;
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Ast::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // and := unary (AND unary)*
    fn parse_and(&mut self) -> Result<Ast, ParseError> {
        let mut left = self.parse_unary()?;
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_unary()?;
            left = Ast::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // unary := NOT unary | primary
    fn parse_unary(&mut self) -> Result<Ast, ParseError> {
        if *self.peek() == Token::Not {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(Ast::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    // primary := '(' or ')' | comparison
    fn parse_primary(&mut self) -> Result<Ast, ParseError> {
        if *self.peek() == Token::LParen {
            self.advance();
            let inner = self.parse_or()?;
            if *self.peek() != Token::RParen {
                return Err(self.err("expected ')'"));
            }
            self.advance();
            return Ok(inner);
        }
        self.parse_comparison()
    }

    // comparison := IDENT (OP scalar | IN '(' list ')')
    fn parse_comparison(&mut self) -> Result<Ast, ParseError> {
        let field = match self.advance() {
            Token::Ident(name) => name,
            other => return Err(self.err(format!("expected field name, found {:?}", other))),
        };

        match self.advance() {
            Token::Op(op) => {
                let value = self.parse_scalar()?;
                Ok(Ast::Compare { field, op, value })
            }
            Token::In => {
                if self.advance() != Token::LParen {
                    return Err(self.err("expected '(' after IN"));
                }
                let mut items = vec![self.parse_scalar()?];
                while *self.peek() == Token::Comma {
                    self.advance();
                    items.push(self.parse_scalar()?);
                }
                if self.advance() != Token::RParen {
                    return Err(self.err("expected ')' to close IN list"));
                }
                Ok(Ast::Compare {
                    field,
                    op: Op::In,
                    value: Value::List(items),
                })
            }
            other => Err(self.err(format!("expected an operator, found {:?}", other))),
        }
    }

    fn parse_scalar(&mut self) -> Result<Value, ParseError> {
        match self.advance() {
            Token::Str(s) => Ok(Value::Str(s)),
            Token::Num(n) => Ok(Value::Num(n)),
            other => Err(self.err(format!("expected a string or number, found {:?}", other))),
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query parser:: -- --nocapture`
Expected: PASS (7 tests)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-query/src/lib.rs (append)
pub mod parser;
pub use parser::{parse, ParseError};
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-query/src/parser.rs crates/osiris-query/src/lib.rs
git commit -m "feat(query): OQL recursive-descent parser"
```

### Task 4: Field reference + field-path evaluator

**Files:**
- Create: `crates/osiris-query/src/fields.rs`
- Create: `crates/osiris-query/src/eval.rs`
- Test: both files (inline)

**Interfaces:**
- Consumes: `osiris_schema::CanonicalEvent` (for the eval test fixture); `Op`/`Value` from Task 1.
- Produces: `pub fn known_fields() -> &'static [&'static str]`, `pub fn is_known_field(field: &str) -> bool` (fields.rs); `pub fn get_field(event: &CanonicalEvent, field: &str) -> Option<serde_json::Value>`, `pub fn compare(actual: &serde_json::Value, op: Op, target: &Value) -> bool` (eval.rs) — both consumed by the plan compiler (Task 5, for field validation) and the SQLite residual filter (Task 7, for evaluation).

- [ ] **Step 1: Write the failing test for the field reference**

```rust
// crates/osiris-query/src/fields.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_fields_includes_every_indexed_and_common_column() {
        for f in [
            "event_type", "category", "severity", "timestamp", "host_id",
            "process.pid", "process.exe_path", "process.process_key",
            "user.uid", "user.username", "file.path", "file.inode", "file.device_id",
            "network.src_ip", "network.dst_ip", "dns.query",
            "session.session_id", "service.unit_name", "container.container_id", "tags",
        ] {
            assert!(is_known_field(f), "expected '{}' to be a known field", f);
        }
    }

    #[test]
    fn rejects_an_unknown_field() {
        assert!(!is_known_field("not_a_real_field"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-query fields:: -- --nocapture`
Expected: FAIL with "cannot find function `is_known_field`"

- [ ] **Step 3: Implement the field reference**

```rust
// crates/osiris-query/src/fields.rs (add above the tests module)

/// The OQL field reference (ARCHITECTURE.md §12.3: "generated from the
/// Event Schema so it never drifts out of sync"). This phase implements
/// that as a hand-maintained list checked against a live `CanonicalEvent`
/// by `eval::tests` (Task 4 Step... see eval.rs) rather than a build-time
/// codegen step — a documented simplification matching this workspace's
/// existing "smallest thing that satisfies the requirement" posture
/// (compare `osiris-storage`'s `QueryPlan` doc comment). Whoever adds a
/// field to `osiris-schema::CanonicalEvent` that should be OQL-queryable
/// must add it here too; forgetting to is caught the moment `eval::get_field`
/// is asked for a field this list didn't have a matching path for and a
/// coverage test (Task 4 Step 6, in eval.rs) fails.
const KNOWN_FIELDS: &[&str] = &[
    "event_type",
    "category",
    "severity",
    "timestamp",
    "host_id",
    "process.pid",
    "process.exe_path",
    "process.process_key",
    "parent_process.pid",
    "parent_process.process_key",
    "user.uid",
    "user.username",
    "file.path",
    "file.inode",
    "file.device_id",
    "network.src_ip",
    "network.dst_ip",
    "network.dst_port",
    "dns.query",
    "session.session_id",
    "service.unit_name",
    "container.container_id",
    "tags",
];

pub fn known_fields() -> &'static [&'static str] {
    KNOWN_FIELDS
}

pub fn is_known_field(field: &str) -> bool {
    KNOWN_FIELDS.contains(&field)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query fields:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the failing test for the evaluator**

```rust
// crates/osiris-query/src/eval.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Op, Value};
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, CanonicalEvent,
        SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 12345,
            monotonic_timestamp: 12345,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::High,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 42, 1),
                pid: 42,
                exe_path: "/usr/bin/curl".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec!["suspicious".to_string()],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn get_field_resolves_a_top_level_field() {
        let event = sample_event();
        let v = get_field(&event, "event_type").unwrap();
        assert_eq!(v, serde_json::json!("PROCESS_EXEC"));
    }

    #[test]
    fn get_field_resolves_a_nested_field() {
        let event = sample_event();
        let v = get_field(&event, "process.exe_path").unwrap();
        assert_eq!(v, serde_json::json!("/usr/bin/curl"));
    }

    #[test]
    fn get_field_returns_none_for_an_absent_optional_parent() {
        let event = sample_event();
        assert!(get_field(&event, "user.uid").is_none());
    }

    #[test]
    fn compare_eq_matches_string_and_number() {
        assert!(compare(&serde_json::json!("A"), Op::Eq, &Value::Str("A".to_string())));
        assert!(compare(&serde_json::json!(42), Op::Eq, &Value::Num(42.0)));
        assert!(!compare(&serde_json::json!("A"), Op::Eq, &Value::Str("B".to_string())));
    }

    #[test]
    fn compare_contains_starts_with_ends_with() {
        let hay = serde_json::json!("/usr/bin/curl");
        assert!(compare(&hay, Op::Contains, &Value::Str("bin".to_string())));
        assert!(compare(&hay, Op::StartsWith, &Value::Str("/usr".to_string())));
        assert!(compare(&hay, Op::EndsWith, &Value::Str("curl".to_string())));
        assert!(!compare(&hay, Op::Contains, &Value::Str("nope".to_string())));
    }

    #[test]
    fn compare_ordering_operators_on_numbers() {
        let n = serde_json::json!(10);
        assert!(compare(&n, Op::Gt, &Value::Num(5.0)));
        assert!(compare(&n, Op::Ge, &Value::Num(10.0)));
        assert!(compare(&n, Op::Lt, &Value::Num(20.0)));
        assert!(compare(&n, Op::Le, &Value::Num(10.0)));
        assert!(!compare(&n, Op::Gt, &Value::Num(10.0)));
    }

    #[test]
    fn compare_in_matches_any_list_member() {
        let v = serde_json::json!("PROCESS_EXEC");
        let list = Value::List(vec![
            Value::Str("PROCESS_FORK".to_string()),
            Value::Str("PROCESS_EXEC".to_string()),
        ]);
        assert!(compare(&v, Op::In, &list));
        let miss = Value::List(vec![Value::Str("PROCESS_FORK".to_string())]);
        assert!(!compare(&v, Op::In, &miss));
    }

    #[test]
    fn every_known_field_resolves_or_is_a_documented_optional_absence() {
        // Coverage guard for KNOWN_FIELDS drifting from CanonicalEvent's real
        // shape: every field this crate advertises as queryable must at
        // least parse as a JSON pointer path against a real serialized
        // event (a `None` for an absent optional section, like `user.uid`
        // above, is fine — a field name that doesn't resolve as a path
        // *at all* means fields.rs and the schema have drifted apart).
        let event = sample_event();
        let json = serde_json::to_value(&event).unwrap();
        for field in crate::fields::known_fields() {
            let mut cursor = &json;
            let mut resolved = true;
            for part in field.split('.') {
                match cursor.get(part) {
                    Some(next) => cursor = next,
                    None => {
                        resolved = false;
                        break;
                    }
                }
            }
            assert!(
                resolved || get_field(&event, field).is_none(),
                "field '{}' does not resolve against a real CanonicalEvent",
                field
            );
        }
    }
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cargo test -p osiris-query eval:: -- --nocapture`
Expected: FAIL with "cannot find function `get_field` / `compare`"

- [ ] **Step 7: Implement the evaluator**

```rust
// crates/osiris-query/src/eval.rs (add above the tests module)
use crate::ast::{Op, Value};
use osiris_schema::CanonicalEvent;

/// Resolves a dotted OQL field path (e.g. `"process.exe_path"`) against one
/// event's JSON representation. Returns `None` both when an intermediate
/// section is absent (e.g. `user.uid` on an event with no `user`) and when
/// the path itself doesn't exist — the residual filter (Task 7) treats
/// both as "does not match" for every operator except nothing (there is no
/// "is null" operator in this phase's grammar, matching §12.3 exactly).
pub fn get_field(event: &CanonicalEvent, field: &str) -> Option<serde_json::Value> {
    let json = serde_json::to_value(event).ok()?;
    let mut cursor = &json;
    for part in field.split('.') {
        cursor = cursor.get(part)?;
    }
    Some(cursor.clone())
}

fn as_f64(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn as_str_lossy(v: &serde_json::Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

/// Evaluates one comparison from the AST against a field's actual JSON
/// value, per ARCHITECTURE.md §12.3's operator set.
pub fn compare(actual: &serde_json::Value, op: Op, target: &Value) -> bool {
    match (op, target) {
        (Op::Eq, Value::Str(s)) => as_str_lossy(actual) == *s,
        (Op::Eq, Value::Num(n)) => as_f64(actual) == Some(*n),
        (Op::Ne, Value::Str(s)) => as_str_lossy(actual) != *s,
        (Op::Ne, Value::Num(n)) => as_f64(actual) != Some(*n),
        (Op::Gt, Value::Num(n)) => as_f64(actual).is_some_and(|a| a > *n),
        (Op::Lt, Value::Num(n)) => as_f64(actual).is_some_and(|a| a < *n),
        (Op::Ge, Value::Num(n)) => as_f64(actual).is_some_and(|a| a >= *n),
        (Op::Le, Value::Num(n)) => as_f64(actual).is_some_and(|a| a <= *n),
        (Op::Contains, Value::Str(s)) => as_str_lossy(actual).contains(s.as_str()),
        (Op::StartsWith, Value::Str(s)) => as_str_lossy(actual).starts_with(s.as_str()),
        (Op::EndsWith, Value::Str(s)) => as_str_lossy(actual).ends_with(s.as_str()),
        (Op::In, Value::List(items)) => items.iter().any(|item| compare(actual, Op::Eq, item)),
        _ => false,
    }
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo test -p osiris-query eval:: -- --nocapture`
Expected: PASS (7 tests)

- [ ] **Step 9: Wire into `lib.rs`**

```rust
// crates/osiris-query/src/lib.rs (append)
pub mod eval;
pub mod fields;
pub use eval::{compare, get_field};
pub use fields::{is_known_field, known_fields};
```

- [ ] **Step 10: Add the dev-dependency the test fixture needs**

`osiris-query/Cargo.toml`'s `[dev-dependencies]` already lists `uuid`; the eval test also needs `osiris-schema` at dev-time, but it's already a normal dependency (Task 1), so nothing to add.

- [ ] **Step 11: Commit**

```bash
git add crates/osiris-query/src/fields.rs crates/osiris-query/src/eval.rs crates/osiris-query/src/lib.rs
git commit -m "feat(query): OQL field reference and field-path evaluator"
```

### Task 5: `EventQueryPlan` + compiler + row/time-range cap

**Files:**
- Create: `crates/osiris-query/src/plan.rs`
- Test: `crates/osiris-query/src/plan.rs` (inline)

**Interfaces:**
- Consumes: `Ast`, `parse` (Task 3), `is_known_field`/`known_fields` (Task 4).
- Produces: `pub struct EventQueryPlan { pub filter: Option<Ast>, pub since: Option<u64>, pub until: Option<u64>, pub limit: usize, pub export: bool }`, `pub const DEFAULT_EVENT_LIMIT: usize`, `pub const MAX_EVENT_LIMIT: usize`, `pub fn EventQueryPlan::new() -> Self`, `pub fn EventQueryPlan::with_filter(oql: &str) -> Result<Self, CompileError>`, `pub fn EventQueryPlan::effective_limit(&self) -> usize`, `pub enum CompileError` — consumed by `osiris-storage`'s trait extension (the `Storage::query_events` task), `osiris-storage-sqlite`'s implementation (the `query_events` impl task), the API's `events_handler` change (Part 4), and `osiris-cli`'s `hunt` subcommand (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-query/src/plan.rs
#[cfg(test)]
mod tests {
    use super::*;

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-query plan:: -- --nocapture`
Expected: FAIL with "cannot find type `EventQueryPlan` / `CompileError`"

- [ ] **Step 3: Implement the plan type and compiler**

```rust
// crates/osiris-query/src/plan.rs (add above the tests module)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query plan:: -- --nocapture`
Expected: PASS (7 tests)

- [ ] **Step 5: Wire into `lib.rs`, run the whole crate's tests**

```rust
// crates/osiris-query/src/lib.rs (append)
pub mod plan;
pub use plan::{CompileError, EventQueryPlan, DEFAULT_EVENT_LIMIT, MAX_EVENT_LIMIT};
```

Run: `cargo test -p osiris-query`
Expected: PASS (all tests across ast/lexer/parser/fields/eval/plan)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-query/src/plan.rs crates/osiris-query/src/lib.rs
git commit -m "feat(query): EventQueryPlan compiler with field validation and row/time cap"
```

### Task 6: `eval_ast` (whole-tree evaluation) + `Storage::query_events`

**Files:**
- Modify: `crates/osiris-query/src/eval.rs`
- Modify: `crates/osiris-query/src/lib.rs`
- Modify: `crates/osiris-storage/src/storage.rs`
- Modify: `crates/osiris-storage/Cargo.toml`
- Test: `crates/osiris-query/src/eval.rs` (inline, appended)

**Interfaces:**
- Consumes: `Ast`, `compare`, `get_field` (Task 4/5); `osiris_query::EventQueryPlan` (Task 5).
- Produces: `pub fn eval_ast(event: &CanonicalEvent, ast: &Ast) -> bool` (consumed by Task 7's SQLite implementation); `Storage::query_events(&self, plan: &EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError>` (consumed by Task 7, and by `osiris-investigate`'s stories in Part 2).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-query/src/eval.rs (append to the existing tests module)
    #[test]
    fn eval_ast_combines_and_or_not() {
        let event = sample_event();
        let is_exec = Ast::Compare {
            field: "event_type".to_string(),
            op: Op::Eq,
            value: Value::Str("PROCESS_EXEC".to_string()),
        };
        let is_fork = Ast::Compare {
            field: "event_type".to_string(),
            op: Op::Eq,
            value: Value::Str("PROCESS_FORK".to_string()),
        };
        assert!(eval_ast(&event, &is_exec));
        assert!(!eval_ast(&event, &is_fork));
        assert!(eval_ast(&event, &Ast::Or(Box::new(is_fork.clone()), Box::new(is_exec.clone()))));
        assert!(!eval_ast(&event, &Ast::And(Box::new(is_fork.clone()), Box::new(is_exec.clone()))));
        assert!(eval_ast(&event, &Ast::Not(Box::new(is_fork))));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-query eval:: -- --nocapture`
Expected: FAIL with "cannot find function `eval_ast`" (also need `crate::ast::Ast` imported in the test module — add `use crate::ast::Ast;` next to the existing `use crate::ast::{Op, Value};` line)

- [ ] **Step 3: Implement `eval_ast`**

```rust
// crates/osiris-query/src/eval.rs (add above the tests module, after `compare`)

/// Evaluates a whole OQL AST against one event — the in-memory residual
/// filter `osiris-storage-sqlite`'s `query_events` (Task 7) falls back to
/// for any filter this MVP's SQL pushdown doesn't cover.
pub fn eval_ast(event: &CanonicalEvent, ast: &crate::ast::Ast) -> bool {
    use crate::ast::Ast;
    match ast {
        Ast::And(l, r) => eval_ast(event, l) && eval_ast(event, r),
        Ast::Or(l, r) => eval_ast(event, l) || eval_ast(event, r),
        Ast::Not(inner) => !eval_ast(event, inner),
        Ast::Compare { field, op, value } => match get_field(event, field) {
            Some(actual) => compare(&actual, *op, value),
            None => false,
        },
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-query eval:: -- --nocapture`
Expected: PASS (8 tests)

- [ ] **Step 5: Export `eval_ast`**

```rust
// crates/osiris-query/src/lib.rs — change the eval re-export line to:
pub use eval::{compare, eval_ast, get_field};
```

- [ ] **Step 6: Add `osiris-query` as a dependency of `osiris-storage`**

```toml
# crates/osiris-storage/Cargo.toml — add under [dependencies]
osiris-query = { path = "../osiris-query" }
```

- [ ] **Step 7: Add `query_events` to the `Storage` trait**

```rust
// crates/osiris-storage/src/storage.rs — add to the `Storage` trait, after `query`:
    /// The OQL-backed, backend-agnostic query surface (ARCHITECTURE.md
    /// §12.3), additive to `query` above — `query` and its `QueryPlan`
    /// keep serving every existing caller unchanged (plan Global
    /// Constraint #3).
    fn query_events(&self, plan: &osiris_query::EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError>;
```

There is no test to run for this step in isolation — `cargo build -p osiris-storage` now fails because no implementor of `Storage` defines `query_events` yet; Task 7 fixes that. This is expected and matches the "add the trait method, then add its one implementation" order the rest of this trait's methods were built in.

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-query/src/eval.rs crates/osiris-query/src/lib.rs crates/osiris-storage/src/storage.rs crates/osiris-storage/Cargo.toml
git commit -m "feat(query,storage): eval_ast whole-tree evaluator and Storage::query_events trait method"
```

### Task 7: `SqliteStorage::query_events` (pushdown + residual)

**Files:**
- Modify: `crates/osiris-storage-sqlite/Cargo.toml`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`
- Test: `crates/osiris-storage-sqlite/src/sqlite_storage.rs` (inline, new `#[cfg(test)]` cases alongside the existing ones)

**Interfaces:**
- Consumes: `Storage::query_events` (Task 6), `osiris_query::{EventQueryPlan, Ast, Op, Value, eval_ast}`.
- Produces: the one and only implementation of `query_events` in this workspace — consumed by `osiris-investigate` (Part 2) and `osiris-api`'s `events_handler` (Part 4).

- [ ] **Step 1: Add the dependency**

```toml
# crates/osiris-storage-sqlite/Cargo.toml — add under [dependencies]
osiris-query = { path = "../osiris-query" }
```

- [ ] **Step 2: Write the failing tests**

```rust
// crates/osiris-storage-sqlite/src/sqlite_storage.rs — add to the existing
// #[cfg(test)] mod tests block (find it via `grep -n "mod tests" crates/osiris-storage-sqlite/src/sqlite_storage.rs`)
    #[test]
    fn query_events_with_no_filter_returns_everything_within_the_default_cap() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        for i in 0..3 {
            storage.write(&sample_event(100 + i, None, 1000 + i as u64)).unwrap();
        }
        let plan = osiris_query::EventQueryPlan::new();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn query_events_pushes_down_an_exact_match_event_type_filter() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, None, 100)).unwrap();
        let plan =
            osiris_query::EventQueryPlan::with_filter("event_type = \"PROCESS_EXEC\"").unwrap();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        let plan_miss =
            osiris_query::EventQueryPlan::with_filter("event_type = \"PROCESS_FORK\"").unwrap();
        assert_eq!(storage.query_events(&plan_miss).unwrap().len(), 0);
    }

    #[test]
    fn query_events_residual_filters_a_field_with_no_sql_pushdown() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(42, None, 100)).unwrap();
        storage.write(&sample_event(43, None, 200)).unwrap();
        // process.pid has no dedicated indexed column, so this exercises
        // the in-memory eval_ast fallback, not SQL pushdown.
        let plan = osiris_query::EventQueryPlan::with_filter("process.pid = 42").unwrap();
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process.as_ref().unwrap().pid, 42);
    }

    #[test]
    fn query_events_supports_or_and_not_via_residual_evaluation() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, None, 100)).unwrap();
        storage.write(&sample_event(2, None, 200)).unwrap();
        let plan =
            osiris_query::EventQueryPlan::with_filter("process.pid = 1 OR process.pid = 2").unwrap();
        assert_eq!(storage.query_events(&plan).unwrap().len(), 2);

        let plan_not = osiris_query::EventQueryPlan::with_filter("NOT process.pid = 1").unwrap();
        assert_eq!(storage.query_events(&plan_not).unwrap().len(), 1);
    }

    #[test]
    fn query_events_respects_since_and_until() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        storage.write(&sample_event(1, None, 100)).unwrap();
        storage.write(&sample_event(2, None, 500)).unwrap();
        storage.write(&sample_event(3, None, 900)).unwrap();
        let mut plan = osiris_query::EventQueryPlan::new();
        plan.since = Some(200);
        plan.until = Some(600);
        let events = storage.query_events(&plan).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, 500);
    }

    #[test]
    fn query_events_clamps_to_the_effective_limit() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        for i in 0..5 {
            storage.write(&sample_event(i, None, i as u64)).unwrap();
        }
        let mut plan = osiris_query::EventQueryPlan::new();
        plan.limit = 2;
        assert_eq!(storage.query_events(&plan).unwrap().len(), 2);
    }
```

Note: `sample_event` here is this test module's own existing helper (`fn sample_event(pid: u32, parent_key: Option<ProcessKey>, timestamp: u64) -> CanonicalEvent`) — confirm its exact name/signature via `grep -n "fn sample_event" crates/osiris-storage-sqlite/src/sqlite_storage.rs` before writing these tests, and adapt the calls above if the real signature differs.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-storage-sqlite query_events -- --nocapture`
Expected: FAIL with "no method named `query_events` found"

- [ ] **Step 4: Implement `query_events`**

```rust
// crates/osiris-storage-sqlite/src/sqlite_storage.rs — add to the
// `impl Storage for SqliteStorage` block, after `fn query`:
use osiris_query::{eval_ast, Ast, EventQueryPlan, Op, Value};

    fn query_events(&self, plan: &EventQueryPlan) -> Result<Vec<CanonicalEvent>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;

        // Pushdown: when the filter is a pure AND-conjunction (no OR/NOT),
        // push every leaf this MVP has an indexed column for into SQL —
        // exactly the same 8 columns `query()` already filters on above.
        // Any leaf without a matching column, and the whole filter when it
        // contains OR/NOT, is left to the residual `eval_ast` pass below —
        // pushdown here is a pure performance optimization: every returned
        // row is re-checked against the *entire* original filter before
        // being included, so a pushdown bug can only over-fetch, never
        // return a wrong result.
        let mut sql = "SELECT raw_json FROM events WHERE 1=1".to_string();
        let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(filter) = &plan.filter {
            if let Some(leaves) = conjunction_leaves(filter) {
                for (field, op, value) in leaves {
                    if op != Op::Eq {
                        continue;
                    }
                    let column = match field {
                        "event_type" => "event_type",
                        "process.process_key" => "process_key",
                        "file.path" => "file_path",
                        "dns.query" => "dns_domain",
                        "session.session_id" => "session_id",
                        "user.uid" => "user_uid",
                        "service.unit_name" => "unit_name",
                        "container.container_id" => "container_id",
                        _ => continue,
                    };
                    match value {
                        Value::Str(s) => {
                            sql.push_str(&format!(" AND {} = ?", column));
                            sql_params.push(Box::new(s.clone()));
                        }
                        Value::Num(n) => {
                            sql.push_str(&format!(" AND {} = ?", column));
                            sql_params.push(Box::new(*n as i64));
                        }
                        Value::List(_) => continue,
                    }
                }
            }
        }
        if let Some(since) = plan.since {
            sql.push_str(" AND timestamp >= ?");
            sql_params.push(Box::new(since.min(i64::MAX as u64) as i64));
        }
        if let Some(until) = plan.until {
            sql.push_str(" AND timestamp <= ?");
            sql_params.push(Box::new(until.min(i64::MAX as u64) as i64));
        }
        // Prefetch more than the final cap so the residual pass below has
        // real candidates to filter from when pushdown covered only part
        // (or none) of the filter — still bounded, never a full scan of an
        // unbounded events table.
        const PREFETCH_LIMIT: i64 = 20_000;
        sql.push_str(" ORDER BY timestamp ASC LIMIT ?");
        sql_params.push(Box::new(PREFETCH_LIMIT));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| StorageError::Backend(e.to_string()))?;
            let event: CanonicalEvent = serde_json::from_str(&raw_json)
                .map_err(|e| StorageError::Serialize(e.to_string()))?;
            if plan.filter.as_ref().is_none_or(|f| eval_ast(&event, f)) {
                events.push(event);
            }
            if events.len() >= plan.effective_limit() {
                break;
            }
        }
        Ok(events)
    }
```

```rust
// crates/osiris-storage-sqlite/src/sqlite_storage.rs — free function, added
// near the top of the file (outside the impl block):

/// `Some(leaves)` when `ast` is a pure `AND`-chain of `Compare` leaves (no
/// `OR`/`NOT` anywhere) — the only shape this MVP's pushdown handles.
/// `None` for anything else, telling the caller to skip pushdown for this
/// filter and rely on `eval_ast` alone (still bounded by `since`/`until`
/// and `PREFETCH_LIMIT`).
fn conjunction_leaves(ast: &Ast) -> Option<Vec<(&str, Op, &Value)>> {
    match ast {
        Ast::Compare { field, op, value } => Some(vec![(field.as_str(), *op, value)]),
        Ast::And(l, r) => {
            let mut left = conjunction_leaves(l)?;
            let right = conjunction_leaves(r)?;
            left.extend(right);
            Some(left)
        }
        Ast::Or(_, _) | Ast::Not(_) => None,
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-storage-sqlite query_events -- --nocapture`
Expected: PASS (6 tests)

- [ ] **Step 6: Run the full crate's test suite**

Run: `cargo test -p osiris-storage-sqlite`
Expected: PASS (all existing tests plus the 6 new ones — `query`'s existing behavior is untouched, `query_events` is additive)

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-storage-sqlite/Cargo.toml crates/osiris-storage-sqlite/src/sqlite_storage.rs
git commit -m "feat(storage-sqlite): implement query_events with column pushdown and residual eval_ast fallback"
```

---

## Part 2 — `osiris-investigate`: Investigation Engine

### Task 8: Crate skeleton + shared `Story` type + `assemble` helper

**Files:**
- Create: `crates/osiris-investigate/Cargo.toml`
- Create: `crates/osiris-investigate/src/lib.rs`
- Create: `crates/osiris-investigate/src/support.rs`
- Test: `crates/osiris-investigate/src/support.rs` (inline)

**Interfaces:**
- Consumes: `osiris_schema::{CanonicalEvent, Alert}`, `osiris_storage::{Storage, AlertQueryPlan, StorageError}`.
- Produces: `pub struct Story { pub events: Vec<CanonicalEvent>, pub alerts: Vec<Alert> }` (serde `Serialize`), `pub fn assemble(storage: &dyn Storage, events: Vec<CanonicalEvent>) -> Result<Story, StorageError>` — consumed by every `*_story` task (9-15).

- [ ] **Step 1: Create the crate manifest**

```toml
# crates/osiris-investigate/Cargo.toml
[package]
name = "osiris-investigate"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
uuid = { workspace = true }
osiris-schema = { path = "../osiris-schema" }
osiris-storage = { path = "../osiris-storage" }
osiris-query = { path = "../osiris-query" }
osiris-correlate = { path = "../osiris-correlate" }

[dev-dependencies]
osiris-storage-sqlite = { path = "../osiris-storage-sqlite" }
tempfile = { workspace = true }
serde_json = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

```rust
// crates/osiris-investigate/src/support.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn sample_event(pid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", pid, timestamp),
                pid,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn assemble_sorts_events_by_timestamp_then_event_id() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let late = sample_event(2, 200);
        let early = sample_event(1, 100);
        let story = assemble(&storage, vec![late.clone(), early.clone()]).unwrap();
        assert_eq!(story.events[0].event_id, early.event_id);
        assert_eq!(story.events[1].event_id, late.event_id);
    }

    #[test]
    fn assemble_returns_no_alerts_for_an_empty_event_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let story = assemble(&storage, vec![]).unwrap();
        assert!(story.alerts.is_empty());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p osiris-investigate support:: -- --nocapture`
Expected: FAIL with "cannot find function `assemble` / type `CanonicalEvent`"

- [ ] **Step 4: Implement `Story` and `assemble`**

```rust
// crates/osiris-investigate/src/support.rs (add above the tests module)
use osiris_schema::{Alert, CanonicalEvent};
use osiris_storage::{AlertQueryPlan, Storage, StorageError};
use serde::Serialize;

/// The `{ events, alerts }` shape every `*_story` operation returns
/// (ARCHITECTURE.md §12.1). One shared type serializes identically to the
/// five distinct `FileStory`/`NetworkStory`/... structs `osiris-api` used
/// to define locally (plan Global Constraint #4: the JSON *shape* stays
/// unchanged, even though the Rust type backing it is now shared).
#[derive(Debug, Serialize)]
pub struct Story {
    pub events: Vec<CanonicalEvent>,
    pub alerts: Vec<Alert>,
}

/// Sorts `events` into a stable time order and attaches every `Alert`
/// whose evidence cites one of them — the composition step every
/// `*_story` operation shares (ARCHITECTURE.md §12.1: "assembled and
/// returned as a time-ordered structure").
pub fn assemble(storage: &dyn Storage, mut events: Vec<CanonicalEvent>) -> Result<Story, StorageError> {
    events.sort_by_key(|e| (e.timestamp, e.event_id));

    let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
    let alerts = if evidence_ids.is_empty() {
        vec![]
    } else {
        let mut plan = AlertQueryPlan::new();
        plan.evidence_event_ids = evidence_ids;
        plan.limit = 10_000;
        storage.query_alerts(&plan)?
    };

    Ok(Story { events, alerts })
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p osiris-investigate support:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 6: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs
pub mod support;
pub use support::{assemble, Story};
```

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-investigate/Cargo.toml crates/osiris-investigate/src/lib.rs crates/osiris-investigate/src/support.rs
git commit -m "feat(investigate): osiris-investigate crate skeleton, shared Story type and assemble helper"
```

### Task 9: `file_story` (refactored, behavior preserved, routed through `EventQueryPlan`)

**Files:**
- Create: `crates/osiris-investigate/src/file_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/file_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8), `osiris_query::{EventQueryPlan, ast::{Ast, Op, Value}}`, `osiris_schema::FileIdentity`.
- Produces: `pub fn file_story(storage: &dyn Storage, path: Option<&str>, file_id: Option<FileIdentity>) -> Result<Story, StorageError>` — consumed by `osiris-api`'s refactored `file_story_handler` (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/file_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, FileRef, HostRef, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn file_event(event_type: EventType, path: &str, inode: u64, device_id: u64, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::File,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: Some(FileRef {
                path: path.to_string(),
                previous_path: None,
                inode: Some(inode),
                device_id: Some(device_id),
                size: None,
                mode: None,
                owner_uid: None,
                owner_gid: None,
                hash: None,
            }),
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn file_story_by_path_follows_a_rename_via_inode_and_device_id() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&file_event(EventType::FileCreate, "/tmp/a.txt", 111, 1, 100)).unwrap();
        storage.write(&file_event(EventType::FileRename, "/tmp/b.txt", 111, 1, 200)).unwrap();

        let story = file_story(&storage, Some("/tmp/a.txt"), None).unwrap();
        assert_eq!(story.events.len(), 2, "both the original and renamed-to path must appear");
        assert_eq!(story.events[0].timestamp, 100);
        assert_eq!(story.events[1].timestamp, 200);
    }

    #[test]
    fn file_story_by_file_id_looks_up_identity_directly() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&file_event(EventType::FileCreate, "/tmp/a.txt", 222, 1, 100)).unwrap();
        let identity = osiris_schema::FileIdentity::new(222, 1);

        let story = file_story(&storage, None, Some(identity)).unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[test]
    fn file_story_with_no_matches_returns_an_empty_story() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let story = file_story(&storage, Some("/nowhere"), None).unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate file_story:: -- --nocapture`
Expected: FAIL with "cannot find function `file_story`"

- [ ] **Step 3: Implement `file_story`**

```rust
// crates/osiris-investigate/src/file_story.rs (add above the tests module)
use std::collections::{HashMap, HashSet};

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, FileIdentity};
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

fn identity_filter_plan(identity: FileIdentity) -> EventQueryPlan {
    let ast = Ast::And(
        Box::new(Ast::Compare {
            field: "file.inode".to_string(),
            op: Op::Eq,
            value: Value::Num(identity.inode as f64),
        }),
        Box::new(Ast::Compare {
            field: "file.device_id".to_string(),
            op: Op::Eq,
            value: Value::Num(identity.device_id as f64),
        }),
    );
    EventQueryPlan {
        filter: Some(ast),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

fn path_filter_plan(path: &str) -> EventQueryPlan {
    EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "file.path".to_string(),
            op: Op::Eq,
            value: Value::Str(path.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

/// ARCHITECTURE.md §12.1's File Story, refactored from `osiris-api`'s
/// former `file_story_handler` into a reusable composition: `path`
/// resolves to every event carrying that literal path, plus (via the
/// `FileIdentity` those events carry) every event sharing the same
/// `(inode, device_id)` — the join that survives a `FILE_RENAME` — and
/// `file_id` looks an identity up directly, both routed through
/// `EventQueryPlan` (ARCHITECTURE.md §12.3) instead of the fixed-field
/// `osiris_storage::QueryPlan` the old handler used.
pub fn file_story(
    storage: &dyn Storage,
    path: Option<&str>,
    file_id: Option<FileIdentity>,
) -> Result<Story, StorageError> {
    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
    let mut identities: HashSet<FileIdentity> = HashSet::new();

    if let Some(identity) = file_id {
        identities.insert(identity);
    }

    if let Some(path) = path {
        let path_events = storage.query_events(&path_filter_plan(path))?;
        for e in &path_events {
            if let Some(file) = &e.file {
                if let Some(id) = FileIdentity::from_file_ref(file) {
                    identities.insert(id);
                }
            }
        }
        for e in path_events {
            events_by_id.insert(e.event_id, e);
        }
    }

    for identity in &identities {
        for e in storage.query_events(&identity_filter_plan(*identity))? {
            events_by_id.insert(e.event_id, e);
        }
    }

    assemble(storage, events_by_id.into_values().collect())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate file_story:: -- --nocapture`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod file_story;
pub use file_story::file_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/file_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): file_story, refactored onto EventQueryPlan"
```

### Task 10: `network_story` (refactored, behavior preserved)

**Files:**
- Create: `crates/osiris-investigate/src/network_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/network_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8), `osiris_query::{EventQueryPlan, ast::{Ast, Op, Value}}`.
- Produces: `pub fn network_story(storage: &dyn Storage, ip: Option<&str>, domain: Option<&str>) -> Result<Story, StorageError>` — consumed by `osiris-api`'s refactored `network_story_handler` (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/network_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, DnsRef, EventType, HostRef, NetworkDirection, NetworkRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Network,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None, container: None, namespace: None,
            cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    fn dns_event(query: &str, response_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = base_event(EventType::DnsQuery, timestamp);
        e.dns = Some(DnsRef {
            query: query.to_string(),
            qtype: "A".to_string(),
            response_ips: vec![response_ip.to_string()],
            ttl: None,
        });
        e
    }

    fn network_event(src_ip: &str, dst_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = base_event(EventType::NetworkConnect, timestamp);
        e.network = Some(NetworkRef {
            src_ip: src_ip.to_string(),
            src_port: 12345,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes: None,
        });
        e
    }

    #[test]
    fn network_story_by_domain_unions_in_events_touching_the_resolved_ip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&dns_event("evil.example", "203.0.113.10", 100)).unwrap();
        storage.write(&network_event("10.0.0.5", "203.0.113.10", 200)).unwrap();
        storage.write(&network_event("10.0.0.5", "198.51.100.1", 300)).unwrap();

        let story = network_story(&storage, None, Some("evil.example")).unwrap();
        assert_eq!(story.events.len(), 2, "the DNS event and the one matching network event");
    }

    #[test]
    fn network_story_by_ip_matches_either_side_of_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&network_event("203.0.113.10", "10.0.0.5", 100)).unwrap();
        storage.write(&network_event("10.0.0.5", "203.0.113.10", 200)).unwrap();
        storage.write(&network_event("10.0.0.5", "198.51.100.1", 300)).unwrap();

        let story = network_story(&storage, Some("203.0.113.10"), None).unwrap();
        assert_eq!(story.events.len(), 2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate network_story:: -- --nocapture`
Expected: FAIL with "cannot find function `network_story`"

- [ ] **Step 3: Implement `network_story`**

```rust
// crates/osiris-investigate/src/network_story.rs (add above the tests module)
use std::collections::{HashMap, HashSet};

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::CanonicalEvent;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

fn dns_domain_plan(domain: &str) -> EventQueryPlan {
    EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "dns.query".to_string(),
            op: Op::Eq,
            value: Value::Str(domain.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

fn network_addr_plan(addr: &str) -> EventQueryPlan {
    let ast = Ast::Or(
        Box::new(Ast::Compare { field: "network.src_ip".to_string(), op: Op::Eq, value: Value::Str(addr.to_string()) }),
        Box::new(Ast::Compare { field: "network.dst_ip".to_string(), op: Op::Eq, value: Value::Str(addr.to_string()) }),
    );
    EventQueryPlan {
        filter: Some(ast),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

/// ARCHITECTURE.md §12.1's Network Story, refactored from `osiris-api`'s
/// former `network_story_handler` — the same disclosed asymmetry as
/// before: the domain form resolves DNS then unions in network events
/// touching any resolved address; the IP form matches network events
/// directly and does not reverse-resolve to the DNS side.
pub fn network_story(storage: &dyn Storage, ip: Option<&str>, domain: Option<&str>) -> Result<Story, StorageError> {
    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();

    if let Some(domain) = domain {
        let dns_events = storage.query_events(&dns_domain_plan(domain))?;
        let mut resolved_ips: HashSet<String> = HashSet::new();
        for e in &dns_events {
            if let Some(dns) = &e.dns {
                resolved_ips.extend(dns.response_ips.iter().cloned());
            }
        }
        for e in dns_events {
            events_by_id.insert(e.event_id, e);
        }
        for addr in &resolved_ips {
            for e in storage.query_events(&network_addr_plan(addr))? {
                events_by_id.insert(e.event_id, e);
            }
        }
    }

    if let Some(ip) = ip {
        for e in storage.query_events(&network_addr_plan(ip))? {
            events_by_id.insert(e.event_id, e);
        }
    }

    assemble(storage, events_by_id.into_values().collect())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate network_story:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod network_story;
pub use network_story::network_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/network_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): network_story, refactored onto EventQueryPlan"
```

### Task 11: `identity_story` (refactored, behavior preserved)

**Files:**
- Create: `crates/osiris-investigate/src/identity_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/identity_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8).
- Produces: `pub fn identity_story(storage: &dyn Storage, session_id: Option<&str>, uid: Option<u32>) -> Result<Story, StorageError>` — consumed by `osiris-api`'s refactored `identity_story_handler` (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/identity_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SessionRef, UserRef, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn session_event(session_id: &str, uid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::SessionLogin,
            category: Category::Identity,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: Some(UserRef { uid, gid: uid, euid: uid, egid: uid, username: None, loginuid: Some(uid) }),
            session: Some(SessionRef { session_id: session_id.to_string(), tty: None, remote_addr: None, auth_method: None }),
            process: None, parent_process: None, thread: None, file: None, network: None, dns: None,
            device: None, service: None, container: None, namespace: None, cgroup: None, kernel: None,
            source: Source::Synthetic, provider: "test".to_string(), raw_event: None, relationships: vec![],
            tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn identity_story_by_session_id_returns_the_whole_session() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&session_event("sess-1", 1000, 100)).unwrap();
        storage.write(&session_event("sess-2", 1000, 200)).unwrap();

        let story = identity_story(&storage, Some("sess-1"), None).unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[test]
    fn identity_story_by_uid_and_session_id_intersects_both() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&session_event("sess-1", 1000, 100)).unwrap();
        storage.write(&session_event("sess-1", 2000, 200)).unwrap();

        let story = identity_story(&storage, Some("sess-1"), Some(1000)).unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].user.as_ref().unwrap().uid, 1000);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate identity_story:: -- --nocapture`
Expected: FAIL with "cannot find function `identity_story`"

- [ ] **Step 3: Implement `identity_story`**

```rust
// crates/osiris-investigate/src/identity_story.rs (add above the tests module)
use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Identity Story, refactored from `osiris-api`'s
/// former `identity_story_handler`. `session_id` alone already returns the
/// whole multi-category chain the Enrich stage attaches to every
/// descendant of a login; `uid` alone does NOT expand to every session
/// that user opened (deliberately — that fan-out needs the graph, not a
/// flat filter); both given intersects, expressed as one `AND` node so a
/// single `query_events` call does the intersection.
pub fn identity_story(storage: &dyn Storage, session_id: Option<&str>, uid: Option<u32>) -> Result<Story, StorageError> {
    let session_ast = session_id.map(|s| Ast::Compare {
        field: "session.session_id".to_string(),
        op: Op::Eq,
        value: Value::Str(s.to_string()),
    });
    let uid_ast = uid.map(|u| Ast::Compare {
        field: "user.uid".to_string(),
        op: Op::Eq,
        value: Value::Num(u as f64),
    });

    let filter = match (session_ast, uid_ast) {
        (Some(s), Some(u)) => Some(Ast::And(Box::new(s), Box::new(u))),
        (Some(s), None) => Some(s),
        (None, Some(u)) => Some(u),
        (None, None) => None,
    };

    let plan = EventQueryPlan {
        filter,
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate identity_story:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod identity_story;
pub use identity_story::identity_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/identity_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): identity_story, refactored onto EventQueryPlan"
```

### Task 12: `systemd_story` (refactored, behavior preserved)

**Files:**
- Create: `crates/osiris-investigate/src/systemd_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/systemd_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8).
- Produces: `pub fn systemd_story(storage: &dyn Storage, unit_name: &str) -> Result<Story, StorageError>` — consumed by `osiris-api`'s refactored `systemd_story_handler` (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/systemd_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, ServiceRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn service_event(unit_name: &str, event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Systemd,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None,
            service: Some(ServiceRef { unit_name: unit_name.to_string(), unit_type: "service".to_string(), action: "start".to_string() }),
            container: None, namespace: None, cgroup: None, kernel: None, source: Source::Synthetic,
            provider: "test".to_string(), raw_event: None, relationships: vec![], tags: vec![], risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn systemd_story_covers_both_lifecycle_and_unit_file_events_for_one_unit() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&service_event("evil.service", EventType::ServiceCreate, 100)).unwrap();
        storage.write(&service_event("evil.service", EventType::ServiceStart, 200)).unwrap();
        storage.write(&service_event("other.service", EventType::ServiceStart, 300)).unwrap();

        let story = systemd_story(&storage, "evil.service").unwrap();
        assert_eq!(story.events.len(), 2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate systemd_story:: -- --nocapture`
Expected: FAIL with "cannot find function `systemd_story`"

- [ ] **Step 3: Implement `systemd_story`**

```rust
// crates/osiris-investigate/src/systemd_story.rs (add above the tests module)
use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Systemd Story, refactored from `osiris-api`'s
/// former `systemd_story_handler`. One `service.unit_name` filter spans
/// both the Systemd sensor's runtime lifecycle events and the Persistence
/// Monitor's unit-file lifecycle events, since Normalize populates the
/// field identically for both.
pub fn systemd_story(storage: &dyn Storage, unit_name: &str) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "service.unit_name".to_string(),
            op: Op::Eq,
            value: Value::Str(unit_name.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate systemd_story:: -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod systemd_story;
pub use systemd_story::systemd_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/systemd_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): systemd_story, refactored onto EventQueryPlan"
```

### Task 13: `container_story` (refactored, behavior preserved)

**Files:**
- Create: `crates/osiris-investigate/src/container_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/container_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8).
- Produces: `pub fn container_story(storage: &dyn Storage, container_id: &str) -> Result<Story, StorageError>` — consumed by `osiris-api`'s refactored `container_story_handler` (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/container_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, ContainerRef, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn container_event(container_id: &str, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ContainerStart,
            category: Category::Container,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None,
            container: Some(ContainerRef { container_id: container_id.to_string(), image: "img".to_string(), runtime: "docker".to_string(), pod_ref: None }),
            namespace: None, cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn container_story_returns_only_that_containers_events() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&container_event("c1", 100)).unwrap();
        storage.write(&container_event("c2", 200)).unwrap();

        let story = container_story(&storage, "c1").unwrap();
        assert_eq!(story.events.len(), 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate container_story:: -- --nocapture`
Expected: FAIL with "cannot find function `container_story`"

- [ ] **Step 3: Implement `container_story`**

```rust
// crates/osiris-investigate/src/container_story.rs (add above the tests module)
use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Container Story, refactored from `osiris-api`'s
/// former `container_story_handler`. One `container.container_id` filter
/// spans both the Container sensor's own lifecycle events and every other
/// category's events enriched with that container's id by
/// `NsCgroupResolver`.
pub fn container_story(storage: &dyn Storage, container_id: &str) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "container.container_id".to_string(),
            op: Op::Eq,
            value: Value::Str(container_id.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate container_story:: -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod container_story;
pub use container_story::container_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/container_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): container_story, refactored onto EventQueryPlan"
```

### Task 14: `process_story` (new)

**Files:**
- Create: `crates/osiris-investigate/src/process_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/process_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8), `osiris_schema::ProcessKey`.
- Produces: `pub fn process_story(storage: &dyn Storage, process_key: ProcessKey) -> Result<Story, StorageError>` — consumed by `osiris-api`'s new `process_story` endpoint (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/process_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, FileRef, HostRef, ProcessRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn exec_event(process_key: ProcessKey, parent_key: Option<ProcessKey>, pid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None,
            process: Some(ProcessRef { process_key, pid, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: timestamp }),
            parent_process: parent_key.map(|k| ProcessRef { process_key: k, pid: 0, exe_path: String::new(), cmdline: vec![], exe_hash: None, start_time_mono: 0 }),
            thread: None, file: None, network: None, dns: None, device: None, service: None, container: None,
            namespace: None, cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    fn write_event(process_key: ProcessKey, path: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = exec_event(process_key, None, 1, timestamp);
        e.event_type = EventType::FileWrite;
        e.category = Category::File;
        e.file = Some(FileRef { path: path.to_string(), previous_path: None, inode: None, device_id: None, size: None, mode: None, owner_uid: None, owner_gid: None, hash: None });
        e
    }

    #[test]
    fn process_story_includes_the_processs_own_activity_and_its_direct_children() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_id = Uuid::new_v4();
        let parent_key = ProcessKey::new(host_id, "b", 10, 100);
        let child_key = ProcessKey::new(host_id, "b", 20, 200);

        storage.write(&exec_event(parent_key, None, 10, 100)).unwrap();
        storage.write(&write_event(parent_key, "/etc/passwd", 150)).unwrap();
        storage.write(&exec_event(child_key, Some(parent_key), 20, 200)).unwrap();
        storage.write(&exec_event(ProcessKey::new(host_id, "b", 99, 999), None, 99, 999)).unwrap();

        let story = process_story(&storage, parent_key).unwrap();
        assert_eq!(story.events.len(), 3, "own exec, own file write, and the direct child's exec");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate process_story:: -- --nocapture`
Expected: FAIL with "cannot find function `process_story`"

- [ ] **Step 3: Implement `process_story`**

```rust
// crates/osiris-investigate/src/process_story.rs (add above the tests module)
use std::collections::HashMap;

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, ProcessKey};
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Process Story (new in this phase). Two
/// `EventQueryPlan` queries: every event where this process is the acting
/// `process` (covers exec/exit and every `WROTE`/`READ`/`CONNECTED_TO`/
/// `EXECUTED_AS` category event, since Normalize always attaches the acting
/// process the same way `session_id`/`unit_name`/`container_id` are
/// attached in earlier phases), plus every event where this process is the
/// `parent_process` (its direct children's own exec events — one level of
/// descendant lineage). Full n-level ancestor/descendant graph walking is
/// what `reconstruct_incident` and the Entity Graph v2 subgraph (both
/// later in this Part) provide instead of duplicating a graph walk here.
pub fn process_story(storage: &dyn Storage, process_key: ProcessKey) -> Result<Story, StorageError> {
    let own_plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let children_plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "parent_process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };

    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
    for e in storage.query_events(&own_plan)? {
        events_by_id.insert(e.event_id, e);
    }
    for e in storage.query_events(&children_plan)? {
        events_by_id.insert(e.event_id, e);
    }

    assemble(storage, events_by_id.into_values().collect())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate process_story:: -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod process_story;
pub use process_story::process_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/process_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): process_story (new)"
```

### Task 15: `system_story` (new)

**Files:**
- Create: `crates/osiris-investigate/src/system_story.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/system_story.rs` (inline)

**Interfaces:**
- Consumes: `Story`/`assemble` (Task 8).
- Produces: `pub fn system_story(storage: &dyn Storage, host_id: Uuid, since: u64, until: u64) -> Result<Story, StorageError>` — consumed by `osiris-api`'s new `system_story` endpoint (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/system_story.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;

    fn host_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None, container: None, namespace: None,
            cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn system_story_returns_only_this_hosts_events_within_the_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_a = Uuid::new_v4();
        let host_b = Uuid::new_v4();
        storage.write(&host_event(host_a, 100)).unwrap();
        storage.write(&host_event(host_a, 500)).unwrap();
        storage.write(&host_event(host_a, 900)).unwrap();
        storage.write(&host_event(host_b, 500)).unwrap();

        let story = system_story(&storage, host_a, 200, 600).unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].timestamp, 500);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate system_story:: -- --nocapture`
Expected: FAIL with "cannot find function `system_story`"

- [ ] **Step 3: Implement `system_story`**

```rust
// crates/osiris-investigate/src/system_story.rs (add above the tests module)
use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};
use uuid::Uuid;

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's System Story (new in this phase):
/// `system_story(host_id, time_range) -> SystemStory` — every event on one
/// host within one time range, the whole-host Timeline an investigation
/// starts from before narrowing to a specific process/file/session.
pub fn system_story(storage: &dyn Storage, host_id: Uuid, since: u64, until: u64) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "host_id".to_string(),
            op: Op::Eq,
            value: Value::Str(host_id.to_string()),
        }),
        since: Some(since),
        until: Some(until),
        limit: 10_000,
        export: true,
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate system_story:: -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod system_story;
pub use system_story::system_story;
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/system_story.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): system_story (new)"
```

### Task 16: `Storage::get_event` (event-by-id lookup)

`reconstruct_incident` (Task 17) needs to resolve a `BehavioralChain`'s `event_ids` back into real `CanonicalEvent`s to bucket them by category — something none of the four existing typed plans or `EventQueryPlan` do (both filter by field values, never by primary key list). This task adds the one missing primitive.

**Files:**
- Modify: `crates/osiris-storage/src/storage.rs`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`
- Test: `crates/osiris-storage-sqlite/src/sqlite_storage.rs` (inline, alongside the Task 7 tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError>` on the `Storage` trait — consumed by `reconstruct_incident` (Task 17).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-storage-sqlite/src/sqlite_storage.rs — add to the existing tests module
    #[test]
    fn get_event_returns_the_matching_event_by_id() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let event = sample_event(1, None, 100);
        let event_id = event.event_id;
        storage.write(&event).unwrap();
        let found = storage.get_event(event_id).unwrap();
        assert_eq!(found.unwrap().event_id, event_id);
    }

    #[test]
    fn get_event_returns_none_for_an_unknown_id() {
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        assert!(storage.get_event(Uuid::new_v4()).unwrap().is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-storage-sqlite get_event -- --nocapture`
Expected: FAIL with "no method named `get_event`"

- [ ] **Step 3: Add the trait method**

```rust
// crates/osiris-storage/src/storage.rs — add to the Storage trait, after query_events:
    /// Looks up one event by its primary key. Added for `osiris-investigate`'s
    /// `reconstruct_incident` (ARCHITECTURE.md §12.1), which must resolve a
    /// `BehavioralChain`'s bare `event_id`s back into real events to bucket
    /// them by category — none of this trait's field-filtering query
    /// methods can do that.
    fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError>;
```

Add `use uuid::Uuid;` to `crates/osiris-storage/src/storage.rs`'s imports if not already present (check with `grep -n "^use" crates/osiris-storage/src/storage.rs` first).

- [ ] **Step 4: Implement it in `SqliteStorage`**

```rust
// crates/osiris-storage-sqlite/src/sqlite_storage.rs — add to `impl Storage for SqliteStorage`, after query_events:
    fn get_event(&self, event_id: Uuid) -> Result<Option<CanonicalEvent>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StorageError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM events WHERE event_id = ?",
                rusqlite::params![event_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => {
                let event = serde_json::from_str(&json).map_err(|e| StorageError::Serialize(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-storage-sqlite get_event -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-storage/src/storage.rs crates/osiris-storage-sqlite/src/sqlite_storage.rs
git commit -m "feat(storage): add Storage::get_event for event-id lookup"
```

### Task 17: `reconstruct_incident` (new)

**Files:**
- Create: `crates/osiris-investigate/src/reconstruct_incident.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/reconstruct_incident.rs` (inline)

**Interfaces:**
- Consumes: `osiris_correlate::{CorrelationEngine, EdgeSource, BehavioralChain}`, `osiris_schema::{EntityRef, Category}`, `Storage::query_relationships`/`get_event` (Task 16).
- Produces: `pub struct IncidentReconstruction { pub seed: EntityRef, pub stages: Vec<IncidentStage> }`, `pub struct IncidentStage { pub category: Category, pub event_ids: Vec<Uuid> }`, `pub fn reconstruct_incident(storage: &dyn Storage, seed: EntityRef, since: u64, until: u64) -> Result<IncidentReconstruction, StorageError>` — consumed by `osiris-api`'s new `reconstruct_incident` endpoint (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/reconstruct_incident.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, NetworkDirection, NetworkRef, ProcessKey, ProcessRef,
        Relation, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage::EntityRelationship;
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(category: Category, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::NetworkConnect,
            category,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: Some(NetworkRef { src_ip: "10.0.0.1".to_string(), src_port: 1, dst_ip: "10.0.0.2".to_string(), dst_port: 2, proto: "tcp".to_string(), direction: NetworkDirection::Outbound, bytes: None }),
            dns: None, device: None, service: None, container: None, namespace: None, cgroup: None,
            kernel: None, source: Source::Synthetic, provider: "test".to_string(), raw_event: None,
            relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn reconstruct_incident_buckets_the_chains_events_by_category_in_time_order() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 1, 1);

        let exec_event = { let mut e = base_event(Category::Process, 100); e.event_type = EventType::ProcessExec; e.process = Some(ProcessRef { process_key, pid: 1, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 100 }); e.network = None; e };
        let network_event = base_event(Category::Network, 200);
        storage.write(&exec_event).unwrap();
        storage.write(&network_event).unwrap();

        let seed = EntityRef::Process { process_key };
        storage
            .write_relationships(&[EntityRelationship {
                from: seed.clone(),
                to: EntityRef::Ip { addr: "10.0.0.2".to_string() },
                relation: Relation::ConnectedTo,
                event_id: network_event.event_id,
                timestamp: 200,
            }])
            .unwrap();

        let reconstruction = reconstruct_incident(&storage, seed.clone(), 0, 1000).unwrap();
        assert_eq!(reconstruction.seed, seed);
        let network_stage = reconstruction
            .stages
            .iter()
            .find(|s| s.category == Category::Network)
            .expect("expected a Network stage");
        assert!(network_stage.event_ids.contains(&network_event.event_id));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate reconstruct_incident:: -- --nocapture`
Expected: FAIL with "cannot find function `reconstruct_incident`"

- [ ] **Step 3: Implement `reconstruct_incident`**

```rust
// crates/osiris-investigate/src/reconstruct_incident.rs (add above the tests module)
use serde::Serialize;
use uuid::Uuid;

use osiris_correlate::{CorrelationEngine, EdgeSource};
use osiris_schema::{Category, CanonicalEvent, EntityRef, EntityRelationship};
use osiris_storage::{RelationshipQueryPlan, Storage, StorageError};

/// The staged bucketing order ARCHITECTURE.md §12.1 and the master
/// prompt's worked trace call for: `INITIAL EVENT -> EXECUTION ->
/// FILESYSTEM -> NETWORK -> PRIVILEGE -> PERSISTENCE -> IMPACT`, expressed
/// in terms of this schema's `Category` values (`Dns`/`KernelModule`/
/// `Container`/`Security`/`System` are appended after the named stages so
/// no category is silently dropped from a chain that touches one of them).
const STAGE_ORDER: &[Category] = &[
    Category::Identity,
    Category::Process,
    Category::File,
    Category::Network,
    Category::Privilege,
    Category::Persistence,
    Category::Systemd,
    Category::Dns,
    Category::KernelModule,
    Category::Container,
    Category::Security,
    Category::System,
];

#[derive(Debug, Serialize)]
pub struct IncidentStage {
    pub category: Category,
    pub event_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct IncidentReconstruction {
    pub seed: EntityRef,
    pub stages: Vec<IncidentStage>,
}

struct StorageEdgeSource<'s> {
    storage: &'s dyn Storage,
}

impl EdgeSource for StorageEdgeSource<'_> {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship> {
        let plan = RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(since),
            until: Some(until),
            ..RelationshipQueryPlan::new()
        };
        self.storage.query_relationships(&plan).unwrap_or_default()
    }
}

/// ARCHITECTURE.md §12.1's `reconstruct_incident(seed_entity, time_range)`:
/// walks the Correlation Engine's `BehavioralChain` from `seed`, resolves
/// every edge's `event_id` back into a real event (Task 16's
/// `Storage::get_event`), and buckets them by `category` in `STAGE_ORDER`
/// — every bucket entry is a bare `event_id`, so a caller always has the
/// exact evidence for each stage (ARCHITECTURE.md §44: "every conclusion
/// must have evidence").
pub fn reconstruct_incident(
    storage: &dyn Storage,
    seed: EntityRef,
    since: u64,
    until: u64,
) -> Result<IncidentReconstruction, StorageError> {
    let source = StorageEdgeSource { storage };
    let engine = CorrelationEngine::new(5, (until.saturating_sub(since)).max(1));
    let seed_time_ns = since + (until.saturating_sub(since)) / 2;
    let chain = engine.build_chain(&source, seed.clone(), seed_time_ns);

    let mut by_category: std::collections::HashMap<Category, Vec<Uuid>> = std::collections::HashMap::new();
    for event_id in &chain.event_ids {
        if let Some(event) = storage.get_event(*event_id)? {
            by_category.entry(event.category).or_default().push(*event_id);
        }
    }

    let stages = STAGE_ORDER
        .iter()
        .filter_map(|category| {
            by_category.get(category).map(|event_ids| IncidentStage {
                category: *category,
                event_ids: event_ids.clone(),
            })
        })
        .collect();

    Ok(IncidentReconstruction { seed, stages })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate reconstruct_incident:: -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Wire into `lib.rs`**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod reconstruct_incident;
pub use reconstruct_incident::{reconstruct_incident, IncidentReconstruction, IncidentStage};
```

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/reconstruct_incident.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): reconstruct_incident (new)"
```

### Task 18: Entity Graph v2 — bounded `{nodes, edges}` subgraph

**Files:**
- Create: `crates/osiris-investigate/src/subgraph.rs`
- Modify: `crates/osiris-investigate/src/lib.rs`
- Test: `crates/osiris-investigate/src/subgraph.rs` (inline)

**Interfaces:**
- Consumes: `osiris_schema::{EntityRef, Relation, EntityRelationship}`, `osiris_storage::{RelationshipQueryPlan, Storage, StorageError}`.
- Produces: `pub struct GraphNode { pub id: String, pub kind: String }`, `pub struct GraphEdge { pub from: String, pub to: String, pub relation: Relation, pub event_id: Uuid, pub timestamp: u64 }`, `pub struct Subgraph { pub nodes: Vec<GraphNode>, pub edges: Vec<GraphEdge>, pub truncated: bool }`, `pub fn subgraph(storage: &dyn Storage, seed: EntityRef, max_depth: usize, max_nodes: usize, since: u64, until: u64) -> Result<Subgraph, StorageError>` — consumed by `osiris-api`'s new `/api/v1/graph/subgraph` endpoint (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-investigate/src/subgraph.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_storage_sqlite::SqliteStorage;

    fn edge(from: EntityRef, to: EntityRef, timestamp: u64) -> EntityRelationship {
        EntityRelationship { from, to, relation: Relation::ConnectedTo, event_id: Uuid::now_v7(), timestamp }
    }

    #[test]
    fn subgraph_stops_expanding_once_max_nodes_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let seed = EntityRef::Ip { addr: "10.0.0.1".to_string() };
        // seed -> a -> b -> c -> d, a chain of 5 distinct nodes
        let a = EntityRef::Ip { addr: "10.0.0.2".to_string() };
        let b = EntityRef::Ip { addr: "10.0.0.3".to_string() };
        let c = EntityRef::Ip { addr: "10.0.0.4".to_string() };
        let d = EntityRef::Ip { addr: "10.0.0.5".to_string() };
        storage.write_relationships(&[
            edge(seed.clone(), a.clone(), 100),
            edge(a.clone(), b.clone(), 200),
            edge(b.clone(), c.clone(), 300),
            edge(c.clone(), d.clone(), 400),
        ]).unwrap();

        let result = subgraph(&storage, seed.clone(), 10, 3, 0, 1000).unwrap();
        assert!(result.nodes.len() <= 3);
        assert!(result.truncated);
    }

    #[test]
    fn subgraph_reports_not_truncated_when_everything_reachable_fits() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let seed = EntityRef::Ip { addr: "10.0.0.1".to_string() };
        let a = EntityRef::Ip { addr: "10.0.0.2".to_string() };
        storage.write_relationships(&[edge(seed.clone(), a.clone(), 100)]).unwrap();

        let result = subgraph(&storage, seed, 10, 100, 0, 1000).unwrap();
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.edges.len(), 1);
        assert!(!result.truncated);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-investigate subgraph:: -- --nocapture`
Expected: FAIL with "cannot find function `subgraph`"

- [ ] **Step 3: Implement `subgraph`**

```rust
// crates/osiris-investigate/src/subgraph.rs (add above the tests module)
use std::collections::HashSet;

use serde::Serialize;
use uuid::Uuid;

use osiris_schema::{EntityRef, EntityRelationship, Relation};
use osiris_storage::{RelationshipQueryPlan, Storage, StorageError};

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: Relation,
    pub event_id: Uuid,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct Subgraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// `true` when more of the reachable graph existed than `max_nodes`
    /// allowed in — ARCHITECTURE.md §12.5's "never the full graph" made
    /// visible to the caller rather than silently clipped.
    pub truncated: bool,
}

fn kind_of(entity: &EntityRef) -> &'static str {
    match entity {
        EntityRef::Process { .. } => "PROCESS",
        EntityRef::File { .. } => "FILE",
        EntityRef::Ip { .. } => "IP",
        EntityRef::Domain { .. } => "DOMAIN",
        EntityRef::User { .. } => "USER",
        EntityRef::Container { .. } => "CONTAINER",
        EntityRef::Session { .. } => "SESSION",
    }
}

/// Entity Graph v2 (ARCHITECTURE.md §12.5): a bounded-depth **and**
/// bounded-node-count BFS from `seed`, returned as a generic node/edge
/// shape any graph UI can render — distinct from and additive to
/// `/api/v1/graph`'s existing `BehavioralChain` response, which stays
/// depth-bounded only and keeps serving callers that want that specific
/// shape (plan Global Constraint #4's spirit, extended to this endpoint
/// even though `/graph/subgraph` itself is new).
pub fn subgraph(
    storage: &dyn Storage,
    seed: EntityRef,
    max_depth: usize,
    max_nodes: usize,
    since: u64,
    until: u64,
) -> Result<Subgraph, StorageError> {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(seed.storage_key());
    let mut nodes = vec![GraphNode { id: seed.storage_key(), kind: kind_of(&seed).to_string() }];
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut seen_edges: HashSet<(String, String, Uuid)> = HashSet::new();
    let mut frontier = vec![seed];
    let mut truncated = false;

    for _ in 0..max_depth {
        if frontier.is_empty() {
            break;
        }
        let mut next_frontier = Vec::new();
        for entity in &frontier {
            let plan = RelationshipQueryPlan {
                entity: Some(entity.clone()),
                since: Some(since),
                until: Some(until),
                ..RelationshipQueryPlan::new()
            };
            let rels: Vec<EntityRelationship> = storage.query_relationships(&plan)?;
            for rel in rels {
                let edge_key = (rel.from.storage_key(), rel.to.storage_key(), rel.event_id);
                if !seen_edges.insert(edge_key) {
                    continue;
                }
                let this_key = entity.storage_key();
                let other = if rel.from.storage_key() == this_key { rel.to.clone() } else { rel.from.clone() };
                let other_key = other.storage_key();
                if !visited.contains(&other_key) {
                    if nodes.len() >= max_nodes {
                        // The edge would point at a node this response
                        // doesn't include — record the truncation and
                        // drop the edge too, rather than emit a dangling
                        // reference.
                        truncated = true;
                        continue;
                    }
                    visited.insert(other_key.clone());
                    nodes.push(GraphNode { id: other_key, kind: kind_of(&other).to_string() });
                    next_frontier.push(other);
                }
                edges.push(GraphEdge {
                    from: rel.from.storage_key(),
                    to: rel.to.storage_key(),
                    relation: rel.relation,
                    event_id: rel.event_id,
                    timestamp: rel.timestamp,
                });
            }
        }
        frontier = next_frontier;
    }

    Ok(Subgraph { nodes, edges, truncated })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-investigate subgraph:: -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire into `lib.rs`, then run the whole crate's tests**

```rust
// crates/osiris-investigate/src/lib.rs (append)
pub mod subgraph;
pub use subgraph::{subgraph, GraphEdge, GraphNode, Subgraph};
```

Run: `cargo test -p osiris-investigate`
Expected: PASS (every test across support/file_story/network_story/identity_story/systemd_story/container_story/process_story/system_story/reconstruct_incident/subgraph)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-investigate/src/subgraph.rs crates/osiris-investigate/src/lib.rs
git commit -m "feat(investigate): Entity Graph v2 bounded {nodes, edges} subgraph"
```

---

## Part 3 — `osiris-evidence`: Evidence + Incident Engine

This crate never depends on `osiris-storage` (Global Constraint #6) — it is its own small control-plane SQLite store (ARCHITECTURE.md §10.3), the same posture `osiris-audit`'s `FileAuditLog` already takes.

### Task 19: Crate skeleton + `Evidence` (append-only, validated) + `SqliteEvidenceStore`

**Files:**
- Create: `crates/osiris-evidence/Cargo.toml`
- Create: `crates/osiris-evidence/src/lib.rs`
- Create: `crates/osiris-evidence/src/evidence.rs`
- Create: `crates/osiris-evidence/src/store.rs`
- Test: `crates/osiris-evidence/src/evidence.rs`, `crates/osiris-evidence/src/store.rs` (inline)

**Interfaces:**
- Consumes: `osiris_schema::EntityRef`.
- Produces: `pub enum EvidenceSource`, `pub struct Integrity { pub hash: String, pub immutable_since: u64 }`, `pub struct Evidence` (private fields, getters, `Evidence::new(...) -> Result<Self, EvidenceError>`), `pub trait EvidenceStore { fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>; fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>; }`, `pub struct SqliteEvidenceStore` — consumed by the join-table task (Task 21) and the API's evidence endpoints (Part 4).

- [ ] **Step 1: Create the crate manifest**

```toml
# crates/osiris-evidence/Cargo.toml
[package]
name = "osiris-evidence"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
uuid = { workspace = true }
rusqlite = { workspace = true }
osiris-schema = { path = "../osiris-schema" }
osiris-audit = { path = "../osiris-audit" }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Write the failing test for `Evidence`**

```rust
// crates/osiris-evidence/src/evidence.rs
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn integrity() -> Integrity {
        Integrity { hash: "abc123".to_string(), immutable_since: 1000 }
    }

    #[test]
    fn a_valid_evidence_record_carries_every_field() {
        let evidence = Evidence::new(EvidenceSource::EventCapture, 1000, integrity(), vec![], None).unwrap();
        assert_eq!(evidence.source(), EvidenceSource::EventCapture);
        assert_eq!(evidence.timestamp(), 1000);
        assert_eq!(evidence.integrity().hash, "abc123");
        assert!(evidence.supersedes().is_none());
    }

    #[test]
    fn rejects_an_empty_integrity_hash() {
        let bad = Integrity { hash: String::new(), immutable_since: 1000 };
        let err = Evidence::new(EvidenceSource::EventCapture, 1000, bad, vec![], None).unwrap_err();
        assert_eq!(err, EvidenceError::EmptyHash);
    }

    #[test]
    fn supersedes_links_to_the_record_it_replaces() {
        let old_id = Uuid::now_v7();
        let evidence = Evidence::new(EvidenceSource::ManualUpload, 2000, integrity(), vec![], Some(old_id)).unwrap();
        assert_eq!(evidence.supersedes(), Some(old_id));
    }

    #[test]
    fn json_round_trip_preserves_validation() {
        let evidence = Evidence::new(EvidenceSource::EventCapture, 1000, integrity(), vec![], None).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evidence_id(), evidence.evidence_id());
    }

    #[test]
    fn deserialize_rejects_a_wire_payload_with_an_empty_hash() {
        let json = serde_json::json!({
            "evidence_id": Uuid::now_v7(),
            "source": "EVENT_CAPTURE",
            "timestamp": 1000,
            "integrity": { "hash": "", "immutable_since": 1000 },
            "relationships": [],
            "supersedes": null,
        });
        let result: Result<Evidence, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p osiris-evidence evidence:: -- --nocapture`
Expected: FAIL with "cannot find type `Evidence` / `EvidenceSource` / `Integrity` / `EvidenceError`"

- [ ] **Step 4: Implement `Evidence`**

```rust
// crates/osiris-evidence/src/evidence.rs (add above the tests module)
use osiris_schema::EntityRef;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    EventCapture,
    FileSnapshot,
    ManualUpload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub hash: String,
    pub immutable_since: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence must carry a non-empty integrity hash (ARCHITECTURE.md §12.6)")]
    EmptyHash,
}

/// A DFIR evidence record (ARCHITECTURE.md §12.6). Fields are private —
/// construction goes through the validating `new()`, and deserialization
/// through the same validation, mirroring `osiris_schema::Alert`'s
/// "enforced at the type level" posture. Append-only: there is no setter,
/// no `&mut self` method anywhere on this type — "correcting" a record is
/// always constructing a new one with `supersedes: Some(old_id)` and
/// inserting it (plan Global Constraint #7).
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    evidence_id: Uuid,
    source: EvidenceSource,
    timestamp: u64,
    integrity: Integrity,
    relationships: Vec<EntityRef>,
    supersedes: Option<Uuid>,
}

impl Evidence {
    pub fn new(
        source: EvidenceSource,
        timestamp: u64,
        integrity: Integrity,
        relationships: Vec<EntityRef>,
        supersedes: Option<Uuid>,
    ) -> Result<Self, EvidenceError> {
        Self::validate(&integrity)?;
        Ok(Self {
            evidence_id: Uuid::now_v7(),
            source,
            timestamp,
            integrity,
            relationships,
            supersedes,
        })
    }

    fn validate(integrity: &Integrity) -> Result<(), EvidenceError> {
        if integrity.hash.trim().is_empty() {
            return Err(EvidenceError::EmptyHash);
        }
        Ok(())
    }

    pub fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }
    pub fn source(&self) -> EvidenceSource {
        self.source
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }
    pub fn relationships(&self) -> &[EntityRef] {
        &self.relationships
    }
    pub fn supersedes(&self) -> Option<Uuid> {
        self.supersedes
    }
}

#[derive(Deserialize)]
struct EvidenceWire {
    evidence_id: Uuid,
    source: EvidenceSource,
    timestamp: u64,
    integrity: Integrity,
    relationships: Vec<EntityRef>,
    supersedes: Option<Uuid>,
}

impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EvidenceWire::deserialize(deserializer)?;
        Evidence::validate(&wire.integrity).map_err(serde::de::Error::custom)?;
        Ok(Evidence {
            evidence_id: wire.evidence_id,
            source: wire.source,
            timestamp: wire.timestamp,
            integrity: wire.integrity,
            relationships: wire.relationships,
            supersedes: wire.supersedes,
        })
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p osiris-evidence evidence:: -- --nocapture`
Expected: PASS (5 tests)

- [ ] **Step 6: Write the failing test for `SqliteEvidenceStore`**

```rust
// crates/osiris-evidence/src/store.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, EvidenceSource, Integrity};

    fn sample() -> Evidence {
        Evidence::new(
            EvidenceSource::EventCapture,
            1000,
            Integrity { hash: "abc".to_string(), immutable_since: 1000 },
            vec![],
            None,
        )
        .unwrap()
    }

    #[test]
    fn insert_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let inserted = store.insert(sample()).unwrap();
        let found = store.get(inserted.evidence_id()).unwrap().unwrap();
        assert_eq!(found.evidence_id(), inserted.evidence_id());
    }

    #[test]
    fn get_returns_none_for_an_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        assert!(store.get(uuid::Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn insert_never_overwrites_an_existing_record() {
        // There is no `update` method on EvidenceStore at all (plan Global
        // Constraint #7) — this test documents that inserting the *same*
        // evidence_id twice is rejected rather than silently replacing it,
        // since `Evidence` always mints a fresh `Uuid::now_v7()` in `new()`
        // and nothing on this trait accepts a caller-supplied id to collide.
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap();
        let evidence = sample();
        store.insert(evidence.clone()).unwrap();
        let err = store.insert(evidence).unwrap_err();
        assert!(matches!(err, EvidenceStoreError::Backend(_)));
    }
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cargo test -p osiris-evidence store:: -- --nocapture`
Expected: FAIL with "cannot find type `SqliteEvidenceStore` / `EvidenceStoreError`"

- [ ] **Step 8: Implement `EvidenceStore` and `SqliteEvidenceStore`**

```rust
// crates/osiris-evidence/src/store.rs (add above the tests module)
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use crate::evidence::Evidence;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceStoreError {
    #[error("evidence store backend error: {0}")]
    Backend(String),
    #[error("evidence serialize/deserialize error: {0}")]
    Serialize(String),
}

/// No `update`/`delete` method exists on this trait anywhere in this
/// crate — append-only is enforced by the trait's shape, not by
/// convention (plan Global Constraint #7).
pub trait EvidenceStore: Send + Sync {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError>;
    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError>;
}

/// Evidence's own SQLite file, independent of `osiris-storage`
/// (ARCHITECTURE.md §10.3's control-plane store, plan Global Constraint #6).
pub struct SqliteEvidenceStore {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceStoreError> {
        let conn = Connection::open(path).map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                raw_json TEXT NOT NULL
            );",
        )
        .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl EvidenceStore for SqliteEvidenceStore {
    fn insert(&self, evidence: Evidence) -> Result<Evidence, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json =
            serde_json::to_string(&evidence).map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?;
        conn.execute(
            "INSERT INTO evidence (evidence_id, raw_json) VALUES (?1, ?2)",
            rusqlite::params![evidence.evidence_id().to_string(), raw_json],
        )
        .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        Ok(evidence)
    }

    fn get(&self, evidence_id: Uuid) -> Result<Option<Evidence>, EvidenceStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EvidenceStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM evidence WHERE evidence_id = ?1",
                rusqlite::params![evidence_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| EvidenceStoreError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| EvidenceStoreError::Serialize(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `cargo test -p osiris-evidence store:: -- --nocapture`
Expected: PASS (3 tests)

- [ ] **Step 10: Wire into `lib.rs`**

```rust
// crates/osiris-evidence/src/lib.rs
pub mod evidence;
pub mod store;

pub use evidence::{Evidence, EvidenceError, EvidenceSource, Integrity};
pub use store::{EvidenceStore, EvidenceStoreError, SqliteEvidenceStore};
```

- [ ] **Step 11: Commit**

```bash
git add crates/osiris-evidence/Cargo.toml crates/osiris-evidence/src/lib.rs crates/osiris-evidence/src/evidence.rs crates/osiris-evidence/src/store.rs
git commit -m "feat(evidence): osiris-evidence crate, append-only Evidence type and SqliteEvidenceStore"
```

### Task 20: `Incident` + `IncidentStore` with audited status transitions

`osiris_audit::NewAuditEntry.target` is typed `EntityRef` (no "Incident" variant exists in `osiris_schema::EntityRef`, and adding one is out of scope — it's a shared type many things key off). This task's `transition_status` therefore audits against the incident's first associated entity, requiring `Incident::entities` to be non-empty — a deliberate, documented judgment call, not an oversight.

**Files:**
- Create: `crates/osiris-evidence/src/incident.rs`
- Modify: `crates/osiris-evidence/src/lib.rs`
- Test: `crates/osiris-evidence/src/incident.rs` (inline)

**Interfaces:**
- Consumes: `osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry}`, `osiris_schema::EntityRef`.
- Produces: `pub enum IncidentStatus`, `pub struct Incident { pub incident_id: Uuid, pub status: IncidentStatus, pub entities: Vec<EntityRef>, pub alert_ids: Vec<Uuid>, pub notes: Vec<String> }`, `pub trait IncidentStore { fn create(...); fn get(...); fn list(...); fn transition_status(...); }`, `pub struct SqliteIncidentStore`, `pub enum IncidentStoreError` — consumed by the API's incident endpoints (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-evidence/src/incident.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::{ActorRef, FileAuditLog};
    use osiris_schema::EntityRef;
    use uuid::Uuid;

    fn sample_incident() -> Incident {
        Incident {
            incident_id: Uuid::now_v7(),
            status: IncidentStatus::New,
            entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
            alert_ids: vec![],
            notes: vec![],
        }
    }

    #[test]
    fn create_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let created = store.create(sample_incident()).unwrap();
        let found = store.get(created.incident_id).unwrap().unwrap();
        assert_eq!(found.status, IncidentStatus::New);
    }

    #[test]
    fn list_returns_every_created_incident() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        store.create(sample_incident()).unwrap();
        store.create(sample_incident()).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn transition_status_writes_an_audit_entry_before_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let audit_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let created = store.create(sample_incident()).unwrap();

        let updated = store
            .transition_status(
                created.incident_id,
                IncidentStatus::Investigating,
                ActorRef::User { user_id: Uuid::now_v7() },
                Some("starting triage".to_string()),
                &audit_log,
            )
            .unwrap();

        assert_eq!(updated.status, IncidentStatus::Investigating);
        let persisted = store.get(created.incident_id).unwrap().unwrap();
        assert_eq!(persisted.status, IncidentStatus::Investigating);

        let entries = audit_log.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].what.contains("Investigating"));
    }

    #[test]
    fn transition_status_fails_for_an_unknown_incident() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap();
        let audit_log = FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let err = store
            .transition_status(Uuid::now_v7(), IncidentStatus::Resolved, ActorRef::System, None, &audit_log)
            .unwrap_err();
        assert!(matches!(err, IncidentStoreError::NotFound));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-evidence incident:: -- --nocapture`
Expected: FAIL with "cannot find type `Incident` / `IncidentStatus` / `SqliteIncidentStore`"

- [ ] **Step 3: Implement `Incident`, `IncidentStore`, `SqliteIncidentStore`**

```rust
// crates/osiris-evidence/src/incident.rs (add above the tests module)
use std::path::Path;
use std::sync::Mutex;

use osiris_audit::{ActorRef, AuditLog, AuditResult, NewAuditEntry};
use osiris_schema::EntityRef;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentStatus {
    New,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

/// A control-plane incident record (ARCHITECTURE.md §12.7). `actions` from
/// the architecture's full shape is deliberately omitted — Response Engine
/// is out of scope for this phase (plan Global Constraint #1), so there is
/// nothing to populate it with yet; a later phase adds it back when
/// `osiris-response` exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: Uuid,
    pub status: IncidentStatus,
    pub entities: Vec<EntityRef>,
    pub alert_ids: Vec<Uuid>,
    pub notes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IncidentStoreError {
    #[error("incident store backend error: {0}")]
    Backend(String),
    #[error("incident serialize/deserialize error: {0}")]
    Serialize(String),
    #[error("incident not found")]
    NotFound,
    #[error("incident has no associated entities to audit a transition against")]
    NoEntities,
    #[error("audit log error: {0}")]
    Audit(String),
}

pub trait IncidentStore: Send + Sync {
    fn create(&self, incident: Incident) -> Result<Incident, IncidentStoreError>;
    fn get(&self, incident_id: Uuid) -> Result<Option<Incident>, IncidentStoreError>;
    fn list(&self) -> Result<Vec<Incident>, IncidentStoreError>;

    /// Writes an audit entry via `audit_log` *before* persisting the new
    /// status (plan Global Constraint #8) — if the audit write fails, this
    /// returns `Err` and the incident's persisted status is untouched.
    fn transition_status(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
        actor: ActorRef,
        why: Option<String>,
        audit_log: &dyn AuditLog,
    ) -> Result<Incident, IncidentStoreError>;
}

pub struct SqliteIncidentStore {
    conn: Mutex<Connection>,
}

impl SqliteIncidentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IncidentStoreError> {
        let conn = Connection::open(path).map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                raw_json TEXT NOT NULL
            );",
        )
        .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn write_row(&self, incident: &Incident) -> Result<(), IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json =
            serde_json::to_string(incident).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?;
        conn.execute(
            "INSERT INTO incidents (incident_id, raw_json) VALUES (?1, ?2)
             ON CONFLICT(incident_id) DO UPDATE SET raw_json = excluded.raw_json",
            rusqlite::params![incident.incident_id.to_string(), raw_json],
        )
        .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl IncidentStore for SqliteIncidentStore {
    fn create(&self, incident: Incident) -> Result<Incident, IncidentStoreError> {
        self.write_row(&incident)?;
        Ok(incident)
    }

    fn get(&self, incident_id: Uuid) -> Result<Option<Incident>, IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT raw_json FROM incidents WHERE incident_id = ?1",
                rusqlite::params![incident_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        match raw_json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<Incident>, IncidentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| IncidentStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT raw_json FROM incidents")
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
        let mut incidents = Vec::new();
        for row in rows {
            let raw_json = row.map_err(|e| IncidentStoreError::Backend(e.to_string()))?;
            incidents.push(
                serde_json::from_str(&raw_json).map_err(|e| IncidentStoreError::Serialize(e.to_string()))?,
            );
        }
        Ok(incidents)
    }

    fn transition_status(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
        actor: ActorRef,
        why: Option<String>,
        audit_log: &dyn AuditLog,
    ) -> Result<Incident, IncidentStoreError> {
        let mut incident = self.get(incident_id)?.ok_or(IncidentStoreError::NotFound)?;
        let target = incident
            .entities
            .first()
            .cloned()
            .ok_or(IncidentStoreError::NoEntities)?;

        audit_log
            .append(NewAuditEntry {
                who: actor,
                what: format!("incident {} status -> {:?}", incident_id, new_status),
                target,
                why,
                result: AuditResult::Success,
            })
            .map_err(|e| IncidentStoreError::Audit(e.to_string()))?;

        incident.status = new_status;
        self.write_row(&incident)?;
        Ok(incident)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-evidence incident:: -- --nocapture`
Expected: PASS (4 tests)

- [ ] **Step 5: Add `osiris-audit` version consistency check and wire into `lib.rs`**

```rust
// crates/osiris-evidence/src/lib.rs (append)
pub mod incident;
pub use incident::{Incident, IncidentStatus, IncidentStore, IncidentStoreError, SqliteIncidentStore};
```

Run: `cargo test -p osiris-evidence`
Expected: PASS (every test across evidence/store/incident)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-evidence/src/incident.rs crates/osiris-evidence/src/lib.rs
git commit -m "feat(evidence): Incident type and SqliteIncidentStore with audited status transitions"
```

### Task 21: Evidence↔Incident many-to-many join

**Files:**
- Create: `crates/osiris-evidence/src/links.rs`
- Modify: `crates/osiris-evidence/src/lib.rs`
- Test: `crates/osiris-evidence/src/links.rs` (inline)

**Interfaces:**
- Consumes: nothing new (plain `Uuid` ids).
- Produces: `pub trait EvidenceIncidentLinks { fn link(&self, incident_id: Uuid, evidence_id: Uuid) -> Result<(), LinkStoreError>; fn evidence_ids_for_incident(&self, incident_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>; fn incident_ids_for_evidence(&self, evidence_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>; }`, `pub struct SqliteEvidenceIncidentLinks`, `pub enum LinkStoreError` — consumed by the API's evidence/incident endpoints (Part 4).

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-evidence/src/links.rs
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn linking_the_same_evidence_to_two_incidents_is_visible_from_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let evidence_id = Uuid::now_v7();
        let incident_a = Uuid::now_v7();
        let incident_b = Uuid::now_v7();

        links.link(incident_a, evidence_id).unwrap();
        links.link(incident_b, evidence_id).unwrap();

        let incidents = links.incident_ids_for_evidence(evidence_id).unwrap();
        assert_eq!(incidents.len(), 2);
        assert!(incidents.contains(&incident_a));
        assert!(incidents.contains(&incident_b));
    }

    #[test]
    fn evidence_ids_for_incident_returns_every_linked_evidence_record() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let incident_id = Uuid::now_v7();
        let evidence_a = Uuid::now_v7();
        let evidence_b = Uuid::now_v7();
        links.link(incident_id, evidence_a).unwrap();
        links.link(incident_id, evidence_b).unwrap();

        let found = links.evidence_ids_for_incident(incident_id).unwrap();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn linking_the_same_pair_twice_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let links = SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap();
        let incident_id = Uuid::now_v7();
        let evidence_id = Uuid::now_v7();
        links.link(incident_id, evidence_id).unwrap();
        links.link(incident_id, evidence_id).unwrap();
        assert_eq!(links.evidence_ids_for_incident(incident_id).unwrap().len(), 1);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-evidence links:: -- --nocapture`
Expected: FAIL with "cannot find type `SqliteEvidenceIncidentLinks`"

- [ ] **Step 3: Implement `EvidenceIncidentLinks` and `SqliteEvidenceIncidentLinks`**

```rust
// crates/osiris-evidence/src/links.rs (add above the tests module)
use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum LinkStoreError {
    #[error("evidence/incident link store backend error: {0}")]
    Backend(String),
}

/// The many-to-many join between `Evidence` and `Incident`
/// (ARCHITECTURE.md §12.6: "a many-to-many join table, not a foreign key
/// on the evidence record, since one piece of evidence can be relevant to
/// more than one incident").
pub trait EvidenceIncidentLinks: Send + Sync {
    fn link(&self, incident_id: Uuid, evidence_id: Uuid) -> Result<(), LinkStoreError>;
    fn evidence_ids_for_incident(&self, incident_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>;
    fn incident_ids_for_evidence(&self, evidence_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError>;
}

pub struct SqliteEvidenceIncidentLinks {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceIncidentLinks {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LinkStoreError> {
        let conn = Connection::open(path).map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS evidence_incident_links (
                incident_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_links_evidence ON evidence_incident_links(evidence_id);",
        )
        .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl EvidenceIncidentLinks for SqliteEvidenceIncidentLinks {
    fn link(&self, incident_id: Uuid, evidence_id: Uuid) -> Result<(), LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        conn.execute(
            "INSERT OR IGNORE INTO evidence_incident_links (incident_id, evidence_id) VALUES (?1, ?2)",
            rusqlite::params![incident_id.to_string(), evidence_id.to_string()],
        )
        .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn evidence_ids_for_incident(&self, incident_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT evidence_id FROM evidence_incident_links WHERE incident_id = ?1")
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![incident_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            let s = row.map_err(|e| LinkStoreError::Backend(e.to_string()))?;
            ids.push(s.parse().map_err(|_| LinkStoreError::Backend(format!("invalid uuid '{}'", s)))?);
        }
        Ok(ids)
    }

    fn incident_ids_for_evidence(&self, evidence_id: Uuid) -> Result<Vec<Uuid>, LinkStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LinkStoreError::Backend("poisoned lock".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT incident_id FROM evidence_incident_links WHERE evidence_id = ?1")
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![evidence_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| LinkStoreError::Backend(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            let s = row.map_err(|e| LinkStoreError::Backend(e.to_string()))?;
            ids.push(s.parse().map_err(|_| LinkStoreError::Backend(format!("invalid uuid '{}'", s)))?);
        }
        Ok(ids)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-evidence links:: -- --nocapture`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire into `lib.rs`, run the whole crate's tests**

```rust
// crates/osiris-evidence/src/lib.rs (append)
pub mod links;
pub use links::{EvidenceIncidentLinks, LinkStoreError, SqliteEvidenceIncidentLinks};
```

Run: `cargo test -p osiris-evidence`
Expected: PASS (every test across evidence/store/incident/links)

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-evidence/src/links.rs crates/osiris-evidence/src/lib.rs
git commit -m "feat(evidence): Evidence-Incident many-to-many join store"
```

---

## Part 4 — `osiris-api` and `osiris-cli` integration

### Task 22: `GET /api/v1/events?q=<OQL>`

**Files:**
- Modify: `crates/osiris-api/Cargo.toml`
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (inline, alongside the existing `events_endpoint_*` tests)

**Interfaces:**
- Consumes: `osiris_query::{EventQueryPlan, CompileError}` (Part 1), `Storage::query_events` (Task 6/7).
- Produces: `events_handler` now accepts `?q=<OQL>` in addition to its existing `event_type`/`since`/`until`/`limit` params, and a 400 with a syntax/field-validation message on a bad `q`.

- [ ] **Step 1: Add `osiris-query` as a dependency**

```toml
# crates/osiris-api/Cargo.toml — add under [dependencies]
osiris-query = { path = "../osiris-query" }
```

- [ ] **Step 2: Write the failing tests**

```rust
// crates/osiris-api/src/lib.rs — add to the existing tests module
    #[tokio::test]
    async fn events_endpoint_filters_by_oql_query_string() {
        let (_dir, storage) = test_storage();
        storage.write(&sample_event(1, None, 100)).unwrap();
        storage.write(&sample_event(2, None, 200)).unwrap();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            q: Some("process.pid = 1".to_string()),
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn events_endpoint_rejects_a_malformed_oql_query_string() {
        let (_dir, storage) = test_storage();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            q: Some("process.pid =".to_string()),
        };
        let err = events_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn events_endpoint_rejects_an_unknown_field_in_the_oql_query_string() {
        let (_dir, storage) = test_storage();
        let q = EventsQuery {
            event_type: None,
            since: None,
            until: None,
            limit: None,
            q: Some("bogus_field = 1".to_string()),
        };
        let err = events_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("bogus_field"));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-api events_endpoint_filters_by_oql -- --nocapture`
Expected: FAIL with "no field `q` on type `EventsQuery`"

- [ ] **Step 4: Update `EventsQuery` and `events_handler`**

```rust
// crates/osiris-api/src/lib.rs — replace the existing EventsQuery struct and events_handler with:
#[derive(Debug, Deserialize)]
struct EventsQuery {
    event_type: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
    limit: Option<usize>,
    /// Free-form OQL (ARCHITECTURE.md §12.3). When both `q` and
    /// `event_type` are given they intersect (`AND`), matching how the old
    /// fixed-field filters composed before this task.
    q: Option<String>,
}

async fn events_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<CanonicalEvent>>, (StatusCode, String)> {
    let mut plan = if let Some(oql) = &q.q {
        osiris_query::EventQueryPlan::with_filter(oql)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        osiris_query::EventQueryPlan::new()
    };

    if let Some(et) = &q.event_type {
        // Validate the sugar param the same way the OQL path would, so a
        // typo here gets the same 400 an OQL typo would.
        serde_json::from_str::<EventType>(&format!("\"{}\"", et)).map_err(|_| {
            (StatusCode::BAD_REQUEST, format!("invalid event_type: {}", et))
        })?;
        let event_type_ast = osiris_query::ast::Ast::Compare {
            field: "event_type".to_string(),
            op: osiris_query::ast::Op::Eq,
            value: osiris_query::ast::Value::Str(et.clone()),
        };
        plan.filter = Some(match plan.filter {
            Some(existing) => osiris_query::ast::Ast::And(Box::new(existing), Box::new(event_type_ast)),
            None => event_type_ast,
        });
    }
    plan.since = q.since;
    plan.until = q.until;
    if let Some(limit) = q.limit {
        plan.limit = limit;
        plan.export = true;
    }

    let events = tokio::task::spawn_blocking(move || storage.query_events(&plan))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(events))
}
```

Update every other test in this file that constructs an `EventsQuery { .. }` literal (search with `grep -n "EventsQuery {" crates/osiris-api/src/lib.rs`) to add `q: None,` to the struct literal, since the new field has no `Default` derive on this struct.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-api events_endpoint`
Expected: PASS (existing `events_endpoint_*` tests plus the 3 new ones)

- [ ] **Step 6: Run the whole crate's test suite, then commit**

Run: `cargo test -p osiris-api`
Expected: PASS

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/events accepts an OQL q= parameter"
```

### Task 23: Refactor the 5 existing story handlers onto `osiris-investigate` (routes and response shapes unchanged)

**Files:**
- Modify: `crates/osiris-api/Cargo.toml`
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (the existing `*_story` tests must keep passing unmodified — this task is a refactor, not a behavior change)

**Interfaces:**
- Consumes: `osiris_investigate::{file_story, network_story, identity_story, systemd_story, container_story, Story}`.
- Produces: the same 5 routes, same query param structs, same JSON response shape — just no longer implemented inline in `osiris-api`.

- [ ] **Step 1: Add `osiris-investigate` as a dependency**

```toml
# crates/osiris-api/Cargo.toml — add under [dependencies]
osiris-investigate = { path = "../osiris-investigate" }
```

- [ ] **Step 2: Confirm the existing tests still describe the behavior to preserve**

Run: `cargo test -p osiris-api file_story network_story identity_story systemd_story container_story -- --list`
Expected: lists the existing test names (e.g. `file_story_handler_by_path_follows_a_rename...` or similar — the exact names are whatever `grep -n "fn.*_story" crates/osiris-api/src/lib.rs`'s existing test module shows); note them, they must all still pass after this task.

- [ ] **Step 3: Replace the 5 handler bodies to delegate to `osiris-investigate`, and delete the now-redundant local `Story` structs**

```rust
// crates/osiris-api/src/lib.rs — replace file_story_handler's body (keep
// FileStoryQuery and the route registration exactly as they are; delete
// the local `struct FileStory { events, alerts }` above it and use
// `osiris_investigate::Story` as the handler's return type instead):
async fn file_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<FileStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.path.is_none() && q.file_id.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide path or file_id".to_string()));
    }
    let file_id = match &q.file_id {
        Some(raw) => Some(
            FileIdentity::parse_key(raw)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid file_id: {}", raw)))?,
        ),
        None => None,
    };
    let path = q.path.clone();
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::file_story(storage.as_ref(), path.as_deref(), file_id)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// network_story_handler — same treatment, delete `struct NetworkStory`:
async fn network_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<NetworkStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.ip.is_none() && q.domain.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide ip or domain".to_string()));
    }
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::network_story(storage.as_ref(), q.ip.as_deref(), q.domain.as_deref())
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// identity_story_handler — same treatment, delete `struct IdentityStory`:
async fn identity_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<IdentityStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    if q.session_id.is_none() && q.uid.is_none() {
        return Err((StatusCode::BAD_REQUEST, "must provide session_id or uid".to_string()));
    }
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::identity_story(storage.as_ref(), q.session_id.as_deref(), q.uid)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// systemd_story_handler — same treatment, delete `struct SystemdStory`:
async fn systemd_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SystemdStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let Some(unit_name) = q.unit_name else {
        return Err((StatusCode::BAD_REQUEST, "must provide unit_name".to_string()));
    };
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::systemd_story(storage.as_ref(), &unit_name)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// container_story_handler — same treatment, delete `struct ContainerStory`:
async fn container_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<ContainerStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let Some(container_id) = q.container_id else {
        return Err((StatusCode::BAD_REQUEST, "must provide container_id".to_string()));
    };
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::container_story(storage.as_ref(), &container_id)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

- [ ] **Step 4: Run the existing story tests to confirm behavior is preserved**

Run: `cargo test -p osiris-api file_story network_story identity_story systemd_story container_story`
Expected: PASS — every test from Step 2's listing, unmodified, still passes (only the implementation moved; the JSON shape `{ "events": [...], "alerts": [...] }` is identical since `osiris_investigate::Story`'s field names match the deleted local structs exactly)

- [ ] **Step 5: Run the whole crate's test suite, then commit**

Run: `cargo test -p osiris-api`
Expected: PASS

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/lib.rs
git commit -m "refactor(api): delegate the 5 existing story handlers to osiris-investigate"
```

### Task 24: `GET /api/v1/processes/:process_key/story` (new)

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (inline)

**Interfaces:**
- Consumes: `osiris_investigate::process_story` (Task 14).
- Produces: the new route, registered in `build_router`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-api/src/lib.rs — add to the tests module
    #[tokio::test]
    async fn process_story_endpoint_returns_the_processs_own_events() {
        let (_dir, storage) = test_storage();
        let event = sample_event(100, None, 1000);
        let process_key = event.process.as_ref().unwrap().process_key;
        storage.write(&event).unwrap();

        let Json(story) = process_story_handler(State(storage), Path(process_key.as_hex())).await.unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[tokio::test]
    async fn process_story_endpoint_rejects_a_malformed_process_key() {
        let (_dir, storage) = test_storage();
        let err = process_story_handler(State(storage), Path("not-hex".to_string())).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-api process_story_endpoint -- --nocapture`
Expected: FAIL with "cannot find function `process_story_handler`"

- [ ] **Step 3: Implement the handler and register the route**

```rust
// crates/osiris-api/src/lib.rs — add near the other *_story handlers:
async fn process_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(process_key_hex): Path<String>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let process_key: ProcessKey = serde_json::from_value(serde_json::Value::String(process_key_hex.clone()))
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid process_key: {}", process_key_hex)))?;
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::process_story(storage.as_ref(), process_key)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// crates/osiris-api/src/lib.rs — in build_router, add:
        .route("/api/v1/processes/:process_key/story", get(process_story_handler))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-api process_story_endpoint -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/processes/:process_key/story"
```

### Task 25: `GET /api/v1/system/story` (new)

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (inline)

**Interfaces:**
- Consumes: `osiris_investigate::system_story` (Task 15).
- Produces: the new route.

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-api/src/lib.rs — add to the tests module
    #[tokio::test]
    async fn system_story_endpoint_filters_by_host_and_time_range() {
        let (_dir, storage) = test_storage();
        let event = sample_event(1, None, 500);
        let host_id = event.host_id;
        storage.write(&event).unwrap();
        storage.write(&sample_event(2, None, 5000)).unwrap();

        let q = SystemStoryQuery { host_id: host_id.to_string(), since: Some(0), until: Some(1000) };
        let Json(story) = system_story_handler(State(storage), Query(q)).await.unwrap();
        assert_eq!(story.events.len(), 1);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-api system_story_endpoint -- --nocapture`
Expected: FAIL with "cannot find function `system_story_handler` / type `SystemStoryQuery`"

- [ ] **Step 3: Implement the query struct, handler, and route**

```rust
// crates/osiris-api/src/lib.rs — add near the other *StoryQuery structs:
#[derive(Debug, Deserialize)]
struct SystemStoryQuery {
    host_id: String,
    since: Option<u64>,
    until: Option<u64>,
}

async fn system_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SystemStoryQuery>,
) -> Result<Json<osiris_investigate::Story>, (StatusCode, String)> {
    let host_id: uuid::Uuid = q
        .host_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid host_id: {}", q.host_id)))?;
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);
    let story = tokio::task::spawn_blocking(move || {
        osiris_investigate::system_story(storage.as_ref(), host_id, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(story))
}
```

```rust
// crates/osiris-api/src/lib.rs — in build_router, add:
        .route("/api/v1/system/story", get(system_story_handler))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-api system_story_endpoint -- --nocapture`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/system/story"
```

### Task 26: `GET /api/v1/incidents/:seed_entity/reconstruct` (new)

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (inline)

**Interfaces:**
- Consumes: `osiris_investigate::reconstruct_incident` (Task 17).
- Produces: the new route.

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-api/src/lib.rs — add to the tests module
    #[tokio::test]
    async fn reconstruct_incident_endpoint_returns_a_reconstruction_for_a_known_entity() {
        let (_dir, storage) = test_storage();
        let seed = EntityRef::Ip { addr: "203.0.113.10".to_string() };
        let q = ReconstructQuery { since: Some(0), until: Some(10_000) };
        let Json(reconstruction) =
            reconstruct_incident_handler(State(storage), Path(seed.storage_key()), Query(q))
                .await
                .unwrap();
        assert_eq!(reconstruction.seed, seed);
    }

    #[tokio::test]
    async fn reconstruct_incident_endpoint_rejects_a_malformed_seed_key() {
        let (_dir, storage) = test_storage();
        let q = ReconstructQuery { since: None, until: None };
        let err = reconstruct_incident_handler(State(storage), Path("not-a-key".to_string()), Query(q))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-api reconstruct_incident_endpoint -- --nocapture`
Expected: FAIL with "cannot find function `reconstruct_incident_handler` / type `ReconstructQuery`"

- [ ] **Step 3: Implement the query struct, handler, and route**

```rust
// crates/osiris-api/src/lib.rs — add near the graph handler:
#[derive(Debug, Deserialize)]
struct ReconstructQuery {
    since: Option<u64>,
    until: Option<u64>,
}

async fn reconstruct_incident_handler(
    State(storage): State<Arc<dyn Storage>>,
    Path(seed_key): Path<String>,
    Query(q): Query<ReconstructQuery>,
) -> Result<Json<osiris_investigate::IncidentReconstruction>, (StatusCode, String)> {
    let seed = EntityRef::parse_storage_key(&seed_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);
    let reconstruction = tokio::task::spawn_blocking(move || {
        osiris_investigate::reconstruct_incident(storage.as_ref(), seed, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(reconstruction))
}
```

```rust
// crates/osiris-api/src/lib.rs — in build_router, add:
        .route("/api/v1/incidents/:seed_entity/reconstruct", get(reconstruct_incident_handler))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-api reconstruct_incident_endpoint -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/incidents/:seed_entity/reconstruct"
```

### Task 27: `GET /api/v1/graph/subgraph` (new — Entity Graph v2)

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/lib.rs` (inline)

**Interfaces:**
- Consumes: `osiris_investigate::subgraph` (Task 18).
- Produces: the new route, `/api/v1/graph` (the existing `BehavioralChain` endpoint) left untouched.

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-api/src/lib.rs — add to the tests module
    #[tokio::test]
    async fn subgraph_endpoint_bounds_by_node_count() {
        let (_dir, storage) = test_storage();
        let seed = EntityRef::Ip { addr: "10.0.0.1".to_string() };
        let other = EntityRef::Ip { addr: "10.0.0.2".to_string() };
        storage
            .write_relationships(&[EntityRelationship {
                from: seed.clone(),
                to: other,
                relation: osiris_schema::Relation::ConnectedTo,
                event_id: uuid::Uuid::now_v7(),
                timestamp: 100,
            }])
            .unwrap();

        let q = SubgraphQuery { entity: Some(seed.storage_key()), depth: Some(5), max_nodes: Some(1), since: None, until: None };
        let Json(result) = subgraph_handler(State(storage), Query(q)).await.unwrap();
        assert!(result.nodes.len() <= 1);
    }

    #[tokio::test]
    async fn subgraph_endpoint_requires_an_entity_parameter() {
        let (_dir, storage) = test_storage();
        let q = SubgraphQuery { entity: None, depth: None, max_nodes: None, since: None, until: None };
        let err = subgraph_handler(State(storage), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-api subgraph_endpoint -- --nocapture`
Expected: FAIL with "cannot find function `subgraph_handler` / type `SubgraphQuery`"

- [ ] **Step 3: Implement the query struct, handler, and route**

```rust
// crates/osiris-api/src/lib.rs — add near graph_handler:
const MAX_SUBGRAPH_NODES: usize = 500;

#[derive(Debug, Deserialize)]
struct SubgraphQuery {
    entity: Option<String>,
    depth: Option<usize>,
    max_nodes: Option<usize>,
    since: Option<u64>,
    until: Option<u64>,
}

async fn subgraph_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SubgraphQuery>,
) -> Result<Json<osiris_investigate::Subgraph>, (StatusCode, String)> {
    let Some(entity_key) = q.entity else {
        return Err((StatusCode::BAD_REQUEST, "must provide entity".to_string()));
    };
    let seed = EntityRef::parse_storage_key(&entity_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let depth = q.depth.unwrap_or(MAX_GRAPH_DEPTH).min(MAX_GRAPH_DEPTH);
    let max_nodes = q.max_nodes.unwrap_or(MAX_SUBGRAPH_NODES).min(MAX_SUBGRAPH_NODES);
    let since = q.since.unwrap_or(0);
    let until = q.until.unwrap_or(u64::MAX);

    let result = tokio::task::spawn_blocking(move || {
        osiris_investigate::subgraph(storage.as_ref(), seed, depth, max_nodes, since, until)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(result))
}
```

```rust
// crates/osiris-api/src/lib.rs — in build_router, add:
        .route("/api/v1/graph/subgraph", get(subgraph_handler))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p osiris-api subgraph_endpoint -- --nocapture`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the whole crate's test suite, then commit**

Run: `cargo test -p osiris-api`
Expected: PASS

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/graph/subgraph (Entity Graph v2)"
```

### Task 28: Incident CRUD endpoints (new sub-router, own state)

Incident/Evidence endpoints need `osiris-evidence`'s stores and `osiris-audit`'s log as state, not `Storage` — rather than widening every existing handler's `State<Arc<dyn Storage>>` to a bigger shared state type, this task adds a **separate, fully-`with_state`'d sub-router** (`Router` with no open state parameter) that `osiris-server` merges with the existing one via `axum::Router::merge` (Task 30). This keeps every handler touched by Tasks 22-27 completely unchanged.

**Files:**
- Create: `crates/osiris-api/src/incidents.rs`
- Modify: `crates/osiris-api/Cargo.toml`
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/incidents.rs` (inline)

**Interfaces:**
- Consumes: `osiris_evidence::{Incident, IncidentStatus, IncidentStore, SqliteIncidentStore}`, `osiris_audit::{ActorRef, AuditLog}`.
- Produces: `pub struct IncidentEvidenceState { pub incidents: Arc<dyn IncidentStore>, pub evidence: Arc<dyn EvidenceStore>, pub links: Arc<dyn EvidenceIncidentLinks>, pub audit_log: Arc<dyn AuditLog + Send + Sync> }`, `pub fn build_incident_evidence_router(state: IncidentEvidenceState) -> Router` — consumed by `osiris-server`'s startup (Task 30).

- [ ] **Step 1: Add the dependency**

```toml
# crates/osiris-api/Cargo.toml — add under [dependencies]
osiris-evidence = { path = "../osiris-evidence" }
osiris-audit = { path = "../osiris-audit" }
```

- [ ] **Step 2: Write the failing test**

```rust
// crates/osiris-api/src/incidents.rs
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
    use osiris_schema::EntityRef;

    fn test_state() -> (tempfile::TempDir, IncidentEvidenceState) {
        let dir = tempfile::tempdir().unwrap();
        let state = IncidentEvidenceState {
            incidents: Arc::new(SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap()),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap()),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        (dir, state)
    }

    #[tokio::test]
    async fn create_then_get_incident_round_trips() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody {
            entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
        };
        let Json(created) = create_incident_handler(State(state.clone()), Json(body)).await.unwrap();
        assert_eq!(created.status, IncidentStatus::New);

        let Json(found) = get_incident_handler(State(state), Path(created.incident_id.to_string())).await.unwrap();
        assert_eq!(found.incident_id, created.incident_id);
    }

    #[tokio::test]
    async fn list_incidents_returns_every_created_incident() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody { entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }] };
        create_incident_handler(State(state.clone()), Json(body.clone())).await.unwrap();
        create_incident_handler(State(state.clone()), Json(body)).await.unwrap();
        let Json(list) = list_incidents_handler(State(state)).await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn patch_incident_transitions_status_and_audits_it() {
        let (_dir, state) = test_state();
        let body = CreateIncidentBody { entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }] };
        let Json(created) = create_incident_handler(State(state.clone()), Json(body)).await.unwrap();

        let patch = PatchIncidentBody { status: IncidentStatus::Investigating, why: Some("starting triage".to_string()) };
        let Json(updated) = patch_incident_handler(State(state), Path(created.incident_id.to_string()), Json(patch))
            .await
            .unwrap();
        assert_eq!(updated.status, IncidentStatus::Investigating);
    }

    #[tokio::test]
    async fn patch_incident_returns_404_for_an_unknown_id() {
        let (_dir, state) = test_state();
        let patch = PatchIncidentBody { status: IncidentStatus::Resolved, why: None };
        let err = patch_incident_handler(State(state), Path(uuid::Uuid::now_v7().to_string()), Json(patch))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p osiris-api incidents:: -- --nocapture`
Expected: FAIL with "cannot find type `IncidentEvidenceState` / function `create_incident_handler`"

- [ ] **Step 4: Implement the state struct, handlers, and router**

```rust
// crates/osiris-api/src/incidents.rs (add above the tests module)
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use osiris_audit::{ActorRef, AuditLog};
use osiris_evidence::{
    EvidenceIncidentLinks, EvidenceStore, Incident, IncidentStatus, IncidentStore,
};
use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct IncidentEvidenceState {
    pub incidents: Arc<dyn IncidentStore>,
    pub evidence: Arc<dyn EvidenceStore>,
    pub links: Arc<dyn EvidenceIncidentLinks>,
    pub audit_log: Arc<dyn AuditLog + Send + Sync>,
}

pub fn build_incident_evidence_router(state: IncidentEvidenceState) -> Router {
    Router::new()
        .route("/api/v1/incidents", get(list_incidents_handler).post(create_incident_handler))
        .route(
            "/api/v1/incidents/:incident_id",
            get(get_incident_handler).patch(patch_incident_handler),
        )
        .with_state(state)
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateIncidentBody {
    pub entities: Vec<EntityRef>,
}

async fn create_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Json(body): Json<CreateIncidentBody>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    let incident = Incident {
        incident_id: Uuid::now_v7(),
        status: IncidentStatus::New,
        entities: body.entities,
        alert_ids: vec![],
        notes: vec![],
    };
    let created = tokio::task::spawn_blocking(move || state.incidents.create(incident))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(created))
}

async fn get_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Path(incident_id): Path<String>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    let incident_id: Uuid = incident_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid incident_id: {}", incident_id)))?;
    let incident = tokio::task::spawn_blocking(move || state.incidents.get(incident_id))
        .await
        .unwrap()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "incident not found".to_string()))?;
    Ok(Json(incident))
}

async fn list_incidents_handler(State(state): State<IncidentEvidenceState>) -> Json<Vec<Incident>> {
    let incidents = tokio::task::spawn_blocking(move || state.incidents.list())
        .await
        .unwrap()
        .unwrap_or_default();
    Json(incidents)
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchIncidentBody {
    pub status: IncidentStatus,
    pub why: Option<String>,
}

async fn patch_incident_handler(
    State(state): State<IncidentEvidenceState>,
    Path(incident_id): Path<String>,
    Json(body): Json<PatchIncidentBody>,
) -> Result<Json<Incident>, (StatusCode, String)> {
    let incident_id: Uuid = incident_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid incident_id: {}", incident_id)))?;
    let updated = tokio::task::spawn_blocking(move || {
        state.incidents.transition_status(
            incident_id,
            body.status,
            ActorRef::System,
            body.why,
            state.audit_log.as_ref(),
        )
    })
    .await
    .unwrap();
    match updated {
        Ok(incident) => Ok(Json(incident)),
        Err(osiris_evidence::IncidentStoreError::NotFound) => {
            Err((StatusCode::NOT_FOUND, "incident not found".to_string()))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
```

`GET` and `PATCH` on `/api/v1/incidents/:incident_id` are registered together in one chained call (`get(...).patch(...)`) since axum builds one `MethodRouter` per path — this crate's existing `build_router` never needed to combine two methods on one path before, so this is new but standard axum usage, not a deviation from anything already established.

- [ ] **Step 5: Wire the module into `lib.rs`**

```rust
// crates/osiris-api/src/lib.rs (append)
pub mod incidents;
pub use incidents::{build_incident_evidence_router, IncidentEvidenceState};
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p osiris-api incidents:: -- --nocapture`
Expected: PASS (4 tests)

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-api/Cargo.toml crates/osiris-api/src/incidents.rs crates/osiris-api/src/lib.rs
git commit -m "feat(api): Incident CRUD endpoints on a merged sub-router"
```

### Task 29: Evidence endpoints (same sub-router, same state)

**Files:**
- Create: `crates/osiris-api/src/evidence.rs`
- Modify: `crates/osiris-api/src/incidents.rs` (extend `build_incident_evidence_router`)
- Modify: `crates/osiris-api/src/lib.rs`
- Test: `crates/osiris-api/src/evidence.rs` (inline)

**Interfaces:**
- Consumes: `IncidentEvidenceState` (Task 28), `osiris_evidence::{Evidence, EvidenceSource, Integrity}`.
- Produces: `GET /api/v1/evidence?incident_id=...`, `POST /api/v1/evidence`, both merged into the same router `build_incident_evidence_router` returns.

- [ ] **Step 1: Write the failing test**

```rust
// crates/osiris-api/src/evidence.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::incidents::IncidentEvidenceState;
    use osiris_audit::FileAuditLog;
    use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
    use osiris_schema::EntityRef;

    fn test_state() -> (tempfile::TempDir, IncidentEvidenceState) {
        let dir = tempfile::tempdir().unwrap();
        let state = IncidentEvidenceState {
            incidents: Arc::new(SqliteIncidentStore::open(dir.path().join("incidents.db")).unwrap()),
            evidence: Arc::new(SqliteEvidenceStore::open(dir.path().join("evidence.db")).unwrap()),
            links: Arc::new(SqliteEvidenceIncidentLinks::open(dir.path().join("links.db")).unwrap()),
            audit_log: Arc::new(FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
        };
        (dir, state)
    }

    #[tokio::test]
    async fn create_evidence_links_it_to_an_incident_when_given_one() {
        let (_dir, state) = test_state();
        let incident = state
            .incidents
            .create(osiris_evidence::Incident {
                incident_id: uuid::Uuid::now_v7(),
                status: osiris_evidence::IncidentStatus::New,
                entities: vec![EntityRef::Ip { addr: "203.0.113.10".to_string() }],
                alert_ids: vec![],
                notes: vec![],
            })
            .unwrap();

        let body = CreateEvidenceBody {
            source: EvidenceSource::EventCapture,
            hash: "abc123".to_string(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: Some(incident.incident_id),
        };
        let Json(created) = create_evidence_handler(State(state.clone()), Json(body)).await.unwrap();

        let list_query = ListEvidenceQuery { incident_id: incident.incident_id.to_string() };
        let Json(list) = list_evidence_handler(State(state), Query(list_query)).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].evidence_id(), created.evidence_id());
    }

    #[tokio::test]
    async fn create_evidence_rejects_an_empty_hash() {
        let (_dir, state) = test_state();
        let body = CreateEvidenceBody {
            source: EvidenceSource::ManualUpload,
            hash: String::new(),
            immutable_since: 1000,
            relationships: vec![],
            supersedes: None,
            incident_id: None,
        };
        let err = create_evidence_handler(State(state), Json(body)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_evidence_requires_a_valid_incident_id() {
        let (_dir, state) = test_state();
        let q = ListEvidenceQuery { incident_id: "not-a-uuid".to_string() };
        let err = list_evidence_handler(State(state), Query(q)).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
```

This test module builds its incident fixture by calling `state.incidents.create(...)` directly (the `IncidentStore` trait method), not through any HTTP handler — the only thing it imports from `incidents.rs` is the `IncidentEvidenceState` type itself.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p osiris-api evidence:: -- --nocapture`
Expected: FAIL with "cannot find function `create_evidence_handler` / type `CreateEvidenceBody`"

- [ ] **Step 3: Implement the handlers**

```rust
// crates/osiris-api/src/evidence.rs (add above the tests module)
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use osiris_evidence::{Evidence, EvidenceSource, Integrity};
use osiris_schema::EntityRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::incidents::IncidentEvidenceState;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEvidenceBody {
    pub source: EvidenceSource,
    pub hash: String,
    pub immutable_since: u64,
    pub relationships: Vec<EntityRef>,
    pub supersedes: Option<Uuid>,
    pub incident_id: Option<Uuid>,
}

pub async fn create_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Json(body): Json<CreateEvidenceBody>,
) -> Result<Json<Evidence>, (StatusCode, String)> {
    let integrity = Integrity { hash: body.hash, immutable_since: body.immutable_since };
    let evidence = Evidence::new(body.source, body.immutable_since, integrity, body.relationships, body.supersedes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let incident_id = body.incident_id;
    let links = state.links.clone();
    let evidence_store = state.evidence.clone();
    let created = tokio::task::spawn_blocking(move || -> Result<Evidence, String> {
        let created = evidence_store.insert(evidence).map_err(|e| e.to_string())?;
        if let Some(incident_id) = incident_id {
            links.link(incident_id, created.evidence_id()).map_err(|e| e.to_string())?;
        }
        Ok(created)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(created))
}

#[derive(Debug, Deserialize)]
pub struct ListEvidenceQuery {
    pub incident_id: String,
}

pub async fn list_evidence_handler(
    State(state): State<IncidentEvidenceState>,
    Query(q): Query<ListEvidenceQuery>,
) -> Result<Json<Vec<Evidence>>, (StatusCode, String)> {
    let incident_id: Uuid = q
        .incident_id
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid incident_id: {}", q.incident_id)))?;

    let evidence_list = tokio::task::spawn_blocking(move || -> Result<Vec<Evidence>, String> {
        let evidence_ids = state.links.evidence_ids_for_incident(incident_id).map_err(|e| e.to_string())?;
        let mut evidence = Vec::new();
        for id in evidence_ids {
            if let Some(record) = state.evidence.get(id).map_err(|e| e.to_string())? {
                evidence.push(record);
            }
        }
        Ok(evidence)
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(evidence_list))
}
```

`Evidence` needs `Serialize` (already derived in Task 19) for `Json<Evidence>`/`Json<Vec<Evidence>>` to work — no change needed there.

- [ ] **Step 4: Register the two routes in `build_incident_evidence_router`**

```rust
// crates/osiris-api/src/incidents.rs — update build_incident_evidence_router to:
pub fn build_incident_evidence_router(state: IncidentEvidenceState) -> Router {
    Router::new()
        .route("/api/v1/incidents", get(list_incidents_handler).post(create_incident_handler))
        .route(
            "/api/v1/incidents/:incident_id",
            get(get_incident_handler).patch(patch_incident_handler),
        )
        .route(
            "/api/v1/evidence",
            get(crate::evidence::list_evidence_handler).post(crate::evidence::create_evidence_handler),
        )
        .with_state(state)
}
```

The two functions this pulls in from `evidence.rs` (`create_evidence_handler`, `list_evidence_handler`) are already declared `pub async fn` in Task 29 Step 3, since they are referenced across the `incidents`/`evidence` module boundary here.

- [ ] **Step 5: Wire the module into `lib.rs`**

```rust
// crates/osiris-api/src/lib.rs (append)
pub mod evidence;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p osiris-api evidence:: -- --nocapture`
Expected: PASS (3 tests)

- [ ] **Step 7: Run the whole crate's test suite, then commit**

Run: `cargo test -p osiris-api`
Expected: PASS

```bash
git add crates/osiris-api/src/evidence.rs crates/osiris-api/src/incidents.rs crates/osiris-api/src/lib.rs
git commit -m "feat(api): Evidence create/list endpoints"
```

### Task 30: Wire the incident/evidence router into `osiris-server`

**Files:**
- Modify: `crates/osiris-server/Cargo.toml`
- Modify: `crates/osiris-server/src/config.rs`
- Modify: `crates/osiris-server/src/main.rs`
- Test: `crates/osiris-server/src/config.rs` (inline)

**Interfaces:**
- Consumes: `osiris_api::{build_incident_evidence_router, IncidentEvidenceState}` (Task 28), `osiris_evidence::{SqliteIncidentStore, SqliteEvidenceStore, SqliteEvidenceIncidentLinks}`, `osiris_audit::FileAuditLog`.
- Produces: the merged router actually served by the `osiris-server` binary, so every endpoint added in Tasks 22-29 is reachable over real HTTP, not just unit-tested in isolation.

- [ ] **Step 1: Add the dependencies**

```toml
# crates/osiris-server/Cargo.toml — add under [dependencies]
osiris-evidence = { path = "../osiris-evidence" }
osiris-audit = { path = "../osiris-audit" }
```

- [ ] **Step 2: Write the failing test for the new config fields**

```rust
// crates/osiris-server/src/config.rs — add to the existing tests module
    #[test]
    fn loads_a_config_with_incident_evidence_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\nincidents_db_path: /tmp/incidents.db\nevidence_db_path: /tmp/evidence.db\nlinks_db_path: /tmp/links.db\ninvestigate_audit_log_path: /tmp/investigate-audit.jsonl\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.incidents_db_path.as_deref(), Some("/tmp/incidents.db"));
        assert_eq!(config.evidence_db_path.as_deref(), Some("/tmp/evidence.db"));
        assert_eq!(config.links_db_path.as_deref(), Some("/tmp/links.db"));
        assert_eq!(config.investigate_audit_log_path.as_deref(), Some("/tmp/investigate-audit.jsonl"));
    }

    #[test]
    fn loads_a_minimal_config_without_the_new_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert!(config.incidents_db_path.is_none());
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-server loads_a_config_with_incident_evidence_paths -- --nocapture`
Expected: FAIL with "no field `incidents_db_path`"

- [ ] **Step 4: Add the new config fields**

```rust
// crates/osiris-server/src/config.rs — add to ServerConfig, after risk_weights_path:
    /// Phase 7a: the Incident/Evidence/link control-plane stores' own
    /// SQLite files (ARCHITECTURE.md §10.3), independent of `db_path`'s
    /// telemetry tables — same posture `baseline_db_path` already
    /// established. All four are optional so an existing config keeps
    /// loading unmodified; `main.rs` applies documented defaults.
    #[serde(default)]
    pub incidents_db_path: Option<String>,
    #[serde(default)]
    pub evidence_db_path: Option<String>,
    #[serde(default)]
    pub links_db_path: Option<String>,
    #[serde(default)]
    pub investigate_audit_log_path: Option<String>,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p osiris-server config:: -- --nocapture`
Expected: PASS (existing config tests plus the 2 new ones)

- [ ] **Step 6: Merge the incident/evidence router into `main.rs`**

```rust
// crates/osiris-server/src/main.rs — add near the top, alongside the
// other `use` lines:
use osiris_api::{build_incident_evidence_router, IncidentEvidenceState};
use osiris_audit::FileAuditLog;
use osiris_evidence::{SqliteEvidenceIncidentLinks, SqliteEvidenceStore, SqliteIncidentStore};
```

```rust
// crates/osiris-server/src/main.rs — replace:
//     let app = build_router(storage);
// with:
    let incidents_db_path = config.incidents_db_path.clone().unwrap_or_else(|| "/var/lib/osiris/incidents.db".to_string());
    let evidence_db_path = config.evidence_db_path.clone().unwrap_or_else(|| "/var/lib/osiris/evidence.db".to_string());
    let links_db_path = config.links_db_path.clone().unwrap_or_else(|| "/var/lib/osiris/links.db".to_string());
    let investigate_audit_log_path = config
        .investigate_audit_log_path
        .clone()
        .unwrap_or_else(|| "/var/lib/osiris/investigate-audit.jsonl".to_string());

    let incident_evidence_state = IncidentEvidenceState {
        incidents: Arc::new(SqliteIncidentStore::open(&incidents_db_path).unwrap()),
        evidence: Arc::new(SqliteEvidenceStore::open(&evidence_db_path).unwrap()),
        links: Arc::new(SqliteEvidenceIncidentLinks::open(&links_db_path).unwrap()),
        audit_log: Arc::new(FileAuditLog::open(&investigate_audit_log_path).unwrap()),
    };

    let app = build_router(storage).merge(build_incident_evidence_router(incident_evidence_state));
```

- [ ] **Step 7: Run the whole workspace's tests, then commit**

Run: `cargo test -p osiris-server`
Expected: PASS

```bash
git add crates/osiris-server/Cargo.toml crates/osiris-server/src/config.rs crates/osiris-server/src/main.rs
git commit -m "feat(server): wire the Incident/Evidence router and its config into the binary"
```

### Task 31: `osiris hunt` CLI subcommand + saved query templates

**Files:**
- Create: `hunts/network-download-then-write.oql`
- Create: `hunts/shell-wrote-file-to-web-root.oql`
- Create: `hunts/container-started-in-remote-session.oql`
- Create: `crates/osiris-cli/src/hunts.rs`
- Modify: `crates/osiris-cli/src/client.rs`
- Modify: `crates/osiris-cli/src/lib.rs`
- Modify: `crates/osiris-cli/src/main.rs`
- Test: `crates/osiris-cli/src/hunts.rs`, `crates/osiris-cli/src/client.rs` (inline)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub fn template(name: &str) -> Option<&'static str>` (hunts.rs), `pub fn hunt_url(server: &str, q: &str, since: &Option<u64>, until: &Option<u64>, limit: &Option<usize>) -> String` (client.rs), `pub fn percent_encode(s: &str) -> String` (client.rs) — the `osiris hunt` CLI subcommand.

- [ ] **Step 1: Write the three saved query templates**

Mirroring three of the rule packs already shipped in `config/rules/` (`network_download_then_write.yaml`, `shell_wrote_file_to_web_root.yaml`, `container_started_in_remote_session.yaml`), expressed as hand-typed OQL an analyst would run interactively rather than a compiled detection rule:

```
// hunts/network-download-then-write.oql
event_type = "NETWORK_CONNECT" OR event_type = "FILE_WRITE"
```

```
// hunts/shell-wrote-file-to-web-root.oql
event_type = "FILE_WRITE" AND file.path STARTS_WITH "/var/www/"
```

```
// hunts/container-started-in-remote-session.oql
event_type = "CONTAINER_START" AND session.session_id != ""
```

- [ ] **Step 2: Write the failing test for the template lookup**

```rust
// crates/osiris-cli/src/hunts.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_resolves_a_known_name() {
        let oql = template("network-download-then-write").unwrap();
        assert!(oql.contains("NETWORK_CONNECT"));
    }

    #[test]
    fn template_returns_none_for_an_unknown_name() {
        assert!(template("does-not-exist").is_none());
    }

    #[test]
    fn every_known_template_is_non_empty() {
        for name in known_template_names() {
            let oql = template(name).unwrap();
            assert!(!oql.trim().is_empty());
        }
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p osiris-cli hunts:: -- --nocapture`
Expected: FAIL with "cannot find function `template` / `known_template_names`"

- [ ] **Step 4: Implement the template lookup**

```rust
// crates/osiris-cli/src/hunts.rs (add above the tests module)

/// Saved OQL query templates (ARCHITECTURE.md §12.2), checked in under
/// `hunts/` at the repo root (same pattern as `rules/`) and embedded at
/// compile time — this CLI is a thin HTTP client that can run on a
/// different machine than the server, so template *content* travels with
/// the binary rather than being read from a server-side path at runtime.
pub fn known_template_names() -> &'static [&'static str] {
    &[
        "network-download-then-write",
        "shell-wrote-file-to-web-root",
        "container-started-in-remote-session",
    ]
}

pub fn template(name: &str) -> Option<&'static str> {
    match name {
        "network-download-then-write" => Some(include_str!("../../../hunts/network-download-then-write.oql")),
        "shell-wrote-file-to-web-root" => Some(include_str!("../../../hunts/shell-wrote-file-to-web-root.oql")),
        "container-started-in-remote-session" => {
            Some(include_str!("../../../hunts/container-started-in-remote-session.oql"))
        }
        _ => None,
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p osiris-cli hunts:: -- --nocapture`
Expected: PASS (3 tests)

- [ ] **Step 6: Write the failing test for `hunt_url`/`percent_encode`**

```rust
// crates/osiris-cli/src/client.rs — add to the existing tests module
    #[test]
    fn percent_encode_escapes_spaces_quotes_and_parens() {
        let encoded = percent_encode("a = \"b\" AND (c = 1)");
        assert_eq!(encoded, "a%20%3D%20%22b%22%20AND%20%28c%20%3D%201%29");
    }

    #[test]
    fn percent_encode_leaves_alphanumerics_and_dots_untouched() {
        assert_eq!(percent_encode("process.pid_1"), "process.pid_1");
    }

    #[test]
    fn hunt_url_includes_the_encoded_query_and_optional_filters() {
        let url = hunt_url("http://localhost:8080", "a = \"b\"", &Some(100), &None, &Some(10));
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/events?q=a%20%3D%20%22b%22&since=100&limit=10"
        );
    }
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cargo test -p osiris-cli percent_encode -- --nocapture`
Expected: FAIL with "cannot find function `percent_encode` / `hunt_url`"

- [ ] **Step 8: Implement `percent_encode` and `hunt_url`**

```rust
// crates/osiris-cli/src/client.rs (add above the tests module)

/// Minimal percent-encoding for the one context this CLI needs it in: an
/// OQL string placed into a `?q=` query parameter. Unreserved characters
/// (letters, digits, `-`, `_`, `.`, `~`) pass through unescaped per RFC
/// 3986; everything else — including the space, `"`, `(`, `)`, `=` that
/// every non-trivial OQL query contains — is escaped, unlike
/// `container_story_url`'s documented no-encoding posture (that function's
/// hex/container-id inputs never contain such characters; OQL always can).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Builds the `/api/v1/events?q=...` request URL for `osiris hunt`.
pub fn hunt_url(server: &str, q: &str, since: &Option<u64>, until: &Option<u64>, limit: &Option<usize>) -> String {
    let mut url = format!("{}/api/v1/events?q={}", server.trim_end_matches('/'), percent_encode(q));
    if let Some(s) = since {
        url.push_str(&format!("&since={}", s));
    }
    if let Some(u) = until {
        url.push_str(&format!("&until={}", u));
    }
    if let Some(l) = limit {
        url.push_str(&format!("&limit={}", l));
    }
    url
}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `cargo test -p osiris-cli percent_encode hunt_url -- --nocapture`
Expected: PASS (4 tests)

- [ ] **Step 10: Wire `hunts` into `lib.rs` and add the `Hunt` subcommand**

```rust
// crates/osiris-cli/src/lib.rs — add:
pub mod hunts;
```

```rust
// crates/osiris-cli/src/main.rs — add to `use osiris_cli::client::{...}`:
use osiris_cli::client::{
    chain_url, container_story_url, events_url, format_events_table, hunt_url, risk_url,
};
use osiris_cli::hunts::template;
```

```rust
// crates/osiris-cli/src/main.rs — add a new Command variant, alongside Risk:
    /// Run a saved or ad-hoc OQL hunt (ARCHITECTURE.md §12.2). Exactly one
    /// of `query` or `--template` must be given.
    Hunt {
        query: Option<String>,
        #[arg(long)]
        template: Option<String>,
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
    },
```

```rust
// crates/osiris-cli/src/main.rs — add a match arm, alongside Risk:
        Command::Hunt { query, template: template_name, since, until, limit } => {
            let resolved = match (query, template_name) {
                (Some(q), None) => q.clone(),
                (None, Some(name)) => match template(name) {
                    Some(oql) => oql.to_string(),
                    None => {
                        eprintln!("unknown hunt template: {}", name);
                        std::process::exit(1);
                    }
                },
                (Some(_), Some(_)) => {
                    eprintln!("provide either a query or --template, not both");
                    std::process::exit(1);
                }
                (None, None) => {
                    eprintln!("provide either a query or --template");
                    std::process::exit(1);
                }
            };
            let url = hunt_url(&cli.server, &resolved, since, until, limit);
            get(&client, url)
        }
```

- [ ] **Step 11: Run the whole crate's test suite, then commit**

Run: `cargo test -p osiris-cli`
Expected: PASS

```bash
git add hunts/ crates/osiris-cli/src/hunts.rs crates/osiris-cli/src/client.rs crates/osiris-cli/src/lib.rs crates/osiris-cli/src/main.rs
git commit -m "feat(cli): osiris hunt subcommand with saved OQL query templates"
```

---

## Part 5 — Dependency graph and final vertical-slice e2e test

### Task 32: Extend `tools/check-dep-graph.sh` for the 3 new crates

**Files:**
- Modify: `tools/check-dep-graph.sh`

**Interfaces:**
- Consumes: nothing new (a shell script, no Rust interface).
- Produces: the same script, now also failing CI if `osiris-query`/`osiris-investigate`/`osiris-evidence` ever reach the privileged Agent side.

- [ ] **Step 1: Add the three new crates to the existing privilege-boundary checks**

```bash
# tools/check-dep-graph.sh — change this line:
check_forbidden osiris-server osiris-sensors osiris-ebpf osiris-kernel
# to also cover the 3 new crates by adding 3 more check_forbidden calls
# right after it:
check_forbidden osiris-query osiris-sensors osiris-agent osiris-ebpf osiris-kernel
check_forbidden osiris-investigate osiris-sensors osiris-agent osiris-ebpf osiris-kernel
check_forbidden osiris-evidence osiris-sensors osiris-agent osiris-ebpf osiris-kernel
```

Also update the script's own header comment to name the 3 new crates in the "must never reach osiris-agent" family, alongside the existing `osiris-detect, osiris-correlate, osiris-risk, osiris-baseline` list:

```bash
# tools/check-dep-graph.sh — update the top comment block's second sentence to:
# osiris-storage-*, osiris-detect, osiris-correlate, osiris-risk,
# osiris-baseline, osiris-query, osiris-investigate, osiris-evidence must
# never reach osiris-agent; osiris-schema and osiris-fileutil
```

- [ ] **Step 2: Run the script to verify it passes**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED` — none of the 3 new crates depend on `osiris-sensors`/`osiris-agent`/`osiris-ebpf`/`osiris-kernel` (they never had a reason to), so this is confirming a fact already true, not fixing a violation.

- [ ] **Step 3: Commit**

```bash
git add tools/check-dep-graph.sh
git commit -m "chore(ci): extend dependency-graph check for osiris-query/investigate/evidence"
```

### Task 33: Final e2e test proving the Phase 7a vertical slice

Reuses the exact same real Agent → Server → SqliteStorage pipeline and `network_download_then_write` synthetic scenario the Phase 6 e2e test (`network_download_then_write_scenario_flows_end_to_end_through_every_phase_6_engine`, `crates/osiris-e2e-tests/tests/end_to_end.rs`) already established — that scenario is known to produce a `curl` process exec event plus a network connect and a file create event it performs, which is exactly the substrate `process_story`, `reconstruct_incident`, and the Entity Graph v2 subgraph need. This task adds OQL hunting and the Incident/Evidence lifecycle on top, over real HTTP.

**Files:**
- Modify: `crates/osiris-e2e-tests/Cargo.toml`
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs`

**Interfaces:**
- Consumes: everything built in this plan, exercised together for the first time.
- Produces: one new `#[tokio::test(flavor = "multi_thread")]` proving the Phase 7a vertical slice end-to-end.

- [ ] **Step 1: Add the dependencies**

```toml
# crates/osiris-e2e-tests/Cargo.toml — this crate keeps every dependency
# under [dev-dependencies] (its [dependencies] section is empty) — add the
# 4 new crates there, alongside the existing osiris-api/osiris-storage-sqlite lines:
osiris-query = { path = "../osiris-query" }
osiris-investigate = { path = "../osiris-investigate" }
osiris-evidence = { path = "../osiris-evidence" }
osiris-audit = { path = "../osiris-audit" }
```

- [ ] **Step 2: Write the test**

```rust
// crates/osiris-e2e-tests/tests/end_to_end.rs (append at the end of the file, before the free-function helpers `urlencoding_lite`/`cli_binary_path`)
#[tokio::test(flavor = "multi_thread")]
async fn phase_7a_investigation_evidence_hunting_flows_end_to_end_over_real_http() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let db_path = dir.path().join("events.db");

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };

    let agent_config = AgentConfig {
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("network_download_then_write".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string()).await.unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());
    let ingestion_cancellation = CancellationToken::new();
    let (baseline_engine, risk_engine, correlation_engine) = phase6_engines(dir.path());
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        Arc::new(DetectionEngine::new(vec![])),
        baseline_engine,
        risk_engine,
        correlation_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(1500)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    let events = storage.query(&QueryPlan::new()).unwrap();
    let curl_process_key = events
        .iter()
        .find(|e| e.process.as_ref().is_some_and(|p| p.exe_path == "/usr/bin/curl"))
        .expect("scenario must produce a curl exec event")
        .process
        .as_ref()
        .unwrap()
        .process_key;
    let seed_entity = EntityRef::Process { process_key: curl_process_key };

    let incidents_db = dir.path().join("incidents.db");
    let evidence_db = dir.path().join("evidence.db");
    let links_db = dir.path().join("links.db");
    let audit_log_path = dir.path().join("investigate-audit.jsonl");
    let incident_evidence_state = osiris_api::IncidentEvidenceState {
        incidents: Arc::new(osiris_evidence::SqliteIncidentStore::open(&incidents_db).unwrap()),
        evidence: Arc::new(osiris_evidence::SqliteEvidenceStore::open(&evidence_db).unwrap()),
        links: Arc::new(osiris_evidence::SqliteEvidenceIncidentLinks::open(&links_db).unwrap()),
        audit_log: Arc::new(osiris_audit::FileAuditLog::open(&audit_log_path).unwrap()),
    };

    let app = build_router(storage.clone())
        .merge(osiris_api::build_incident_evidence_router(incident_evidence_state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = reqwest::Client::new();

    // 1. OQL hunting: GET /api/v1/events?q=... finds the curl exec event.
    let hunted: Vec<serde_json::Value> = client
        .get(format!(
            "http://{}/api/v1/events?q={}",
            addr,
            urlencoding_lite("process.exe_path = \"/usr/bin/curl\"")
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(hunted.len(), 1, "OQL query must find exactly the curl exec event");

    // 2. Process Story: the curl process's own activity (exec + whatever
    //    else it did — connect and/or file write, per the scenario).
    let story: serde_json::Value = client
        .get(format!("http://{}/api/v1/processes/{}/story", addr, curl_process_key.as_hex()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        story["events"].as_array().unwrap().len() >= 1,
        "process_story must include at least the curl process's own exec event"
    );

    // 3. Entity Graph v2 subgraph: bounded {nodes, edges} from the curl process.
    let subgraph: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/graph/subgraph?entity={}&depth=5&max_nodes=50",
            addr,
            urlencoding_lite(&seed_entity.storage_key())
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!subgraph["nodes"].as_array().unwrap().is_empty());

    // 4. reconstruct_incident buckets the chain by category.
    let reconstruction: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/incidents/{}/reconstruct",
            addr,
            urlencoding_lite(&seed_entity.storage_key())
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!reconstruction["stages"].as_array().unwrap().is_empty());

    // 5. Incident + Evidence lifecycle, over real HTTP.
    let created_incident: serde_json::Value = client
        .post(format!("http://{}/api/v1/incidents", addr))
        .json(&serde_json::json!({ "entities": [seed_entity] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let incident_id = created_incident["incident_id"].as_str().unwrap().to_string();
    assert_eq!(created_incident["status"], "NEW");

    let created_evidence: serde_json::Value = client
        .post(format!("http://{}/api/v1/evidence", addr))
        .json(&serde_json::json!({
            "source": "EVENT_CAPTURE",
            "hash": "deadbeef",
            "immutable_since": 1000,
            "relationships": [],
            "supersedes": null,
            "incident_id": incident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(created_evidence["evidence_id"].is_string());

    let evidence_list: Vec<serde_json::Value> = client
        .get(format!("http://{}/api/v1/evidence?incident_id={}", addr, incident_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence_list.len(), 1);

    let patched: serde_json::Value = client
        .patch(format!("http://{}/api/v1/incidents/{}", addr, incident_id))
        .json(&serde_json::json!({ "status": "INVESTIGATING", "why": "e2e test triage" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(patched["status"], "INVESTIGATING");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p osiris-e2e-tests phase_7a_investigation_evidence_hunting -- --nocapture`
Expected: PASS

- [ ] **Step 4: Run the entire workspace's tests, clippy, and the dep-graph check — this plan's exit criterion**

Run: `cargo test --workspace`
Expected: PASS (every test across every crate touched by this plan, plus every Phase 0-6 test unmodified)

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-e2e-tests/Cargo.toml crates/osiris-e2e-tests/tests/end_to_end.rs
git commit -m "test(e2e): prove the Phase 7a investigation/evidence/hunting vertical slice end-to-end"
```

## Exit Criterion

`cargo test --workspace` passes with zero warnings under `cargo clippy --workspace --all-targets -- -D warnings`, `bash tools/check-dep-graph.sh` passes, `osiris-query`/`osiris-investigate`/`osiris-evidence` exist and are used by `osiris-api`/`osiris-cli`/`osiris-server` exactly as described in this plan, the 5 pre-existing story endpoints are behaviorally unchanged from an API consumer's perspective, and no `osiris-response` crate or `ResponseAction` type exists anywhere in the workspace. Phase 7b (Web Console) is a separate plan that consumes the API surface this plan produces.
