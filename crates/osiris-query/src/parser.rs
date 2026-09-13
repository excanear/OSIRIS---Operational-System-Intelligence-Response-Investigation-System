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

/// How deeply a query may nest `(...)` / `NOT` before the parser refuses it.
///
/// The parser is recursive-descent, so nesting depth is stack depth: without
/// this bound a query like `"(".repeat(100_000)` would overflow the native
/// stack, and a Rust stack overflow is an immediate process abort, not a
/// catchable error. `/api/v1/events?q=...` is reachable before any
/// `spawn_blocking`, so that abort would take the whole server down.
/// 64 is far deeper than any hand-written analyst query and far shallower
/// than the real stack limit.
pub const MAX_PARSE_DEPTH: usize = 64;

pub fn parse(input: &str) -> Result<Ast, ParseError> {
    let tokens = Lexer::tokenize(input)?;
    // A fresh `Parser` per `parse` call, so `depth` never needs resetting
    // across calls.
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let ast = p.parse_or()?;
    p.expect_eof()?;
    Ok(ast)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(self.err(format!(
                "query nesting is too deep (limit {} levels)",
                MAX_PARSE_DEPTH
            )));
        }
        Ok(())
    }

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
        self.enter()?;
        let out = self.parse_or_inner();
        self.depth -= 1;
        out
    }

    fn parse_or_inner(&mut self) -> Result<Ast, ParseError> {
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
        self.enter()?;
        let out = self.parse_unary_inner();
        self.depth -= 1;
        out
    }

    fn parse_unary_inner(&mut self) -> Result<Ast, ParseError> {
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
            Token::Op(Op::In) => {
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
            Token::Op(op) => {
                let value = self.parse_scalar()?;
                Ok(Ast::Compare { field, op, value })
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

    #[test]
    fn rejects_deeply_nested_parens_instead_of_overflowing_the_stack() {
        let query = format!("{}event_type = \"X\"{}", "(".repeat(5000), ")".repeat(5000));
        let err = parse(&query).unwrap_err();
        assert!(
            err.message.contains("too deep"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn rejects_deeply_nested_not_instead_of_overflowing_the_stack() {
        let query = format!("{}event_type = \"X\"", "NOT ".repeat(5000));
        let err = parse(&query).unwrap_err();
        assert!(err.message.contains("too deep"));
    }

    #[test]
    fn nesting_within_the_depth_limit_still_parses() {
        // 20 levels of parens is well inside MAX_PARSE_DEPTH even counting
        // the two guarded frames (`or` + `unary`) each level costs.
        let query = format!("{}event_type = \"X\"{}", "(".repeat(20), ")".repeat(20));
        assert!(parse(&query).is_ok());
    }
}
