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
                        "IN" => Token::Op(Op::In),
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

#[cfg(test)]
mod tests {
    use crate::lexer::{Lexer, Token};

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
