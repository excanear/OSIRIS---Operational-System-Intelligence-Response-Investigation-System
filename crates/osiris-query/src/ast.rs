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
