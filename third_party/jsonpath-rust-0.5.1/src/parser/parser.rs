use crate::parser::errors::JsonPathParserError::ParserError;
use crate::parser::errors::{parser_err, JsonPathParserError};
use crate::parser::model::FilterExpression::{And, Not, Or};
use crate::parser::model::{
    FilterExpression, FilterSign, Function, JsonPath, JsonPathIndex, Operand,
};
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use serde_json::Value;

#[derive(Parser)]
#[grammar = "parser/grammar/json_path.pest"]
struct JsonPathParser;

/// Parses a string into a [JsonPath].
///
/// # Errors
///
/// Returns a variant of [JsonPathParserError] if the parsing operation failed.
pub fn parse_json_path(jp_str: &str) -> Result<JsonPath, JsonPathParserError> {
    JsonPathParser::parse(Rule::path, jp_str)?
        .next()
        .ok_or(parser_err(jp_str))
        .and_then(parse_internal)
}

/// Internal function takes care of the logic by parsing the operators and unrolling the string into the final result.
///
/// # Errors
///
/// Returns a variant of [JsonPathParserError] if the parsing operation failed
fn parse_internal(rule: Pair<Rule>) -> Result<JsonPath, JsonPathParserError> {
    match rule.as_rule() {
        Rule::path => rule
            .into_inner()
            .next()
            .ok_or(parser_err("expected a Rule::path but found nothing"))
            .and_then(parse_internal),
        Rule::current => rule
            .into_inner()
            .next()
            .map(parse_internal)
            .unwrap_or(Ok(JsonPath::Empty))
            .map(JsonPath::current),
        Rule::chain => rule
            .into_inner()
            .map(parse_internal)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonPath::Chain),
        Rule::root => Ok(JsonPath::Root),
        Rule::wildcard => Ok(JsonPath::Wildcard),
        Rule::descent => parse_key(down(rule)?)?
            .map(JsonPath::Descent)
            .ok_or(parser_err("expected a JsonPath::Descent but found nothing")),
        Rule::descent_w => Ok(JsonPath::DescentW),
        Rule::function => Ok(JsonPath::Fn(Function::Length)),
        Rule::field => parse_key(down(rule)?)?
            .map(JsonPath::Field)
            .ok_or(parser_err("expected a JsonPath::Field but found nothing")),
        Rule::index => parse_index(rule).map(JsonPath::Index),
        _ => Err(ParserError(format!("{rule} did not match any 'Rule' "))),
    }
}

/// parsing the rule 'key' with the structures either .key or .\['key'\]
fn parse_key(rule: Pair<Rule>) -> Result<Option<String>, JsonPathParserError> {
    let parsed_key = match rule.as_rule() {
        Rule::key | Rule::key_unlim | Rule::string_qt => parse_key(down(rule)?),
        Rule::key_lim | Rule::inner => Ok(Some(String::from(rule.as_str()))),
        _ => Ok(None),
    };
    parsed_key
}

fn parse_slice(pairs: Pairs<Rule>) -> Result<JsonPathIndex, JsonPathParserError> {
    let mut start = 0;
    let mut end = 0;
    let mut step = 1;
    for in_pair in pairs {
        match in_pair.as_rule() {
            Rule::start_slice => start = in_pair.as_str().parse::<i32>().unwrap_or(start),
            Rule::end_slice => end = in_pair.as_str().parse::<i32>().unwrap_or(end),
            Rule::step_slice => step = down(in_pair)?.as_str().parse::<usize>().unwrap_or(step),
            _ => (),
        }
    }
    Ok(JsonPathIndex::Slice(start, end, step))
}

fn parse_unit_keys(pairs: Pairs<Rule>) -> Result<JsonPathIndex, JsonPathParserError> {
    let mut keys = vec![];

    for pair in pairs {
        keys.push(String::from(down(pair)?.as_str()));
    }
    Ok(JsonPathIndex::UnionKeys(keys))
}

fn number_to_value(number: &str) -> Result<Value, JsonPathParserError> {
    match number
        .parse::<i64>()
        .ok()
        .map(Value::from)
        .or_else(|| number.parse::<f64>().ok().map(Value::from))
    {
        Some(value) => Ok(value),
        None => Err(JsonPathParserError::ParserError(format!(
            "Failed to parse {number} as either f64 or i64"
        ))),
    }
}

fn parse_unit_indexes(pairs: Pairs<Rule>) -> Result<JsonPathIndex, JsonPathParserError> {
    let mut keys = vec![];

    for pair in pairs {
        keys.push(number_to_value(pair.as_str())?);
    }
    Ok(JsonPathIndex::UnionIndex(keys))
}

fn parse_chain_in_operand(rule: Pair<Rule>) -> Result<Operand, JsonPathParserError> {
    let parsed_chain = match parse_internal(rule)? {
        JsonPath::Chain(elems) => {
            if elems.len() == 1 {
                match elems.first() {
                    Some(JsonPath::Index(JsonPathIndex::UnionKeys(keys))) => {
                        Operand::val(Value::from(keys.clone()))
                    }
                    Some(JsonPath::Index(JsonPathIndex::UnionIndex(keys))) => {
                        Operand::val(Value::from(keys.clone()))
                    }
                    Some(JsonPath::Field(f)) => {
                        Operand::val(Value::Array(vec![Value::from(f.clone())]))
                    }
                    _ => Operand::Dynamic(Box::new(JsonPath::Chain(elems))),
                }
            } else {
                Operand::Dynamic(Box::new(JsonPath::Chain(elems)))
            }
        }
        jp => Operand::Dynamic(Box::new(jp)),
    };
    Ok(parsed_chain)
}

fn parse_filter_index(pair: Pair<Rule>) -> Result<JsonPathIndex, JsonPathParserError> {
    Ok(JsonPathIndex::Filter(parse_logic_or(pair.into_inner())?))
}

fn parse_logic_or(pairs: Pairs<Rule>) -> Result<FilterExpression, JsonPathParserError> {
    let mut expr: Option<FilterExpression> = None;
    let error_message = format!("Failed to parse logical expression: {:?}", pairs);
    for pair in pairs {
        let next_expr = parse_logic_and(pair.into_inner())?;
        match expr {
            None => expr = Some(next_expr),
            Some(e) => expr = Some(Or(Box::new(e), Box::new(next_expr))),
        }
    }
    match expr {
        Some(expr) => Ok(expr),
        None => Err(JsonPathParserError::ParserError(error_message)),
    }
}

fn parse_logic_and(pairs: Pairs<Rule>) -> Result<FilterExpression, JsonPathParserError> {
    let mut expr: Option<FilterExpression> = None;
    let error_message = format!("Failed to parse logical `and` expression: {:?}", pairs,);
    for pair in pairs {
        let next_expr = parse_logic_not(pair.into_inner())?;
        match expr {
            None => expr = Some(next_expr),
            Some(e) => expr = Some(And(Box::new(e), Box::new(next_expr))),
        }
    }
    match expr {
        Some(expr) => Ok(expr),
        None => Err(JsonPathParserError::ParserError(error_message)),
    }
}

fn parse_logic_not(mut pairs: Pairs<Rule>) -> Result<FilterExpression, JsonPathParserError> {
    if let Some(rule) = pairs.peek().map(|x| x.as_rule()) {
        match rule {
            Rule::not => {
                pairs.next().expect("unreachable in arithmetic: should have a value as pairs.peek() was Some(_)");
                parse_logic_not(pairs)
                    .map(|expr|Not(Box::new(expr)))
            },
            Rule::logic_atom => parse_logic_atom(pairs.next().expect("unreachable in arithmetic: should have a value as pairs.peek() was Some(_)").into_inner()),
            x => Err(JsonPathParserError::UnexpectedRuleLogicError(x, pairs)),
        }
    } else {
        Err(JsonPathParserError::UnexpectedNoneLogicError(pairs))
    }
}

fn parse_logic_atom(mut pairs: Pairs<Rule>) -> Result<FilterExpression, JsonPathParserError> {
    if let Some(rule) = pairs.peek().map(|x| x.as_rule()) {
        match rule {
            Rule::logic_or => parse_logic_or(pairs.next().expect("unreachable in arithmetic: should have a value as pairs.peek() was Some(_)").into_inner()),
            Rule::atom => {
                let left: Operand = parse_atom(pairs.next().unwrap())?;
                if pairs.peek().is_none() {
                    Ok(FilterExpression::exists(left))
                } else {
                    let sign: FilterSign = FilterSign::new(pairs.next().expect("unreachable in arithmetic: should have a value as pairs.peek() was Some(_)").as_str());
                    let right: Operand =
                        parse_atom(pairs.next().expect("unreachable in arithemetic: should have a right side operand"))?;
                    Ok(FilterExpression::Atom(left, sign, right))
                }
            }
            x => Err(JsonPathParserError::UnexpectedRuleLogicError(x, pairs)),
        }
    } else {
        Err(JsonPathParserError::UnexpectedNoneLogicError(pairs))
    }
}

fn parse_atom(rule: Pair<Rule>) -> Result<Operand, JsonPathParserError> {
    let atom = down(rule.clone())?;
    let parsed_atom = match atom.as_rule() {
        Rule::number => Operand::Static(number_to_value(rule.as_str())?),
        Rule::string_qt => Operand::Static(Value::from(down(atom)?.as_str())),
        Rule::chain => parse_chain_in_operand(down(rule)?)?,
        Rule::boolean => Operand::Static(rule.as_str().parse::<Value>()?),
        _ => Operand::Static(Value::Null),
    };
    Ok(parsed_atom)
}

fn parse_index(rule: Pair<Rule>) -> Result<JsonPathIndex, JsonPathParserError> {
    let next = down(rule)?;
    let parsed_index = match next.as_rule() {
        Rule::unsigned => JsonPathIndex::Single(number_to_value(next.as_str())?),
        Rule::slice => parse_slice(next.into_inner())?,
        Rule::unit_indexes => parse_unit_indexes(next.into_inner())?,
        Rule::unit_keys => parse_unit_keys(next.into_inner())?,
        Rule::filter => parse_filter_index(down(next)?)?,
        _ => JsonPathIndex::Single(number_to_value(next.as_str())?),
    };
    Ok(parsed_index)
}

fn down(rule: Pair<Rule>) -> Result<Pair<Rule>, JsonPathParserError> {
    let error_message = format!("Failed to get inner pairs for {:?}", rule);
    match rule.into_inner().next() {
        Some(rule) => Ok(rule.to_owned()),
        None => Err(ParserError(error_message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chain, filter, function, idx, op, path};
    use serde_json::json;
    use std::panic;

    fn test_failed(input: &str) {
        match parse_json_path(input) {
            Ok(elem) => panic!("should be false but got {:?}", elem),
            Err(e) => println!("{}", e),
        }
    }

    fn test(input: &str, expected: Vec<JsonPath>) {
        match parse_json_path(input) {
            Ok(JsonPath::Chain(elems)) => assert_eq!(elems, expected),
            Ok(e) => panic!("unexpected value {:?}", e),
            Err(e) => {
                panic!("parsing error {}", e);
            }
        }
    }

    #[test]
    fn path_test() {
        test("$.k.['k']['k']..k..['k'].*.[*][*][1][1,2]['k','k'][:][10:][:10][10:10:10][?(@)][?(@.abc >= 10)]",
             vec![
                 path!($),
                 path!("k"),
                 path!("k"),
                 path!("k"),
                 path!(.."k"),
                 path!(.."k"),
                 path!(*),
                 path!(*),
                 path!(*),
                 path!(idx!(1)),
                 path!(idx!(idx 1,2)),
                 path!(idx!("k","k")),
                 path!(idx!([; ;])),
                 path!(idx!([10; ;])),
                 path!(idx!([;10;])),
                 path!(idx!([10;10;10])),
                 path!(idx!(?filter!(op!(chain!(path!(@path!()))), "exists", op!(path!())))),
                 path!(idx!(?filter!(op!(chain!(path!(@,path!("abc")))), ">=", op!(10)))),
             ]);
        test(
            "$..*[?(@.isbn)].title",
            vec![
                // Root, DescentW, Index(Filter(Atom(Dynamic(Chain([Current(Chain([Field("isbn")]))])), Exists, Dynamic(Empty)))), Field("title")
                path!($),
                path!(..*),
                path!(idx!(?filter!(op!(chain!(path!(@,path!("isbn")))), "exists", op!(path!())))),
                path!("title"),
            ],
        )
    }

    #[test]
    fn descent_test() {
        test("..abc", vec![path!(.."abc")]);
        test("..['abc']", vec![path!(.."abc")]);
        test_failed("...['abc']");
        test_failed("...abc");
    }

    #[test]
    fn field_test() {
        test(".abc", vec![path!("abc")]);
        test(".['abc']", vec![path!("abc")]);
        test("['abc']", vec![path!("abc")]);
        test(".['abc\\\"abc']", vec![path!("abc\\\"abc")]);
        test_failed(".abc()abc");
        test_failed("..[abc]");
        test_failed(".'abc'");
    }

    #[test]
    fn wildcard_test() {
        test(".*", vec![path!(*)]);
        test(".[*]", vec![path!(*)]);
        test(".abc.*", vec![path!("abc"), path!(*)]);
        test(".abc.[*]", vec![path!("abc"), path!(*)]);
        test(".abc[*]", vec![path!("abc"), path!(*)]);
        test("..*", vec![path!(..*)]);
        test_failed("abc*");
    }

    #[test]
    fn index_single_test() {
        test("[1]", vec![path!(idx!(1))]);
        test_failed("[-1]");
        test_failed("[1a]");
    }

    #[test]
    fn index_slice_test() {
        test("[1:1000:10]", vec![path!(idx!([1; 1000; 10]))]);
        test("[:1000:10]", vec![path!(idx!([0; 1000; 10]))]);
        test("[:1000]", vec![path!(idx!([;1000;]))]);
        test("[:]", vec![path!(idx!([;;]))]);
        test("[::10]", vec![path!(idx!([;;10]))]);
        test_failed("[::-1]");
        test_failed("[:::0]");
    }

    #[test]
    fn index_union_test() {
        test("[1,2,3]", vec![path!(idx!(idx 1,2,3))]);
        test("['abc','bcd']", vec![path!(idx!("abc", "bcd"))]);
        test_failed("[]");
        test("[-1,-2]", vec![path!(idx!(idx - 1, -2))]);
        test_failed("[abc,bcd]");
        test("[\"abc\",\"bcd\"]", vec![path!(idx!("abc", "bcd"))]);
    }

    #[test]
    fn array_start_test() {
        test(
            "$.[?(@.verb== \"TEST\")]",
            vec![
                path!($),
                path!(idx!(?filter!(op!(chain!(path!(@,path!("verb")))),"==",op!("TEST")))),
            ],
        );
    }

    #[test]
    fn logical_filter_test() {
        test(
            "$.[?(@.verb == 'T' || @.size > 0 && @.size < 10)]",
            vec![
                path!($),
                path!(idx!(?
                filter!(
                    filter!(op!(chain!(path!(@,path!("verb")))), "==", op!("T")),
                    ||,
                    filter!(
                        filter!(op!(chain!(path!(@,path!("size")))), ">", op!(0)),
                        &&,
                        filter!(op!(chain!(path!(@,path!("size")))), "<", op!(10))
                    )
                ))),
            ],
        );
        test(
            "$.[?((@.verb == 'T' || @.size > 0) && @.size < 10)]",
            vec![
                path!($),
                path!(idx!(?
                filter!(
                    filter!(
                       filter!(op!(chain!(path!(@,path!("verb")))), "==", op!("T")),
                        ||,
                        filter!(op!(chain!(path!(@,path!("size")))), ">", op!(0))
                    ),
                    &&,
                    filter!(op!(chain!(path!(@,path!("size")))), "<", op!(10))
                ))),
            ],
        );
        test(
            "$.[?(@.verb == 'T' || @.size > 0 && @.size < 10 && @.elem == 0)]",
            vec![
                path!($),
                path!(idx!(?filter!(
                    filter!(op!(chain!(path!(@,path!("verb")))), "==", op!("T")),
                    ||,
                    filter!(
                        filter!(
                            filter!(op!(chain!(path!(@,path!("size")))), ">", op!(0)),
                            &&,
                            filter!(op!(chain!(path!(@,path!("size")))), "<", op!(10))
                        ),
                        &&,
                        filter!(op!(chain!(path!(@,path!("elem")))), "==", op!(0))
                    )

                ))),
            ],
        );
    }

    #[test]
    fn index_filter_test() {
        test(
            "[?('abc' == 'abc')]",
            vec![path!(idx!(?filter!(op!("abc"),"==",op!("abc") )))],
        );
        test(
            "[?('abc' == 1)]",
            vec![path!(idx!(?filter!( op!("abc"),"==",op!(1))))],
        );
        test(
            "[?('abc' == true)]",
            vec![path!(idx!(?filter!( op!("abc"),"==",op!(true))))],
        );
        test(
            "[?('abc' == null)]",
            vec![path!(
                idx!(?filter!( op!("abc"),"==",Operand::Static(Value::Null)))
            )],
        );

        test(
            "[?(@.abc in ['abc','bcd'])]",
            vec![path!(
                idx!(?filter!(op!(chain!(path!(@,path!("abc")))),"in",Operand::val(json!(["abc","bcd"]))))
            )],
        );

        test(
            "[?(@.abc.[*] in ['abc','bcd'])]",
            vec![path!(idx!(?filter!(
               op!(chain!(path!(@,path!("abc"), path!(*)))),
                "in",
                op!(s json!(["abc","bcd"]))
            )))],
        );
        test(
            "[?(@.[*]..next in ['abc','bcd'])]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@,path!(*), path!(.."next")))),
                "in",
                op!(s json!(["abc","bcd"]))
            )))],
        );

        test(
            "[?(@[1] in ['abc','bcd'])]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@,path!(idx!(1))))),
                "in",
                op!(s json!(["abc","bcd"]))
            )))],
        );
        test(
            "[?(@ == 'abc')]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@path!()))),"==",op!("abc")
            )))],
        );
        test(
            "[?(@ subsetOf ['abc'])]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@path!()))),"subsetOf",op!(s json!(["abc"]))
            )))],
        );
        test(
            "[?(@[1] subsetOf ['abc','abc'])]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@,path!(idx!(1))))),
                "subsetOf",
                op!(s json!(["abc","abc"]))
            )))],
        );
        test(
            "[?(@ subsetOf [1,2,3])]",
            vec![path!(idx!(?filter!(
                op!(chain!(path!(@path!()))),"subsetOf",op!(s json!([1,2,3]))
            )))],
        );

        test_failed("[?(@[1] subsetof ['abc','abc'])]");
        test_failed("[?(@ >< ['abc','abc'])]");
        test_failed("[?(@ in {\"abc\":1})]");
    }

    #[test]
    fn fn_size_test() {
        test(
            "$.k.length()",
            vec![path!($), path!("k"), function!(length)],
        );

        test(
            "$.k.length.field",
            vec![path!($), path!("k"), path!("length"), path!("field")],
        )
    }

    #[test]
    fn parser_error_test_invalid_rule() {
        let result = parse_json_path("notapath");

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .starts_with("Failed to parse rule"));
    }

    #[test]
    fn parser_error_test_empty_rule() {
        let result = parse_json_path("");

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .starts_with("Failed to parse rule"));
    }
}
