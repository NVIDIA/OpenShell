use crate::parse_json_path;
use serde_json::Value;
use std::convert::TryFrom;

/// The basic structures for parsing json paths.
/// The common logic of the structures pursues to correspond the internal parsing structure.
#[derive(Debug, Clone)]
pub enum JsonPath {
    /// The $ operator
    Root,
    /// Field represents key
    Field(String),
    /// The whole chain of the path.
    Chain(Vec<JsonPath>),
    /// The .. operator
    Descent(String),
    /// The ..* operator
    DescentW,
    /// The indexes for array
    Index(JsonPathIndex),
    /// The @ operator
    Current(Box<JsonPath>),
    /// The * operator
    Wildcard,
    /// The item uses to define the unresolved state
    Empty,
    /// Functions that can calculate some expressions
    Fn(Function),
}

impl JsonPath {
    pub fn current(jp: JsonPath) -> Self {
        JsonPath::Current(Box::new(jp))
    }
}

impl TryFrom<&str> for JsonPath {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_json_path(value).map_err(|e| e.to_string())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Function {
    /// length()
    Length,
}
#[derive(Debug, Clone)]
pub enum JsonPathIndex {
    /// A single element in array
    Single(Value),
    /// Union represents a several indexes
    UnionIndex(Vec<Value>),
    /// Union represents a several keys
    UnionKeys(Vec<String>),
    /// DEfault slice where the items are start/end/step respectively
    Slice(i32, i32, usize),
    /// Filter ?()
    Filter(FilterExpression),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpression {
    /// a single expression like a > 2
    Atom(Operand, FilterSign, Operand),
    /// and with &&
    And(Box<FilterExpression>, Box<FilterExpression>),
    /// or with ||
    Or(Box<FilterExpression>, Box<FilterExpression>),
    /// not with !
    Not(Box<FilterExpression>),
}

impl FilterExpression {
    pub fn exists(op: Operand) -> Self {
        FilterExpression::Atom(
            op,
            FilterSign::Exists,
            Operand::Dynamic(Box::new(JsonPath::Empty)),
        )
    }
}

/// Operand for filtering expressions
#[derive(Debug, Clone)]
pub enum Operand {
    Static(Value),
    Dynamic(Box<JsonPath>),
}

#[allow(dead_code)]
impl Operand {
    pub fn val(v: Value) -> Self {
        Operand::Static(v)
    }
}

/// The operators for filtering functions
#[derive(Debug, Clone, PartialEq)]
pub enum FilterSign {
    Equal,
    Unequal,
    Less,
    Greater,
    LeOrEq,
    GrOrEq,
    Regex,
    In,
    Nin,
    Size,
    NoneOf,
    AnyOf,
    SubSetOf,
    Exists,
}

impl FilterSign {
    pub fn new(key: &str) -> Self {
        match key {
            "==" => FilterSign::Equal,
            "!=" => FilterSign::Unequal,
            "<" => FilterSign::Less,
            ">" => FilterSign::Greater,
            "<=" => FilterSign::LeOrEq,
            ">=" => FilterSign::GrOrEq,
            "~=" => FilterSign::Regex,
            "in" => FilterSign::In,
            "nin" => FilterSign::Nin,
            "size" => FilterSign::Size,
            "noneOf" => FilterSign::NoneOf,
            "anyOf" => FilterSign::AnyOf,
            "subsetOf" => FilterSign::SubSetOf,
            _ => FilterSign::Exists,
        }
    }
}

impl PartialEq for JsonPath {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JsonPath::Root, JsonPath::Root) => true,
            (JsonPath::Descent(k1), JsonPath::Descent(k2)) => k1 == k2,
            (JsonPath::DescentW, JsonPath::DescentW) => true,
            (JsonPath::Field(k1), JsonPath::Field(k2)) => k1 == k2,
            (JsonPath::Wildcard, JsonPath::Wildcard) => true,
            (JsonPath::Empty, JsonPath::Empty) => true,
            (JsonPath::Current(jp1), JsonPath::Current(jp2)) => jp1 == jp2,
            (JsonPath::Chain(ch1), JsonPath::Chain(ch2)) => ch1 == ch2,
            (JsonPath::Index(idx1), JsonPath::Index(idx2)) => idx1 == idx2,
            (JsonPath::Fn(fn1), JsonPath::Fn(fn2)) => fn2 == fn1,
            (_, _) => false,
        }
    }
}

impl PartialEq for JsonPathIndex {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JsonPathIndex::Slice(s1, e1, st1), JsonPathIndex::Slice(s2, e2, st2)) => {
                s1 == s2 && e1 == e2 && st1 == st2
            }
            (JsonPathIndex::Single(el1), JsonPathIndex::Single(el2)) => el1 == el2,
            (JsonPathIndex::UnionIndex(elems1), JsonPathIndex::UnionIndex(elems2)) => {
                elems1 == elems2
            }
            (JsonPathIndex::UnionKeys(elems1), JsonPathIndex::UnionKeys(elems2)) => {
                elems1 == elems2
            }
            (JsonPathIndex::Filter(left), JsonPathIndex::Filter(right)) => left.eq(right),
            (_, _) => false,
        }
    }
}

impl PartialEq for Operand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Operand::Static(v1), Operand::Static(v2)) => v1 == v2,
            (Operand::Dynamic(jp1), Operand::Dynamic(jp2)) => jp1 == jp2,
            (_, _) => false,
        }
    }
}
