#[macro_export]
macro_rules! filter {
   () => {FilterExpression::Atom(op!,FilterSign::new(""),op!())};
   ( $left:expr, $s:literal, $right:expr) => {
      FilterExpression::Atom($left,FilterSign::new($s),$right)
   };
   ( $left:expr,||, $right:expr) => {FilterExpression::Or(Box::new($left),Box::new($right)) };
   ( $left:expr,&&, $right:expr) => {FilterExpression::And(Box::new($left),Box::new($right)) };
}
#[macro_export]
macro_rules! op {
    ( ) => {
        Operand::Dynamic(Box::new(JsonPath::Empty))
    };
    ( $s:literal) => {
        Operand::Static(json!($s))
    };
    ( s $s:expr) => {
        Operand::Static(json!($s))
    };
    ( $s:expr) => {
        Operand::Dynamic(Box::new($s))
    };
}

#[macro_export]
macro_rules! idx {
   ( $s:literal) => {JsonPathIndex::Single(json!($s))};
   ( idx $($ss:literal),+) => {{
        let mut ss_vec = Vec::new();
        $( ss_vec.push(json!($ss)) ; )+
        JsonPathIndex::UnionIndex(ss_vec)
   }};
   ( $($ss:literal),+) => {{
        let mut ss_vec = Vec::new();
        $( ss_vec.push($ss.to_string()) ; )+
        JsonPathIndex::UnionKeys(ss_vec)
   }};
   ( $s:literal) => {JsonPathIndex::Single(json!($s))};
   ( ? $s:expr) => {JsonPathIndex::Filter($s)};
   ( [$l:literal;$m:literal;$r:literal]) => {JsonPathIndex::Slice($l,$m,$r)};
   ( [$l:literal;$m:literal;]) => {JsonPathIndex::Slice($l,$m,1)};
   ( [$l:literal;;$m:literal]) => {JsonPathIndex::Slice($l,0,$m)};
   ( [;$l:literal;$m:literal]) => {JsonPathIndex::Slice(0,$l,$m)};
   ( [;;$m:literal]) => {JsonPathIndex::Slice(0,0,$m)};
   ( [;$m:literal;]) => {JsonPathIndex::Slice(0,$m,1)};
   ( [$m:literal;;]) => {JsonPathIndex::Slice($m,0,1)};
   ( [;;]) => {JsonPathIndex::Slice(0,0,1)};
}

#[macro_export]
macro_rules! chain {
    ($($ss:expr),+) => {{
        let mut ss_vec = Vec::new();
        $( ss_vec.push($ss) ; )+
        JsonPath::Chain(ss_vec)
   }};
}

#[macro_export]
macro_rules! path {
   ( ) => {JsonPath::Empty};
   (*) => {JsonPath::Wildcard};
   ($) => {JsonPath::Root};
   (@) => {JsonPath::Current(Box::new(JsonPath::Empty))};
   (@$e:expr) => {JsonPath::Current(Box::new($e))};
   (@,$($ss:expr),+) => {{
        let mut ss_vec = Vec::new();
        $( ss_vec.push($ss) ; )+
        let chain = JsonPath::Chain(ss_vec);
        JsonPath::Current(Box::new(chain))
   }};
   (..$e:literal) => {JsonPath::Descent($e.to_string())};
   (..*) => {JsonPath::DescentW};
   ($e:literal) => {JsonPath::Field($e.to_string())};
   ($e:expr) => {JsonPath::Index($e)};
}
#[macro_export]
macro_rules! function {
    (length) => {
        JsonPath::Fn(Function::Length)
    };
}
