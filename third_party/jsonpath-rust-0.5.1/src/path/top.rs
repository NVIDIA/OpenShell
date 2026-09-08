use crate::parser::model::*;
use crate::path::config::JsonPathConfig;
use crate::path::{json_path_instance, JsonPathValue, Path, PathInstance};
use crate::JsonPathValue::{NewValue, NoValue, Slice};
use crate::{jsp_idx, jsp_obj, JsPathStr};
use serde_json::value::Value::{Array, Object};
use serde_json::{json, Value};

/// to process the element [*]
pub(crate) struct Wildcard {}

impl<'a> Path<'a> for Wildcard {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        data.flat_map_slice(|data, pref| {
            let res = match data {
                Array(elems) => {
                    let mut res = vec![];
                    for (idx, el) in elems.iter().enumerate() {
                        res.push(Slice(el, jsp_idx(&pref, idx)));
                    }

                    res
                }
                Object(elems) => {
                    let mut res = vec![];
                    for (key, el) in elems.into_iter() {
                        res.push(Slice(el, jsp_obj(&pref, key)));
                    }
                    res
                }
                _ => vec![],
            };
            if res.is_empty() {
                vec![NoValue]
            } else {
                res
            }
        })
    }
}

/// empty path. Returns incoming data.
pub(crate) struct IdentityPath {}

impl<'a> Path<'a> for IdentityPath {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        vec![data]
    }
}

pub(crate) struct EmptyPath {}

impl<'a> Path<'a> for EmptyPath {
    type Data = Value;

    fn find(&self, _data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        vec![]
    }
}

/// process $ element
pub(crate) struct RootPointer<'a, T> {
    root: &'a T,
}

impl<'a, T> RootPointer<'a, T> {
    pub(crate) fn new(root: &'a T) -> RootPointer<'a, T> {
        RootPointer { root }
    }
}

impl<'a> Path<'a> for RootPointer<'a, Value> {
    type Data = Value;

    fn find(&self, _data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        vec![JsonPathValue::from_root(self.root)]
    }
}

/// process object fields like ['key'] or .key
pub(crate) struct ObjectField<'a> {
    key: &'a str,
}

impl<'a> ObjectField<'a> {
    pub(crate) fn new(key: &'a str) -> ObjectField<'a> {
        ObjectField { key }
    }
}

impl<'a> Clone for ObjectField<'a> {
    fn clone(&self) -> Self {
        ObjectField::new(self.key)
    }
}

impl<'a> Path<'a> for FnPath {
    type Data = Value;

    fn flat_find(
        &self,
        input: Vec<JsonPathValue<'a, Self::Data>>,
        is_search_length: bool,
    ) -> Vec<JsonPathValue<'a, Self::Data>> {
        // todo rewrite
        if JsonPathValue::only_no_value(&input) {
            return vec![NoValue];
        }
        let res = if is_search_length {
            NewValue(json!(input.iter().filter(|v| v.has_value()).count()))
        } else {
            let take_len = |v: &Value| match v {
                Array(elems) => NewValue(json!(elems.len())),
                _ => NoValue,
            };

            match input.first() {
                Some(v) => match v {
                    NewValue(d) => take_len(d),
                    Slice(s, _) => take_len(s),
                    NoValue => NoValue,
                },
                None => NoValue,
            }
        };
        vec![res]
    }

    fn needs_all(&self) -> bool {
        true
    }
}

pub(crate) enum FnPath {
    Size,
}

impl<'a> Path<'a> for ObjectField<'a> {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        let take_field = |v: &'a Value| match v {
            Object(fields) => fields.get(self.key),
            _ => None,
        };

        let res = match data {
            Slice(js, p) => take_field(js)
                .map(|v| JsonPathValue::new_slice(v, jsp_obj(&p, self.key)))
                .unwrap_or_else(|| NoValue),
            _ => NoValue,
        };
        vec![res]
    }
}

/// the top method of the processing ..*
pub(crate) struct DescentWildcard;

impl<'a> Path<'a> for DescentWildcard {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        data.map_slice(deep_flatten)
    }
}

// todo rewrite to tail rec
fn deep_flatten(data: &Value, pref: JsPathStr) -> Vec<(&Value, JsPathStr)> {
    let mut acc = vec![];
    match data {
        Object(elems) => {
            for (f, v) in elems.into_iter() {
                let pref = jsp_obj(&pref, f);
                acc.push((v, pref.clone()));
                acc.append(&mut deep_flatten(v, pref));
            }
        }
        Array(elems) => {
            for (i, v) in elems.iter().enumerate() {
                let pref = jsp_idx(&pref, i);
                acc.push((v, pref.clone()));
                acc.append(&mut deep_flatten(v, pref));
            }
        }
        _ => (),
    }
    acc
}

// todo rewrite to tail rec
fn deep_path_by_key<'a>(
    data: &'a Value,
    key: ObjectField<'a>,
    pref: JsPathStr,
) -> Vec<(&'a Value, JsPathStr)> {
    let mut result: Vec<(&'a Value, JsPathStr)> =
        JsonPathValue::vec_as_pair(key.find(JsonPathValue::new_slice(data, pref.clone())));
    match data {
        Object(elems) => {
            let mut next_levels: Vec<(&'a Value, JsPathStr)> = elems
                .into_iter()
                .flat_map(|(k, v)| deep_path_by_key(v, key.clone(), jsp_obj(&pref, k)))
                .collect();
            result.append(&mut next_levels);
            result
        }
        Array(elems) => {
            let mut next_levels: Vec<(&'a Value, JsPathStr)> = elems
                .iter()
                .enumerate()
                .flat_map(|(i, v)| deep_path_by_key(v, key.clone(), jsp_idx(&pref, i)))
                .collect();
            result.append(&mut next_levels);
            result
        }
        _ => result,
    }
}

/// processes decent object like ..
pub(crate) struct DescentObject<'a> {
    key: &'a str,
}

impl<'a> Path<'a> for DescentObject<'a> {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        data.flat_map_slice(|data, pref| {
            let res_col = deep_path_by_key(data, ObjectField::new(self.key), pref.clone());
            if res_col.is_empty() {
                vec![NoValue]
            } else {
                JsonPathValue::map_vec(res_col)
            }
        })
    }
}

impl<'a> DescentObject<'a> {
    pub fn new(key: &'a str) -> Self {
        DescentObject { key }
    }
}

/// the top method of the processing representing the chain of other operators
pub(crate) struct Chain<'a> {
    chain: Vec<PathInstance<'a>>,
    is_search_length: bool,
}

impl<'a> Chain<'a> {
    pub fn new(chain: Vec<PathInstance<'a>>, is_search_length: bool) -> Self {
        Chain {
            chain,
            is_search_length,
        }
    }
    pub fn from(chain: &'a [JsonPath], root: &'a Value, cfg: JsonPathConfig) -> Self {
        let chain_len = chain.len();
        let is_search_length = if chain_len > 2 {
            let mut res = false;
            // if the result of the slice expected to be a slice, union or filter -
            // length should return length of resulted array
            // In all other cases, including single index, we should fetch item from resulting array
            // and return length of that item
            res = match chain.get(chain_len - 1).expect("chain element disappeared") {
                JsonPath::Fn(Function::Length) => {
                    for item in chain.iter() {
                        match (item, res) {
                            // if we found union, slice, filter or wildcard - set search to true
                            (
                                JsonPath::Index(JsonPathIndex::UnionIndex(_))
                                | JsonPath::Index(JsonPathIndex::UnionKeys(_))
                                | JsonPath::Index(JsonPathIndex::Slice(_, _, _))
                                | JsonPath::Index(JsonPathIndex::Filter(_))
                                | JsonPath::Wildcard,
                                false,
                            ) => {
                                res = true;
                            }
                            // if we found a fetching of single index - reset search to false
                            (JsonPath::Index(JsonPathIndex::Single(_)), true) => {
                                res = false;
                            }
                            (_, _) => {}
                        }
                    }
                    res
                }
                _ => false,
            };
            res
        } else {
            false
        };

        Chain::new(
            chain
                .iter()
                .map(|p| json_path_instance(p, root, cfg.clone()))
                .collect(),
            is_search_length,
        )
    }
}

impl<'a> Path<'a> for Chain<'a> {
    type Data = Value;

    fn find(&self, data: JsonPathValue<'a, Self::Data>) -> Vec<JsonPathValue<'a, Self::Data>> {
        let mut res = vec![data];

        for inst in self.chain.iter() {
            if inst.needs_all() {
                res = inst.flat_find(res, self.is_search_length)
            } else {
                res = res.into_iter().flat_map(|d| inst.find(d)).collect()
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::model::{JsonPath, JsonPathIndex};
    use crate::path::top::{deep_flatten, json_path_instance, Function, ObjectField, RootPointer};
    use crate::path::{JsonPathValue, Path};
    use crate::JsonPathValue::NoValue;
    use crate::{chain, function, idx, jp_v, path};
    use serde_json::json;
    use serde_json::Value;

    #[test]
    fn object_test() {
        let js = json!({"product": {"key":42}});
        let res_income = jp_v!(&js);

        let key = String::from("product");
        let mut field = ObjectField::new(&key);
        let js = json!({"key":42});
        assert_eq!(
            field.find(res_income.clone()),
            vec![jp_v!(&js;".['product']")]
        );

        let key = String::from("fake");
        field.key = &key;
        assert_eq!(field.find(res_income), vec![NoValue]);
    }

    #[test]
    fn root_test() {
        let res_income = json!({"product": {"key":42}});

        let root = RootPointer::<Value>::new(&res_income);

        assert_eq!(root.find(jp_v!(&res_income)), jp_v!(&res_income;"$",))
    }

    #[test]
    fn path_instance_test() {
        let json = json!({"v": {"k":{"f":42,"array":[0,1,2,3,4,5],"object":{"field1":"val1","field2":"val2"}}}});
        let field1 = path!("v");
        let field2 = path!("k");
        let field3 = path!("f");
        let field4 = path!("array");
        let field5 = path!("object");

        let path_inst = json_path_instance(&path!($), &json, Default::default());
        assert_eq!(path_inst.find(jp_v!(&json)), jp_v!(&json;"$",));

        let path_inst = json_path_instance(&field1, &json, Default::default());
        let exp_json =
            json!({"k":{"f":42,"array":[0,1,2,3,4,5],"object":{"field1":"val1","field2":"val2"}}});
        assert_eq!(path_inst.find(jp_v!(&json)), jp_v!(&exp_json;".['v']",));

        let chain = chain!(path!($), field1.clone(), field2.clone(), field3);

        let path_inst = json_path_instance(&chain, &json, Default::default());
        let exp_json = json!(42);
        assert_eq!(
            path_inst.find(jp_v!(&json)),
            jp_v!(&exp_json;"$.['v'].['k'].['f']",)
        );

        let chain = chain!(
            path!($),
            field1.clone(),
            field2.clone(),
            field4.clone(),
            path!(idx!(3))
        );
        let path_inst = json_path_instance(&chain, &json, Default::default());
        let exp_json = json!(3);
        assert_eq!(
            path_inst.find(jp_v!(&json)),
            jp_v!(&exp_json;"$.['v'].['k'].['array'][3]",)
        );

        let index = idx!([1;-1;2]);
        let chain = chain!(
            path!($),
            field1.clone(),
            field2.clone(),
            field4.clone(),
            path!(index)
        );
        let path_inst = json_path_instance(&chain, &json, Default::default());
        let one = json!(1);
        let tree = json!(3);
        assert_eq!(
            path_inst.find(jp_v!(&json)),
            jp_v!(&one;"$.['v'].['k'].['array'][1]", &tree;"$.['v'].['k'].['array'][3]")
        );

        let union = idx!(idx 1,2 );
        let chain = chain!(
            path!($),
            field1.clone(),
            field2.clone(),
            field4,
            path!(union)
        );
        let path_inst = json_path_instance(&chain, &json, Default::default());
        let tree = json!(1);
        let two = json!(2);
        assert_eq!(
            path_inst.find(jp_v!(&json)),
            jp_v!(&tree;"$.['v'].['k'].['array'][1]",&two;"$.['v'].['k'].['array'][2]")
        );

        let union = idx!("field1", "field2");
        let chain = chain!(path!($), field1.clone(), field2, field5, path!(union));
        let path_inst = json_path_instance(&chain, &json, Default::default());
        let one = json!("val1");
        let two = json!("val2");
        assert_eq!(
            path_inst.find(jp_v!(&json)),
            jp_v!(
            &one;"$.['v'].['k'].['object'].['field1']",
            &two;"$.['v'].['k'].['object'].['field2']")
        );
    }

    #[test]
    fn path_descent_arr_test() {
        let json = json!([{"a":1}]);
        let chain = chain!(path!($), path!(.."a"));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let one = json!(1);
        let expected_res = jp_v!(&one;"$[0].['a']",);
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn deep_path_test() {
        let value = json!([1]);
        let r = deep_flatten(&value, "".to_string());
        assert_eq!(r, vec![(&json!(1), "[0]".to_string())])
    }

    #[test]
    fn path_descent_w_array_test() {
        let json = json!(
        {
            "key1": [1]
        });
        let chain = chain!(path!($), path!(..*));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let arr = json!([1]);
        let one = json!(1);

        let expected_res = jp_v!(&arr;"$.['key1']",&one;"$.['key1'][0]");
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn path_descent_w_nested_array_test() {
        let json = json!(
        {
            "key2" : [{"a":1},{}]
        });
        let chain = chain!(path!($), path!(..*));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let arr2 = json!([{"a": 1},{}]);
        let obj = json!({"a": 1});
        let empty = json!({});

        let one = json!(1);

        let expected_res = jp_v!(
            &arr2;"$.['key2']",
            &obj;"$.['key2'][0]",
            &one;"$.['key2'][0].['a']",
            &empty;"$.['key2'][1]"
        );
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn path_descent_w_test() {
        let json = json!(
        {
            "key1": [1],
            "key2": "key",
            "key3": {
                "key1": "key1",
                "key2": {
                    "key1": {
                        "key1": 0
                         }
                     }
            }
        });
        let chain = chain!(path!($), path!(..*));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let key1 = json!([1]);
        let one = json!(1);
        let zero = json!(0);
        let key = json!("key");
        let key1_s = json!("key1");

        let key_3 = json!(  {
          "key1": "key1",
          "key2": {
            "key1": {
              "key1": 0
            }
          }
        });
        let key_sec = json!(    {
          "key1": {
            "key1": 0
          }
        });
        let key_th = json!(  {
          "key1": 0
        });

        let expected_res = vec![
            jp_v!(&key1;"$.['key1']"),
            jp_v!(&one;"$.['key1'][0]"),
            jp_v!(&key;"$.['key2']"),
            jp_v!(&key_3;"$.['key3']"),
            jp_v!(&key1_s;"$.['key3'].['key1']"),
            jp_v!(&key_sec;"$.['key3'].['key2']"),
            jp_v!(&key_th;"$.['key3'].['key2'].['key1']"),
            jp_v!(&zero;"$.['key3'].['key2'].['key1'].['key1']"),
        ];
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn path_descent_test() {
        let json = json!(
        {
            "key1": [1,2,3],
            "key2": "key",
            "key3": {
                "key1": "key1",
                "key2": {
                    "key1": {
                        "key1": 0
                         }
                     }
            }
        });
        let chain = chain!(path!($), path!(.."key1"));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let res1 = json!([1, 2, 3]);
        let res2 = json!("key1");
        let res3 = json!({"key1":0});
        let res4 = json!(0);

        let expected_res = jp_v!(
            &res1;"$.['key1']",
            &res2;"$.['key3'].['key1']",
            &res3;"$.['key3'].['key2'].['key1']",
            &res4;"$.['key3'].['key2'].['key1'].['key1']",
        );
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn wildcard_test() {
        let json = json!({
            "key1": [1,2,3],
            "key2": "key",
            "key3": {}
        });

        let chain = chain!(path!($), path!(*));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        let res1 = json!([1, 2, 3]);
        let res2 = json!("key");
        let res3 = json!({});

        let expected_res = jp_v!(&res1;"$.['key1']", &res2;"$.['key2']", &res3;"$.['key3']");
        assert_eq!(path_inst.find(jp_v!(&json)), expected_res)
    }

    #[test]
    fn length_test() {
        let json = json!({
            "key1": [1,2,3],
            "key2": "key",
            "key3": {}
        });

        let chain = chain!(path!($), path!(*), function!(length));
        let path_inst = json_path_instance(&chain, &json, Default::default());

        assert_eq!(
            path_inst.flat_find(vec![jp_v!(&json)], true),
            vec![jp_v!(json!(3))]
        );

        let chain = chain!(path!($), path!("key1"), function!(length));
        let path_inst = json_path_instance(&chain, &json, Default::default());
        assert_eq!(
            path_inst.flat_find(vec![jp_v!(&json)], false),
            vec![jp_v!(json!(3))]
        );
    }
}
