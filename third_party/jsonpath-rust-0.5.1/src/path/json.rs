use crate::path::config::cache::{RegexCache, RegexCacheInst};
use regex::Regex;
use serde_json::Value;

/// compare sizes of json elements
/// The method expects to get a number on the right side and array or string or object on the left
/// where the number of characters, elements or fields will be compared respectively.
pub fn size(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if let Some(Value::Number(n)) = right.first() {
        if let Some(sz) = n.as_f64() {
            for el in left.iter() {
                match el {
                    Value::String(v) if v.len() == sz as usize => true,
                    Value::Array(elems) if elems.len() == sz as usize => true,
                    Value::Object(fields) if fields.len() == sz as usize => true,
                    _ => return false,
                };
            }
            return true;
        }
    }
    false
}

/// ensure the array on the left side is a subset of the array on the right side.
//todo change the naive impl to sets
pub fn sub_set_of(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if left.is_empty() {
        return true;
    }
    if right.is_empty() {
        return false;
    }

    if let Some(elems) = left.first().and_then(|e| e.as_array()) {
        if let Some(Value::Array(right_elems)) = right.first() {
            if right_elems.is_empty() {
                return false;
            }

            for el in elems {
                let mut res = false;

                for r in right_elems.iter() {
                    if el.eq(r) {
                        res = true
                    }
                }
                if !res {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

/// ensure at least one element in the array  on the left side belongs to the array on the right side.
//todo change the naive impl to sets
pub fn any_of(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if left.is_empty() {
        return true;
    }
    if right.is_empty() {
        return false;
    }

    if let Some(Value::Array(elems)) = right.first() {
        if elems.is_empty() {
            return false;
        }

        for el in left.iter() {
            if let Some(left_elems) = el.as_array() {
                for l in left_elems.iter() {
                    for r in elems.iter() {
                        if l.eq(r) {
                            return true;
                        }
                    }
                }
            } else {
                for r in elems.iter() {
                    if el.eq(&r) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// ensure that the element on the left sides matches the regex on the right side
pub fn regex(
    left: Vec<&Value>,
    right: Vec<&Value>,
    cache: &RegexCache<impl RegexCacheInst + Clone>,
) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }

    match right.first() {
        Some(Value::String(str)) => {
            if cache.is_implemented() {
                cache
                    .get_instance()
                    .and_then(|inst| inst.validate(str, left))
                    .unwrap_or(false)
            } else if let Ok(regex) = Regex::new(str) {
                for el in left.iter() {
                    if let Some(v) = el.as_str() {
                        if regex.is_match(v) {
                            return true;
                        }
                    }
                }
                false
            } else {
                false
            }
        }
        _ => false,
    }
}

/// ensure that the element on the left side belongs to the array on the right side.
pub fn inside(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if left.is_empty() {
        return false;
    }

    match right.first() {
        Some(Value::Array(elems)) => {
            for el in left.iter() {
                if elems.contains(el) {
                    return true;
                }
            }
            false
        }
        Some(Value::Object(elems)) => {
            for el in left.iter() {
                for r in elems.values() {
                    if el.eq(&r) {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// ensure the number on the left side is less the number on the right side
pub fn less(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if left.len() == 1 && right.len() == 1 {
        match (left.first(), right.first()) {
            (Some(Value::Number(l)), Some(Value::Number(r))) => l
                .as_f64()
                .and_then(|v1| r.as_f64().map(|v2| v1 < v2))
                .unwrap_or(false),
            _ => false,
        }
    } else {
        false
    }
}

/// compare elements
pub fn eq(left: Vec<&Value>, right: Vec<&Value>) -> bool {
    if left.len() != right.len() {
        false
    } else {
        left.iter().zip(right).map(|(a, b)| a.eq(&b)).all(|a| a)
    }
}

#[cfg(test)]
mod tests {
    use crate::path::config::cache::RegexCache;
    use crate::path::json::{any_of, eq, less, regex, size, sub_set_of};
    use serde_json::{json, Value};

    #[test]
    fn value_eq_test() {
        let left = json!({"value":42});
        let right = json!({"value":42});
        let right_uneq = json!([42]);

        assert!(&left.eq(&right));
        assert!(!&left.eq(&right_uneq));
    }

    #[test]
    fn vec_value_test() {
        let left = json!({"value":42});
        let left1 = json!(42);
        let left2 = json!([1, 2, 3]);
        let left3 = json!({"value2":[42],"value":[42]});

        let right = json!({"value":42});
        let right1 = json!(42);
        let right2 = json!([1, 2, 3]);
        let right3 = json!({"value":[42],"value2":[42]});

        assert!(eq(vec![&left], vec![&right]));

        assert!(!eq(vec![], vec![&right]));
        assert!(!eq(vec![&right], vec![]));

        assert!(eq(
            vec![&left, &left1, &left2, &left3],
            vec![&right, &right1, &right2, &right3],
        ));

        assert!(!eq(
            vec![&left1, &left, &left2, &left3],
            vec![&right, &right1, &right2, &right3],
        ));
    }

    #[test]
    fn less_value_test() {
        let left = json!(10);
        let right = json!(11);

        assert!(less(vec![&left], vec![&right]));
        assert!(!less(vec![&right], vec![&left]));

        let left = json!(-10);
        let right = json!(-11);

        assert!(!less(vec![&left], vec![&right]));
        assert!(less(vec![&right], vec![&left]));

        let left = json!(-10.0);
        let right = json!(-11.0);

        assert!(!less(vec![&left], vec![&right]));
        assert!(less(vec![&right], vec![&left]));

        assert!(!less(vec![], vec![&right]));
        assert!(!less(vec![&right, &right], vec![&left]));
    }

    #[test]
    fn regex_test() {
        let right = json!("[a-zA-Z]+[0-9]#[0-9]+");
        let left1 = json!("a11#");
        let left2 = json!("a1#1");
        let left3 = json!("a#11");
        let left4 = json!("#a11");

        assert!(regex(
            vec![&left1, &left2, &left3, &left4],
            vec![&right],
            &RegexCache::default()
        ));
        assert!(!regex(
            vec![&left1, &left3, &left4],
            vec![&right],
            &RegexCache::default()
        ))
    }

    #[test]
    fn any_of_test() {
        let right = json!([1, 2, 3, 4, 5, 6]);
        let left = json!([1, 100, 101]);
        assert!(any_of(vec![&left], vec![&right]));

        let left = json!([11, 100, 101]);
        assert!(!any_of(vec![&left], vec![&right]));

        let left1 = json!(1);
        let left2 = json!(11);
        assert!(any_of(vec![&left1, &left2], vec![&right]));
    }

    #[test]
    fn sub_set_of_test() {
        let left1 = json!(1);
        let left2 = json!(2);
        let left3 = json!(3);
        let left40 = json!(40);
        let right = json!([1, 2, 3, 4, 5, 6]);
        assert!(sub_set_of(
            vec![&Value::Array(vec![
                left1.clone(),
                left2.clone(),
                left3.clone(),
            ])],
            vec![&right],
        ));
        assert!(!sub_set_of(
            vec![&Value::Array(vec![left1, left2, left3, left40])],
            vec![&right],
        ));
    }

    #[test]
    fn size_test() {
        let left1 = json!("abc");
        let left2 = json!([1, 2, 3]);
        let left3 = json!([1, 2, 3, 4]);
        let right = json!(3);
        assert!(size(vec![&left1], vec![&right]));
        assert!(size(vec![&left2], vec![&right]));
        assert!(!size(vec![&left3], vec![&right]));
    }
}
