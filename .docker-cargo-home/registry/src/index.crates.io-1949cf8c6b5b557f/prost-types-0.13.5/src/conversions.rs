use crate::protobuf::Value;
use crate::value;
use crate::String;
use crate::Vec;
use ::prost::alloc::collections::BTreeMap;

impl From<value::Kind> for Value {
    fn from(value: value::Kind) -> Self {
        Value { kind: Some(value) }
    }
}

macro_rules! impl_number_value {
    ($t: ty) => {
        impl From<$t> for Value {
            fn from(value: $t) -> Self {
                value::Kind::NumberValue(value.into()).into()
            }
        }
    };
}

impl_number_value!(u8);
impl_number_value!(u16);
impl_number_value!(u32);

impl_number_value!(i8);
impl_number_value!(i16);
impl_number_value!(i32);

impl_number_value!(f32);
impl_number_value!(f64);

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        value::Kind::BoolValue(value).into()
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        value::Kind::StringValue(value).into()
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        value::Kind::StringValue(value.into()).into()
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        value::Kind::ListValue(crate::protobuf::ListValue { values: value }).into()
    }
}

impl From<BTreeMap<String, Value>> for Value {
    fn from(value: BTreeMap<String, Value>) -> Self {
        value::Kind::StructValue(crate::protobuf::Struct { fields: value }).into()
    }
}
