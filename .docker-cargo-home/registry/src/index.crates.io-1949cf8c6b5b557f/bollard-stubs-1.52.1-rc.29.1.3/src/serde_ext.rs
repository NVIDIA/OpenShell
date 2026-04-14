
pub(crate) mod none_as_empty_string {
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: serde::Serializer,
    {
        match value {
            Some(v) => serializer.serialize_str(&v.to_string()),
            None => serializer.serialize_str(""),
        }
    }

    pub fn deserialize<'de, Str, D>(deserializer: D) -> Result<Option<Str>, D::Error>
    where
        Str: FromStr,
        Str::Err: Display,
        D: serde::Deserializer<'de>,
    {
        let s: Option<String> = serde::Deserialize::deserialize(deserializer)?;
        match s.as_deref() {
            None | Some("") => Ok(None),
            Some(v) => match Str::from_str(v) {
                Ok(parsed) => Ok(Some(parsed)),
                Err(err) => Err(serde::de::Error::custom(err.to_string())),
            },
        }
    }
}
