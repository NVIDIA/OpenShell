//! Implementation details of the `include_dir`.
//!
//! You probably don't want to use this crate directly.
#![cfg_attr(feature = "nightly", feature(track_path, proc_macro_tracked_env))]

use proc_macro::{TokenStream, TokenTree};
use proc_macro2::Literal;
use quote::quote;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Embed the contents of a directory in your crate.
#[proc_macro]
pub fn include_dir(input: TokenStream) -> TokenStream {
    let tokens: Vec<_> = input.into_iter().collect();

    let path = match tokens.as_slice() {
        [TokenTree::Literal(lit)] => unwrap_string_literal(lit),
        _ => panic!("This macro only accepts a single, non-empty string argument"),
    };

    let path = resolve_path(&path, get_env).unwrap();

    expand_dir(&path, &path).into()
}

fn unwrap_string_literal(lit: &proc_macro::Literal) -> String {
    let mut repr = lit.to_string();
    if !repr.starts_with('"') || !repr.ends_with('"') {
        panic!("This macro only accepts a single, non-empty string argument")
    }

    repr.remove(0);
    repr.pop();

    repr
}

fn expand_dir(root: &Path, path: &Path) -> proc_macro2::TokenStream {
    let children = read_dir(path).unwrap_or_else(|e| {
        panic!(
            "Unable to read the entries in \"{}\": {}",
            path.display(),
            e
        )
    });

    let mut child_tokens = Vec::new();

    for child in children {
        if child.is_dir() {
            let tokens = expand_dir(root, &child);
            child_tokens.push(quote! {
                include_dir::DirEntry::Dir(#tokens)
            });
        } else if child.is_file() {
            let tokens = expand_file(root, &child);
            child_tokens.push(quote! {
                include_dir::DirEntry::File(#tokens)
            });
        } else {
            panic!("\"{}\" is neither a file nor a directory", child.display());
        }
    }

    let path = normalize_path(root, path);

    quote! {
        include_dir::Dir::new(#path, {
            const ENTRIES: &'static [include_dir::DirEntry<'static>] = &[ #(#child_tokens),*];
            ENTRIES
    })
    }
}

fn expand_file(root: &Path, path: &Path) -> proc_macro2::TokenStream {
    let abs = path
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to resolve \"{}\": {}", path.display(), e));
    let literal = match abs.to_str() {
        Some(abs) => quote!(include_bytes!(#abs)),
        None => {
            let contents = read_file(path);
            let literal = Literal::byte_string(&contents);
            quote!(#literal)
        }
    };

    let normalized_path = normalize_path(root, path);

    let tokens = quote! {
        include_dir::File::new(#normalized_path, #literal)
    };

    match metadata(path) {
        Some(metadata) => quote!(#tokens.with_metadata(#metadata)),
        None => tokens,
    }
}

fn metadata(path: &Path) -> Option<proc_macro2::TokenStream> {
    fn to_unix(t: SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    if !cfg!(feature = "metadata") {
        return None;
    }

    let meta = path.metadata().ok()?;
    let accessed = meta.accessed().map(to_unix).ok()?;
    let created = meta.created().map(to_unix).ok()?;
    let modified = meta.modified().map(to_unix).ok()?;

    Some(quote! {
        include_dir::Metadata::new(
            std::time::Duration::from_secs(#accessed),
            std::time::Duration::from_secs(#created),
            std::time::Duration::from_secs(#modified),
        )
    })
}

/// Make sure that paths use the same separator regardless of whether the host
/// machine is Windows or Linux.
fn normalize_path(root: &Path, path: &Path) -> String {
    let stripped = path
        .strip_prefix(root)
        .expect("Should only ever be called using paths inside the root path");
    let as_string = stripped.to_string_lossy();

    as_string.replace('\\', "/")
}

fn read_dir(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if !dir.is_dir() {
        panic!("\"{}\" is not a directory", dir.display());
    }

    track_path(dir);

    let mut paths = Vec::new();

    for entry in dir.read_dir()? {
        let entry = entry?;
        paths.push(entry.path());
    }

    paths.sort();

    Ok(paths)
}

fn read_file(path: &Path) -> Vec<u8> {
    track_path(path);
    std::fs::read(path).unwrap_or_else(|e| panic!("Unable to read \"{}\": {}", path.display(), e))
}

fn resolve_path(
    raw: &str,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut unprocessed = raw;
    let mut resolved = String::new();

    while let Some(dollar_sign) = unprocessed.find('$') {
        let (head, tail) = unprocessed.split_at(dollar_sign);
        resolved.push_str(head);

        match parse_identifier(&tail[1..]) {
            Some((variable, rest)) => {
                let value = get_env(variable).ok_or_else(|| MissingVariable {
                    variable: variable.to_string(),
                })?;
                resolved.push_str(&value);
                unprocessed = rest;
            }
            None => {
                return Err(UnableToParseVariable { rest: tail.into() }.into());
            }
        }
    }
    resolved.push_str(unprocessed);

    Ok(PathBuf::from(resolved))
}

#[derive(Debug, PartialEq)]
struct MissingVariable {
    variable: String,
}

impl Error for MissingVariable {}

impl Display for MissingVariable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to resolve ${}", self.variable)
    }
}

#[derive(Debug, PartialEq)]
struct UnableToParseVariable {
    rest: String,
}

impl Error for UnableToParseVariable {}

impl Display for UnableToParseVariable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to parse a variable from \"{}\"", self.rest)
    }
}

fn parse_identifier(text: &str) -> Option<(&str, &str)> {
    let mut calls = 0;

    let (head, tail) = take_while(text, |c| {
        calls += 1;

        match c {
            '_' => true,
            letter if letter.is_ascii_alphabetic() => true,
            digit if digit.is_ascii_digit() && calls > 1 => true,
            _ => false,
        }
    });

    if head.is_empty() {
        None
    } else {
        Some((head, tail))
    }
}

fn take_while(s: &str, mut predicate: impl FnMut(char) -> bool) -> (&str, &str) {
    let mut index = 0;

    for c in s.chars() {
        if predicate(c) {
            index += c.len_utf8();
        } else {
            break;
        }
    }

    s.split_at(index)
}

#[cfg(feature = "nightly")]
fn get_env(variable: &str) -> Option<String> {
    proc_macro::tracked_env::var(variable).ok()
}

#[cfg(not(feature = "nightly"))]
fn get_env(variable: &str) -> Option<String> {
    std::env::var(variable).ok()
}

fn track_path(_path: &Path) {
    #[cfg(feature = "nightly")]
    proc_macro::tracked_path::path(_path.to_string_lossy());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_with_no_environment_variables() {
        let path = "./file.txt";

        let resolved = resolve_path(path, |_| unreachable!()).unwrap();

        assert_eq!(resolved.to_str().unwrap(), path);
    }

    #[test]
    fn simple_environment_variable() {
        let path = "./$VAR";

        let resolved = resolve_path(path, |name| {
            assert_eq!(name, "VAR");
            Some("file.txt".to_string())
        })
        .unwrap();

        assert_eq!(resolved.to_str().unwrap(), "./file.txt");
    }

    #[test]
    fn dont_resolve_recursively() {
        let path = "./$TOP_LEVEL.txt";

        let resolved = resolve_path(path, |name| match name {
            "TOP_LEVEL" => Some("$NESTED".to_string()),
            "$NESTED" => unreachable!("Shouldn't resolve recursively"),
            _ => unreachable!(),
        })
        .unwrap();

        assert_eq!(resolved.to_str().unwrap(), "./$NESTED.txt");
    }

    #[test]
    fn parse_valid_identifiers() {
        let inputs = vec![
            ("a", "a"),
            ("a_", "a_"),
            ("_asf", "_asf"),
            ("a1", "a1"),
            ("a1_#sd", "a1_"),
        ];

        for (src, expected) in inputs {
            let (got, rest) = parse_identifier(src).unwrap();
            assert_eq!(got.len() + rest.len(), src.len());
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn unknown_environment_variable() {
        let path = "$UNKNOWN";

        let err = resolve_path(path, |_| None).unwrap_err();

        let missing_variable = err.downcast::<MissingVariable>().unwrap();
        assert_eq!(
            *missing_variable,
            MissingVariable {
                variable: String::from("UNKNOWN"),
            }
        );
    }

    #[test]
    fn invalid_variables() {
        let inputs = &["$1", "$"];

        for input in inputs {
            let err = resolve_path(input, |_| unreachable!()).unwrap_err();

            let err = err.downcast::<UnableToParseVariable>().unwrap();
            assert_eq!(
                *err,
                UnableToParseVariable {
                    rest: input.to_string(),
                }
            );
        }
    }
}
