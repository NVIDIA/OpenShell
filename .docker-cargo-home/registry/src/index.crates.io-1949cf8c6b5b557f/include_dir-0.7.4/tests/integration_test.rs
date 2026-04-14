use include_dir::{include_dir, Dir};
use std::path::Path;
use tempfile::TempDir;

static PARENT_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR");

#[test]
fn included_all_files_in_the_include_dir_crate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    validate_included(&PARENT_DIR, root, root);
    assert!(PARENT_DIR.contains("src/lib.rs"));
}

#[test]
fn extract_all_files() {
    let tmpdir = TempDir::new().unwrap();
    let root = tmpdir.path();
    PARENT_DIR.extract(root).unwrap();

    validate_extracted(&PARENT_DIR, root);
}

// Validates that all files on the filesystem exist in the inclusion
fn validate_included(dir: &Dir<'_>, path: &Path, root: &Path) {
    for entry in path.read_dir().unwrap() {
        let entry = entry.unwrap().path();
        let entry = entry.strip_prefix(root).unwrap();

        let name = entry.file_name().unwrap();

        assert!(dir.contains(entry), "Can't find {}", entry.display());

        if entry.is_dir() {
            let child_path = path.join(name);
            validate_included(
                dir.get_entry(entry).unwrap().as_dir().unwrap(),
                &child_path,
                root,
            );
        }
    }
}

// Validates that all files in the inclusion were extracted to the filesystem
fn validate_extracted(dir: &Dir, path: &Path) {
    // Check if all the subdirectories exist, recursing on each
    for subdir in dir.dirs() {
        let subdir_path = path.join(dir.path());
        assert!(subdir_path.exists());
        validate_extracted(subdir, &subdir_path);
    }

    // Check if the files at the root of this directory exist
    for file in dir.files() {
        let file_path = path.join(file.path());
        assert!(file_path.exists());
    }
}

#[test]
fn msrv_is_in_sync() {
    let msrv = (include_str!("../../Cargo.toml"))
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .find_map(|(key, value)| {
            if key.trim() == "rust-version" {
                Some(value.trim().trim_matches('"'))
            } else {
                None
            }
        })
        .unwrap();

    let toolchain_version = (include_str!("../../.rust-toolchain.toml"))
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .find_map(|(key, value)| {
            if key.trim() == "channel" {
                Some(value.trim().trim_matches('"'))
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(toolchain_version, msrv);

    let workflow_msrv = (include_str!("../../.github/workflows/main.yml"))
        .lines()
        .skip_while(|line| line.trim() != "# MSRV")
        .skip(1)
        .map(|line| line.trim().trim_start_matches('-').trim().trim_matches('"'))
        .next()
        .unwrap();
    assert_eq!(workflow_msrv, msrv);
}
