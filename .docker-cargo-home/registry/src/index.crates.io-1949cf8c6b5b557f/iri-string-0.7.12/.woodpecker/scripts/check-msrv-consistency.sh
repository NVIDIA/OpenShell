#!/bin/sh
set -eu

cd "$(readlink -f "$(dirname "$0")/../..")"

# Get MSRV from the toplevel Cargo.toml
MSRV="$(sed -ne 's/^rust-version\s*=\s*[^0-9#]\([0-9.]\+\).*$/\1/p' Cargo.toml)"
echo "MSRV=${MSRV}"
MSRV_REGEX="$(echo "$MSRV" | sed -e 's/\./\\./g')"

check_readme() {
    echo "checking README.md"
    grep --color=always --with-filename --line-number --ignore-case 'minimum supported rust\(c\)\? version.*'"${MSRV_REGEX}" README.md
}
check_readme

check_woodpecker() {
    for yml_path in .woodpecker/*.yml ; do
        echo "checking ${yml_path}"

        # Check `msrv_channel` variable.
        if grep --quiet '^\s*msrv_channel:' "$yml_path" ; then
            grep --color=always --with-filename --line-number '^\s*msrv_channel:[^#]*'"${MSRV_REGEX}"'\>' "$yml_path"
        fi

        # Check `rust_msrv_image` variable.
        if grep --quiet '^\s*rust_msrv_image:' "$yml_path" ; then
            grep --color=always --with-filename --line-number '^\s*rust_msrv_image:[^#]*'"${MSRV_REGEX}"'\>' "$yml_path"
        fi
    done
}
check_woodpecker

# vim: set expandtab tabstop=4 :
