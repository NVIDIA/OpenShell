#! /bin/bash

declare -a enums=(
    "ast_kind"
    "ast_print_mode"
    "decl_kind"
    "error_code"
    "goal_prec"
    "param_kind"
    "parameter_kind"
    "sort_kind"
    "symbol_kind"
)

for e in "${enums[@]}"
do
    bindgen --no-doc-comments \
            --rustified-enum Z3_$e \
            --whitelist-type Z3_$e \
            $1 \
    > src/generated/$e.rs
done
