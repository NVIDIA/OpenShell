macro_rules! declare_generated_mods {
    ($($mod_name: ident),*) => {
        $(
            // Allow dead code in the generated module as varying versions
            // of Z3 in use might mean that we don't have the exact same
            // symbols available, so not all will be used by our mapping
            // code.
            #[allow(dead_code)]
            mod $mod_name {
                include!(concat!(env!("OUT_DIR"), "/", stringify!($mod_name), ".rs"));
            }
        )*
    };
}

declare_generated_mods! {
    ast_kind,
    ast_print_mode,
    decl_kind,
    error_code,
    goal_prec,
    param_kind,
    parameter_kind,
    sort_kind,
    symbol_kind
}

pub use self::ast_kind::Z3_ast_kind;
pub use self::ast_print_mode::Z3_ast_print_mode;
pub use self::decl_kind::Z3_decl_kind;
pub use self::error_code::Z3_error_code;
pub use self::goal_prec::Z3_goal_prec;
pub use self::param_kind::Z3_param_kind;
pub use self::parameter_kind::Z3_parameter_kind;
pub use self::sort_kind::Z3_sort_kind;
pub use self::symbol_kind::Z3_symbol_kind;
