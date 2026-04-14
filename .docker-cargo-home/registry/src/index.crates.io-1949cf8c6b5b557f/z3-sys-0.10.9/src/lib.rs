//! # Z3
//!
//! Z3 is a theorem prover [from Microsoft Research](https://github.com/Z3Prover/z3/).
//!
//! This crate provides low-level bindings that provide no real
//! affordances for usage from Rust and that mirror the C API.
//!
//! For bindings that are easier to use from Rust, see the higher level
//! bindings in the [Z3](https://crates.io/crates/z3/) crate.
//!
//! # Build configuration
//!
//! This crate needs to locate a Z3 library at build time. The method is
//! controlled by Cargo features and environment variables.
//!
//! ## Features
//!
//! | Feature | Behaviour |
//! |---------|-----------|
//! | *(default)* | Link against a system-installed Z3 (`brew install z3`, etc.) |
//! | `bundled` | Build Z3 from source using `cmake` and statically link it |
//! | `gh-release` | Build against a pre-compiled Z3 static library from GitHub Releases |
//! | `vcpkg` | Use a Z3 installed via vcpkg |
//!
//! ## Environment variables
//!
//! ### `bundled` feature
//!
//! The `bundled` feature builds Z3 from source using `cmake` and statically
//! links it. Despite the name, **Z3 source is not included in the crate
//! tarball** published to crates.io. In cases where the user does not provide
//! the source tree, the z3-sys `build.rs` script _must reach out to GitHub
//! to fetch the source tree_. At build time, the build script resolves
//! a Z3 source tree in the following order:
//!
//! 1. **`Z3_SYS_BUNDLED_DIR_OVERRIDE` is set** — that path is used directly;
//!    no network access occurs.
//! 2. **Build output cache** (`OUT_DIR/z3`) already exists from a prior
//!    build — the cached source is reused; no network access occurs.
//! 3. **Local submodule** (`CARGO_MANIFEST_DIR/z3`) exists — only relevant
//!    when building `z3-sys` itself from its git repository, not when using
//!    it as a crate dependency.
//! 4. **GitHub fetch** — the build script calls the GitHub Contents API to
//!    look up which Z3 commit the `z3-sys` git submodule pointed to at the
//!    time of the current release (using the `z3-sys-vX.Y.Z` git tag), then
//!    downloads and extracts that Z3 source archive into `OUT_DIR/z3`.
//!
//! By default, the Z3 version built is whatever commit the `z3-sys` release
//! pinned in its submodule. You can build any (compatible) Z3 version by pointing
//! `Z3_SYS_BUNDLED_DIR_OVERRIDE` at your own checkout (see below). To use a
//! specific version without managing source yourself, `gh-release` with
//! `Z3_SYS_Z3_VERSION` is a simpler alternative.
//!
//! > **Network access:** A first build from crates.io requires outbound HTTPS
//! > to `api.github.com` (submodule ref lookup) and `github.com` (archive
//! > download). Set `READ_ONLY_GITHUB_TOKEN` to a GitHub PAT to avoid
//! > rate-limiting in CI. The downloaded source is cached in `OUT_DIR` and
//! > reused on subsequent builds until `cargo clean`.
//!
//! **Using your own Z3 checkout:** Set `Z3_SYS_BUNDLED_DIR_OVERRIDE` to the
//! **absolute path** of a Z3 source tree to skip the network fetch entirely:
//!
//! ```text
//! Z3_SYS_BUNDLED_DIR_OVERRIDE=/absolute/path/to/z3 cargo build
//! ```
//!
//! To use a **project-relative** path, add the following to your project's
//! `.cargo/config.toml`. The `relative = true` key tells Cargo to resolve
//! the path relative to the config file's location:
//!
//! ```toml
//! [env]
//! Z3_SYS_BUNDLED_DIR_OVERRIDE = { value = "path/to/z3", relative = true }
//! ```
//!
//! > **Note:** A `z3` directory in your own project or workspace is **not**
//! > picked up automatically — you must set `Z3_SYS_BUNDLED_DIR_OVERRIDE`
//! > explicitly, even if you have a Z3 git submodule in your repo.
//!
//! ### Other variables
//!
//! | Variable | Feature | Description |
//! |----------|---------|-------------|
//! | `Z3_SYS_Z3_HEADER` | default | Override the path to `z3.h` used during binding generation |
//! | `Z3_LIBRARY_PATH_OVERRIDE` | default | Add an extra library search path for the linker |
//! | `Z3_SYS_Z3_VERSION` | `gh-release` | Z3 version to download (e.g. `4.13.0`) |
//! | `READ_ONLY_GITHUB_TOKEN` | `bundled`, `gh-release` | GitHub PAT to avoid API rate limits in CI |
//! | `CXXSTDLIB` | any | Override which C++ standard library to link (e.g. `c++`, `stdc++`) |
//!
//! # Example
//!
//! ```
//! use z3_sys::*;
//!
//! unsafe {
//!     let cfg = Z3_mk_config().unwrap();
//!     let ctx = Z3_mk_context(cfg).unwrap();
//!
//!     let a = Z3_mk_not(ctx, Z3_mk_eq(ctx, Z3_mk_false(ctx).unwrap(), Z3_mk_true(ctx).unwrap()).unwrap()).unwrap();
//!     let b = Z3_mk_not(ctx, Z3_mk_iff(ctx, Z3_mk_false(ctx).unwrap(), Z3_mk_true(ctx).unwrap()).unwrap()).unwrap();
//!     assert_eq!(Z3_mk_true(ctx), Z3_simplify(ctx, a));
//!     assert_eq!(Z3_mk_true(ctx), Z3_simplify(ctx, b));
//!
//!     Z3_del_config(cfg);
//!     Z3_del_context(ctx);
//! }
//! ```

#![allow(non_camel_case_types)]
#![allow(clippy::unreadable_literal)]
#![warn(clippy::doc_markdown)]
#![no_std]

use core::ptr::NonNull;

mod generated;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_symbol {
    _unused: [u8; 0],
}
/// Lisp-like symbol used to name types, constants, and functions.
/// A symbol can be created using string or integers.
///
/// # See also:
///
/// - [`Z3_get_symbol_int`]
/// - [`Z3_get_symbol_kind`]
/// - [`Z3_get_symbol_string`]
/// - [`Z3_mk_int_symbol`]
/// - [`Z3_mk_string_symbol`]
pub type Z3_symbol = NonNull<_Z3_symbol>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_literals {
    _unused: [u8; 0],
}

pub type Z3_literals = NonNull<_Z3_literals>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_config {
    _unused: [u8; 0],
}
/// Configuration object used to initialize logical contexts.
pub type Z3_config = NonNull<_Z3_config>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_context {
    _unused: [u8; 0],
}
/// Manager of all other Z3 objects, global configuration options, etc.
pub type Z3_context = NonNull<_Z3_context>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_sort {
    _unused: [u8; 0],
}
/// Kind of AST used to represent types.
pub type Z3_sort = NonNull<_Z3_sort>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_func_decl {
    _unused: [u8; 0],
}
/// Kind of AST used to represent function symbols.
pub type Z3_func_decl = NonNull<_Z3_func_decl>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_ast {
    _unused: [u8; 0],
}
/// Abstract Syntax Tree node. That is, the data structure used in Z3
/// to represent terms, formulas, and types.
pub type Z3_ast = NonNull<_Z3_ast>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_app {
    _unused: [u8; 0],
}
/// Kind of AST used to represent function applications.
pub type Z3_app = NonNull<_Z3_app>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_pattern {
    _unused: [u8; 0],
}
/// Kind of AST used to represent pattern and multi-patterns used
/// to guide quantifier instantiation.
pub type Z3_pattern = NonNull<_Z3_pattern>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_model {
    _unused: [u8; 0],
}
/// Model for the constraints inserted into the logical context.
pub type Z3_model = NonNull<_Z3_model>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_constructor {
    _unused: [u8; 0],
}
/// Type constructor for a (recursive) datatype.
pub type Z3_constructor = NonNull<_Z3_constructor>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_constructor_list {
    _unused: [u8; 0],
}
/// List of constructors for a (recursive) datatype.
pub type Z3_constructor_list = NonNull<_Z3_constructor_list>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_params {
    _unused: [u8; 0],
}
/// Parameter set used to configure many components such as:
/// simplifiers, tactics, solvers, etc.
pub type Z3_params = NonNull<_Z3_params>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_param_descrs {
    _unused: [u8; 0],
}
/// Provides a collection of parameter names, their types,
/// default values and documentation strings. Solvers, tactics,
/// and other objects accept different collection of parameters.
pub type Z3_param_descrs = NonNull<_Z3_param_descrs>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_goal {
    _unused: [u8; 0],
}
/// Set of formulas that can be solved and/or transformed using
/// tactics and solvers.
pub type Z3_goal = NonNull<_Z3_goal>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_tactic {
    _unused: [u8; 0],
}
/// Basic building block for creating custom solvers for specific
/// problem domains.
pub type Z3_tactic = NonNull<_Z3_tactic>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_probe {
    _unused: [u8; 0],
}
/// Function/predicate used to inspect a goal and collect information
/// that may be used to decide which solver and/or preprocessing step
/// will be used.
pub type Z3_probe = NonNull<_Z3_probe>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_stats {
    _unused: [u8; 0],
}
/// Statistical data for a solver.
pub type Z3_stats = NonNull<_Z3_stats>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_solver {
    _unused: [u8; 0],
}
/// (Incremental) solver, possibly specialized by a particular
/// tactic or logic.
pub type Z3_solver = NonNull<_Z3_solver>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_ast_vector {
    _unused: [u8; 0],
}
/// Vector of [`Z3_ast`] objects.
pub type Z3_ast_vector = NonNull<_Z3_ast_vector>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_ast_map {
    _unused: [u8; 0],
}
/// Mapping from [`Z3_ast`] to [`Z3_ast`] objects.
pub type Z3_ast_map = NonNull<_Z3_ast_map>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_apply_result {
    _unused: [u8; 0],
}
/// Collection of subgoals resulting from applying of a tactic
/// to a goal.
pub type Z3_apply_result = NonNull<_Z3_apply_result>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_func_interp {
    _unused: [u8; 0],
}
/// Interpretation of a function in a model.
pub type Z3_func_interp = NonNull<_Z3_func_interp>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_func_entry {
    _unused: [u8; 0],
}
/// Representation of the value of a [`Z3_func_interp`]
/// at a particular point.
pub type Z3_func_entry = NonNull<_Z3_func_entry>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_fixedpoint {
    _unused: [u8; 0],
}
/// Context for the recursive predicate solver.
pub type Z3_fixedpoint = NonNull<_Z3_fixedpoint>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_optimize {
    _unused: [u8; 0],
}
/// Context for solving optimization queries.
pub type Z3_optimize = NonNull<_Z3_optimize>;

#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _Z3_rcf_num {
    _unused: [u8; 0],
}
pub type Z3_rcf_num = NonNull<_Z3_rcf_num>;

/// Z3 string type. It is just an alias for `const char *`.
pub type Z3_string = *const ::core::ffi::c_char;

pub type Z3_string_ptr = *mut Z3_string;

pub const Z3_L_FALSE: Z3_lbool = -1;
pub const Z3_L_UNDEF: Z3_lbool = 0;
pub const Z3_L_TRUE: Z3_lbool = 1;

/// Lifted Boolean type: `false`, `undefined`, `true`.
pub type Z3_lbool = i32;

/// The different kinds of symbol.
/// In Z3, a symbol can be represented using integers and
/// strings. See [`Z3_get_symbol_kind`].
///
/// This corresponds to `Z3_symbol_kind` in the C API.
///
/// # See also:
///
/// - [`Z3_mk_int_symbol`]
/// - [`Z3_mk_string_symbol`]
/// - [`Z3_symbol`]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// An integer symbol.
    ///
    /// This corresponds to `Z3_INT_SYMBOL` in the C API.
    Int = generated::Z3_symbol_kind::Z3_INT_SYMBOL as u32,
    /// A string symbol.
    ///
    /// This corresponds to `Z3_STRING_SYMBOL` in the C API.
    String = generated::Z3_symbol_kind::Z3_STRING_SYMBOL as u32,
}

/// The different kinds of parameters that can be associated with function symbols.
///
/// This corresponds to `Z3_parameter_kind` in the C API.
///
/// # See also:
///
/// - [`Z3_get_decl_num_parameters`]
/// - [`Z3_get_decl_parameter_kind`]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ParameterKind {
    /// An integer parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_INT` in the C API.
    Int = generated::Z3_parameter_kind::Z3_PARAMETER_INT as u32,
    /// A double parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_DOUBLE` in the C API.
    Double = generated::Z3_parameter_kind::Z3_PARAMETER_DOUBLE as u32,
    /// A rational number parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_RATIONAL` in the C API.
    Rational = generated::Z3_parameter_kind::Z3_PARAMETER_RATIONAL as u32,
    /// A symbol parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_SYMBOL` in the C API.
    Symbol = generated::Z3_parameter_kind::Z3_PARAMETER_SYMBOL as u32,
    /// A sort parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_SORT` in the C API.
    Sort = generated::Z3_parameter_kind::Z3_PARAMETER_SORT as u32,
    /// An expression parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_AST` in the C API.
    AST = generated::Z3_parameter_kind::Z3_PARAMETER_AST as u32,
    /// A function declaration parameter.
    ///
    /// This corresponds to `Z3_PARAMETER_FUNC_DECL` in the C API.
    FuncDecl = generated::Z3_parameter_kind::Z3_PARAMETER_FUNC_DECL as u32,
}

/// The different kinds of Z3 types.
///
/// This corresponds to `Z3_sort_kind` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortKind {
    /// This corresponds to `Z3_UNINTERPRETED_SORT` in the C API.
    Uninterpreted = generated::Z3_sort_kind::Z3_UNINTERPRETED_SORT as u32,
    /// This corresponds to `Z3_BOOL_SORT` in the C API.
    Bool = generated::Z3_sort_kind::Z3_BOOL_SORT as u32,
    /// This corresponds to `Z3_INT_SORT` in the C API.
    Int = generated::Z3_sort_kind::Z3_INT_SORT as u32,
    /// This corresponds to `Z3_REAL_SORT` in the C API.
    Real = generated::Z3_sort_kind::Z3_REAL_SORT as u32,
    /// This corresponds to `Z3_BV_SORT` in the C API.
    BV = generated::Z3_sort_kind::Z3_BV_SORT as u32,
    /// This corresponds to `Z3_ARRAY_SORT` in the C API.
    Array = generated::Z3_sort_kind::Z3_ARRAY_SORT as u32,
    /// This corresponds to `Z3_DATATYPE_SORT` in the C API.
    Datatype = generated::Z3_sort_kind::Z3_DATATYPE_SORT as u32,
    /// This corresponds to `Z3_RELATION_SORT` in the C API.
    Relation = generated::Z3_sort_kind::Z3_RELATION_SORT as u32,
    /// This corresponds to `Z3_FINITE_DOMAIN_SORT` in the C API.
    FiniteDomain = generated::Z3_sort_kind::Z3_FINITE_DOMAIN_SORT as u32,
    /// This corresponds to `Z3_FLOATING_POINT_SORT` in the C API.
    FloatingPoint = generated::Z3_sort_kind::Z3_FLOATING_POINT_SORT as u32,
    /// This corresponds to `Z3_ROUNDING_MODE_SORT` in the C API.
    RoundingMode = generated::Z3_sort_kind::Z3_ROUNDING_MODE_SORT as u32,
    /// This corresponds to `Z3_SEQ_SORT` in the C API.
    Seq = generated::Z3_sort_kind::Z3_SEQ_SORT as u32,
    /// This corresponds to `Z3_RE_SORT` in the C API.
    RE = generated::Z3_sort_kind::Z3_RE_SORT as u32,
    /// This corresponds to `Z3_UNKNOWN_SORT` in the C API.
    Unknown = generated::Z3_sort_kind::Z3_UNKNOWN_SORT as u32,
}

/// The different kinds of Z3 AST (abstract syntax trees). That is, terms, formulas and types.
///
/// This corresponds to `Z3_ast_kind` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AstKind {
    /// numeral constants
    ///
    /// This corresponds to `Z3_NUMERAL_AST` in the C API.
    Numeral = generated::Z3_ast_kind::Z3_NUMERAL_AST as u32,
    /// constant and applications
    ///
    /// This corresponds to `Z3_APP_AST` in the C API.
    App = generated::Z3_ast_kind::Z3_APP_AST as u32,
    /// bound variables
    ///
    /// This corresponds to `Z3_VAR_AST` in the C API.
    Var = generated::Z3_ast_kind::Z3_VAR_AST as u32,
    /// quantifiers
    ///
    /// This corresponds to `Z3_QUANTIFIER_AST` in the C API.
    Quantifier = generated::Z3_ast_kind::Z3_QUANTIFIER_AST as u32,
    /// sort
    ///
    /// This corresponds to `Z3_SORT_AST` in the C API.
    Sort = generated::Z3_ast_kind::Z3_SORT_AST as u32,
    /// function declaration
    ///
    /// This corresponds to `Z3_FUNC_DECL_AST` in the C API.
    FuncDecl = generated::Z3_ast_kind::Z3_FUNC_DECL_AST as u32,
    /// internal
    ///
    /// This corresponds to `Z3_UNKNOWN_AST` in the C API.
    Unknown = generated::Z3_ast_kind::Z3_UNKNOWN_AST as u32,
}

/// The different kinds of interpreted function kinds.
///
/// This corresponds to `Z3_decl_kind` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DeclKind {
    /// The constant `true`.
    TRUE = generated::Z3_decl_kind::Z3_OP_TRUE as u32,
    /// The constant `false`.
    FALSE = generated::Z3_decl_kind::Z3_OP_FALSE as u32,
    /// The equality predicate.
    EQ = generated::Z3_decl_kind::Z3_OP_EQ as u32,
    /// The n-ary distinct predicate (every argument is mutually distinct).
    DISTINCT = generated::Z3_decl_kind::Z3_OP_DISTINCT as u32,
    /// The ternary if-then-else term.
    ITE = generated::Z3_decl_kind::Z3_OP_ITE as u32,
    /// n-ary conjunction.
    AND = generated::Z3_decl_kind::Z3_OP_AND as u32,
    /// n-ary disjunction.
    OR = generated::Z3_decl_kind::Z3_OP_OR as u32,
    /// equivalence (binary).
    IFF = generated::Z3_decl_kind::Z3_OP_IFF as u32,
    /// Exclusive or.
    XOR = generated::Z3_decl_kind::Z3_OP_XOR as u32,
    /// Negation.
    NOT = generated::Z3_decl_kind::Z3_OP_NOT as u32,
    /// Implication.
    IMPLIES = generated::Z3_decl_kind::Z3_OP_IMPLIES as u32,
    /// Binary equivalence modulo namings. This binary predicate is used
    /// in proof terms. It captures equisatisfiability and equivalence
    /// modulo renamings.
    OEQ = generated::Z3_decl_kind::Z3_OP_OEQ as u32,
    /// Arithmetic numeral.
    ANUM = generated::Z3_decl_kind::Z3_OP_ANUM as u32,
    /// Arithmetic algebraic numeral. Algebraic numbers are used to
    /// represent irrational numbers in Z3.
    AGNUM = generated::Z3_decl_kind::Z3_OP_AGNUM as u32,
    /// `<=`.
    LE = generated::Z3_decl_kind::Z3_OP_LE as u32,
    /// `>=`.
    GE = generated::Z3_decl_kind::Z3_OP_GE as u32,
    /// `<`.
    LT = generated::Z3_decl_kind::Z3_OP_LT as u32,
    /// `>`.
    GT = generated::Z3_decl_kind::Z3_OP_GT as u32,
    /// Addition - Binary.
    ADD = generated::Z3_decl_kind::Z3_OP_ADD as u32,
    /// Binary subtraction.
    SUB = generated::Z3_decl_kind::Z3_OP_SUB as u32,
    /// Unary minus.
    UMINUS = generated::Z3_decl_kind::Z3_OP_UMINUS as u32,
    /// Multiplication - Binary.
    MUL = generated::Z3_decl_kind::Z3_OP_MUL as u32,
    /// Division - Binary.
    DIV = generated::Z3_decl_kind::Z3_OP_DIV as u32,
    /// Integer division - Binary.
    IDIV = generated::Z3_decl_kind::Z3_OP_IDIV as u32,
    /// Remainder - Binary.
    REM = generated::Z3_decl_kind::Z3_OP_REM as u32,
    /// Modulus - Binary.
    MOD = generated::Z3_decl_kind::Z3_OP_MOD as u32,
    /// Coercion of integer to real - Unary.
    TO_REAL = generated::Z3_decl_kind::Z3_OP_TO_REAL as u32,
    /// Coercion of real to integer - Unary.
    TO_INT = generated::Z3_decl_kind::Z3_OP_TO_INT as u32,
    /// Check if real is also an integer - Unary.
    IS_INT = generated::Z3_decl_kind::Z3_OP_IS_INT as u32,
    /// Power operator `x^y`.
    POWER = generated::Z3_decl_kind::Z3_OP_POWER as u32,
    /// Array store. It satisfies `select(store(a,i,v),j) = if i = j then v else select(a,j)`.
    /// Array store takes at least 3 arguments.
    STORE = generated::Z3_decl_kind::Z3_OP_STORE as u32,
    /// Array select.
    SELECT = generated::Z3_decl_kind::Z3_OP_SELECT as u32,
    /// The constant array. For example, `select(const(v),i) = v`
    /// holds for every `v` and `i`. The function is unary.
    CONST_ARRAY = generated::Z3_decl_kind::Z3_OP_CONST_ARRAY as u32,
    /// Array map operator.
    /// It satisfies `map[f](a1,..,a_n)[i] = f(a1[i],...,a_n[i])` for every `i`.
    ARRAY_MAP = generated::Z3_decl_kind::Z3_OP_ARRAY_MAP as u32,
    /// Default value of arrays. For example `default(const(v)) = v`. The function is unary.
    ARRAY_DEFAULT = generated::Z3_decl_kind::Z3_OP_ARRAY_DEFAULT as u32,
    /// Set union between two Boolean arrays (two arrays whose range
    /// type is Boolean). The function is binary.
    SET_UNION = generated::Z3_decl_kind::Z3_OP_SET_UNION as u32,
    /// Set intersection between two Boolean arrays. The function is binary.
    SET_INTERSECT = generated::Z3_decl_kind::Z3_OP_SET_INTERSECT as u32,
    /// Set difference between two Boolean arrays. The function is binary.
    SET_DIFFERENCE = generated::Z3_decl_kind::Z3_OP_SET_DIFFERENCE as u32,
    /// Set complement of a Boolean array. The function is unary.
    SET_COMPLEMENT = generated::Z3_decl_kind::Z3_OP_SET_COMPLEMENT as u32,
    /// Subset predicate between two Boolean arrays. The relation is binary.
    SET_SUBSET = generated::Z3_decl_kind::Z3_OP_SET_SUBSET as u32,
    /// An array value that behaves as the function graph of the
    /// function passed as parameter.
    AS_ARRAY = generated::Z3_decl_kind::Z3_OP_AS_ARRAY as u32,
    /// Array extensionality function. It takes two arrays as arguments and
    /// produces an index, such that the arrays
    /// are different if they are different on the index.
    ARRAY_EXT = generated::Z3_decl_kind::Z3_OP_ARRAY_EXT as u32,
    /// Bit-vector numeral.
    BNUM = generated::Z3_decl_kind::Z3_OP_BNUM as u32,
    /// One bit bit-vector.
    BIT1 = generated::Z3_decl_kind::Z3_OP_BIT1 as u32,
    /// Zero bit bit-vector.
    BIT0 = generated::Z3_decl_kind::Z3_OP_BIT0 as u32,
    /// Unary minus.
    BNEG = generated::Z3_decl_kind::Z3_OP_BNEG as u32,
    /// Binary addition.
    BADD = generated::Z3_decl_kind::Z3_OP_BADD as u32,
    /// Binary subtraction.
    BSUB = generated::Z3_decl_kind::Z3_OP_BSUB as u32,
    /// Binary multiplication.
    BMUL = generated::Z3_decl_kind::Z3_OP_BMUL as u32,
    /// Binary signed division.
    BSDIV = generated::Z3_decl_kind::Z3_OP_BSDIV as u32,
    /// Binary unsigned division.
    BUDIV = generated::Z3_decl_kind::Z3_OP_BUDIV as u32,
    /// Binary signed remainder.
    BSREM = generated::Z3_decl_kind::Z3_OP_BSREM as u32,
    /// Binary unsigned remainder.
    BUREM = generated::Z3_decl_kind::Z3_OP_BUREM as u32,
    /// Binary signed modulus.
    BSMOD = generated::Z3_decl_kind::Z3_OP_BSMOD as u32,
    /// Unary function. `bsdiv(x, 0)` is congruent to `bsdiv0(x)`.
    BSDIV0 = generated::Z3_decl_kind::Z3_OP_BSDIV0 as u32,
    /// Unary function. `budiv(x, 0)` is congruent to `budiv0(x)`.
    BUDIV0 = generated::Z3_decl_kind::Z3_OP_BUDIV0 as u32,
    /// Unary function. `bsrem(x, 0)` is congruent to `bsrem0(x)`.
    BSREM0 = generated::Z3_decl_kind::Z3_OP_BSREM0 as u32,
    /// Unary function. `burem(x, 0)` is congruent to `burem0(x)`.
    BUREM0 = generated::Z3_decl_kind::Z3_OP_BUREM0 as u32,
    /// Unary function. `bsmod(x, 0)` is congruent to `bsmod0(x)`.
    BSMOD0 = generated::Z3_decl_kind::Z3_OP_BSMOD0 as u32,
    /// Unsigned bit-vector <= - Binary relation.
    ULEQ = generated::Z3_decl_kind::Z3_OP_ULEQ as u32,
    /// Signed bit-vector  <= - Binary relation.
    SLEQ = generated::Z3_decl_kind::Z3_OP_SLEQ as u32,
    /// Unsigned bit-vector  >= - Binary relation.
    UGEQ = generated::Z3_decl_kind::Z3_OP_UGEQ as u32,
    /// Signed bit-vector  >= - Binary relation.
    SGEQ = generated::Z3_decl_kind::Z3_OP_SGEQ as u32,
    /// Unsigned bit-vector  < - Binary relation.
    ULT = generated::Z3_decl_kind::Z3_OP_ULT as u32,
    /// Signed bit-vector < - Binary relation.
    SLT = generated::Z3_decl_kind::Z3_OP_SLT as u32,
    /// Unsigned bit-vector > - Binary relation.
    UGT = generated::Z3_decl_kind::Z3_OP_UGT as u32,
    /// Signed bit-vector > - Binary relation.
    SGT = generated::Z3_decl_kind::Z3_OP_SGT as u32,
    /// Bit-wise and - Binary.
    BAND = generated::Z3_decl_kind::Z3_OP_BAND as u32,
    /// Bit-wise or - Binary.
    BOR = generated::Z3_decl_kind::Z3_OP_BOR as u32,
    /// Bit-wise not - Unary.
    BNOT = generated::Z3_decl_kind::Z3_OP_BNOT as u32,
    /// Bit-wise xor - Binary.
    BXOR = generated::Z3_decl_kind::Z3_OP_BXOR as u32,
    /// Bit-wise nand - Binary.
    BNAND = generated::Z3_decl_kind::Z3_OP_BNAND as u32,
    /// Bit-wise nor - Binary.
    BNOR = generated::Z3_decl_kind::Z3_OP_BNOR as u32,
    /// Bit-wise xnor - Binary.
    BXNOR = generated::Z3_decl_kind::Z3_OP_BXNOR as u32,
    /// Bit-vector concatenation - Binary.
    CONCAT = generated::Z3_decl_kind::Z3_OP_CONCAT as u32,
    /// Bit-vector sign extension.
    SIGN_EXT = generated::Z3_decl_kind::Z3_OP_SIGN_EXT as u32,
    /// Bit-vector zero extension.
    ZERO_EXT = generated::Z3_decl_kind::Z3_OP_ZERO_EXT as u32,
    /// Bit-vector extraction.
    EXTRACT = generated::Z3_decl_kind::Z3_OP_EXTRACT as u32,
    /// Repeat bit-vector n times.
    REPEAT = generated::Z3_decl_kind::Z3_OP_REPEAT as u32,
    /// Bit-vector reduce or - Unary.
    BREDOR = generated::Z3_decl_kind::Z3_OP_BREDOR as u32,
    /// Bit-vector reduce and - Unary.
    BREDAND = generated::Z3_decl_kind::Z3_OP_BREDAND as u32,
    BCOMP = generated::Z3_decl_kind::Z3_OP_BCOMP as u32,
    /// Shift left.
    BSHL = generated::Z3_decl_kind::Z3_OP_BSHL as u32,
    /// Logical shift right.
    BLSHR = generated::Z3_decl_kind::Z3_OP_BLSHR as u32,
    /// Arithmetical shift right.
    BASHR = generated::Z3_decl_kind::Z3_OP_BASHR as u32,
    /// Left rotation.
    ROTATE_LEFT = generated::Z3_decl_kind::Z3_OP_ROTATE_LEFT as u32,
    /// Right rotation.
    ROTATE_RIGHT = generated::Z3_decl_kind::Z3_OP_ROTATE_RIGHT as u32,
    /// (extended) Left rotation. Similar to `DeclKind::ROTATE_LEFT`,
    /// but it is a binary operator instead of a parametric one.
    EXT_ROTATE_LEFT = generated::Z3_decl_kind::Z3_OP_EXT_ROTATE_LEFT as u32,
    /// (extended) Right rotation. Similar to `DeclKind::ROTATE_RIGHT`,
    /// but it is a binary operator instead of a parametric one.
    EXT_ROTATE_RIGHT = generated::Z3_decl_kind::Z3_OP_EXT_ROTATE_RIGHT as u32,
    BIT2BOOL = generated::Z3_decl_kind::Z3_OP_BIT2BOOL as u32,
    /// Coerce integer to bit-vector.
    ///
    /// NB. This function is not supported by the decision procedures.
    /// Only the most rudimentary simplification rules are applied to
    /// this function.
    INT2BV = generated::Z3_decl_kind::Z3_OP_INT2BV as u32,
    /// Coerce bit-vector to integer.
    ///
    /// NB. This function is not supported by the decision procedures.
    /// Only the most rudimentary simplification rules are applied to
    /// this function.
    BV2INT = generated::Z3_decl_kind::Z3_OP_BV2INT as u32,
    /// Compute the carry bit in a full-adder.
    /// The meaning is given by the equivalence:
    ///
    /// ```text
    /// (carry l1 l2 l3) <=> (or (and l1 l2) (and l1 l3) (and l2 l3)))
    /// ```
    CARRY = generated::Z3_decl_kind::Z3_OP_CARRY as u32,
    /// Compute ternary XOR.
    ///
    /// The meaning is given by the equivalence:
    ///
    /// ```text
    /// (xor3 l1 l2 l3) <=> (xor (xor l1 l2) l3)
    /// ```
    XOR3 = generated::Z3_decl_kind::Z3_OP_XOR3 as u32,
    /// Check that bit-wise signed multiplication does not overflow.
    ///
    /// Signed multiplication overflows if the operands have the
    /// same sign and the result of multiplication does not fit
    /// within the available bits.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bvmul_no_overflow`]
    BSMUL_NO_OVFL = generated::Z3_decl_kind::Z3_OP_BSMUL_NO_OVFL as u32,
    /// Check that bit-wise unsigned multiplication does not overflow.
    ///
    /// Unsigned multiplication overflows if the result does not fit
    /// within the available bits.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bvmul_no_overflow`]
    BUMUL_NO_OVFL = generated::Z3_decl_kind::Z3_OP_BUMUL_NO_OVFL as u32,
    /// Check that bit-wise signed multiplication does not underflow.
    ///
    /// Signed multiplication underflows if the operands have opposite
    /// signs and the result of multiplication does not fit within the
    /// available bits.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bvmul_no_underflow`]
    BSMUL_NO_UDFL = generated::Z3_decl_kind::Z3_OP_BSMUL_NO_UDFL as u32,
    /// Binary signed division.
    ///
    /// It has the same semantics as `DeclKind::BSDIV`, but created in
    /// a context where the second operand can be assumed to be non-zero.
    BSDIV_I = generated::Z3_decl_kind::Z3_OP_BSDIV_I as u32,
    /// Binary unsigned division.
    ///
    /// It has the same semantics as `DeclKind::BUDIV`, but created in a
    /// context where the second operand can be assumed to be non-zero.
    BUDIV_I = generated::Z3_decl_kind::Z3_OP_BUDIV_I as u32,
    /// Binary signed remainder.
    ///
    /// It has the same semantics as `DeclKind::BSREM`, but created in a
    /// context where the second operand can be assumed to be non-zero.
    BSREM_I = generated::Z3_decl_kind::Z3_OP_BSREM_I as u32,
    /// Binary unsigned remainder.
    ///
    /// It has the same semantics as `DeclKind::BUREM`, but created in a
    /// context where the second operand can be assumed to be non-zero.
    BUREM_I = generated::Z3_decl_kind::Z3_OP_BUREM_I as u32,
    /// Binary signed modulus.
    ///
    /// It has the same semantics as `DeclKind::BSMOD`, but created in a
    /// context where the second operand can be assumed to be non-zero.
    BSMOD_I = generated::Z3_decl_kind::Z3_OP_BSMOD_I as u32,
    /// Undef/Null proof object.
    PR_UNDEF = generated::Z3_decl_kind::Z3_OP_PR_UNDEF as u32,
    /// Proof for the expression 'true'.
    PR_TRUE = generated::Z3_decl_kind::Z3_OP_PR_TRUE as u32,
    /// Proof for a fact asserted by the user.
    PR_ASSERTED = generated::Z3_decl_kind::Z3_OP_PR_ASSERTED as u32,
    /// Proof for a fact (tagged as goal) asserted by the user.
    PR_GOAL = generated::Z3_decl_kind::Z3_OP_PR_GOAL as u32,
    /// Given a proof for p and a proof for (implies p q), produces a proof for q.
    ///
    /// ```text
    /// T1: p
    /// T2: (implies p q)
    /// [mp T1 T2]: q
    /// ```
    ///
    /// The second antecedents may also be a proof for `(iff p q)`.
    PR_MODUS_PONENS = generated::Z3_decl_kind::Z3_OP_PR_MODUS_PONENS as u32,
    /// A proof for `(R t t)`, where `R` is a reflexive relation.
    ///
    /// This proof object has no antecedents.
    ///
    /// The only reflexive relations that are used are
    /// equivalence modulo namings, equality and equivalence.
    /// That is, `R` is either `~`, `=` or `iff`.
    PR_REFLEXIVITY = generated::Z3_decl_kind::Z3_OP_PR_REFLEXIVITY as u32,
    /// Given an symmetric relation `R` and a proof for `(R t s)`,
    /// produces a proof for `(R s t)`.
    ///
    /// ```text
    /// T1: (R t s)
    /// [symmetry T1]: (R s t)
    /// ```
    ///
    /// `T1` is the antecedent of this proof object.
    PR_SYMMETRY = generated::Z3_decl_kind::Z3_OP_PR_SYMMETRY as u32,
    /// Given a transitive relation `R`, and proofs for `(R t s)` and
    /// `(R s u)`, produces a proof for `(R t u)`.
    ///
    /// ```text
    /// T1: (R t s)
    /// T2: (R s u)
    /// [trans T1 T2]: (R t u)
    /// ```
    PR_TRANSITIVITY = generated::Z3_decl_kind::Z3_OP_PR_TRANSITIVITY as u32,
    /// Condensed transitivity proof.
    ///
    /// It combines several symmetry and transitivity proofs.
    ///
    /// Example:
    ///
    /// ```text
    /// T1: (R a b)
    /// T2: (R c b)
    /// T3: (R c d)
    /// [trans* T1 T2 T3]: (R a d)
    /// ```
    ///
    /// `R` must be a symmetric and transitive relation.
    ///
    /// Assuming that this proof object is a proof for `(R s t)`, then
    /// a proof checker must check if it is possible to prove `(R s t)`
    /// using the antecedents, symmetry and transitivity.  That is,
    /// if there is a path from `s` to `t`, if we view every
    /// antecedent `(R a b)` as an edge between `a` and `b`.
    PR_TRANSITIVITY_STAR = generated::Z3_decl_kind::Z3_OP_PR_TRANSITIVITY_STAR as u32,
    /// Monotonicity proof object.
    ///
    /// ```text
    /// T1: (R t_1 s_1)
    /// ...
    /// Tn: (R t_n s_n)
    /// [monotonicity T1 ... Tn]: (R (f t_1 ... t_n) (f s_1 ... s_n))
    /// ```
    ///
    /// Remark: if `t_i == s_i`, then the antecedent `Ti` is suppressed.
    /// That is, reflexivity proofs are suppressed to save space.
    PR_MONOTONICITY = generated::Z3_decl_kind::Z3_OP_PR_MONOTONICITY as u32,
    /// Given a proof for `(~ p q)`, produces a proof for
    /// `(~ (forall (x) p) (forall (x) q))`.
    ///
    /// ```text
    /// T1: (~ p q)
    /// [quant-intro T1]: (~ (forall (x) p) (forall (x) q))
    /// ```
    PR_QUANT_INTRO = generated::Z3_decl_kind::Z3_OP_PR_QUANT_INTRO as u32,

    /// Given a proof `p`, produces a proof of `lambda x . p`, where `x` are free
    /// variables in `p`.
    ///
    /// ```text
    /// T1: f
    /// [proof-bind T1] forall (x) f
    /// ```
    PR_BIND = generated::Z3_decl_kind::Z3_OP_PR_BIND as u32,
    /// Distributivity proof object.
    ///
    /// Given that `f (= or)` distributes over `g (= and)`, produces a proof for
    ///
    /// ```text
    /// (= (f a (g c d))
    /// (g (f a c) (f a d)))
    /// ```
    ///
    /// If `f` and `g` are associative, this proof also justifies the following equality:
    ///
    /// ```text
    /// (= (f (g a b) (g c d))
    /// (g (f a c) (f a d) (f b c) (f b d)))
    /// ```
    ///
    /// where each `f` and `g` can have arbitrary number of arguments.
    ///
    /// This proof object has no antecedents.
    ///
    /// Remark: This rule is used by the CNF conversion pass and
    /// instantiated by `f = or`, and `g = and`.
    PR_DISTRIBUTIVITY = generated::Z3_decl_kind::Z3_OP_PR_DISTRIBUTIVITY as u32,
    /// Given a proof for `(and l_1 ... l_n)`, produces a proof
    /// for `l_i`.
    ///
    /// ```text
    /// T1: (and l_1 ... l_n)
    /// [and-elim T1]: l_i
    /// ```
    PR_AND_ELIM = generated::Z3_decl_kind::Z3_OP_PR_AND_ELIM as u32,
    /// Given a proof for `(not (or l_1 ... l_n))`, produces a
    /// proof for `(not l_i)`.
    ///
    /// ```text
    /// T1: (not (or l_1 ... l_n))
    /// [not-or-elim T1]: (not l_i)
    /// ```
    PR_NOT_OR_ELIM = generated::Z3_decl_kind::Z3_OP_PR_NOT_OR_ELIM as u32,
    /// A proof for a local rewriting step `(= t s)`.
    ///
    /// The head function symbol of `t` is interpreted.
    ///
    /// This proof object has no antecedents.
    ///
    /// The conclusion of a rewrite rule is either an equality `(= t s)`,
    /// an equivalence `(iff t s)`, or equi-satisfiability `(~ t s)`.
    ///
    /// Remark: if `f` is `bool`, then `=` is `iff`.
    ///
    /// Examples:
    ///
    /// ```text
    /// (= (+ x 0) x)
    /// (= (+ x 1 2) (+ 3 x))
    /// (iff (or x false) x)
    /// ```
    PR_REWRITE = generated::Z3_decl_kind::Z3_OP_PR_REWRITE as u32,
    /// A proof for rewriting an expression `t` into an expression `s`.
    ///
    /// This proof object can have `n` antecedents. The antecedents are
    /// proofs for equalities used as substitution rules.
    ///
    /// The object is also used in a few cases. The cases are:
    ///
    /// - When applying contextual simplification `(CONTEXT_SIMPLIFIER=true)`.
    /// - When converting bit-vectors to Booleans `(BIT2BOOL=true)`.
    PR_REWRITE_STAR = generated::Z3_decl_kind::Z3_OP_PR_REWRITE_STAR as u32,
    /// A proof for `(iff (f (forall (x) q(x)) r) (forall (x) (f (q x) r)))`.
    ///
    /// This proof object has no antecedents.
    PR_PULL_QUANT = generated::Z3_decl_kind::Z3_OP_PR_PULL_QUANT as u32,
    /// A proof for:
    ///
    /// ```text
    /// (iff (forall (x_1 ... x_m) (and p_1[x_1 ... x_m] ... p_n[x_1 ... x_m]))
    /// (and (forall (x_1 ... x_m) p_1[x_1 ... x_m])
    /// ...
    /// (forall (x_1 ... x_m) p_n[x_1 ... x_m])))
    /// ```
    ///
    /// This proof object has no antecedents.
    PR_PUSH_QUANT = generated::Z3_decl_kind::Z3_OP_PR_PUSH_QUANT as u32,
    /// A proof for
    ///
    /// ```text
    /// (iff (forall (x_1 ... x_n y_1 ... y_m) p[x_1 ... x_n])
    /// (forall (x_1 ... x_n) p[x_1 ... x_n]))
    /// ```
    ///
    /// It is used to justify the elimination of unused variables.
    ///
    /// This proof object has no antecedents.
    PR_ELIM_UNUSED_VARS = generated::Z3_decl_kind::Z3_OP_PR_ELIM_UNUSED_VARS as u32,
    /// A proof for destructive equality resolution:
    ///
    /// ```text
    /// (iff (forall (x) (or (not (= x t)) P[x])) P[t])
    /// ```
    ///
    /// if `x` does not occur in `t`.
    ///
    /// This proof object has no antecedents.
    ///
    /// Several variables can be eliminated simultaneously.
    PR_DER = generated::Z3_decl_kind::Z3_OP_PR_DER as u32,
    /// A proof of `(or (not (forall (x) (P x))) (P a))`.
    PR_QUANT_INST = generated::Z3_decl_kind::Z3_OP_PR_QUANT_INST as u32,
    /// Mark a hypothesis in a natural deduction style proof.
    PR_HYPOTHESIS = generated::Z3_decl_kind::Z3_OP_PR_HYPOTHESIS as u32,
    /// ```text
    /// T1: false
    /// [lemma T1]: (or (not l_1) ... (not l_n))
    /// ```
    ///
    /// This proof object has one antecedent: a hypothetical proof for false.
    ///
    /// It converts the proof in a proof for `(or (not l_1) ... (not l_n))`,
    /// when `T1` contains the open hypotheses: `l_1, ..., l_n`.
    ///
    /// The hypotheses are closed after an application of a lemma.
    ///
    /// Furthermore, there are no other open hypotheses in the subtree covered by
    /// the lemma.
    PR_LEMMA = generated::Z3_decl_kind::Z3_OP_PR_LEMMA as u32,
    /// ```text
    /// T1:      (or l_1 ... l_n l_1' ... l_m')
    /// T2:      (not l_1)
    /// ...
    /// T(n+1):  (not l_n)
    /// [unit-resolution T1 ... T(n+1)]: (or l_1' ... l_m')
    /// ```
    PR_UNIT_RESOLUTION = generated::Z3_decl_kind::Z3_OP_PR_UNIT_RESOLUTION as u32,
    /// ```text
    /// T1: p
    /// [iff-true T1]: (iff p true)
    /// ```
    PR_IFF_TRUE = generated::Z3_decl_kind::Z3_OP_PR_IFF_TRUE as u32,
    /// ```text
    /// T1: (not p)
    /// [iff-false T1]: (iff p false)
    /// ```
    PR_IFF_FALSE = generated::Z3_decl_kind::Z3_OP_PR_IFF_FALSE as u32,
    /// ```text
    /// [comm]: (= (f a b) (f b a))
    /// ```
    ///
    /// `f` is a commutative operator.
    ///
    /// This proof object has no antecedents.
    ///
    /// Remark: if `f` is `bool`, then `=` is `iff`.
    PR_COMMUTATIVITY = generated::Z3_decl_kind::Z3_OP_PR_COMMUTATIVITY as u32,
    /// Proof object used to justify Tseitin's like axioms:
    ///
    /// ```text
    /// (or (not (and p q)) p)
    /// (or (not (and p q)) q)
    /// (or (not (and p q r)) p)
    /// (or (not (and p q r)) q)
    /// (or (not (and p q r)) r)
    /// ...
    /// (or (and p q) (not p) (not q))
    /// (or (not (or p q)) p q)
    /// (or (or p q) (not p))
    /// (or (or p q) (not q))
    /// (or (not (iff p q)) (not p) q)
    /// (or (not (iff p q)) p (not q))
    /// (or (iff p q) (not p) (not q))
    /// (or (iff p q) p q)
    /// (or (not (ite a b c)) (not a) b)
    /// (or (not (ite a b c)) a c)
    /// (or (ite a b c) (not a) (not b))
    /// (or (ite a b c) a (not c))
    /// (or (not (not a)) (not a))
    /// (or (not a) a)
    /// ```
    ///
    /// This proof object has no antecedents.
    ///
    /// Note: all axioms are propositional tautologies.
    /// Note also that `and` and `or` can take multiple arguments.
    /// You can recover the propositional tautologies by
    /// unfolding the Boolean connectives in the axioms a small
    /// bounded number of steps `(=3)`.
    PR_DEF_AXIOM = generated::Z3_decl_kind::Z3_OP_PR_DEF_AXIOM as u32,
    /// Introduces a name for a formula/term.
    ///
    /// Suppose `e` is an expression with free variables `x`, and
    /// `def-intro` introduces the name `n(x)`. The possible cases are:
    ///
    /// When e is of Boolean type:
    ///
    /// ```text
    /// [def-intro]: (and (or n (not e)) (or (not n) e))
    /// ```
    ///
    /// or:
    ///
    /// ```text
    /// [def-intro]: (or (not n) e)
    /// ```
    ///
    /// when e only occurs positively.
    ///
    /// When e is of the form `(ite cond th el)`:
    ///
    /// ```text
    /// [def-intro]: (and (or (not cond) (= n th)) (or cond (= n el)))
    /// ```
    ///
    /// Otherwise:
    ///
    /// ```text
    /// [def-intro]: (= n e)
    /// ```
    PR_DEF_INTRO = generated::Z3_decl_kind::Z3_OP_PR_DEF_INTRO as u32,
    /// ```text
    /// [apply-def T1]: F ~ n
    /// ```
    ///
    /// `F` is 'equivalent' to `n`, given that `T1` is a proof that
    /// `n` is a name for `F`.
    PR_APPLY_DEF = generated::Z3_decl_kind::Z3_OP_PR_APPLY_DEF as u32,
    /// ```text
    /// T1: (iff p q)
    /// [iff~ T1]: (~ p q)
    /// ```
    PR_IFF_OEQ = generated::Z3_decl_kind::Z3_OP_PR_IFF_OEQ as u32,
    /// Proof for a (positive) NNF step. Example:
    ///
    /// ```text
    /// T1: (not s_1) ~ r_1
    /// T2: (not s_2) ~ r_2
    /// T3: s_1 ~ r_1'
    /// T4: s_2 ~ r_2'
    /// [nnf-pos T1 T2 T3 T4]: (~ (iff s_1 s_2)
    /// (and (or r_1 r_2') (or r_1' r_2)))
    /// ```
    ///
    /// The negation normal form steps `NNF_POS` and `NNF_NEG` are used in the
    /// following cases:
    ///
    /// - When creating the NNF of a positive force quantifier.
    ///   The quantifier is retained (unless the bound variables are eliminated).
    ///   Example:
    ///   ```text
    ///   T1: q ~ q_new
    ///   [nnf-pos T1]: (~ (forall (x T) q) (forall (x T) q_new))
    ///   ```
    /// - When recursively creating NNF over Boolean formulas, where the top-level
    ///   connective is changed during NNF conversion. The relevant Boolean connectives
    ///   for `NNF_POS` are `implies`, `iff`, `xor`, `ite`.
    ///   `NNF_NEG` furthermore handles the case where negation is pushed
    ///   over Boolean connectives `and` and `or`.
    PR_NNF_POS = generated::Z3_decl_kind::Z3_OP_PR_NNF_POS as u32,
    /// Proof for a (negative) NNF step. Examples:
    ///
    /// ```text
    /// T1: (not s_1) ~ r_1
    /// ...
    /// Tn: (not s_n) ~ r_n
    /// [nnf-neg T1 ... Tn]: (not (and s_1 ... s_n)) ~ (or r_1 ... r_n)
    /// ```
    ///
    /// and
    ///
    /// ```text
    /// T1: (not s_1) ~ r_1
    /// ...
    /// Tn: (not s_n) ~ r_n
    /// [nnf-neg T1 ... Tn]: (not (or s_1 ... s_n)) ~ (and r_1 ... r_n)
    /// ```
    ///
    /// and
    ///
    /// ```text
    /// T1: (not s_1) ~ r_1
    /// T2: (not s_2) ~ r_2
    /// T3: s_1 ~ r_1'
    /// T4: s_2 ~ r_2'
    /// [nnf-neg T1 T2 T3 T4]: (~ (not (iff s_1 s_2))
    /// (and (or r_1 r_2) (or r_1' r_2')))
    /// ```
    PR_NNF_NEG = generated::Z3_decl_kind::Z3_OP_PR_NNF_NEG as u32,
    /// Proof for:
    ///
    /// ```text
    /// [sk]: (~ (not (forall x (p x y))) (not (p (sk y) y)))
    /// [sk]: (~ (exists x (p x y)) (p (sk y) y))
    /// ```
    ///
    /// This proof object has no antecedents.
    PR_SKOLEMIZE = generated::Z3_decl_kind::Z3_OP_PR_SKOLEMIZE as u32,
    /// Modus ponens style rule for equi-satisfiability.
    ///
    /// ```text
    /// T1: p
    /// T2: (~ p q)
    /// [mp~ T1 T2]: q
    /// ```
    PR_MODUS_PONENS_OEQ = generated::Z3_decl_kind::Z3_OP_PR_MODUS_PONENS_OEQ as u32,
    /// Generic proof for theory lemmas.
    ///
    /// The theory lemma function comes with one or more parameters.
    ///
    /// The first parameter indicates the name of the theory.
    ///
    /// For the theory of arithmetic, additional parameters provide hints for
    /// checking the theory lemma.
    ///
    /// The hints for arithmetic are:
    ///
    /// - `farkas` - followed by rational coefficients. Multiply the coefficients to the
    ///   inequalities in the lemma, add the (negated) inequalities and obtain a contradiction.
    /// - `triangle-eq` - Indicates a lemma related to the equivalence:
    ///   ```text
    ///   (iff (= t1 t2) (and (<= t1 t2) (<= t2 t1)))
    ///   ```
    /// - `gcd-test` - Indicates an integer linear arithmetic lemma that uses a gcd test.
    PR_TH_LEMMA = generated::Z3_decl_kind::Z3_OP_PR_TH_LEMMA as u32,
    /// Hyper-resolution rule.
    ///
    /// The premises of the rules is a sequence of clauses.
    /// The first clause argument is the main clause of the rule.
    /// with a literal from the first (main) clause.
    ///
    /// Premises of the rules are of the form
    ///
    /// ```text
    /// (or l0 l1 l2 .. ln)
    /// ```
    ///
    /// or
    ///
    /// ```text
    /// (=> (and l1 l2 .. ln) l0)
    /// ```
    ///
    /// or in the most general (ground) form:
    ///
    /// ```text
    /// (=> (and ln+1 ln+2 .. ln+m) (or l0 l1 .. ln))
    /// ```
    ///
    /// In other words we use the following (Prolog style) convention for Horn
    /// implications:
    ///
    /// - the head of a Horn implication is position 0,
    /// - the first conjunct in the body of an implication is position 1
    /// - the second conjunct in the body of an implication is position 2
    ///
    /// For general implications where the head is a disjunction, the
    /// first n positions correspond to the n disjuncts in the head.
    /// The next m positions correspond to the m conjuncts in the body.
    ///
    /// The premises can be universally quantified so that the most
    /// general non-ground form is:
    ///
    /// ```text
    /// (forall (vars) (=> (and ln+1 ln+2 .. ln+m) (or l0 l1 .. ln)))
    /// ```
    ///
    /// The hyper-resolution rule takes a sequence of parameters.
    /// The parameters are substitutions of bound variables separated by pairs
    /// of literal positions from the main clause and side clause.
    PR_HYPER_RESOLVE = generated::Z3_decl_kind::Z3_OP_PR_HYPER_RESOLVE as u32,
    /// Insert a record into a relation.
    ///
    /// The function takes `n`+1 arguments, where the first argument
    /// is the relation and the remaining `n` elements
    /// correspond to the `n` columns of the relation.
    RA_STORE = generated::Z3_decl_kind::Z3_OP_RA_STORE as u32,
    /// Creates the empty relation.
    RA_EMPTY = generated::Z3_decl_kind::Z3_OP_RA_EMPTY as u32,
    /// Tests if the relation is empty.
    RA_IS_EMPTY = generated::Z3_decl_kind::Z3_OP_RA_IS_EMPTY as u32,
    /// Create the relational join.
    RA_JOIN = generated::Z3_decl_kind::Z3_OP_RA_JOIN as u32,
    /// Create the union or convex hull of two relations.
    ///
    /// The function takes two arguments.
    RA_UNION = generated::Z3_decl_kind::Z3_OP_RA_UNION as u32,
    /// Widen two relations.
    ///
    /// The function takes two arguments.
    RA_WIDEN = generated::Z3_decl_kind::Z3_OP_RA_WIDEN as u32,
    /// Project the columns (provided as numbers in the parameters).
    ///
    /// The function takes one argument.
    RA_PROJECT = generated::Z3_decl_kind::Z3_OP_RA_PROJECT as u32,
    /// Filter (restrict) a relation with respect to a predicate.
    ///
    /// The first argument is a relation.
    ///
    /// The second argument is a predicate with free de-Bruijn indices
    /// corresponding to the columns of the relation.
    ///
    /// So the first column in the relation has index 0.
    RA_FILTER = generated::Z3_decl_kind::Z3_OP_RA_FILTER as u32,
    /// Intersect the first relation with respect to negation
    /// of the second relation (the function takes two arguments).
    ///
    /// Logically, the specification can be described by a function
    ///
    /// ```text
    /// target = filter_by_negation(pos, neg, columns)
    /// ```
    ///
    /// where columns are pairs `c1`, `d1`, ..,  `cN`, `dN` of columns
    /// from `pos` and `neg`, such that target are elements in `x` in `pos`,
    /// such that there is no `y` in `neg` that agrees with
    /// `x` on the columns `c1`, `d1`, .., `cN`, `dN`.
    RA_NEGATION_FILTER = generated::Z3_decl_kind::Z3_OP_RA_NEGATION_FILTER as u32,
    /// Rename columns in the relation.
    ///
    /// The function takes one argument.
    ///
    /// The parameters contain the renaming as a cycle.
    RA_RENAME = generated::Z3_decl_kind::Z3_OP_RA_RENAME as u32,
    /// Complement the relation.
    RA_COMPLEMENT = generated::Z3_decl_kind::Z3_OP_RA_COMPLEMENT as u32,
    /// Check if a record is an element of the relation.
    ///
    /// The function takes `n`+1 arguments, where the first argument is a relation,
    /// and the remaining `n` arguments correspond to a record.
    RA_SELECT = generated::Z3_decl_kind::Z3_OP_RA_SELECT as u32,
    /// Create a fresh copy (clone) of a relation.
    ///
    /// The function is logically the identity, but
    /// in the context of a register machine allows
    /// for [`DeclKind::RA_UNION`]
    /// to perform destructive updates to the first argument.
    RA_CLONE = generated::Z3_decl_kind::Z3_OP_RA_CLONE as u32,
    FD_CONSTANT = generated::Z3_decl_kind::Z3_OP_FD_CONSTANT as u32,
    /// A less than predicate over the finite domain `SortKind::FiniteDomain`.
    FD_LT = generated::Z3_decl_kind::Z3_OP_FD_LT as u32,
    SEQ_UNIT = generated::Z3_decl_kind::Z3_OP_SEQ_UNIT as u32,
    SEQ_EMPTY = generated::Z3_decl_kind::Z3_OP_SEQ_EMPTY as u32,
    SEQ_CONCAT = generated::Z3_decl_kind::Z3_OP_SEQ_CONCAT as u32,
    SEQ_PREFIX = generated::Z3_decl_kind::Z3_OP_SEQ_PREFIX as u32,
    SEQ_SUFFIX = generated::Z3_decl_kind::Z3_OP_SEQ_SUFFIX as u32,
    SEQ_CONTAINS = generated::Z3_decl_kind::Z3_OP_SEQ_CONTAINS as u32,
    SEQ_EXTRACT = generated::Z3_decl_kind::Z3_OP_SEQ_EXTRACT as u32,
    SEQ_REPLACE = generated::Z3_decl_kind::Z3_OP_SEQ_REPLACE as u32,
    SEQ_AT = generated::Z3_decl_kind::Z3_OP_SEQ_AT as u32,
    SEQ_LENGTH = generated::Z3_decl_kind::Z3_OP_SEQ_LENGTH as u32,
    SEQ_INDEX = generated::Z3_decl_kind::Z3_OP_SEQ_INDEX as u32,
    SEQ_TO_RE = generated::Z3_decl_kind::Z3_OP_SEQ_TO_RE as u32,
    SEQ_IN_RE = generated::Z3_decl_kind::Z3_OP_SEQ_IN_RE as u32,
    STR_TO_INT = generated::Z3_decl_kind::Z3_OP_STR_TO_INT as u32,
    INT_TO_STR = generated::Z3_decl_kind::Z3_OP_INT_TO_STR as u32,
    RE_PLUS = generated::Z3_decl_kind::Z3_OP_RE_PLUS as u32,
    RE_STAR = generated::Z3_decl_kind::Z3_OP_RE_STAR as u32,
    RE_OPTION = generated::Z3_decl_kind::Z3_OP_RE_OPTION as u32,
    RE_CONCAT = generated::Z3_decl_kind::Z3_OP_RE_CONCAT as u32,
    RE_UNION = generated::Z3_decl_kind::Z3_OP_RE_UNION as u32,
    RE_RANGE = generated::Z3_decl_kind::Z3_OP_RE_RANGE as u32,
    RE_LOOP = generated::Z3_decl_kind::Z3_OP_RE_LOOP as u32,
    RE_INTERSECT = generated::Z3_decl_kind::Z3_OP_RE_INTERSECT as u32,
    RE_EMPTY_SET = generated::Z3_decl_kind::Z3_OP_RE_EMPTY_SET as u32,
    RE_FULL_SET = generated::Z3_decl_kind::Z3_OP_RE_FULL_SET as u32,
    RE_COMPLEMENT = generated::Z3_decl_kind::Z3_OP_RE_COMPLEMENT as u32,
    /// A label (used by the Boogie Verification condition generator).
    ///
    /// The label has two parameters, a string and a Boolean polarity.
    ///
    /// It takes one argument, a formula.
    LABEL = generated::Z3_decl_kind::Z3_OP_LABEL as u32,
    /// A label literal (used by the Boogie Verification condition generator).
    ///
    /// A label literal has a set of string parameters. It takes no arguments.
    LABEL_LIT = generated::Z3_decl_kind::Z3_OP_LABEL_LIT as u32,
    /// Datatype constructor.
    DT_CONSTRUCTOR = generated::Z3_decl_kind::Z3_OP_DT_CONSTRUCTOR as u32,
    /// Datatype recognizer.
    DT_RECOGNISER = generated::Z3_decl_kind::Z3_OP_DT_RECOGNISER as u32,
    /// Datatype recognizer.
    DT_IS = generated::Z3_decl_kind::Z3_OP_DT_IS as u32,
    /// Datatype accessor.
    DT_ACCESSOR = generated::Z3_decl_kind::Z3_OP_DT_ACCESSOR as u32,
    /// Datatype field update.
    DT_UPDATE_FIELD = generated::Z3_decl_kind::Z3_OP_DT_UPDATE_FIELD as u32,
    /// Cardinality constraint.
    ///
    /// Example: `x + y + z <= 2`
    PB_AT_MOST = generated::Z3_decl_kind::Z3_OP_PB_AT_MOST as u32,
    /// Cardinality constraint.
    ///
    /// Example: `x + y + z >= 2`
    PB_AT_LEAST = generated::Z3_decl_kind::Z3_OP_PB_AT_LEAST as u32,
    /// Generalized Pseudo-Boolean cardinality constraint.
    ///
    /// Example: `2*x + 3*y <= 4`
    PB_LE = generated::Z3_decl_kind::Z3_OP_PB_LE as u32,
    /// Generalized Pseudo-Boolean cardinality constraint.
    ///
    /// Example: `2*x + 3*y + 2*z >= 4`
    PB_GE = generated::Z3_decl_kind::Z3_OP_PB_GE as u32,
    /// Generalized Pseudo-Boolean equality constraint.
    ///
    /// Example: `2*x + 1*y + 2*z + 1*u = 4`
    PB_EQ = generated::Z3_decl_kind::Z3_OP_PB_EQ as u32,
    /// Floating-point rounding mode RNE
    FPA_RM_NEAREST_TIES_TO_EVEN = generated::Z3_decl_kind::Z3_OP_FPA_RM_NEAREST_TIES_TO_EVEN as u32,
    /// Floating-point rounding mode RNA
    FPA_RM_NEAREST_TIES_TO_AWAY = generated::Z3_decl_kind::Z3_OP_FPA_RM_NEAREST_TIES_TO_AWAY as u32,
    /// Floating-point rounding mode RTP
    FPA_RM_TOWARD_POSITIVE = generated::Z3_decl_kind::Z3_OP_FPA_RM_TOWARD_POSITIVE as u32,
    /// Floating-point rounding mode RTN
    FPA_RM_TOWARD_NEGATIVE = generated::Z3_decl_kind::Z3_OP_FPA_RM_TOWARD_NEGATIVE as u32,
    /// Floating-point rounding mode RTZ
    FPA_RM_TOWARD_ZERO = generated::Z3_decl_kind::Z3_OP_FPA_RM_TOWARD_ZERO as u32,
    /// Floating-point value
    FPA_NUM = generated::Z3_decl_kind::Z3_OP_FPA_NUM as u32,
    /// Floating-point +oo
    FPA_PLUS_INF = generated::Z3_decl_kind::Z3_OP_FPA_PLUS_INF as u32,
    /// Floating-point -oo
    FPA_MINUS_INF = generated::Z3_decl_kind::Z3_OP_FPA_MINUS_INF as u32,
    /// Floating-point NaN
    FPA_NAN = generated::Z3_decl_kind::Z3_OP_FPA_NAN as u32,
    /// Floating-point +zero
    FPA_PLUS_ZERO = generated::Z3_decl_kind::Z3_OP_FPA_PLUS_ZERO as u32,
    /// Floating-point -zero
    FPA_MINUS_ZERO = generated::Z3_decl_kind::Z3_OP_FPA_MINUS_ZERO as u32,
    /// Floating-point addition
    FPA_ADD = generated::Z3_decl_kind::Z3_OP_FPA_ADD as u32,
    /// Floating-point subtraction
    FPA_SUB = generated::Z3_decl_kind::Z3_OP_FPA_SUB as u32,
    /// Floating-point negation
    FPA_NEG = generated::Z3_decl_kind::Z3_OP_FPA_NEG as u32,
    /// Floating-point multiplication
    FPA_MUL = generated::Z3_decl_kind::Z3_OP_FPA_MUL as u32,
    /// Floating-point division
    FPA_DIV = generated::Z3_decl_kind::Z3_OP_FPA_DIV as u32,
    /// Floating-point remainder
    FPA_REM = generated::Z3_decl_kind::Z3_OP_FPA_REM as u32,
    /// Floating-point absolute value
    FPA_ABS = generated::Z3_decl_kind::Z3_OP_FPA_ABS as u32,
    /// Floating-point minimum
    FPA_MIN = generated::Z3_decl_kind::Z3_OP_FPA_MIN as u32,
    /// Floating-point maximum
    FPA_MAX = generated::Z3_decl_kind::Z3_OP_FPA_MAX as u32,
    /// Floating-point fused multiply-add
    FPA_FMA = generated::Z3_decl_kind::Z3_OP_FPA_FMA as u32,
    /// Floating-point square root
    FPA_SQRT = generated::Z3_decl_kind::Z3_OP_FPA_SQRT as u32,
    /// Floating-point round to integral
    FPA_ROUND_TO_INTEGRAL = generated::Z3_decl_kind::Z3_OP_FPA_ROUND_TO_INTEGRAL as u32,
    /// Floating-point equality
    FPA_EQ = generated::Z3_decl_kind::Z3_OP_FPA_EQ as u32,
    /// Floating-point less than
    FPA_LT = generated::Z3_decl_kind::Z3_OP_FPA_LT as u32,
    /// Floating-point greater than
    FPA_GT = generated::Z3_decl_kind::Z3_OP_FPA_GT as u32,
    /// Floating-point less than or equal
    FPA_LE = generated::Z3_decl_kind::Z3_OP_FPA_LE as u32,
    /// Floating-point greater than or equal
    FPA_GE = generated::Z3_decl_kind::Z3_OP_FPA_GE as u32,
    /// Floating-point isNaN
    FPA_IS_NAN = generated::Z3_decl_kind::Z3_OP_FPA_IS_NAN as u32,
    /// Floating-point isInfinite
    FPA_IS_INF = generated::Z3_decl_kind::Z3_OP_FPA_IS_INF as u32,
    /// Floating-point isZero
    FPA_IS_ZERO = generated::Z3_decl_kind::Z3_OP_FPA_IS_ZERO as u32,
    /// Floating-point isNormal
    FPA_IS_NORMAL = generated::Z3_decl_kind::Z3_OP_FPA_IS_NORMAL as u32,
    /// Floating-point isSubnormal
    FPA_IS_SUBNORMAL = generated::Z3_decl_kind::Z3_OP_FPA_IS_SUBNORMAL as u32,
    /// Floating-point isNegative
    FPA_IS_NEGATIVE = generated::Z3_decl_kind::Z3_OP_FPA_IS_NEGATIVE as u32,
    /// Floating-point isPositive
    FPA_IS_POSITIVE = generated::Z3_decl_kind::Z3_OP_FPA_IS_POSITIVE as u32,
    /// Floating-point constructor from 3 bit-vectors
    FPA_FP = generated::Z3_decl_kind::Z3_OP_FPA_FP as u32,
    /// Floating-point conversion (various)
    FPA_TO_FP = generated::Z3_decl_kind::Z3_OP_FPA_TO_FP as u32,
    /// Floating-point conversion from unsigned bit-vector
    FPA_TO_FP_UNSIGNED = generated::Z3_decl_kind::Z3_OP_FPA_TO_FP_UNSIGNED as u32,
    /// Floating-point conversion to unsigned bit-vector
    FPA_TO_UBV = generated::Z3_decl_kind::Z3_OP_FPA_TO_UBV as u32,
    /// Floating-point conversion to signed bit-vector
    FPA_TO_SBV = generated::Z3_decl_kind::Z3_OP_FPA_TO_SBV as u32,
    /// Floating-point conversion to real number
    FPA_TO_REAL = generated::Z3_decl_kind::Z3_OP_FPA_TO_REAL as u32,
    /// Floating-point conversion to IEEE-754 bit-vector
    FPA_TO_IEEE_BV = generated::Z3_decl_kind::Z3_OP_FPA_TO_IEEE_BV as u32,
    /// Implicitly) represents the internal bitvector-representation
    /// of a floating-point term (used for the lazy encoding
    /// of non-relevant terms in `theory_fpa`)
    FPA_BVWRAP = generated::Z3_decl_kind::Z3_OP_FPA_BVWRAP as u32,
    /// Conversion of a 3-bit bit-vector term to a
    /// floating-point rounding-mode term.
    ///
    /// The conversion uses the following values:
    ///
    /// 0 = 000 = `DeclKind::FPA_RM_NEAREST_TIES_TO_EVEN`,
    /// 1 = 001 = `DeclKind::FPA_RM_NEAREST_TIES_TO_AWAY`,
    /// 2 = 010 = `DeclKind::FPA_RM_TOWARD_POSITIVE`,
    /// 3 = 011 = `DeclKind::FPA_RM_TOWARD_NEGATIVE`,
    /// 4 = 100 = `DeclKind::FPA_RM_TOWARD_ZERO`.
    FPA_BV2RM = generated::Z3_decl_kind::Z3_OP_FPA_BV2RM as u32,
    /// Internal (often interpreted) symbol, but no additional
    /// information is exposed. Tools may use the string
    /// representation of the function declaration to obtain
    /// more information.
    INTERNAL = generated::Z3_decl_kind::Z3_OP_INTERNAL as u32,
    /// Kind used for uninterpreted symbols.
    UNINTERPRETED = generated::Z3_decl_kind::Z3_OP_UNINTERPRETED as u32,
}

/// The different kinds of parameters that can be associated with parameter sets.
/// (see [`Z3_mk_params`]).
///
/// This corresponds to `Z3_param_kind` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// integer parameters.
    ///
    /// This corresponds to `Z3_PK_UINT` in the C API.
    UInt = generated::Z3_param_kind::Z3_PK_UINT as u32,
    /// boolean parameters.
    ///
    /// This corresponds to `Z3_PK_BOOL` in the C API.
    Bool = generated::Z3_param_kind::Z3_PK_BOOL as u32,
    /// double parameters.
    ///
    /// This corresponds to `Z3_PK_DOUBLE` in the C API.
    Double = generated::Z3_param_kind::Z3_PK_DOUBLE as u32,
    /// symbol parameters.
    ///
    /// This corresponds to `Z3_PK_SYMBOL` in the C API.
    Symbol = generated::Z3_param_kind::Z3_PK_SYMBOL as u32,
    /// string parameters.
    ///
    /// This corresponds to `Z3_PK_STRING` in the C API.
    String = generated::Z3_param_kind::Z3_PK_STRING as u32,
    /// all internal parameter kinds which are not exposed in the API.
    ///
    /// This corresponds to `Z3_PK_OTHER` in the C API.
    Other = generated::Z3_param_kind::Z3_PK_OTHER as u32,
    /// invalid parameter.
    ///
    /// This corresponds to `Z3_PK_INVALID` in the C API.
    Invalid = generated::Z3_param_kind::Z3_PK_INVALID as u32,
}

/// Z3 pretty printing modes (See [`Z3_set_ast_print_mode`]).
///
/// This corresponds to `Z3_ast_print_mode` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AstPrintMode {
    /// Print AST nodes in SMTLIB verbose format.
    ///
    /// This corresponds to `Z3_PRINT_SMTLIB_FULL` in the C API.
    SmtLibFull = generated::Z3_ast_print_mode::Z3_PRINT_SMTLIB_FULL as u32,
    /// Print AST nodes using a low-level format.
    ///
    /// This corresponds to `Z3_PRINT_LOW_LEVEL` in the C API.
    LowLevel = generated::Z3_ast_print_mode::Z3_PRINT_LOW_LEVEL as u32,
    /// Print AST nodes in SMTLIB 2.x compliant format.
    ///
    /// This corresponds to `Z3_PRINT_SMTLIB2_COMPLIANT` in the C API.
    SmtLib2Compliant = generated::Z3_ast_print_mode::Z3_PRINT_SMTLIB2_COMPLIANT as u32,
}

/// Z3 error codes (See [`Z3_get_error_code`]).
///
/// This corresponds to `Z3_error_code` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// No error.
    ///
    /// This corresponds to `Z3_OK` in the C API.
    OK = generated::Z3_error_code::Z3_OK as u32,
    /// User tried to build an invalid (type incorrect) AST.
    ///
    /// This corresponds to `Z3_SORT_ERROR` in the C API.
    SortError = generated::Z3_error_code::Z3_SORT_ERROR as u32,
    /// Index out of bounds.
    ///
    /// This corresponds to `Z3_IOB` in the C API.
    IOB = generated::Z3_error_code::Z3_IOB as u32,
    /// Invalid argument was provided.
    ///
    /// This corresponds to `Z3_INVALID_ARG` in the C API.
    InvalidArg = generated::Z3_error_code::Z3_INVALID_ARG as u32,
    /// An error occurred when parsing a string or file.
    ///
    /// This corresponds to `Z3_PARSER_ERROR` in the C API.
    ParserError = generated::Z3_error_code::Z3_PARSER_ERROR as u32,
    /// Parser output is not available, that is, user didn't invoke
    /// [`Z3_parse_smtlib2_string`] or [`Z3_parse_smtlib2_file`].
    ///
    /// This corresponds to `Z3_NO_PARSER` in the C API.
    NoParser = generated::Z3_error_code::Z3_NO_PARSER as u32,
    /// Invalid pattern was used to build a quantifier.
    ///
    /// This corresponds to `Z3_INVALID_PATTERN` in the C API.
    InvalidPattern = generated::Z3_error_code::Z3_INVALID_PATTERN as u32,
    /// A memory allocation failure was encountered.
    ///
    /// This corresponds to `Z3_MEMOUT_FAIL` in the C API.
    MemoutFail = generated::Z3_error_code::Z3_MEMOUT_FAIL as u32,
    /// A file could not be accessed.
    ///
    /// This corresponds to `Z3_FILE_ACCESS_ERROR` in the C API.
    FileAccessError = generated::Z3_error_code::Z3_FILE_ACCESS_ERROR as u32,
    /// An error internal to Z3 occurred.
    ///
    /// This corresponds to `Z3_INTERNAL_FATAL` in the C API.
    InternalFatal = generated::Z3_error_code::Z3_INTERNAL_FATAL as u32,
    /// API call is invalid in the current state.
    ///
    /// This corresponds to `Z3_INVALID_USAGE` in the C API.
    InvalidUsage = generated::Z3_error_code::Z3_INVALID_USAGE as u32,
    /// Trying to decrement the reference counter of an AST that was
    /// deleted or the reference counter was not initialized with
    /// [`Z3_inc_ref`].
    ///
    /// This corresponds to `Z3_DEC_REF_ERROR` in the C API.
    DecRefError = generated::Z3_error_code::Z3_DEC_REF_ERROR as u32,
    /// Internal Z3 exception. Additional details can be retrieved
    /// using [`Z3_get_error_msg`].
    ///
    /// This corresponds to `Z3_EXCEPTION` in the C API.
    Exception = generated::Z3_error_code::Z3_EXCEPTION as u32,
}

/// Z3 custom error handler (See [`Z3_set_error_handler`]).
pub type Z3_error_handler =
    ::core::option::Option<unsafe extern "C" fn(c: Z3_context, e: ErrorCode)>;

/// Precision of a given goal. Some goals can be transformed using over/under approximations.
///
/// This corresponds to `Z3_goal_prec` in the C API.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum GoalPrec {
    /// Approximations/Relaxations were not applied on the goal
    /// (sat and unsat answers were preserved).
    ///
    /// This corresponds to `Z3_GOAL_PRECISE` in the C API.
    Precise = generated::Z3_goal_prec::Z3_GOAL_PRECISE as u32,
    /// Goal is the product of a under-approximation (sat answers are preserved).
    ///
    /// This corresponds to `Z3_GOAL_UNDER` in the C API.
    Under = generated::Z3_goal_prec::Z3_GOAL_UNDER as u32,
    /// Goal is the product of an over-approximation (unsat answers are preserved).
    ///
    /// This corresponds to `Z3_GOAL_OVER` in the C API.
    Over = generated::Z3_goal_prec::Z3_GOAL_OVER as u32,
    /// Goal is garbage (it is the product of over- and under-approximations,
    /// sat and unsat answers are not preserved).
    ///
    /// This corresponds to `Z3_GOAL_UNDER_OVER` in the C API.
    UnderOver = generated::Z3_goal_prec::Z3_GOAL_UNDER_OVER as u32,
}

unsafe extern "C" {
    /// Set a global (or module) parameter.
    /// This setting is shared by all Z3 contexts.
    ///
    /// When a Z3 module is initialized it will use the value of these parameters
    /// when [`Z3_params`] objects are not provided.
    ///
    /// The name of parameter can be composed of characters \[a-z\]\[A-Z\], digits \[0-9\], '-' and '_'.
    /// The character '.' is a delimiter (more later).
    ///
    /// The parameter names are case-insensitive. The character '-' should be viewed as an "alias" for '_'.
    /// Thus, the following parameter names are considered equivalent: `"pp.decimal-precision"`
    /// and `"PP.DECIMAL_PRECISION"`.
    ///
    /// This function can be used to set parameters for a specific Z3 module.
    /// This can be done by using `<module-name>.<parameter-name>`.
    ///
    /// For example:
    /// `Z3_global_param_set('pp.decimal', 'true')`
    /// will set the parameter `"decimal"` in the module `"pp"` to true.
    ///
    /// # See also:
    ///
    /// - [`Z3_global_param_get`]
    /// - [`Z3_global_param_reset_all`]
    pub fn Z3_global_param_set(param_id: Z3_string, param_value: Z3_string);

    /// Restore the value of all global (and module) parameters.
    /// This command will not affect already created objects (such as tactics and solvers).
    ///
    /// # See also:
    ///
    /// - [`Z3_global_param_get`]
    /// - [`Z3_global_param_set`]
    pub fn Z3_global_param_reset_all();

    /// Get a global (or module) parameter.
    ///
    /// Returns `false` if the parameter value does not exist.
    ///
    /// # See also:
    ///
    /// - [`Z3_global_param_reset_all`]
    /// - [`Z3_global_param_set`]
    ///
    /// NOTE: This function cannot be invoked simultaneously from different threads without synchronization.
    /// The result string stored in `param_value` is stored in shared location.
    pub fn Z3_global_param_get(param_id: Z3_string, param_value: Z3_string_ptr) -> bool;

    /// Create a configuration object for the Z3 context object.
    ///
    /// Configurations are created in order to assign parameters prior to creating
    /// contexts for Z3 interaction. For example, if the users wishes to use proof
    /// generation, then call:
    ///
    /// `Z3_set_param_value(cfg, "proof", "true")`
    ///
    /// NOTE: In previous versions of Z3, the [`Z3_config`] was used to store
    /// global and module configurations. Now, we should use [`Z3_global_param_set`].
    ///
    /// The following parameters can be set:
    ///
    /// - `proof`  (Boolean)           Enable proof generation
    /// - `debug_ref_count` (Boolean)  Enable debug support for [`Z3_ast`] reference counting
    /// - `trace`  (Boolean)           Tracing support for VCC
    /// - `trace_file_name` (String)   Trace out file for VCC traces
    /// - `timeout` (unsigned)         default timeout (in milliseconds) used for solvers
    /// - `well_sorted_check`          type checker
    /// - `auto_config`                use heuristics to automatically select solver and configure it
    /// - `model`                      model generation for solvers, this parameter can be overwritten when creating a solver
    /// - `model_validate`             validate models produced by solvers
    /// - `unsat_core`                 unsat-core generation for solvers, this parameter can be overwritten when creating a solver
    ///
    /// # See also:
    ///
    /// - [`Z3_set_param_value`]
    /// - [`Z3_del_config`]
    pub fn Z3_mk_config() -> Option<Z3_config>;

    /// Delete the given configuration object.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_config`]
    pub fn Z3_del_config(c: Z3_config);

    /// Set a configuration parameter.
    ///
    /// The following parameters can be set for
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_config`]
    pub fn Z3_set_param_value(c: Z3_config, param_id: Z3_string, param_value: Z3_string);

    /// Create a context using the given configuration.
    ///
    /// After a context is created, the configuration cannot be changed,
    /// although some parameters can be changed using [`Z3_update_param_value`].
    /// All main interaction with Z3 happens in the context of a [`Z3_context`].
    ///
    /// In contrast to [`Z3_mk_context_rc`], the life time of [`Z3_ast`]
    /// objects are determined by the scope level of [`Z3_solver_push`]
    /// and [`Z3_solver_pop`]. In other words, a [`Z3_ast`] object remains
    /// valid until there is a call to [`Z3_solver_pop`] that
    /// takes the current scope below the level where
    /// the object was created.
    ///
    /// Note that all other reference counted objects, including [`Z3_model`],
    /// [`Z3_solver`], [`Z3_func_interp`] have to be managed by the caller.
    /// Their reference counts are not handled by the context.
    ///
    /// Further remarks:
    /// - [`Z3_sort`], [`Z3_func_decl`], [`Z3_app`], [`Z3_pattern`] are [`Z3_ast`]'s.
    /// - Z3 uses hash-consing, i.e., when the same [`Z3_ast`] is created twice,
    ///   Z3 will return the same pointer twice.
    ///
    /// # See also:
    ///
    /// - [`Z3_del_context`]
    pub fn Z3_mk_context(c: Z3_config) -> Option<Z3_context>;

    /// Create a context using the given configuration.
    /// This function is similar to [`Z3_mk_context`]. However,
    /// in the context returned by this function, the user
    /// is responsible for managing [`Z3_ast`] reference counters.
    /// Managing reference counters is a burden and error-prone,
    /// but allows the user to use the memory more efficiently.
    /// The user must invoke [`Z3_inc_ref`] for any [`Z3_ast`] returned
    /// by Z3, and [`Z3_dec_ref`] whenever the [`Z3_ast`] is not needed
    /// anymore. This idiom is similar to the one used in
    /// BDD (binary decision diagrams) packages such as CUDD.
    ///
    /// Remarks:
    ///
    /// - [`Z3_sort`], [`Z3_func_decl`], [`Z3_app`], [`Z3_pattern`] are [`Z3_ast`]'s.
    /// - After a context is created, the configuration cannot be changed.
    /// - All main interaction with Z3 happens in the context of a [`Z3_context`].
    /// - Z3 uses hash-consing, i.e., when the same [`Z3_ast`] is created twice,
    ///   Z3 will return the same pointer twice.
    pub fn Z3_mk_context_rc(c: Z3_config) -> Option<Z3_context>;

    /// Delete the given logical context.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_context`]
    pub fn Z3_del_context(c: Z3_context);

    /// Increment the reference counter of the given AST.
    /// The context `c` should have been created using [`Z3_mk_context_rc`].
    /// This function is a NOOP if `c` was created using [`Z3_mk_context`].
    pub fn Z3_inc_ref(c: Z3_context, a: Z3_ast);

    /// Decrement the reference counter of the given AST.
    /// The context `c` should have been created using [`Z3_mk_context_rc`].
    /// This function is a NOOP if `c` was created using [`Z3_mk_context`].
    pub fn Z3_dec_ref(c: Z3_context, a: Z3_ast);

    /// Set a value of a context parameter.
    ///
    /// # See also:
    ///
    /// - [`Z3_global_param_set`]
    pub fn Z3_update_param_value(c: Z3_context, param_id: Z3_string, param_value: Z3_string);

    /// Interrupt the execution of a Z3 procedure.
    ///
    /// This procedure can be used to interrupt: solvers, simplifiers and tactics.
    ///
    /// This method can be invoked from a thread different from the one executing the
    /// interruptible procedure.
    pub fn Z3_interrupt(c: Z3_context);

    /// Create a Z3 (empty) parameter set.
    /// Starting at Z3 4.0, parameter sets are used to configure many components such as:
    /// simplifiers, tactics, solvers, etc.
    ///
    /// NOTE: Reference counting must be used to manage parameter
    /// sets, even when the [`Z3_context`] was created using
    /// [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_params(c: Z3_context) -> Option<Z3_params>;

    /// Increment the reference counter of the given parameter set.
    pub fn Z3_params_inc_ref(c: Z3_context, p: Z3_params);

    /// Decrement the reference counter of the given parameter set.
    pub fn Z3_params_dec_ref(c: Z3_context, p: Z3_params);

    /// Add a Boolean parameter `k` with value `v` to the parameter set `p`.
    pub fn Z3_params_set_bool(c: Z3_context, p: Z3_params, k: Z3_symbol, v: bool);

    /// Add a unsigned parameter `k` with value `v` to the parameter set `p`.
    pub fn Z3_params_set_uint(c: Z3_context, p: Z3_params, k: Z3_symbol, v: ::core::ffi::c_uint);

    /// Add a double parameter `k` with value `v` to the parameter set `p`.
    pub fn Z3_params_set_double(c: Z3_context, p: Z3_params, k: Z3_symbol, v: f64);

    /// Add a symbol parameter `k` with value `v` to the parameter set `p`.
    pub fn Z3_params_set_symbol(c: Z3_context, p: Z3_params, k: Z3_symbol, v: Z3_symbol);

    /// Convert a parameter set into a string. This function is mainly used for printing the
    /// contents of a parameter set.
    pub fn Z3_params_to_string(c: Z3_context, p: Z3_params) -> Z3_string;

    /// Validate the parameter set `p` against the parameter description set `d`.
    ///
    /// The procedure invokes the error handler if `p` is invalid.
    pub fn Z3_params_validate(c: Z3_context, p: Z3_params, d: Z3_param_descrs);

    /// Increment the reference counter of the given parameter description set.
    pub fn Z3_param_descrs_inc_ref(c: Z3_context, p: Z3_param_descrs);

    /// Decrement the reference counter of the given parameter description set.
    pub fn Z3_param_descrs_dec_ref(c: Z3_context, p: Z3_param_descrs);

    /// Return the kind associated with the given parameter name `n`.
    pub fn Z3_param_descrs_get_kind(c: Z3_context, p: Z3_param_descrs, n: Z3_symbol) -> ParamKind;

    /// Return the number of parameters in the given parameter description set.
    pub fn Z3_param_descrs_size(c: Z3_context, p: Z3_param_descrs) -> ::core::ffi::c_uint;

    /// Return the number of parameters in the given parameter description set.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_param_descrs_size(c, p)`
    pub fn Z3_param_descrs_get_name(
        c: Z3_context,
        p: Z3_param_descrs,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_symbol>;

    /// Retrieve documentation string corresponding to parameter name `s`.
    pub fn Z3_param_descrs_get_documentation(
        c: Z3_context,
        p: Z3_param_descrs,
        s: Z3_symbol,
    ) -> Z3_string;

    /// Convert a parameter description set into a string. This function is mainly used for printing the
    /// contents of a parameter description set.
    pub fn Z3_param_descrs_to_string(c: Z3_context, p: Z3_param_descrs) -> Z3_string;

    /// Create a Z3 symbol using an integer.
    ///
    /// Symbols are used to name several term and type constructors.
    ///
    /// NB. Not all integers can be passed to this function.
    /// The legal range of unsigned integers is 0 to 2^30-1.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_symbol_int`]
    /// - [`Z3_mk_string_symbol`]
    pub fn Z3_mk_int_symbol(c: Z3_context, i: ::core::ffi::c_int) -> Option<Z3_symbol>;

    /// Create a Z3 symbol using a C string.
    ///
    /// Symbols are used to name several term and type constructors.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_symbol_string`]
    /// - [`Z3_mk_int_symbol`]
    pub fn Z3_mk_string_symbol(c: Z3_context, s: Z3_string) -> Option<Z3_symbol>;

    /// Create a free (uninterpreted) type using the given name (symbol).
    ///
    /// Two free types are considered the same iff the have the same name.
    pub fn Z3_mk_uninterpreted_sort(c: Z3_context, s: Z3_symbol) -> Option<Z3_sort>;

    /// Create the Boolean type.
    ///
    /// This type is used to create propositional variables and predicates.
    pub fn Z3_mk_bool_sort(c: Z3_context) -> Option<Z3_sort>;

    /// Create the integer type.
    ///
    /// This type is not the int type found in programming languages.
    /// A machine integer can be represented using bit-vectors. The function
    /// [`Z3_mk_bv_sort`] creates a bit-vector type.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bv_sort`]
    pub fn Z3_mk_int_sort(c: Z3_context) -> Option<Z3_sort>;

    /// Create the real type.
    ///
    /// Note that this type is not a floating point number.
    pub fn Z3_mk_real_sort(c: Z3_context) -> Option<Z3_sort>;

    /// Create a bit-vector type of the given size.
    ///
    /// This type can also be seen as a machine integer.
    ///
    /// NOTE: The size of the bit-vector type must be greater than zero.
    pub fn Z3_mk_bv_sort(c: Z3_context, sz: ::core::ffi::c_uint) -> Option<Z3_sort>;

    /// Create a named finite domain sort.
    ///
    /// To create constants that belong to the finite domain,
    /// use the APIs for creating numerals and pass a numeric
    /// constant together with the sort returned by this call.
    /// The numeric constant should be between 0 and the less
    /// than the size of the domain.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_finite_domain_sort_size`]
    pub fn Z3_mk_finite_domain_sort(c: Z3_context, name: Z3_symbol, size: u64) -> Option<Z3_sort>;

    /// Create an array type.
    ///
    /// We usually represent the array type as: `[domain -> range]`.
    /// Arrays are usually used to model the heap/memory in software verification.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_select`]
    /// - [`Z3_mk_store`]
    pub fn Z3_mk_array_sort(c: Z3_context, domain: Z3_sort, range: Z3_sort) -> Option<Z3_sort>;

    /// Create an array type with N arguments
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_select_n`]
    /// - [`Z3_mk_store_n`]
    pub fn Z3_mk_array_sort_n(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        domain: *const Z3_sort,
        range: Z3_sort,
    ) -> Option<Z3_sort>;

    /// Create a tuple type.
    ///
    /// A tuple with `n` fields has a constructor and `n` projections.
    /// This function will also declare the constructor and projection functions.
    ///
    /// - `c`: logical context
    /// - `mk_tuple_name`: name of the constructor function associated with the tuple type.
    /// - `num_fields`: number of fields in the tuple type.
    /// - `field_names`: name of the projection functions.
    /// - `field_sorts`: type of the tuple fields.
    /// - `mk_tuple_decl`: output parameter that will contain the constructor declaration.
    /// - `proj_decl`: output parameter that will contain the projection function declarations. This field must be a buffer of size `num_fields` allocated by the user.
    pub fn Z3_mk_tuple_sort(
        c: Z3_context,
        mk_tuple_name: Z3_symbol,
        num_fields: ::core::ffi::c_uint,
        field_names: *const Z3_symbol,
        field_sorts: *const Z3_sort,
        mk_tuple_decl: *mut *mut _Z3_func_decl,
        proj_decl: *mut *mut _Z3_func_decl,
    ) -> Option<Z3_sort>;

    /// Create a enumeration sort.
    ///
    /// An enumeration sort with `n` elements.
    /// This function will also declare the functions corresponding to the enumerations.
    ///
    /// - `c`: logical context
    /// - `name`: name of the enumeration sort.
    /// - `n`: number of elements in enumeration sort.
    /// - `enum_names`: names of the enumerated elements.
    /// - `enum_consts`: constants corresponding to the enumerated elements.
    /// - `enum_testers`: predicates testing if terms of the enumeration sort correspond to an enumeration.
    ///
    /// For example, if this function is called with three symbols A, B, C and the name S, then
    /// `s` is a sort whose name is S, and the function returns three terms corresponding to A, B, C in
    /// `enum_consts`. The array `enum_testers` has three predicates of type `(s -> Bool)`.
    /// The first predicate (corresponding to A) is true when applied to A, and false otherwise.
    /// Similarly for the other predicates.
    pub fn Z3_mk_enumeration_sort(
        c: Z3_context,
        name: Z3_symbol,
        n: ::core::ffi::c_uint,
        enum_names: *const Z3_symbol,
        enum_consts: *mut *mut _Z3_func_decl,
        enum_testers: *mut *mut _Z3_func_decl,
    ) -> Option<Z3_sort>;

    /// Create a list sort
    ///
    /// A list sort over `elem_sort`
    /// This function declares the corresponding constructors and testers for lists.
    ///
    /// - `c`: logical context
    /// - `name`: name of the list sort.
    /// - `elem_sort`: sort of list elements.
    /// - `nil_decl`: declaration for the empty list.
    /// - `is_nil_decl`: test for the empty list.
    /// - `cons_decl`: declaration for a cons cell.
    /// - `is_cons_decl`: cons cell test.
    /// - `head_decl`: list head.
    /// - `tail_decl`: list tail.
    pub fn Z3_mk_list_sort(
        c: Z3_context,
        name: Z3_symbol,
        elem_sort: Z3_sort,
        nil_decl: *mut *mut _Z3_func_decl,
        is_nil_decl: *mut *mut _Z3_func_decl,
        cons_decl: *mut *mut _Z3_func_decl,
        is_cons_decl: *mut *mut _Z3_func_decl,
        head_decl: *mut *mut _Z3_func_decl,
        tail_decl: *mut *mut _Z3_func_decl,
    ) -> Option<Z3_sort>;

    /// Create a constructor.
    ///
    /// - `c`: logical context.
    /// - `name`: constructor name.
    /// - `recognizer`: name of recognizer function.
    /// - `num_fields`: number of fields in constructor.
    /// - `field_names`: names of the constructor fields.
    /// - `sorts`: field sorts, 0 if the field sort refers to a recursive sort.
    /// - `sort_refs`: reference to datatype sort that is an argument to the constructor; if the corresponding
    ///   sort reference is 0, then the value in `sort_refs` should be an index referring to
    ///   one of the recursive datatypes that is declared.
    ///
    /// # See also:
    ///
    /// - [`Z3_del_constructor`]
    /// - [`Z3_mk_constructor_list`]
    /// - [`Z3_query_constructor`]
    pub fn Z3_mk_constructor(
        c: Z3_context,
        name: Z3_symbol,
        recognizer: Z3_symbol,
        num_fields: ::core::ffi::c_uint,
        field_names: *const Z3_symbol,
        sorts: *const Option<Z3_sort>,
        sort_refs: *mut ::core::ffi::c_uint,
    ) -> Option<Z3_constructor>;

    /// Reclaim memory allocated to constructor.
    ///
    /// - `c`: logical context.
    /// - `constr`: constructor.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_constructor`]
    pub fn Z3_del_constructor(c: Z3_context, constr: Z3_constructor);

    /// Create datatype, such as lists, trees, records, enumerations or unions of records.
    /// The datatype may be recursive. Return the datatype sort.
    ///
    /// - `c`: logical context.
    /// - `name`: name of datatype.
    /// - `num_constructors`: number of constructors passed in.
    /// - `constructors`: array of constructor containers.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_constructor`]
    /// - [`Z3_mk_constructor_list`]
    /// - [`Z3_mk_datatypes`]
    pub fn Z3_mk_datatype(
        c: Z3_context,
        name: Z3_symbol,
        num_constructors: ::core::ffi::c_uint,
        constructors: *mut Z3_constructor,
    ) -> Option<Z3_sort>;

    /// Create list of constructors.
    ///
    /// - `c`: logical context.
    /// - `num_constructors`: number of constructors in list.
    /// - `constructors`: list of constructors.
    ///
    /// # See also:
    ///
    /// - [`Z3_del_constructor_list`]
    /// - [`Z3_mk_constructor`]
    pub fn Z3_mk_constructor_list(
        c: Z3_context,
        num_constructors: ::core::ffi::c_uint,
        constructors: *const Z3_constructor,
    ) -> Option<Z3_constructor_list>;

    /// Reclaim memory allocated for constructor list.
    ///
    /// Each constructor inside the constructor list must be independently reclaimed using [`Z3_del_constructor`].
    ///
    /// - `c`: logical context.
    /// - `clist`: constructor list container.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_constructor_list`]
    pub fn Z3_del_constructor_list(c: Z3_context, clist: Z3_constructor_list);

    /// Create mutually recursive datatypes.
    ///
    /// - `c`: logical context.
    /// - `num_sorts`: number of datatype sorts.
    /// - `sort_names`: names of datatype sorts.
    /// - `sorts`: array of datatype sorts.
    /// - `constructor_lists`: list of constructors, one list per sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_constructor`]
    /// - [`Z3_mk_constructor_list`]
    /// - [`Z3_mk_datatype`]
    pub fn Z3_mk_datatypes(
        c: Z3_context,
        num_sorts: ::core::ffi::c_uint,
        sort_names: *const Z3_symbol,
        sorts: *mut Z3_sort,
        constructor_lists: *mut Z3_constructor_list,
    );

    /// Query constructor for declared functions.
    ///
    /// - `c`: logical context.
    /// - `constr`: constructor container. The container must have been passed in to a [`Z3_mk_datatype`] call.
    /// - `num_fields`: number of accessor fields in the constructor.
    /// - `constructor`: constructor function declaration, allocated by user.
    /// - `tester`: constructor test function declaration, allocated by user.
    /// - `accessors`: array of accessor function declarations allocated by user. The array must contain `num_fields` elements.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_constructor`]
    pub fn Z3_query_constructor(
        c: Z3_context,
        constr: Z3_constructor,
        num_fields: ::core::ffi::c_uint,
        constructor: *mut *mut _Z3_func_decl,
        tester: *mut *mut _Z3_func_decl,
        accessors: *mut *mut _Z3_func_decl,
    );

    /// Declare a constant or function.
    ///
    /// - `c`: logical context.
    /// - `s`: name of the constant or function.
    /// - `domain_size`: number of arguments. It is 0 when declaring a constant.
    /// - `domain`: array containing the sort of each argument. The array must contain `domain_size` elements. It is 0 when declaring a constant.
    /// - `range`: sort of the constant or the return sort of the function.
    ///
    /// After declaring a constant or function, the function
    /// [`Z3_mk_app`] can be used to create a constant or function
    /// application.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_app`]
    /// - [`Z3_mk_fresh_func_decl`]
    /// - [`Z3_mk_rec_func_decl`]
    pub fn Z3_mk_func_decl(
        c: Z3_context,
        s: Z3_symbol,
        domain_size: ::core::ffi::c_uint,
        domain: *const Z3_sort,
        range: Z3_sort,
    ) -> Option<Z3_func_decl>;

    /// Create a constant or function application.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fresh_func_decl`]
    /// - [`Z3_mk_func_decl`]
    /// - [`Z3_mk_rec_func_decl`]
    pub fn Z3_mk_app(
        c: Z3_context,
        d: Z3_func_decl,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Declare and create a constant.
    ///
    /// This function is a shorthand for:
    ///
    /// ```c
    /// Z3_func_decl d = Z3_mk_func_decl(c, s, 0, 0, ty);
    /// Z3_ast n             = Z3_mk_app(c, d, 0, 0);
    /// ```
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_app`]
    /// - [`Z3_mk_fresh_const`]
    /// - [`Z3_mk_func_decl`]
    pub fn Z3_mk_const(c: Z3_context, s: Z3_symbol, ty: Z3_sort) -> Option<Z3_ast>;

    /// Declare a fresh constant or function.
    ///
    /// Z3 will generate an unique name for this function declaration.
    /// If prefix is different from `NULL`, then the name generate by Z3 will start with `prefix`.
    ///
    /// NOTE: If `prefix` is `NULL`, then it is assumed to be the empty string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_func_decl`]
    pub fn Z3_mk_fresh_func_decl(
        c: Z3_context,
        prefix: Z3_string,
        domain_size: ::core::ffi::c_uint,
        domain: *const Z3_sort,
        range: Z3_sort,
    ) -> Option<Z3_func_decl>;

    /// Declare and create a fresh constant.
    ///
    /// This function is a shorthand for:
    /// ```c
    /// Z3_func_decl d = Z3_mk_fresh_func_decl(c, prefix, 0, 0, ty);
    /// Z3_ast n = Z3_mk_app(c, d, 0, 0);
    /// ```
    ///
    /// NOTE: If `prefix` is `NULL`, then it is assumed to be the empty string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_app`]
    /// - [`Z3_mk_const`]
    /// - [`Z3_mk_fresh_func_decl`]
    /// - [`Z3_mk_func_decl`]
    pub fn Z3_mk_fresh_const(c: Z3_context, prefix: Z3_string, ty: Z3_sort) -> Option<Z3_ast>;

    /// Declare a recursive function
    ///
    /// * `c`: logical context.
    /// * `s`: name of the function.
    /// * `domain_size`: number of arguments. It should be greater than 0.
    /// * `domain`: array containing the sort of each argument. The array must contain `domain_size` elements.
    /// * `range`: sort of the constant or the return sort of the function.
    ///
    /// After declaring recursive function, it should be associated with a
    /// recursive definition with [`Z3_add_rec_def`]. The function
    /// [`Z3_mk_app`] can be used to create a constant or function
    /// application.
    ///
    /// # See also:
    ///
    /// * [`Z3_add_rec_def`]
    /// * [`Z3_mk_app`]
    /// * [`Z3_mk_func_decl`]
    pub fn Z3_mk_rec_func_decl(
        c: Z3_context,
        s: Z3_symbol,
        domain_size: ::core::ffi::c_uint,
        domain: *const Z3_sort,
        range: Z3_sort,
    ) -> Option<Z3_func_decl>;

    /// Define the body of a recursive function.
    ///
    /// * `c`: logical context.
    /// * `f`: function declaration.
    /// * `n`: number of arguments to the function
    /// * `args`: constants that are used as arguments to the recursive function in the definition.
    /// * `body`: body of the recursive function
    ///
    /// After declaring a recursive function or a collection of  mutually recursive functions, use
    /// this function to provide the definition for the recursive function.
    ///
    /// # See also:
    ///
    /// * [`Z3_mk_rec_func_decl`]
    pub fn Z3_add_rec_def(
        c: Z3_context,
        f: Z3_func_decl,
        n: ::core::ffi::c_uint,
        args: *mut Z3_ast,
        body: Z3_ast,
    );

    /// Create a `FuncDecl` representing a partial order
    pub fn Z3_mk_partial_order(c: Z3_context, a: Z3_sort, id: usize) -> Option<Z3_func_decl>;

    /// Create a `FuncDecl` representing a piecewise linear order
    pub fn Z3_mk_piecewise_linear_order(
        c: Z3_context,
        a: Z3_sort,
        id: usize,
    ) -> Option<Z3_func_decl>;

    /// Create a `FuncDecl` representing a linear order
    pub fn Z3_mk_linear_order(c: Z3_context, a: Z3_sort, id: usize) -> Option<Z3_func_decl>;

    /// Create a `FuncDecl` representing a tree order
    pub fn Z3_mk_tree_order(c: Z3_context, a: Z3_sort, id: usize) -> Option<Z3_func_decl>;

    /// Create a `FuncDecl` representing a transitive closure
    pub fn Z3_mk_transitive_closure(c: Z3_context, f: Z3_func_decl) -> Option<Z3_func_decl>;

    /// Create an AST node representing `true`.
    pub fn Z3_mk_true(c: Z3_context) -> Option<Z3_ast>;

    /// Create an AST node representing `false`.
    pub fn Z3_mk_false(c: Z3_context) -> Option<Z3_ast>;

    /// Create an AST node representing `l = r`.
    ///
    /// The nodes `l` and `r` must have the same type.
    pub fn Z3_mk_eq(c: Z3_context, l: Z3_ast, r: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `distinct(args[0], ..., args[num_args-1])`.
    ///
    /// The `distinct` construct is used for declaring the arguments pairwise distinct.
    /// That is, `Forall 0 <= i < j < num_args. not args[i] = args[j]`.
    ///
    /// All arguments must have the same sort.
    ///
    /// NOTE: The number of arguments of a distinct construct must be greater than one.
    pub fn Z3_mk_distinct(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `not(a)`.
    ///
    /// The node `a` must have Boolean sort.
    pub fn Z3_mk_not(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing an if-then-else: `ite(t1, t2, t3)`.
    ///
    /// The node `t1` must have Boolean sort, `t2` and `t3` must have the same sort.
    /// The sort of the new node is equal to the sort of `t2` and `t3`.
    pub fn Z3_mk_ite(c: Z3_context, t1: Z3_ast, t2: Z3_ast, t3: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `t1 iff t2`.
    ///
    /// The nodes `t1` and `t2` must have Boolean sort.
    pub fn Z3_mk_iff(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `t1 implies t2`.
    ///
    /// The nodes `t1` and `t2` must have Boolean sort.
    pub fn Z3_mk_implies(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `t1 xor t2`.
    ///
    /// The nodes `t1` and `t2` must have Boolean sort.
    pub fn Z3_mk_xor(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `args[0] and ... and args[num_args-1]`.
    ///
    /// The array `args` must have `num_args` elements.
    /// All arguments must have Boolean sort.
    ///
    /// NOTE: The number of arguments must be greater than zero.
    pub fn Z3_mk_and(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `args[0] or ... or args[num_args-1]`.
    ///
    /// The array `args` must have `num_args` elements.
    /// All arguments must have Boolean sort.
    ///
    /// NOTE: The number of arguments must be greater than zero.
    pub fn Z3_mk_or(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `args[0] + ... + args[num_args-1]`.
    ///
    /// The array `args` must have `num_args` elements.
    /// All arguments must have int or real sort.
    ///
    /// NOTE: The number of arguments must be greater than zero.
    pub fn Z3_mk_add(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `args[0] * ... * args[num_args-1]`.
    ///
    /// The array `args` must have `num_args` elements.
    /// All arguments must have int or real sort.
    ///
    /// NOTE: Z3 has limited support for non-linear arithmetic.
    /// NOTE: The number of arguments must be greater than zero.
    pub fn Z3_mk_mul(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `args[0] - ... - args[num_args - 1]`.
    ///
    /// The array `args` must have `num_args` elements.
    /// All arguments must have int or real sort.
    ///
    /// NOTE: The number of arguments must be greater than zero.
    pub fn Z3_mk_sub(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an AST node representing `- arg`.
    ///
    /// The arguments must have int or real type.
    pub fn Z3_mk_unary_minus(c: Z3_context, arg: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `arg1 div arg2`.
    ///
    /// The arguments must either both have int type or both have real type.
    /// If the arguments have int type, then the result type is an int type, otherwise the
    /// the result type is real.
    pub fn Z3_mk_div(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `arg1 mod arg2`.
    ///
    /// The arguments must have int type.
    pub fn Z3_mk_mod(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `arg1 rem arg2`.
    ///
    /// The arguments must have int type.
    pub fn Z3_mk_rem(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create an AST node representing `arg1 ^ arg2`.
    ///
    /// The arguments must have int or real type.
    pub fn Z3_mk_power(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create less than.
    ///
    /// The nodes `t1` and `t2` must have the same sort, and must be int or real.
    pub fn Z3_mk_lt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create less than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same sort, and must be int or real.
    pub fn Z3_mk_le(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create greater than.
    ///
    /// The nodes `t1` and `t2` must have the same sort, and must be int or real.
    pub fn Z3_mk_gt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create greater than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same sort, and must be int or real.
    pub fn Z3_mk_ge(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Coerce an integer to a real.
    ///
    /// There is also a converse operation exposed.
    /// It follows the semantics prescribed by the SMT-LIB standard.
    ///
    /// You can take the floor of a real by
    /// creating an auxiliary integer constant `k` and
    /// and asserting `mk_int2real(k) <= t1 < mk_int2real(k)+1`.
    ///
    /// The node `t1` must have sort integer.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_real2int`]
    /// - [`Z3_mk_is_int`]
    pub fn Z3_mk_int2real(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Coerce a real to an integer.
    ///
    /// The semantics of this function follows the SMT-LIB standard
    /// for the function `to_int`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_int2real`]
    /// - [`Z3_mk_is_int`]
    pub fn Z3_mk_real2int(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Check if a real number is an integer.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_int2real`]
    /// - [`Z3_mk_real2int`]
    pub fn Z3_mk_is_int(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise negation.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_bvnot(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Take conjunction of bits in vector, return vector of length 1.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_bvredand(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Take disjunction of bits in vector, return vector of length 1.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_bvredor(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise and.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvand(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise or.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvor(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise exclusive-or.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvxor(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise nand.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvnand(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise nor.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvnor(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Bitwise xnor.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvxnor(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Standard two's complement unary minus.
    ///
    /// The node `t1` must have bit-vector sort.
    pub fn Z3_mk_bvneg(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Standard two's complement addition.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvadd(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Standard two's complement subtraction.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsub(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Standard two's complement multiplication.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvmul(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned division.
    ///
    /// It is defined as the `floor` of `t1/t2` if `t2` is
    /// different from zero. If `t2` is zero, then the result
    /// is undefined.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvudiv(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed division.
    ///
    /// It is defined in the following way:
    ///
    /// - The `floor` of `t1/t2` if `t2` is different from zero, and `t1*t2 >= 0`.
    ///
    /// - The `ceiling` of `t1/t2` if `t2` is different from zero, and `t1*t2 < 0`.
    ///
    /// If `t2` is zero, then the result is undefined.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsdiv(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned remainder.
    ///
    /// It is defined as `t1 - (t1 /u t2) * t2`, where `/u` represents unsigned division.
    ///
    /// If `t2` is zero, then the result is undefined.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvurem(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed remainder (sign follows dividend).
    ///
    /// It is defined as `t1 - (t1 /s t2) * t2`, where `/s` represents signed division.
    /// The most significant bit (sign) of the result is equal to the most significant bit of `t1`.
    ///
    /// If `t2` is zero, then the result is undefined.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bvsmod`]
    pub fn Z3_mk_bvsrem(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed remainder (sign follows divisor).
    ///
    /// If `t2` is zero, then the result is undefined.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bvsrem`]
    pub fn Z3_mk_bvsmod(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned less than.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvult(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed less than.
    ///
    /// It abbreviates:
    /// ```text
    /// (or (and (= (extract[|m-1|:|m-1|] t1) bit1)
    /// (= (extract[|m-1|:|m-1|] t2) bit0))
    /// (and (= (extract[|m-1|:|m-1|] t1) (extract[|m-1|:|m-1|] t2))
    /// (bvult t1 t2)))
    /// ```
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvslt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned less than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvule(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed less than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsle(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned greater than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvuge(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed greater than or equal to.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsge(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Unsigned greater than.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvugt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Two's complement signed greater than.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsgt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Concatenate the given bit-vectors.
    ///
    /// The nodes `t1` and `t2` must have (possibly different) bit-vector sorts
    ///
    /// The result is a bit-vector of size `n1+n2`, where `n1` (`n2`) is the size
    /// of `t1` (`t2`).
    pub fn Z3_mk_concat(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Extract the bits `high` down to `low` from a bit-vector of
    /// size `m` to yield a new bit-vector of size `n`, where `n = high - low + 1`.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_extract(
        c: Z3_context,
        high: ::core::ffi::c_uint,
        low: ::core::ffi::c_uint,
        t1: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Sign-extend of the given bit-vector to the (signed) equivalent bit-vector of
    /// size `m+i`, where `m` is the size of the given
    /// bit-vector.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_sign_ext(c: Z3_context, i: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Extend the given bit-vector with zeros to the (unsigned) equivalent
    /// bit-vector of size `m+i`, where `m` is the size of the
    /// given bit-vector.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_zero_ext(c: Z3_context, i: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Repeat the given bit-vector up length `i`.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_repeat(c: Z3_context, i: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Shift left.
    ///
    /// It is equivalent to multiplication by `2^x` where `x` is the value of the
    /// third argument.
    ///
    /// NB. The semantics of shift operations varies between environments. This
    /// definition does not necessarily capture directly the semantics of the
    /// programming language or assembly architecture you are modeling.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvshl(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Logical shift right.
    ///
    /// It is equivalent to unsigned division by `2^x` where `x` is the
    /// value of the third argument.
    ///
    /// NB. The semantics of shift operations varies between environments. This
    /// definition does not necessarily capture directly the semantics of the
    /// programming language or assembly architecture you are modeling.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvlshr(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Arithmetic shift right.
    ///
    /// It is like logical shift right except that the most significant
    /// bits of the result always copy the most significant bit of the
    /// second argument.
    ///
    /// The semantics of shift operations varies between environments. This
    /// definition does not necessarily capture directly the semantics of the
    /// programming language or assembly architecture you are modeling.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvashr(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Rotate bits of `t1` to the left `i` times.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_rotate_left(c: Z3_context, i: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Rotate bits of `t1` to the right `i` times.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_rotate_right(c: Z3_context, i: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Rotate bits of `t1` to the left `t2` times.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_ext_rotate_left(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Rotate bits of `t1` to the right `t2` times.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_ext_rotate_right(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create an `n` bit bit-vector from the integer argument `t1`.
    ///
    /// The resulting bit-vector has `n` bits, where the i'th bit (counting
    /// from `0` to `n-1`) is `1` if `(t1 div 2^i) mod 2` is `1`.
    ///
    /// The node `t1` must have integer sort.
    pub fn Z3_mk_int2bv(c: Z3_context, n: ::core::ffi::c_uint, t1: Z3_ast) -> Option<Z3_ast>;

    /// Create an integer from the bit-vector argument `t1`.
    /// If `is_signed` is false, then the bit-vector `t1` is treated as unsigned.
    /// So the result is non-negative
    /// and in the range `[0..2^N-1]`, where N are the number of bits in `t1`.
    /// If `is_signed` is true, `t1` is treated as a signed bit-vector.
    ///
    /// The node `t1` must have a bit-vector sort.
    pub fn Z3_mk_bv2int(c: Z3_context, t1: Z3_ast, is_signed: bool) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise addition
    /// of `t1` and `t2` does not overflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvadd_no_overflow(
        c: Z3_context,
        t1: Z3_ast,
        t2: Z3_ast,
        is_signed: bool,
    ) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise signed addition
    /// of `t1` and `t2` does not underflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvadd_no_underflow(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise signed subtraction
    /// of `t1` and `t2` does not overflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsub_no_overflow(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise subtraction
    /// of `t1` and `t2` does not underflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsub_no_underflow(
        c: Z3_context,
        t1: Z3_ast,
        t2: Z3_ast,
        is_signed: bool,
    ) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise signed division
    /// of `t1` and `t2` does not overflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvsdiv_no_overflow(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Check that bit-wise negation does not overflow when
    /// `t1` is interpreted as a signed bit-vector.
    ///
    /// The node `t1` must have bit-vector sort.
    pub fn Z3_mk_bvneg_no_overflow(c: Z3_context, t1: Z3_ast) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise multiplication
    /// of `t1` and `t2` does not overflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvmul_no_overflow(
        c: Z3_context,
        t1: Z3_ast,
        t2: Z3_ast,
        is_signed: bool,
    ) -> Option<Z3_ast>;

    /// Create a predicate that checks that the bit-wise signed multiplication
    /// of `t1` and `t2` does not underflow.
    ///
    /// The nodes `t1` and `t2` must have the same bit-vector sort.
    pub fn Z3_mk_bvmul_no_underflow(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Array read.
    /// The argument `a` is the array and `i` is the index of the array that gets read.
    ///
    /// The node `a` must have an array sort `[domain -> range]`,
    /// and `i` must have the sort `domain`.
    /// The sort of the result is `range`.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_array_sort`]
    /// - [`Z3_mk_store`]
    pub fn Z3_mk_select(c: Z3_context, a: Z3_ast, i: Z3_ast) -> Option<Z3_ast>;

    /// n-ary Array read.
    /// The argument `a` is the array and `idxs` are the indices of the array that gets read.
    pub fn Z3_mk_select_n(
        c: Z3_context,
        a: Z3_ast,
        n: ::core::ffi::c_uint,
        idxs: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Array update.
    ///
    /// The node `a` must have an array sort `[domain -> range]`, `i` must have sort `domain`,
    /// `v` must have sort range. The sort of the result is `[domain -> range]`.
    /// The semantics of this function is given by the theory of arrays described in the SMT-LIB
    /// standard. See <http://smtlib.org/> for more details.
    /// The result of this function is an array that is equal to `a` (with respect to `select`)
    /// on all indices except for `i`, where it maps to `v` (and the `select` of `a` with
    /// respect to `i` may be a different value).
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_array_sort`]
    /// - [`Z3_mk_select`]
    pub fn Z3_mk_store(c: Z3_context, a: Z3_ast, i: Z3_ast, v: Z3_ast) -> Option<Z3_ast>;

    /// n-ary Array update.
    pub fn Z3_mk_store_n(
        c: Z3_context,
        a: Z3_ast,
        n: ::core::ffi::c_uint,
        idxs: *const Z3_ast,
        v: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create the constant array.
    ///
    /// The resulting term is an array, such that a `select` on an arbitrary index
    /// produces the value `v`.
    ///
    /// - `c`: logical context.
    /// - `domain`: domain sort for the array.
    /// - `v`: value that the array maps to.
    pub fn Z3_mk_const_array(c: Z3_context, domain: Z3_sort, v: Z3_ast) -> Option<Z3_ast>;

    /// Map f on the argument arrays.
    ///
    /// The `n` nodes `args` must be of array sorts `[domain_i -> range_i]`.
    /// The function declaration `f` must have type `range_1 .. range_n -> range`.
    /// `v` must have sort range. The sort of the result is `[domain_i -> range]`.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_array_sort`]
    /// - [`Z3_mk_store`]
    /// - [`Z3_mk_select`]
    pub fn Z3_mk_map(
        c: Z3_context,
        f: Z3_func_decl,
        n: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Access the array default value.
    /// Produces the default range value, for arrays that can be represented as
    /// finite maps with a default range value.
    ///
    /// - `c`: logical context.
    /// - `array`: array value whose default range value is accessed.
    pub fn Z3_mk_array_default(c: Z3_context, array: Z3_ast) -> Option<Z3_ast>;

    /// Create array with the same interpretation as a function.
    /// The array satisfies the property (f x) = (select (_ as-array f) x)
    /// for every argument x.
    pub fn Z3_mk_as_array(c: Z3_context, f: Z3_func_decl) -> Option<Z3_ast>;

    /// Create Set type.
    pub fn Z3_mk_set_sort(c: Z3_context, ty: Z3_sort) -> Option<Z3_sort>;

    /// Create the empty set.
    pub fn Z3_mk_empty_set(c: Z3_context, domain: Z3_sort) -> Option<Z3_ast>;

    /// Create the full set.
    pub fn Z3_mk_full_set(c: Z3_context, domain: Z3_sort) -> Option<Z3_ast>;

    /// Add an element to a set.
    ///
    /// The first argument must be a set, the second an element.
    pub fn Z3_mk_set_add(c: Z3_context, set: Z3_ast, elem: Z3_ast) -> Option<Z3_ast>;

    /// Remove an element to a set.
    ///
    /// The first argument must be a set, the second an element.
    pub fn Z3_mk_set_del(c: Z3_context, set: Z3_ast, elem: Z3_ast) -> Option<Z3_ast>;

    /// Take the union of a list of sets.
    pub fn Z3_mk_set_union(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Take the intersection of a list of sets.
    pub fn Z3_mk_set_intersect(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Take the set difference between two sets.
    pub fn Z3_mk_set_difference(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Take the complement of a set.
    pub fn Z3_mk_set_complement(c: Z3_context, arg: Z3_ast) -> Option<Z3_ast>;

    /// Check for set membership.
    ///
    /// The first argument should be an element type of the set.
    pub fn Z3_mk_set_member(c: Z3_context, elem: Z3_ast, set: Z3_ast) -> Option<Z3_ast>;

    /// Check for subsetness of sets.
    pub fn Z3_mk_set_subset(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create array extensionality index given two arrays with the same sort.
    /// The meaning is given by the axiom:
    /// (=> (= (select A (array-ext A B)) (select B (array-ext A B))) (= A B))
    pub fn Z3_mk_array_ext(c: Z3_context, arg1: Z3_ast, arg2: Z3_ast) -> Option<Z3_ast>;

    /// Create a numeral of a given sort.
    ///
    /// - `c`: logical context.
    /// - `numeral`: A string representing the numeral value in decimal notation. The string may be of the form `[num]*[.[num]*][E[+|-][num]+]`.
    ///   If the given sort is a real, then the numeral can be a rational, that is, a string of the form `[num]* / [num]*` .
    /// - `ty`: The sort of the numeral. In the current implementation, the given sort can be an int, real, finite-domain, or bit-vectors of arbitrary size.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_int`]
    /// - [`Z3_mk_unsigned_int`]
    pub fn Z3_mk_numeral(c: Z3_context, numeral: Z3_string, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a real from a fraction.
    ///
    /// - `c`: logical context.
    /// - `num`: numerator of rational.
    /// - `den`: denominator of rational.
    ///
    /// # Preconditions:
    ///
    /// - `den != 0`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    /// - [`Z3_mk_int`]
    /// - [`Z3_mk_unsigned_int`]
    pub fn Z3_mk_real(
        c: Z3_context,
        num: ::core::ffi::c_int,
        den: ::core::ffi::c_int,
    ) -> Option<Z3_ast>;

    /// Create a numeral of an int, bit-vector, or finite-domain sort.
    ///
    /// This function can be use to create numerals that fit in a machine integer.
    /// It is slightly faster than [`Z3_mk_numeral`] since it is not necessary to parse a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_int(c: Z3_context, v: ::core::ffi::c_int, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a numeral of a int, bit-vector, or finite-domain sort.
    ///
    /// This function can be use to create numerals that fit in a machine unsigned integer.
    /// It is slightly faster than [`Z3_mk_numeral`] since it is not necessary to parse a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_unsigned_int(c: Z3_context, v: ::core::ffi::c_uint, ty: Z3_sort)
    -> Option<Z3_ast>;

    /// Create a numeral of a int, bit-vector, or finite-domain sort.
    ///
    /// This function can be use to create numerals that fit in a machine `int64_t` integer.
    /// It is slightly faster than [`Z3_mk_numeral`] since it is not necessary to parse a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_int64(c: Z3_context, v: i64, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a numeral of a int, bit-vector, or finite-domain sort.
    ///
    /// This function can be use to create numerals that fit in a machine `uint64_t` integer.
    /// It is slightly faster than [`Z3_mk_numeral`] since it is not necessary to parse a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_unsigned_int64(c: Z3_context, v: u64, ty: Z3_sort) -> Option<Z3_ast>;

    /// create a bit-vector numeral from a vector of Booleans.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_bv_numeral(
        c: Z3_context,
        sz: ::core::ffi::c_uint,
        bits: *const bool,
    ) -> Option<Z3_ast>;

    /// Create a sequence sort out of the sort for the elements.
    pub fn Z3_mk_seq_sort(c: Z3_context, s: Z3_sort) -> Option<Z3_sort>;

    /// Check if `s` is a sequence sort.
    pub fn Z3_is_seq_sort(c: Z3_context, s: Z3_sort) -> bool;

    /// Create a regular expression sort out of a sequence sort.
    pub fn Z3_mk_re_sort(c: Z3_context, seq: Z3_sort) -> Option<Z3_sort>;

    /// Check if `s` is a regular expression sort.
    pub fn Z3_is_re_sort(c: Z3_context, s: Z3_sort) -> bool;

    /// Create a sort for 8 bit strings.
    ///
    /// This function creates a sort for ASCII strings.
    /// Each character is 8 bits.
    pub fn Z3_mk_string_sort(c: Z3_context) -> Option<Z3_sort>;

    /// Check if `s` is a string sort.
    pub fn Z3_is_string_sort(c: Z3_context, s: Z3_sort) -> bool;

    /// Create a string constant out of the string that is passed in
    pub fn Z3_mk_string(c: Z3_context, s: Z3_string) -> Option<Z3_ast>;

    /// Determine if `s` is a string constant.
    pub fn Z3_is_string(c: Z3_context, s: Z3_ast) -> bool;

    /// Retrieve the string constant stored in `s`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_is_string(c, s)`
    pub fn Z3_get_string(c: Z3_context, s: Z3_ast) -> Z3_string;

    /// Create an empty sequence of the sequence sort `seq`.
    ///
    /// # Preconditions:
    ///
    /// - `s` is a sequence sort.
    pub fn Z3_mk_seq_empty(c: Z3_context, seq: Z3_sort) -> Option<Z3_ast>;

    /// Create a unit sequence of `a`.
    pub fn Z3_mk_seq_unit(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Concatenate sequences.
    ///
    /// # Preconditions:
    ///
    /// - `n > 0`
    pub fn Z3_mk_seq_concat(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Check if `prefix` is a prefix of `s`.
    ///
    /// # Preconditions:
    ///
    /// - `prefix` and `s` are the same sequence sorts.
    pub fn Z3_mk_seq_prefix(c: Z3_context, prefix: Z3_ast, s: Z3_ast) -> Option<Z3_ast>;

    /// Check if `suffix` is a suffix of `s`.
    ///
    /// # Preconditions:
    ///
    /// - `suffix` and `s` are the same sequence sorts.
    pub fn Z3_mk_seq_suffix(c: Z3_context, suffix: Z3_ast, s: Z3_ast) -> Option<Z3_ast>;

    /// Check if `container` contains `containee`.
    ///
    /// # Preconditions:
    ///
    /// - `container` and `containee` are the same sequence sorts.
    pub fn Z3_mk_seq_contains(
        c: Z3_context,
        container: Z3_ast,
        containee: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Extract subsequence starting at `offset` of `length`.
    pub fn Z3_mk_seq_extract(
        c: Z3_context,
        s: Z3_ast,
        offset: Z3_ast,
        length: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Replace the first occurrence of `src` with `dst` in `s`.
    pub fn Z3_mk_seq_replace(c: Z3_context, s: Z3_ast, src: Z3_ast, dst: Z3_ast) -> Option<Z3_ast>;

    /// Retrieve from `s` the unit sequence positioned at position `index`.
    pub fn Z3_mk_seq_at(c: Z3_context, s: Z3_ast, index: Z3_ast) -> Option<Z3_ast>;

    /// Retrieve from `s` the element positioned at position `index`.
    /// The function is under-specified if the index is out of bounds.
    pub fn Z3_mk_seq_nth(c: Z3_context, s: Z3_ast, index: Z3_ast) -> Option<Z3_ast>;

    /// Return the length of the sequence `s`.
    pub fn Z3_mk_seq_length(c: Z3_context, s: Z3_ast) -> Option<Z3_ast>;

    /// Return index of first occurrence of `substr` in `s` starting from offset `offset`.
    /// If `s` does not contain `substr`, then the value is -1, if `offset` is the length of `s`, then the value is -1 as well.
    /// The function is under-specified if `offset` is negative or larger than the length of `s`.
    pub fn Z3_mk_seq_index(
        c: Z3_context,
        s: Z3_ast,
        substr: Z3_ast,
        offset: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Convert string to integer.
    pub fn Z3_mk_str_to_int(c: Z3_context, s: Z3_ast) -> Option<Z3_ast>;

    /// Integer to string conversion.
    pub fn Z3_mk_int_to_str(c: Z3_context, s: Z3_ast) -> Option<Z3_ast>;

    /// Create a regular expression that accepts the sequence `seq`.
    pub fn Z3_mk_seq_to_re(c: Z3_context, seq: Z3_ast) -> Option<Z3_ast>;

    /// Check if `seq` is in the language generated by the regular expression `re`.
    pub fn Z3_mk_seq_in_re(c: Z3_context, seq: Z3_ast, re: Z3_ast) -> Option<Z3_ast>;

    /// Create the regular language `re+`.
    pub fn Z3_mk_re_plus(c: Z3_context, re: Z3_ast) -> Option<Z3_ast>;

    /// Create the regular language `re*`.
    pub fn Z3_mk_re_star(c: Z3_context, re: Z3_ast) -> Option<Z3_ast>;

    /// Create the regular language `re?`.
    pub fn Z3_mk_re_option(c: Z3_context, re: Z3_ast) -> Option<Z3_ast>;

    /// Create the union of the regular languages.
    ///
    /// # Preconditions:
    ///
    /// - `n > 0`
    pub fn Z3_mk_re_union(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create the concatenation of the regular languages.
    ///
    /// # Preconditions:
    ///
    /// - `n > 0`
    pub fn Z3_mk_re_concat(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create the range regular expression over two sequences of length 1.
    pub fn Z3_mk_re_range(c: Z3_context, lo: Z3_ast, hi: Z3_ast) -> Option<Z3_ast>;

    /// Create a regular expression that accepts all singleton sequences of the regular expression sort.
    ///
    /// Requires Z3 4.8.13 or later.
    pub fn Z3_mk_re_allchar(c: Z3_context, regex_sort: Z3_sort) -> Option<Z3_ast>;

    /// Create a regular expression loop. The supplied regular expression `r` is repeated
    /// between `lo` and `hi` times. The `lo` should be below `hi` with one execution: when
    /// supplying the value `hi` as 0, the meaning is to repeat the argument `r` at least
    /// `lo` number of times, and with an unbounded upper bound.
    pub fn Z3_mk_re_loop(
        c: Z3_context,
        r: Z3_ast,
        lo: ::core::ffi::c_uint,
        hi: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Create a power regular expression.
    ///
    /// Requires Z3 4.8.15 or later.
    pub fn Z3_mk_re_power(c: Z3_context, re: Z3_ast, n: ::core::ffi::c_uint) -> Option<Z3_ast>;

    /// Create the intersection of the regular languages.
    ///
    /// # Preconditions:
    ///
    /// - `n > 0`
    pub fn Z3_mk_re_intersect(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create the complement of the regular language `re`.
    pub fn Z3_mk_re_complement(c: Z3_context, re: Z3_ast) -> Option<Z3_ast>;

    /// Create the difference of regular expressions.
    ///
    /// Requires Z3 4.8.14 or later.
    pub fn Z3_mk_re_diff(c: Z3_context, re1: Z3_ast, re2: Z3_ast) -> Option<Z3_ast>;

    /// Create an empty regular expression of sort `re`.
    ///
    /// # Preconditions:
    ///
    /// - `re` is a regular expression sort.
    pub fn Z3_mk_re_empty(c: Z3_context, re: Z3_sort) -> Option<Z3_ast>;

    /// Create an universal regular expression of sort `re`.
    ///
    /// # Preconditions:
    ///
    /// - `re` is a regular expression sort.
    pub fn Z3_mk_re_full(c: Z3_context, re: Z3_sort) -> Option<Z3_ast>;

    /// Create a pattern for quantifier instantiation.
    ///
    /// Z3 uses pattern matching to instantiate quantifiers. If a
    /// pattern is not provided for a quantifier, then Z3 will
    /// automatically compute a set of patterns for it. However, for
    /// optimal performance, the user should provide the patterns.
    ///
    /// Patterns comprise a list of terms. The list should be
    /// non-empty.  If the list comprises of more than one term, it is
    /// a called a multi-pattern.
    ///
    /// In general, one can pass in a list of (multi-)patterns in the
    /// quantifier constructor.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_exists`]
    pub fn Z3_mk_pattern(
        c: Z3_context,
        num_patterns: ::core::ffi::c_uint,
        terms: *const Z3_ast,
    ) -> Option<Z3_pattern>;

    /// Create a bound variable.
    ///
    /// Bound variables are indexed by de-Bruijn indices. It is perhaps easiest to explain
    /// the meaning of de-Bruijn indices by indicating the compilation process from
    /// non-de-Bruijn formulas to de-Bruijn format.
    ///
    /// ```text
    /// abs(forall (x1) phi) = forall (x1) abs1(phi, x1, 0)
    /// abs(forall (x1, x2) phi) = abs(forall (x1) abs(forall (x2) phi))
    /// abs1(x, x, n) = b_n
    /// abs1(y, x, n) = y
    /// abs1(f(t1,...,tn), x, n) = f(abs1(t1,x,n), ..., abs1(tn,x,n))
    /// abs1(forall (x1) phi, x, n) = forall (x1) (abs1(phi, x, n+1))
    /// ```
    ///
    /// The last line is significant: the index of a bound variable is different depending
    /// on the scope in which it appears. The deeper x appears, the higher is its
    /// index.
    ///
    /// - `c`: logical context
    /// - `index`: de-Bruijn index
    /// - `ty`: sort of the bound variable
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_exists`]
    pub fn Z3_mk_bound(c: Z3_context, index: ::core::ffi::c_uint, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a forall formula. It takes an expression `body` that contains bound variables
    /// of the same sorts as the sorts listed in the array `sorts`. The bound variables are de-Bruijn indices created
    /// using [`Z3_mk_bound`]. The array `decl_names` contains the names that the quantified formula uses for the
    /// bound variables. Z3 applies the convention that the last element in the `decl_names` and `sorts` array
    /// refers to the variable with index 0, the second to last element of `decl_names` and `sorts` refers
    /// to the variable with index 1, etc.
    ///
    /// - `c`: logical context.
    /// - `weight`: quantifiers are associated with weights indicating the importance of using the quantifier during instantiation. By default, pass the weight 0.
    /// - `num_patterns`: number of patterns.
    /// - `patterns`: array containing the patterns created using [`Z3_mk_pattern`].
    /// - `num_decls`: number of variables to be bound.
    /// - `sorts`: the sorts of the bound variables.
    /// - `decl_names`: names of the bound variables
    /// - `body`: the body of the quantifier.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_exists`]
    pub fn Z3_mk_forall(
        c: Z3_context,
        weight: ::core::ffi::c_uint,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        num_decls: ::core::ffi::c_uint,
        sorts: *const Z3_sort,
        decl_names: *const Z3_symbol,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create an exists formula. Similar to [`Z3_mk_forall`].
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_quantifier`]
    pub fn Z3_mk_exists(
        c: Z3_context,
        weight: ::core::ffi::c_uint,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        num_decls: ::core::ffi::c_uint,
        sorts: *const Z3_sort,
        decl_names: *const Z3_symbol,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a quantifier - universal or existential, with pattern hints.
    /// See the documentation for [`Z3_mk_forall`] for an explanation of the parameters.
    ///
    /// - `c`: logical context.
    /// - `is_forall`: flag to indicate if this is a universal or existential quantifier.
    /// - `weight`: quantifiers are associated with weights indicating the importance of using the quantifier during instantiation. By default, pass the weight 0.
    /// - `num_patterns`: number of patterns.
    /// - `patterns`: array containing the patterns created using [`Z3_mk_pattern`]
    /// - `num_decls`: number of variables to be bound.
    /// - `sorts`: array of sorts of the bound variables.
    /// - `decl_names`: names of the bound variables.
    /// - `body`: the body of the quantifier.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_exists`]
    pub fn Z3_mk_quantifier(
        c: Z3_context,
        is_forall: bool,
        weight: ::core::ffi::c_uint,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        num_decls: ::core::ffi::c_uint,
        sorts: *const Z3_sort,
        decl_names: *const Z3_symbol,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a quantifier - universal or existential, with pattern hints, no patterns, and attributes
    ///
    /// - `c`: logical context.
    /// - `is_forall`: flag to indicate if this is a universal or existential quantifier.
    /// - `quantifier_id`: identifier to identify quantifier
    /// - `skolem_id`: identifier to identify skolem constants introduced by quantifier.
    /// - `weight`: quantifiers are associated with weights indicating the importance of using the quantifier during instantiation. By default, pass the weight 0.
    /// - `num_patterns`: number of patterns.
    /// - `patterns`: array containing the patterns created using [`Z3_mk_pattern`].
    /// - `num_no_patterns`: number of `no_patterns`.
    /// - `no_patterns`: array containing subexpressions to be excluded from inferred patterns.
    /// - `num_decls`: number of variables to be bound.
    /// - `sorts`: array of sorts of the bound variables.
    /// - `decl_names`: names of the bound variables.
    /// - `body`: the body of the quantifier.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_exists`]
    pub fn Z3_mk_quantifier_ex(
        c: Z3_context,
        is_forall: bool,
        weight: ::core::ffi::c_uint,
        quantifier_id: Z3_symbol,
        skolem_id: Z3_symbol,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        num_no_patterns: ::core::ffi::c_uint,
        no_patterns: *const Z3_ast,
        num_decls: ::core::ffi::c_uint,
        sorts: *const Z3_sort,
        decl_names: *const Z3_symbol,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a universal quantifier using a list of constants that
    /// will form the set of bound variables.
    ///
    /// - `c`: logical context.
    /// - `weight`: quantifiers are associated with weights indicating the importance of using
    ///   the quantifier during instantiation. By default, pass the weight 0.
    /// - `num_bound`: number of constants to be abstracted into bound variables.
    /// - `bound`: array of constants to be abstracted into bound variables.
    /// - `num_patterns`: number of patterns.
    /// - `patterns`: array containing the patterns created using [`Z3_mk_pattern`]
    /// - `body`: the body of the quantifier.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_exists_const`]
    pub fn Z3_mk_forall_const(
        c: Z3_context,
        weight: ::core::ffi::c_uint,
        num_bound: ::core::ffi::c_uint,
        bound: *const Z3_app,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Similar to [`Z3_mk_forall_const`].
    ///
    /// Create an existential quantifier using a list of constants that
    /// will form the set of bound variables.
    ///
    /// - `c`: logical context.
    /// - `weight`: quantifiers are associated with weights indicating the importance of using
    ///   the quantifier during instantiation. By default, pass the weight 0.
    /// - `num_bound`: number of constants to be abstracted into bound variables.
    /// - `bound`: array of constants to be abstracted into bound variables.
    /// - `num_patterns`: number of patterns.
    /// - `patterns`: array containing the patterns created using [`Z3_mk_pattern`].
    /// - `body`: the body of the quantifier.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_pattern`]
    /// - [`Z3_mk_forall_const`]
    pub fn Z3_mk_exists_const(
        c: Z3_context,
        weight: ::core::ffi::c_uint,
        num_bound: ::core::ffi::c_uint,
        bound: *const Z3_app,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a universal or existential quantifier using a list of
    /// constants that will form the set of bound variables.
    pub fn Z3_mk_quantifier_const(
        c: Z3_context,
        is_forall: bool,
        weight: ::core::ffi::c_uint,
        num_bound: ::core::ffi::c_uint,
        bound: *const Z3_app,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a universal or existential quantifier using a list of
    /// constants that will form the set of bound variables.
    pub fn Z3_mk_quantifier_const_ex(
        c: Z3_context,
        is_forall: bool,
        weight: ::core::ffi::c_uint,
        quantifier_id: Z3_symbol,
        skolem_id: Z3_symbol,
        num_bound: ::core::ffi::c_uint,
        bound: *const Z3_app,
        num_patterns: ::core::ffi::c_uint,
        patterns: *const Z3_pattern,
        num_no_patterns: ::core::ffi::c_uint,
        no_patterns: *const Z3_ast,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a lambda expression.
    ///
    /// It takes an expression `body` that contains bound variables of
    /// the same sorts as the sorts listed in the array `sorts`. The
    /// bound variables are de-Bruijn indices created using [`Z3_mk_bound`].
    /// The array `decl_names` contains the names that the quantified
    /// formula uses for the bound variables. Z3 applies the convention
    /// that the last element in the `decl_names` and `sorts` array
    /// refers to the variable with index `0`, the second to last element
    /// of `decl_names` and `sorts` refers to the variable with index `1`, etc.
    ///
    /// The sort of the resulting expression is `(Array sorts range)` where
    /// `range` is the sort of `body`. For example, if the lambda binds two
    /// variables of sort `Int` and `Bool`, and the `body` has sort `Real`,
    /// the sort of the expression is `(Array Int Bool Real)`.
    ///
    /// - `c`: logical context
    /// - `num_decls`: number of variables to be bound.
    /// - `sorts`: the sorts of the bound variables.
    /// - `decl_names`: names of the bound variables
    /// - `body`: the body of the lambda expression.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_lambda_const`]
    pub fn Z3_mk_lambda(
        c: Z3_context,
        num_decls: ::core::ffi::c_uint,
        sorts: *const Z3_sort,
        decl_names: *const Z3_symbol,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Create a lambda expression using a list of constants that form the set
    /// of bound variables
    ///
    /// - `c`: logical context.
    /// - `num_bound`: number of constants to be abstracted into bound variables.
    /// - `bound`: array of constants to be abstracted into bound variables.
    /// - `body`: the body of the lambda expression.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bound`]
    /// - [`Z3_mk_forall`]
    /// - [`Z3_mk_lambda`]
    pub fn Z3_mk_lambda_const(
        c: Z3_context,
        num_bound: ::core::ffi::c_uint,
        bound: *const Z3_app,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Return `SymbolKind::Int` if the symbol was constructed
    /// using [`Z3_mk_int_symbol`],
    /// and `SymbolKind::String` if the symbol
    /// was constructed using [`Z3_mk_string_symbol`].
    pub fn Z3_get_symbol_kind(c: Z3_context, s: Z3_symbol) -> SymbolKind;

    /// Return the symbol int value.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_symbol_kind(s) == SymbolKind::Int`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_int_symbol`]
    pub fn Z3_get_symbol_int(c: Z3_context, s: Z3_symbol) -> ::core::ffi::c_int;

    /// Return the symbol name.
    ///
    /// Warning: The returned buffer is statically allocated by Z3. It will
    /// be automatically deallocated when [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to `Z3_get_symbol_string`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_symbol_kind(s) == SymbolKind::String`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_string_symbol`]
    pub fn Z3_get_symbol_string(c: Z3_context, s: Z3_symbol) -> Z3_string;

    /// Return the sort name as a symbol.
    pub fn Z3_get_sort_name(c: Z3_context, d: Z3_sort) -> Option<Z3_symbol>;

    /// Return a unique identifier for `s`.
    pub fn Z3_get_sort_id(c: Z3_context, s: Z3_sort) -> ::core::ffi::c_uint;

    /// Convert a [`Z3_sort`] into [`Z3_ast`]. This is just type casting.
    ///
    /// # See also:
    ///
    /// - [`Z3_app_to_ast`]
    /// - [`Z3_func_decl_to_ast`]
    /// - [`Z3_pattern_to_ast`]
    pub fn Z3_sort_to_ast(c: Z3_context, s: Z3_sort) -> Option<Z3_ast>;

    /// compare sorts.
    pub fn Z3_is_eq_sort(c: Z3_context, s1: Z3_sort, s2: Z3_sort) -> bool;

    /// Return the sort kind (e.g., array, tuple, int, bool, etc).
    ///
    /// # See also:
    ///
    /// - [`SortKind`]
    pub fn Z3_get_sort_kind(c: Z3_context, t: Z3_sort) -> SortKind;

    /// Return the size of the given bit-vector sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, t) == SortKind::BV`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_bv_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_bv_sort_size(c: Z3_context, t: Z3_sort) -> ::core::ffi::c_uint;

    /// Store the size of the sort in `r`. Return `false` if the call failed.
    /// That is, `Z3_get_sort_kind(s) == SortKind::FiniteDomain`
    pub fn Z3_get_finite_domain_sort_size(c: Z3_context, s: Z3_sort, r: *mut u64) -> bool;

    /// Return the domain of the given array sort.
    ///
    /// In the case of a multi-dimensional array, this function
    /// returns the sort of the first dimension.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, t) == SortKind::Array`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_array_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_array_sort_domain(c: Z3_context, t: Z3_sort) -> Option<Z3_sort>;

    /// Return the range of the given array sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, t) == SortKind::Array`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_array_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_array_sort_range(c: Z3_context, t: Z3_sort) -> Option<Z3_sort>;

    /// Return the constructor declaration of the given tuple
    /// sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, t) == SortKind::Datatype`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_tuple_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_tuple_sort_mk_decl(c: Z3_context, t: Z3_sort) -> Option<Z3_func_decl>;

    /// Return the number of fields of the given tuple sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, t) == SortKind::Datatype`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_tuple_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_tuple_sort_num_fields(c: Z3_context, t: Z3_sort) -> ::core::ffi::c_uint;

    /// Return the i-th field declaration (i.e., projection function declaration)
    /// of the given tuple sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(t) == SortKind::Datatype`
    /// - `i < Z3_get_tuple_sort_num_fields(c, t)`
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_tuple_sort`]
    /// - [`Z3_get_sort_kind`]
    pub fn Z3_get_tuple_sort_field_decl(
        c: Z3_context,
        t: Z3_sort,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return number of constructors for datatype.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(t) == SortKind::Datatype`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_datatype_sort_constructor`]
    /// - [`Z3_get_datatype_sort_recognizer`]
    /// - [`Z3_get_datatype_sort_constructor_accessor`]
    pub fn Z3_get_datatype_sort_num_constructors(c: Z3_context, t: Z3_sort) -> ::core::ffi::c_uint;

    /// Return idx'th constructor.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(t) == SortKind::Datatype`
    /// - `idx < Z3_get_datatype_sort_num_constructors(c, t)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_datatype_sort_num_constructors`]
    /// - [`Z3_get_datatype_sort_recognizer`]
    /// - [`Z3_get_datatype_sort_constructor_accessor`]
    pub fn Z3_get_datatype_sort_constructor(
        c: Z3_context,
        t: Z3_sort,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return idx'th recognizer.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(t) == SortKind::Datatype`
    /// - `idx < Z3_get_datatype_sort_num_constructors(c, t)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_datatype_sort_num_constructors`]
    /// - [`Z3_get_datatype_sort_constructor`]
    /// - [`Z3_get_datatype_sort_constructor_accessor`]
    pub fn Z3_get_datatype_sort_recognizer(
        c: Z3_context,
        t: Z3_sort,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return `idx_a`'th accessor for the `idx_c`'th constructor.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(t) == SortKind::Datatype`
    /// - `idx_c < Z3_get_datatype_sort_num_constructors(c, t)`
    /// - `idx_a < Z3_get_domain_size(c, Z3_get_datatype_sort_constructor(c, idx_c))`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_datatype_sort_num_constructors`]
    /// - [`Z3_get_datatype_sort_constructor`]
    /// - [`Z3_get_datatype_sort_recognizer`]
    pub fn Z3_get_datatype_sort_constructor_accessor(
        c: Z3_context,
        t: Z3_sort,
        idx_c: ::core::ffi::c_uint,
        idx_a: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Update record field with a value.
    ///
    /// This corresponds to the 'with' construct in OCaml.
    /// It has the effect of updating a record field with a given value.
    /// The remaining fields are left unchanged. It is the record
    /// equivalent of an array store (see [`Z3_mk_store`]).
    /// If the datatype has more than one constructor, then the update function
    /// behaves as identity if there is a miss-match between the accessor and
    /// constructor. For example ((_ update-field car) nil 1) is nil,
    /// while `((_ update-field car)` (cons 2 nil) 1) is (cons 1 nil).
    ///
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(Z3_get_sort(c, t)) == Z3_get_domain(c, field_access, 1) == SortKind::Datatype`
    /// - `Z3_get_sort(c, value) == Z3_get_range(c, field_access)`
    pub fn Z3_datatype_update_field(
        c: Z3_context,
        field_access: Z3_func_decl,
        t: Z3_ast,
        value: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Return arity of relation.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(s) == SortKind::Relation`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_relation_column`]
    pub fn Z3_get_relation_arity(c: Z3_context, s: Z3_sort) -> ::core::ffi::c_uint;

    /// Return sort at i'th column of relation sort.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_sort_kind(c, s) == SortKind::Relation`
    /// - `col < Z3_get_relation_arity(c, s)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_relation_arity`]
    pub fn Z3_get_relation_column(
        c: Z3_context,
        s: Z3_sort,
        col: ::core::ffi::c_uint,
    ) -> Option<Z3_sort>;

    /// Pseudo-Boolean relations.
    ///
    /// Encode `p1 + p2 + ... + pn <= k`
    pub fn Z3_mk_atmost(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
        k: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Pseudo-Boolean relations.
    ///
    /// Encode `p1 + p2 + ... + pn >= k`
    pub fn Z3_mk_atleast(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
        k: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Pseudo-Boolean relations.
    ///
    /// Encode `k1*p1 + k2*p2 + ... + kn*pn <= k`
    pub fn Z3_mk_pble(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
        coeffs: *const ::core::ffi::c_int,
        k: ::core::ffi::c_int,
    ) -> Option<Z3_ast>;

    /// Pseudo-Boolean relations.
    ///
    /// Encode `k1*p1 + k2*p2 + ... + kn*pn >= k`
    pub fn Z3_mk_pbge(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
        coeffs: *const ::core::ffi::c_int,
        k: ::core::ffi::c_int,
    ) -> Option<Z3_ast>;

    /// Pseudo-Boolean relations.
    ///
    /// Encode `k1*p1 + k2*p2 + ... + kn*pn = k`
    pub fn Z3_mk_pbeq(
        c: Z3_context,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
        coeffs: *const ::core::ffi::c_int,
        k: ::core::ffi::c_int,
    ) -> Option<Z3_ast>;

    /// Convert a [`Z3_func_decl`] into [`Z3_ast`]. This is just type casting.
    ///
    /// # See also:
    ///
    /// - [`Z3_app_to_ast`]
    /// - [`Z3_pattern_to_ast`]
    /// - [`Z3_sort_to_ast`]
    /// - [`Z3_to_func_decl`]
    pub fn Z3_func_decl_to_ast(c: Z3_context, f: Z3_func_decl) -> Option<Z3_ast>;

    /// Compare terms.
    pub fn Z3_is_eq_func_decl(c: Z3_context, f1: Z3_func_decl, f2: Z3_func_decl) -> bool;

    /// Return a unique identifier for `f`.
    pub fn Z3_get_func_decl_id(c: Z3_context, f: Z3_func_decl) -> ::core::ffi::c_uint;

    /// Return the constant declaration name as a symbol.
    pub fn Z3_get_decl_name(c: Z3_context, d: Z3_func_decl) -> Option<Z3_symbol>;

    /// Return declaration kind corresponding to declaration.
    pub fn Z3_get_decl_kind(c: Z3_context, d: Z3_func_decl) -> DeclKind;

    /// Return the number of parameters of the given declaration.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_arity`]
    pub fn Z3_get_domain_size(c: Z3_context, d: Z3_func_decl) -> ::core::ffi::c_uint;

    /// Alias for `Z3_get_domain_size`.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_domain_size`]
    pub fn Z3_get_arity(c: Z3_context, d: Z3_func_decl) -> ::core::ffi::c_uint;

    /// Return the sort of the i-th parameter of the given function declaration.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_get_domain_size(d)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_domain_size`]
    pub fn Z3_get_domain(c: Z3_context, d: Z3_func_decl, i: ::core::ffi::c_uint)
    -> Option<Z3_sort>;

    /// Return the range of the given declaration.
    ///
    /// If `d` is a constant (i.e., has zero arguments), then this
    /// function returns the sort of the constant.
    pub fn Z3_get_range(c: Z3_context, d: Z3_func_decl) -> Option<Z3_sort>;

    /// Return the number of parameters associated with a declaration.
    pub fn Z3_get_decl_num_parameters(c: Z3_context, d: Z3_func_decl) -> ::core::ffi::c_uint;

    /// Return the parameter type associated with a declaration.
    ///
    /// - `c`: the context
    /// - `d`: the function declaration
    /// - `idx`: is the index of the named parameter it should be between 0 and
    ///   the number of parameters.
    pub fn Z3_get_decl_parameter_kind(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> ParameterKind;

    /// Return the integer value associated with an integer parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::Int`
    pub fn Z3_get_decl_int_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> ::core::ffi::c_int;

    /// Return the double value associated with an double parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::Double`
    pub fn Z3_get_decl_double_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> f64;

    /// Return the double value associated with an double parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::Symbol`
    pub fn Z3_get_decl_symbol_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_symbol>;

    /// Return the sort value associated with a sort parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::Sort`
    pub fn Z3_get_decl_sort_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_sort>;

    /// Return the expression value associated with an expression parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::AST`
    pub fn Z3_get_decl_ast_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Return the expression value associated with an expression parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::FuncDecl`
    pub fn Z3_get_decl_func_decl_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return the rational value, as a string, associated with a rational parameter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_decl_parameter_kind(c, d, idx) == ParameterKind::Rational`
    pub fn Z3_get_decl_rational_parameter(
        c: Z3_context,
        d: Z3_func_decl,
        idx: ::core::ffi::c_uint,
    ) -> Z3_string;

    /// Convert a [`Z3_app`] into [`Z3_ast`]. This is just type casting.
    ///
    /// # See also:
    ///
    /// - [`Z3_to_app`]
    /// - [`Z3_func_decl_to_ast`]
    /// - [`Z3_pattern_to_ast`]
    /// - [`Z3_sort_to_ast`]
    pub fn Z3_app_to_ast(c: Z3_context, a: Z3_app) -> Option<Z3_ast>;

    /// Return the declaration of a constant or function application.
    pub fn Z3_get_app_decl(c: Z3_context, a: Z3_app) -> Option<Z3_func_decl>;

    /// Return the number of argument of an application. If `t`
    /// is an constant, then the number of arguments is 0.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_app_arg`]
    pub fn Z3_get_app_num_args(c: Z3_context, a: Z3_app) -> ::core::ffi::c_uint;

    /// Return the i-th argument of the given application.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_get_app_num_args(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_app_num_args`]
    pub fn Z3_get_app_arg(c: Z3_context, a: Z3_app, i: ::core::ffi::c_uint) -> Option<Z3_ast>;

    /// Compare terms.
    pub fn Z3_is_eq_ast(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> bool;

    /// Return a unique identifier for `t`.
    ///
    /// The identifier is unique up to structural equality. Thus, two ast nodes
    /// created by the same context and having the same children and same function symbols
    /// have the same identifiers. Ast nodes created in the same context, but having
    /// different children or different functions have different identifiers.
    /// Variables and quantifiers are also assigned different identifiers according to
    /// their structure.
    pub fn Z3_get_ast_id(c: Z3_context, t: Z3_ast) -> ::core::ffi::c_uint;

    /// Return a hash code for the given AST.
    ///
    /// The hash code is structural. You can use [`Z3_get_ast_id`]
    /// interchangeably with this function.
    pub fn Z3_get_ast_hash(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Return the sort of an AST node.
    ///
    /// The AST node must be a constant, application, numeral, bound variable, or quantifier.
    pub fn Z3_get_sort(c: Z3_context, a: Z3_ast) -> Option<Z3_sort>;

    /// Return true if the given expression `t` is well sorted.
    pub fn Z3_is_well_sorted(c: Z3_context, t: Z3_ast) -> bool;

    /// Return `Z3_L_TRUE` if `a` is true, `Z3_L_FALSE` if it is false,
    /// and `Z3_L_UNDEF` otherwise.
    pub fn Z3_get_bool_value(c: Z3_context, a: Z3_ast) -> Z3_lbool;

    /// Return the kind of the given AST.
    pub fn Z3_get_ast_kind(c: Z3_context, a: Z3_ast) -> AstKind;

    pub fn Z3_is_app(c: Z3_context, a: Z3_ast) -> bool;

    pub fn Z3_is_numeral_ast(c: Z3_context, a: Z3_ast) -> bool;

    /// Return true if the given AST is a real algebraic number.
    pub fn Z3_is_algebraic_number(c: Z3_context, a: Z3_ast) -> bool;

    /// Convert an `ast` into an [`Z3_app`]. This is just type casting.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::App`
    ///
    /// # See also:
    ///
    /// - [`Z3_app_to_ast`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::App`]
    pub fn Z3_to_app(c: Z3_context, a: Z3_ast) -> Option<Z3_app>;

    /// Convert an AST into a [`Z3_func_decl`]. This is just type casting.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::FuncDecl`
    ///
    /// # See also:
    ///
    /// - [`Z3_func_decl_to_ast`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::FuncDecl`]
    pub fn Z3_to_func_decl(c: Z3_context, a: Z3_ast) -> Option<Z3_func_decl>;

    /// Return numeral value, as a string of a numeric constant term
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_string(c: Z3_context, a: Z3_ast) -> Z3_string;

    /// Return numeral as a string in decimal notation.
    /// The result has at most `precision` decimal places.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::Numeral || Z3_is_algebraic_number(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`Z3_is_algebraic_number`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_decimal_string(
        c: Z3_context,
        a: Z3_ast,
        precision: ::core::ffi::c_uint,
    ) -> Z3_string;

    /// Return numeral as a double.
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::Numeral || Z3_is_algebraic_number(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_double(c: Z3_context, a: Z3_ast) -> f64;

    /// Return the numerator (as a numeral AST) of a numeral AST of sort Real.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numerator(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Return the denominator (as a numeral AST) of a numeral AST of sort Real.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, a) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_denominator(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Return numeral value, as a pair of 64 bit numbers if the representation fits.
    ///
    /// - `c`: logical context.
    /// - `a`: term.
    /// - `num`: numerator.
    /// - `den`: denominator.
    ///
    /// Return `true` if the numeral value fits in 64 bit numerals, `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_small(c: Z3_context, a: Z3_ast, num: *mut i64, den: *mut i64) -> bool;

    /// Similar to [`Z3_get_numeral_string`], but only succeeds if
    /// the value can fit in a machine int. Return `true` if the call succeeded.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, v) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_numeral_string`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_int(c: Z3_context, v: Z3_ast, i: *mut ::core::ffi::c_int) -> bool;

    /// Similar to [`Z3_get_numeral_string`], but only succeeds if
    /// the value can fit in a machine unsigned int.
    /// Return `true` if the call succeeded.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, v) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_numeral_string`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_uint(c: Z3_context, v: Z3_ast, u: *mut ::core::ffi::c_uint) -> bool;

    /// Similar to [`Z3_get_numeral_string`] but only succeeds if the
    /// value can fit in a machine `uint64_t` int.
    /// Return `true` if the call succeeded.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, v) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_numeral_string`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_uint64(c: Z3_context, v: Z3_ast, u: *mut u64) -> bool;

    /// Similar to [`Z3_get_numeral_string`], but only succeeds if the
    /// value can fit in a machine `int64_t` int.
    /// Return `true` if the call succeeded.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, v) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_numeral_string`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_int64(c: Z3_context, v: Z3_ast, i: *mut i64) -> bool;

    /// Similar to [`Z3_get_numeral_string`], but only succeeds if the
    /// value can fit as a rational number as
    /// machine `int64_t` int. Return `true` if the call succeeded.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(c, v) == AstKind::Numeral`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_numeral_string`]
    /// - [`Z3_get_ast_kind`]
    /// - [`AstKind::Numeral`]
    pub fn Z3_get_numeral_rational_int64(
        c: Z3_context,
        v: Z3_ast,
        num: *mut i64,
        den: *mut i64,
    ) -> bool;

    /// Return a lower bound for the given real algebraic number.
    ///
    /// The interval isolating the number is smaller than 1/10^precision.
    /// The result is a numeral AST of sort Real.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_is_algebraic_number(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_is_algebraic_number`]
    pub fn Z3_get_algebraic_number_lower(
        c: Z3_context,
        a: Z3_ast,
        precision: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Return an upper bound for the given real algebraic number.
    ///
    /// The interval isolating the number is smaller than 1/10^precision.
    /// The result is a numeral AST of sort Real.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_is_algebraic_number(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_is_algebraic_number`]
    pub fn Z3_get_algebraic_number_upper(
        c: Z3_context,
        a: Z3_ast,
        precision: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Convert a [`Z3_pattern`] into [`Z3_ast`]. This is just type casting.
    ///
    /// # See also:
    ///
    /// - [`Z3_app_to_ast`]
    /// - [`Z3_func_decl_to_ast`]
    /// - [`Z3_sort_to_ast`]
    pub fn Z3_pattern_to_ast(c: Z3_context, p: Z3_pattern) -> Option<Z3_ast>;

    /// Return number of terms in pattern.
    pub fn Z3_get_pattern_num_terms(c: Z3_context, p: Z3_pattern) -> ::core::ffi::c_uint;

    /// Return i'th ast in pattern.
    pub fn Z3_get_pattern(c: Z3_context, p: Z3_pattern, idx: ::core::ffi::c_uint)
    -> Option<Z3_ast>;

    /// Return index of de-Bruijn bound variable.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Var`
    pub fn Z3_get_index_value(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Determine if quantifier is universal.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_is_quantifier_forall(c: Z3_context, a: Z3_ast) -> bool;

    /// Determine if ast is an existential quantifier.
    pub fn Z3_is_quantifier_exists(c: Z3_context, a: Z3_ast) -> bool;

    /// Determine if ast is a lambda expression.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_is_lambda(c: Z3_context, a: Z3_ast) -> bool;

    /// Obtain weight of quantifier.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_weight(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Return number of patterns used in quantifier.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_num_patterns(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Return i'th pattern.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_pattern_ast(
        c: Z3_context,
        a: Z3_ast,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_pattern>;

    /// Return number of `no_patterns` used in quantifier.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_num_no_patterns(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Return i'th `no_pattern`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_no_pattern_ast(
        c: Z3_context,
        a: Z3_ast,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Return number of bound variables of quantifier.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_num_bound(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_uint;

    /// Return symbol of the i'th bound variable.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_bound_name(
        c: Z3_context,
        a: Z3_ast,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_symbol>;

    /// Return sort of the i'th bound variable.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_bound_sort(
        c: Z3_context,
        a: Z3_ast,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_sort>;

    /// Return body of quantifier.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_ast_kind(a) == AstKind::Quantifier`
    pub fn Z3_get_quantifier_body(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Interface to simplifier.
    ///
    /// Provides an interface to the AST simplifier used by Z3.
    /// It returns an AST object which is equal to the argument.
    /// The returned AST is simplified using algebraic simplification rules,
    /// such as constant propagation (propagating true/false over logical connectives).
    ///
    /// # See also:
    ///
    /// - [`Z3_simplify_ex`]
    pub fn Z3_simplify(c: Z3_context, a: Z3_ast) -> Option<Z3_ast>;

    /// Interface to simplifier.
    ///
    /// Provides an interface to the AST simplifier used by Z3.
    /// This procedure is similar to [`Z3_simplify`],
    /// but the behavior of the simplifier can be configured using the
    /// given parameter set.
    ///
    /// # See also:
    ///
    /// - [`Z3_simplify`]
    /// - [`Z3_simplify_get_help`]
    /// - [`Z3_simplify_get_param_descrs`]
    pub fn Z3_simplify_ex(c: Z3_context, a: Z3_ast, p: Z3_params) -> Option<Z3_ast>;

    /// Return a string describing all available parameters.
    ///
    /// # See also:
    ///
    /// - [`Z3_simplify_ex`]
    /// - [`Z3_simplify_get_param_descrs`]
    pub fn Z3_simplify_get_help(c: Z3_context) -> Z3_string;

    /// Return the parameter description set for the simplify procedure.
    ///
    /// # See also:
    ///
    /// - [`Z3_simplify_ex`]
    /// - [`Z3_simplify_get_help`]
    pub fn Z3_simplify_get_param_descrs(c: Z3_context) -> Option<Z3_param_descrs>;

    /// Update the arguments of term `a` using the arguments `args`.
    ///
    /// The number of arguments `num_args` should coincide
    /// with the number of arguments to `a`.
    ///
    /// If `a` is a quantifier, then `num_args` has to be 1.
    pub fn Z3_update_term(
        c: Z3_context,
        a: Z3_ast,
        num_args: ::core::ffi::c_uint,
        args: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Substitute every occurrence of `from[i]` in `a` with `to[i]`, for `i`
    /// smaller than `num_exprs`.
    ///
    /// The result is the new AST. The arrays `from` and `to` must have
    /// size `num_exprs`.
    ///
    /// For every `i` smaller than `num_exprs`, we must have that sort of
    /// `from[i]` must be equal to sort of `to[i]`.
    pub fn Z3_substitute(
        c: Z3_context,
        a: Z3_ast,
        num_exprs: ::core::ffi::c_uint,
        from: *const Z3_ast,
        to: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Substitute the free variables in `a` with the expressions in `to`.
    ///
    /// For every `i` smaller than `num_exprs`, the variable with de-Bruijn
    /// index `i` is replaced with term `to[i]`.
    pub fn Z3_substitute_vars(
        c: Z3_context,
        a: Z3_ast,
        num_exprs: ::core::ffi::c_uint,
        to: *const Z3_ast,
    ) -> Option<Z3_ast>;

    /// Translate/Copy the AST `a` from context `source` to context `target`.
    ///
    /// AST `a` must have been created using context `source`.
    ///
    /// # Preconditions:
    ///
    /// - `source != target`
    pub fn Z3_translate(source: Z3_context, a: Z3_ast, target: Z3_context) -> Option<Z3_ast>;

    /// Create a fresh model object. It has reference count 0.
    pub fn Z3_mk_model(c: Z3_context) -> Option<Z3_model>;

    /// Increment the reference counter of the given model.
    pub fn Z3_model_inc_ref(c: Z3_context, m: Z3_model);

    /// Decrement the reference counter of the given model.
    pub fn Z3_model_dec_ref(c: Z3_context, m: Z3_model);

    /// Evaluate the AST node `t` in the given model.
    /// Return `true` if succeeded, and store the result in `v`.
    ///
    /// If `model_completion` is `true`, then Z3 will assign an
    /// interpretation for any constant or function that does
    /// not have an interpretation in `m`. These constants and
    /// functions were essentially don't cares.
    ///
    /// If `model_completion` is `false`, then Z3 will not assign
    /// interpretations to constants for functions that do not have
    /// interpretations in `m`. Evaluation behaves as the identify
    /// function in this case.
    ///
    /// The evaluation may fail for the following reasons:
    ///
    /// - `t` contains a quantifier.
    /// - the model `m` is partial, that is, it doesn't have a complete
    ///   interpretation for uninterpreted functions. That is, the option
    ///   `MODEL_PARTIAL=true` was used.
    /// - `t` is type incorrect.
    /// - [`Z3_interrupt`] was invoked during evaluation.
    pub fn Z3_model_eval(
        c: Z3_context,
        m: Z3_model,
        t: Z3_ast,
        model_completion: bool,
        v: *mut Z3_ast,
    ) -> bool;

    /// Return the interpretation (i.e., assignment) of constant `a` in the model `m`.
    ///
    /// Return `NULL`, if the model does not assign an interpretation for `a`.
    /// That should be interpreted as: the value of `a` does not matter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_arity(c, a) == 0`
    pub fn Z3_model_get_const_interp(c: Z3_context, m: Z3_model, a: Z3_func_decl)
    -> Option<Z3_ast>;

    /// Test if there exists an interpretation (i.e., assignment) for `a` in the model `m`.
    pub fn Z3_model_has_interp(c: Z3_context, m: Z3_model, a: Z3_func_decl) -> bool;

    /// Return the interpretation of the function `f` in the model `m`.
    ///
    /// Return `NULL`, if the model does not assign an interpretation for `f`.
    /// That should be interpreted as: the `f` does not matter.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_get_arity(c, f) > 0`
    ///
    /// NOTE: Reference counting must be used to manage [`Z3_func_interp`]
    /// objects, even when the `Z3_context` was created using
    /// [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_model_get_func_interp(
        c: Z3_context,
        m: Z3_model,
        f: Z3_func_decl,
    ) -> Option<Z3_func_interp>;

    /// Return the number of constants assigned by the given model.
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_const_decl`]
    pub fn Z3_model_get_num_consts(c: Z3_context, m: Z3_model) -> ::core::ffi::c_uint;

    /// Return the i-th constant in the given model.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_model_get_num_consts(c, m)`
    ///
    /// # See also:
    ///
    /// - [`Z3_model_eval`]
    /// - [`Z3_model_get_num_consts`]
    pub fn Z3_model_get_const_decl(
        c: Z3_context,
        m: Z3_model,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return the number of function interpretations in the given model.
    ///
    /// A function interpretation is represented as a finite map and an 'else' value.
    /// Each entry in the finite map represents the value of a function given a set of arguments.
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_func_decl`]
    pub fn Z3_model_get_num_funcs(c: Z3_context, m: Z3_model) -> ::core::ffi::c_uint;

    /// Return the declaration of the i-th function in the given model.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_model_get_num_funcs(c, m)`
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_num_funcs`]
    pub fn Z3_model_get_func_decl(
        c: Z3_context,
        m: Z3_model,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_func_decl>;

    /// Return the number of uninterpreted sorts that `m` assigns an
    /// interpretation to.
    ///
    /// Z3 also provides an interpretation for uninterpreted sorts used in
    /// a formula. The interpretation for a sort `s` is a finite set of
    /// distinct values. We say this finite set is the "universe" of `s`.
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_sort`]
    /// - [`Z3_model_get_sort_universe`]
    pub fn Z3_model_get_num_sorts(c: Z3_context, m: Z3_model) -> ::core::ffi::c_uint;

    /// Return an uninterpreted sort that `m` assigns an interpretation.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_model_get_num_sorts(c, m)`
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_num_sorts`]
    /// - [`Z3_model_get_sort_universe`]
    pub fn Z3_model_get_sort(c: Z3_context, m: Z3_model, i: ::core::ffi::c_uint)
    -> Option<Z3_sort>;

    /// Return the finite set of distinct values that represent the interpretation for sort `s`.
    ///
    /// # See also:
    ///
    /// - [`Z3_model_get_num_sorts`]
    /// - [`Z3_model_get_sort`]
    pub fn Z3_model_get_sort_universe(
        c: Z3_context,
        m: Z3_model,
        s: Z3_sort,
    ) -> Option<Z3_ast_vector>;

    /// Translate model from context `c` to context `dst`.
    pub fn Z3_model_translate(c: Z3_context, m: Z3_model, dst: Z3_context) -> Option<Z3_model>;

    /// The `(_ as-array f)` AST node is a construct for assigning interpretations
    /// for arrays in Z3.
    ///
    /// It is the array such that forall indices `i` we have that
    /// `(select (_ as-array f) i)` is equal to `(f i)`. This procedure
    /// returns `true` if the `a` is an `as`-array AST node.
    ///
    /// Z3 current solvers have minimal support for `as_array` nodes.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_as_array_func_decl`]
    pub fn Z3_is_as_array(c: Z3_context, a: Z3_ast) -> bool;

    /// Return the function declaration `f` associated with a `(_ as_array f)` node.
    ///
    /// # See also:
    ///
    /// - [`Z3_is_as_array`]
    pub fn Z3_get_as_array_func_decl(c: Z3_context, a: Z3_ast) -> Option<Z3_func_decl>;

    /// Create a fresh `func_interp` object, add it to a model for a specified function.
    /// It has reference count 0.
    ///
    /// - `c`: context
    /// - `m`: model
    /// - `f`: function declaration
    /// - `default_value`: default value for function interpretation
    pub fn Z3_add_func_interp(
        c: Z3_context,
        m: Z3_model,
        f: Z3_func_decl,
        default_value: Z3_ast,
    ) -> Option<Z3_func_interp>;

    /// Add a constant interpretation.
    pub fn Z3_add_const_interp(c: Z3_context, m: Z3_model, f: Z3_func_decl, a: Z3_ast);

    /// Increment the reference counter of the given `Z3_func_interp` object.
    pub fn Z3_func_interp_inc_ref(c: Z3_context, f: Z3_func_interp);

    /// Decrement the reference counter of the given `Z3_func_interp` object.
    pub fn Z3_func_interp_dec_ref(c: Z3_context, f: Z3_func_interp);

    /// Return the number of entries in the given function interpretation.
    ///
    /// A function interpretation is represented as a finite map and
    /// an 'else' value. Each entry in the finite map represents the
    /// value of a function given a set of arguments. This procedure
    /// return the number of element in the finite map of `f`.
    ///
    /// # See also:
    ///
    /// - [`Z3_func_interp_get_entry`]
    pub fn Z3_func_interp_get_num_entries(c: Z3_context, f: Z3_func_interp) -> ::core::ffi::c_uint;

    /// Return a "point" of the given function interpretation. It represents
    /// the value of `f` in a particular point.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_func_interp_get_num_entries(c, f)`
    ///
    /// # See also:
    ///
    /// - [`Z3_func_interp_get_num_entries`]
    pub fn Z3_func_interp_get_entry(
        c: Z3_context,
        f: Z3_func_interp,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_func_entry>;

    /// Return the 'else' value of the given function interpretation.
    ///
    /// A function interpretation is represented as a finite map and an 'else' value.
    /// This procedure returns the 'else' value.
    pub fn Z3_func_interp_get_else(c: Z3_context, f: Z3_func_interp) -> Option<Z3_ast>;

    /// Set the 'else' value of the given function interpretation.
    ///
    /// A function interpretation is represented as a finite map and an 'else' value.
    /// This procedure can be used to update the 'else' value.
    pub fn Z3_func_interp_set_else(c: Z3_context, f: Z3_func_interp, else_value: Z3_ast);

    /// Return the arity (number of arguments) of the given function interpretation.
    pub fn Z3_func_interp_get_arity(c: Z3_context, f: Z3_func_interp) -> ::core::ffi::c_uint;

    /// add a function entry to a function interpretation.
    ///
    /// - `c`: logical context
    /// - `fi`: a function interpretation to be updated.
    /// - `args`: list of arguments. They should be constant values
    ///   (such as integers) and be of the same types as the domain
    ///   of the function.
    /// - `value`: value of the function when the parameters match args.
    ///
    /// It is assumed that entries added to a function cover disjoint
    /// arguments. If an two entries are added with the same arguments,
    /// only the second insertion survives and the first inserted entry
    /// is removed.
    pub fn Z3_func_interp_add_entry(
        c: Z3_context,
        fi: Z3_func_interp,
        args: Z3_ast_vector,
        value: Z3_ast,
    );

    /// Increment the reference counter of the given `Z3_func_entry` object.
    pub fn Z3_func_entry_inc_ref(c: Z3_context, e: Z3_func_entry);

    /// Decrement the reference counter of the given `Z3_func_entry` object.
    pub fn Z3_func_entry_dec_ref(c: Z3_context, e: Z3_func_entry);

    /// Return the value of this point.
    ///
    /// A `Z3_func_entry` object represents an element in the finite map used
    /// to encode a function interpretation.
    ///
    /// # See also:
    ///
    /// - [`Z3_func_interp_get_entry`]
    pub fn Z3_func_entry_get_value(c: Z3_context, e: Z3_func_entry) -> Option<Z3_ast>;

    /// Return the number of arguments in a `Z3_func_entry` object.
    ///
    /// # See also:
    ///
    /// - [`Z3_func_entry_get_arg`]
    /// - [`Z3_func_interp_get_entry`]
    pub fn Z3_func_entry_get_num_args(c: Z3_context, e: Z3_func_entry) -> ::core::ffi::c_uint;

    /// Return an argument of a `Z3_func_entry` object.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_func_entry_get_num_args(c, e)`
    ///
    /// # See also:
    ///
    /// - [`Z3_func_entry_get_num_args`]
    /// - [`Z3_func_interp_get_entry`]
    pub fn Z3_func_entry_get_arg(
        c: Z3_context,
        e: Z3_func_entry,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Log interaction to a file.
    ///
    /// # See also:
    ///
    /// - [`Z3_append_log`]
    /// - [`Z3_close_log`]
    pub fn Z3_open_log(filename: Z3_string) -> bool;

    /// Append user-defined string to interaction log.
    ///
    /// The interaction log is opened using [`Z3_open_log`].
    /// It contains the formulas that are checked using Z3.
    /// You can use this command to append comments, for instance.
    ///
    /// # See also:
    ///
    /// - [`Z3_open_log`]
    /// - [`Z3_close_log`]
    pub fn Z3_append_log(string: Z3_string);

    /// Close interaction log.
    ///
    /// # See also:
    ///
    /// - [`Z3_append_log`]
    /// - [`Z3_open_log`]
    pub fn Z3_close_log();

    /// Enable/disable printing warning messages to the console.
    ///
    /// Warnings are printed after passing `true`, warning messages are
    /// suppressed after calling this method with `false`.
    pub fn Z3_toggle_warning_messages(enabled: bool);

    /// Select mode for the format used for pretty-printing AST nodes.
    ///
    /// The default mode for pretty printing AST nodes is to produce
    /// SMT-LIB style output where common subexpressions are printed
    /// at each occurrence. The mode is called `AstPrintMode::SmtLibFull`.
    ///
    /// To print shared common subexpressions only once,
    /// use the `AstPrintMode::LowLevel` mode.
    ///
    /// To print in way that conforms to SMT-LIB standards and uses let
    /// expressions to share common sub-expressions use
    /// `AstPrintMode::SmtLib2Compliant`.
    ///
    /// # See also:
    ///
    /// - [`Z3_ast_to_string`]
    /// - [`Z3_pattern_to_string`]
    /// - [`Z3_func_decl_to_string`]
    pub fn Z3_set_ast_print_mode(c: Z3_context, mode: AstPrintMode);

    /// Convert the given AST node into a string.
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to
    /// `Z3_ast_to_string`.
    ///
    /// # See also:
    ///
    /// - [`Z3_func_decl_to_string`]
    /// - [`Z3_pattern_to_string`]
    /// - [`Z3_sort_to_string`]
    pub fn Z3_ast_to_string(c: Z3_context, a: Z3_ast) -> Z3_string;

    /// Convert the given pattern AST node into a string.
    ///
    /// This is a wrapper around [`Z3_ast_to_string`].
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to
    /// [`Z3_ast_to_string`].
    ///
    /// # See also:
    ///
    /// - [`Z3_ast_to_string`]
    /// - [`Z3_func_decl_to_string`]
    /// - [`Z3_sort_to_string`]
    pub fn Z3_pattern_to_string(c: Z3_context, p: Z3_pattern) -> Z3_string;

    /// Convert the given sort AST node into a string.
    ///
    /// This is a wrapper around [`Z3_ast_to_string`].
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to
    /// [`Z3_ast_to_string`].
    ///
    /// # See also:
    ///
    /// - [`Z3_ast_to_string`]
    /// - [`Z3_func_decl_to_string`]
    /// - [`Z3_pattern_to_string`]
    pub fn Z3_sort_to_string(c: Z3_context, s: Z3_sort) -> Z3_string;

    /// Convert the given func decl AST node into a string.
    ///
    /// This is a wrapper around [`Z3_ast_to_string`].
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to
    /// [`Z3_ast_to_string`].
    ///
    /// # See also:
    ///
    /// - [`Z3_ast_to_string`]
    /// - [`Z3_pattern_to_string`]
    /// - [`Z3_sort_to_string`]
    pub fn Z3_func_decl_to_string(c: Z3_context, d: Z3_func_decl) -> Z3_string;

    /// Convert the given model into a string.
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to `Z3_model_to_string`.
    pub fn Z3_model_to_string(c: Z3_context, m: Z3_model) -> Z3_string;

    /// Convert the given benchmark into SMT-LIB formatted string.
    ///
    /// Warning: The result buffer is statically allocated by Z3.
    /// It will be automatically deallocated when
    /// [`Z3_del_context`] is invoked.
    /// So, the buffer is invalidated in the next call to
    /// `Z3_benchmark_to_smtlib_string`.
    ///
    /// - `c`: - context.
    /// - `name`: - name of benchmark. The argument is optional.
    /// - `logic`: - the benchmark logic.
    /// - `status`: - the status string (sat, unsat, or unknown)
    /// - `attributes`: - other attributes, such as source, difficulty or category.
    /// - `num_assumptions`: - number of assumptions.
    /// - `assumptions`: - auxiliary assumptions.
    /// - `formula`: - formula to be checked for consistency in conjunction with assumptions.
    pub fn Z3_benchmark_to_smtlib_string(
        c: Z3_context,
        name: Z3_string,
        logic: Z3_string,
        status: Z3_string,
        attributes: Z3_string,
        num_assumptions: ::core::ffi::c_uint,
        assumptions: *const Z3_ast,
        formula: Z3_ast,
    ) -> Z3_string;

    /// Parse the given string using the SMT-LIB2 parser.
    ///
    /// It returns a formula comprising of the conjunction of assertions
    /// in the scope (up to push/pop) at the end of the string.
    pub fn Z3_parse_smtlib2_string(
        c: Z3_context,
        str: Z3_string,
        num_sorts: ::core::ffi::c_uint,
        sort_names: *const Z3_symbol,
        sorts: *const Z3_sort,
        num_decls: ::core::ffi::c_uint,
        decl_names: *const Z3_symbol,
        decls: *const Z3_func_decl,
    ) -> Option<Z3_ast_vector>;

    /// Similar to [`Z3_parse_smtlib2_string`], but reads the benchmark from a file.
    pub fn Z3_parse_smtlib2_file(
        c: Z3_context,
        file_name: Z3_string,
        num_sorts: ::core::ffi::c_uint,
        sort_names: *const Z3_symbol,
        sorts: *const Z3_sort,
        num_decls: ::core::ffi::c_uint,
        decl_names: *const Z3_symbol,
        decls: *const Z3_func_decl,
    ) -> Option<Z3_ast_vector>;

    /// Parse and evaluate and SMT-LIB2 command sequence. The state from a previous
    /// call is saved so the next evaluation builds on top of the previous call.
    ///
    /// Returns output generated from processing commands.
    pub fn Z3_eval_smtlib2_string(arg1: Z3_context, str: Z3_string) -> Z3_string;

    /// Return the error code for the last API call.
    ///
    /// A call to a Z3 function may return a non `ErrorCode::OK` error code,
    /// when it is not used correctly.
    ///
    /// # See also:
    ///
    /// - [`Z3_set_error_handler`]
    pub fn Z3_get_error_code(c: Z3_context) -> ErrorCode;

    /// Register a Z3 error handler.
    ///
    /// A call to a Z3 function may return a non `ErrorCode::OK` error code, when
    /// it is not used correctly.  An error handler can be registered
    /// and will be called in this case.  To disable the use of the
    /// error handler, simply register with `h`=NULL.
    ///
    /// Warning: Log files, created using [`Z3_open_log`],
    /// may be potentially incomplete/incorrect if error handlers are used.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_error_code`]
    pub fn Z3_set_error_handler(c: Z3_context, h: Z3_error_handler);

    /// Set an error.
    pub fn Z3_set_error(c: Z3_context, e: ErrorCode);

    /// Return a string describing the given error code.
    pub fn Z3_get_error_msg(c: Z3_context, err: ErrorCode) -> Z3_string;

    /// Return Z3 version number information.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_full_version`]
    pub fn Z3_get_version(
        major: *mut ::core::ffi::c_uint,
        minor: *mut ::core::ffi::c_uint,
        build_number: *mut ::core::ffi::c_uint,
        revision_number: *mut ::core::ffi::c_uint,
    );

    /// Return a string that fully describes the version of Z3 in use.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_version`]
    pub fn Z3_get_full_version() -> Z3_string;

    /// Enable tracing messages tagged as `tag` when Z3 is compiled in debug mode.
    /// It is a NOOP otherwise
    ///
    /// # See also:
    ///
    /// - [`Z3_disable_trace`]
    pub fn Z3_enable_trace(tag: Z3_string);

    /// Disable tracing messages tagged as `tag` when Z3 is compiled in debug mode.
    /// It is a NOOP otherwise
    ///
    /// # See also:
    ///
    /// - [`Z3_enable_trace`]
    pub fn Z3_disable_trace(tag: Z3_string);

    /// Reset all allocated resources.
    ///
    /// Use this facility on out-of memory errors.
    /// It allows discharging the previous state and resuming afresh.
    /// Any pointers previously returned by the API
    /// become invalid.
    pub fn Z3_reset_memory();

    /// Destroy all allocated resources.
    ///
    /// Any pointers previously returned by the API become invalid.
    /// Can be used for memory leak detection.
    pub fn Z3_finalize_memory();

    /// Create a goal (aka problem). A goal is essentially a set
    /// of formulas, that can be solved and/or transformed using
    /// tactics and solvers.
    ///
    /// If `models == true`, then model generation is enabled for the
    /// new goal.
    ///
    /// If `unsat_cores == true`, then unsat core generation is enabled
    /// for the new goal.
    ///
    /// If `proofs == true`, then proof generation is enabled for the
    /// new goal.
    ///
    /// NOTE: The Z3 context `c` must have been created with proof
    /// generation support.
    ///
    /// NOTE: Reference counting must be used to manage goals, even
    /// when the [`Z3_context`] was created using
    /// [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_goal(
        c: Z3_context,
        models: bool,
        unsat_cores: bool,
        proofs: bool,
    ) -> Option<Z3_goal>;

    /// Increment the reference counter of the given goal.
    pub fn Z3_goal_inc_ref(c: Z3_context, g: Z3_goal);

    /// Decrement the reference counter of the given goal.
    pub fn Z3_goal_dec_ref(c: Z3_context, g: Z3_goal);

    /// Return the "precision" of the given goal. Goals can be transformed using over and under approximations.
    /// A under approximation is applied when the objective is to find a model for a given goal.
    /// An over approximation is applied when the objective is to find a proof for a given goal.
    pub fn Z3_goal_precision(c: Z3_context, g: Z3_goal) -> GoalPrec;

    /// Add a new formula `a` to the given goal.
    ///
    /// The formula is split according to the following procedure that
    /// is applied until a fixed-point:
    ///
    /// - Conjunctions are split into separate formulas.
    /// - Negations are distributed over disjunctions, resulting in
    ///   separate formulas.
    ///
    /// If the goal is `false`, adding new formulas is a no-op.
    ///
    /// If the formula `a` is `true`, then nothing is added.
    ///
    /// If the formula `a` is `false`, then the entire goal is
    /// replaced by the formula `false`.
    pub fn Z3_goal_assert(c: Z3_context, g: Z3_goal, a: Z3_ast);

    /// Return true if the given goal contains the formula `false`.
    pub fn Z3_goal_inconsistent(c: Z3_context, g: Z3_goal) -> bool;

    /// Return the depth of the given goal. It tracks how many transformations were applied to it.
    pub fn Z3_goal_depth(c: Z3_context, g: Z3_goal) -> ::core::ffi::c_uint;

    /// Erase all formulas from the given goal.
    pub fn Z3_goal_reset(c: Z3_context, g: Z3_goal);

    /// Return the number of formulas in the given goal.
    pub fn Z3_goal_size(c: Z3_context, g: Z3_goal) -> ::core::ffi::c_uint;

    /// Return a formula from the given goal.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_goal_size(c, g)`
    pub fn Z3_goal_formula(c: Z3_context, g: Z3_goal, idx: ::core::ffi::c_uint) -> Option<Z3_ast>;

    /// Return the number of formulas, subformulas and terms in the given goal.
    pub fn Z3_goal_num_exprs(c: Z3_context, g: Z3_goal) -> ::core::ffi::c_uint;

    /// Return true if the goal is empty, and it is precise or the product of a under approximation.
    pub fn Z3_goal_is_decided_sat(c: Z3_context, g: Z3_goal) -> bool;

    /// Return true if the goal contains false, and it is precise or the product of an over approximation.
    pub fn Z3_goal_is_decided_unsat(c: Z3_context, g: Z3_goal) -> bool;

    /// Copy a goal `g` from the context `source` to the context `target`.
    pub fn Z3_goal_translate(source: Z3_context, g: Z3_goal, target: Z3_context)
    -> Option<Z3_goal>;

    /// Convert a model of the formulas of a goal to a model of an original goal.
    /// The model may be null, in which case the returned model is valid if the goal was
    /// established satisfiable.
    pub fn Z3_goal_convert_model(c: Z3_context, g: Z3_goal, m: Z3_model) -> Option<Z3_model>;

    /// Convert a goal into a string.
    pub fn Z3_goal_to_string(c: Z3_context, g: Z3_goal) -> Z3_string;

    /// Convert a goal into a DIMACS formatted string.
    /// The goal must be in CNF. You can convert a goal to CNF
    /// by applying the tseitin-cnf tactic. Bit-vectors are not automatically
    /// converted to Booleans either, so the if caller intends to
    /// preserve satisfiability, it should apply bit-blasting tactics.
    /// Quantifiers and theory atoms will not be encoded.
    pub fn Z3_goal_to_dimacs_string(c: Z3_context, g: Z3_goal) -> Z3_string;

    /// Return a tactic associated with the given name.
    ///
    /// The complete list of tactics may be obtained using the procedures [`Z3_get_num_tactics`] and [`Z3_get_tactic_name`].
    /// It may also be obtained using the command `(help-tactic)` in the SMT 2.0 front-end.
    ///
    /// Tactics are the basic building block for creating custom solvers for specific problem domains.
    pub fn Z3_mk_tactic(c: Z3_context, name: Z3_string) -> Option<Z3_tactic>;

    /// Increment the reference counter of the given tactic.
    pub fn Z3_tactic_inc_ref(c: Z3_context, t: Z3_tactic);

    /// Decrement the reference counter of the given tactic.
    pub fn Z3_tactic_dec_ref(c: Z3_context, g: Z3_tactic);

    /// Return a probe associated with the given name.
    /// The complete list of probes may be obtained using the procedures [`Z3_get_num_probes`] and [`Z3_get_probe_name`].
    /// It may also be obtained using the command `(help-tactic)` in the SMT 2.0 front-end.
    ///
    /// Probes are used to inspect a goal (aka problem) and collect information that may be used to decide
    /// which solver and/or preprocessing step will be used.
    pub fn Z3_mk_probe(c: Z3_context, name: Z3_string) -> Option<Z3_probe>;

    /// Increment the reference counter of the given probe.
    pub fn Z3_probe_inc_ref(c: Z3_context, p: Z3_probe);

    /// Decrement the reference counter of the given probe.
    pub fn Z3_probe_dec_ref(c: Z3_context, p: Z3_probe);

    /// Return a tactic that applies `t1` to a given goal and `t2`
    /// to every subgoal produced by `t1`.
    pub fn Z3_tactic_and_then(c: Z3_context, t1: Z3_tactic, t2: Z3_tactic) -> Option<Z3_tactic>;

    /// Return a tactic that first applies `t1` to a given goal,
    /// if it fails then returns the result of `t2` applied to the given goal.
    pub fn Z3_tactic_or_else(c: Z3_context, t1: Z3_tactic, t2: Z3_tactic) -> Option<Z3_tactic>;

    /// Return a tactic that applies the given tactics in parallel.
    pub fn Z3_tactic_par_or(
        c: Z3_context,
        num: ::core::ffi::c_uint,
        ts: *const Z3_tactic,
    ) -> Option<Z3_tactic>;

    /// Return a tactic that applies `t1` to a given goal and then `t2`
    /// to every subgoal produced by `t1`. The subgoals are processed in parallel.
    pub fn Z3_tactic_par_and_then(c: Z3_context, t1: Z3_tactic, t2: Z3_tactic)
    -> Option<Z3_tactic>;

    /// Return a tactic that applies `t` to a given goal for `ms` milliseconds.
    /// If `t` does not terminate in `ms` milliseconds, then it fails.
    pub fn Z3_tactic_try_for(
        c: Z3_context,
        t: Z3_tactic,
        ms: ::core::ffi::c_uint,
    ) -> Option<Z3_tactic>;

    /// Return a tactic that applies `t` to a given goal is the probe `p` evaluates to true.
    /// If `p` evaluates to false, then the new tactic behaves like the skip tactic.
    pub fn Z3_tactic_when(c: Z3_context, p: Z3_probe, t: Z3_tactic) -> Option<Z3_tactic>;

    /// Return a tactic that applies `t1` to a given goal if the probe `p` evaluates to true,
    /// and `t2` if `p` evaluates to false.
    pub fn Z3_tactic_cond(
        c: Z3_context,
        p: Z3_probe,
        t1: Z3_tactic,
        t2: Z3_tactic,
    ) -> Option<Z3_tactic>;

    /// Return a tactic that keeps applying `t` until the goal is not modified anymore or the maximum
    /// number of iterations `max` is reached.
    pub fn Z3_tactic_repeat(
        c: Z3_context,
        t: Z3_tactic,
        max: ::core::ffi::c_uint,
    ) -> Option<Z3_tactic>;

    /// Return a tactic that just return the given goal.
    pub fn Z3_tactic_skip(c: Z3_context) -> Option<Z3_tactic>;

    /// Return a tactic that always fails.
    pub fn Z3_tactic_fail(c: Z3_context) -> Option<Z3_tactic>;

    /// Return a tactic that fails if the probe `p` evaluates to false.
    pub fn Z3_tactic_fail_if(c: Z3_context, p: Z3_probe) -> Option<Z3_tactic>;

    /// Return a tactic that fails if the goal is not trivially satisfiable (i.e., empty) or
    /// trivially unsatisfiable (i.e., contains false).
    pub fn Z3_tactic_fail_if_not_decided(c: Z3_context) -> Option<Z3_tactic>;

    /// Return a tactic that applies `t` using the given set of parameters.
    pub fn Z3_tactic_using_params(c: Z3_context, t: Z3_tactic, p: Z3_params) -> Option<Z3_tactic>;

    /// Return a probe that always evaluates to val.
    pub fn Z3_probe_const(x: Z3_context, val: f64) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when the value returned by `p1` is less than the value returned by `p2`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_lt(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when the value returned by `p1` is greater than the value returned by `p2`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_gt(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when the value returned by `p1` is less than or equal to the value returned by `p2`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_le(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when the value returned by `p1` is greater than or equal to the value returned by `p2`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_ge(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when the value returned by `p1` is equal to the value returned by `p2`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_eq(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when `p1` and `p2` evaluates to true.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_and(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when `p1` or `p2` evaluates to true.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_or(x: Z3_context, p1: Z3_probe, p2: Z3_probe) -> Option<Z3_probe>;

    /// Return a probe that evaluates to "true" when `p` does not evaluate to true.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn Z3_probe_not(x: Z3_context, p: Z3_probe) -> Option<Z3_probe>;

    /// Return the number of builtin tactics available in Z3.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_tactic_name`]
    pub fn Z3_get_num_tactics(c: Z3_context) -> ::core::ffi::c_uint;

    /// Return the name of the idx tactic.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_get_num_tactics(c)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_num_tactics`]
    pub fn Z3_get_tactic_name(c: Z3_context, i: ::core::ffi::c_uint) -> Z3_string;

    /// Return the number of builtin probes available in Z3.
    ///
    /// # See also:
    ///
    /// - [`Z3_get_probe_name`]
    pub fn Z3_get_num_probes(c: Z3_context) -> ::core::ffi::c_uint;

    /// Return the name of the `i` probe.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_get_num_probes(c)`
    ///
    /// # See also:
    ///
    /// - [`Z3_get_num_probes`]
    pub fn Z3_get_probe_name(c: Z3_context, i: ::core::ffi::c_uint) -> Z3_string;

    /// Return a string containing a description of parameters accepted by the given tactic.
    pub fn Z3_tactic_get_help(c: Z3_context, t: Z3_tactic) -> Z3_string;

    /// Return the parameter description set for the given tactic object.
    pub fn Z3_tactic_get_param_descrs(c: Z3_context, t: Z3_tactic) -> Option<Z3_param_descrs>;

    /// Return a string containing a description of the tactic with the given name.
    pub fn Z3_tactic_get_descr(c: Z3_context, name: Z3_string) -> Z3_string;

    /// Return a string containing a description of the probe with the given name.
    pub fn Z3_probe_get_descr(c: Z3_context, name: Z3_string) -> Z3_string;

    /// Execute the probe over the goal. The probe always produce a double value.
    /// "Boolean" probes return 0.0 for false, and a value different from 0.0 for true.
    pub fn Z3_probe_apply(c: Z3_context, p: Z3_probe, g: Z3_goal) -> f64;

    /// Apply tactic `t` to the goal `g`.
    ///
    /// # See also:
    ///
    /// - [`Z3_tactic_apply_ex`]
    pub fn Z3_tactic_apply(c: Z3_context, t: Z3_tactic, g: Z3_goal) -> Option<Z3_apply_result>;

    /// Apply tactic `t` to the goal `g` using the parameter set `p`.
    ///
    /// # See also:
    ///
    /// - [`Z3_tactic_apply`]
    pub fn Z3_tactic_apply_ex(
        c: Z3_context,
        t: Z3_tactic,
        g: Z3_goal,
        p: Z3_params,
    ) -> Option<Z3_apply_result>;

    /// Increment the reference counter of the given `Z3_apply_result` object.
    pub fn Z3_apply_result_inc_ref(c: Z3_context, r: Z3_apply_result);

    /// Decrement the reference counter of the given `Z3_apply_result` object.
    pub fn Z3_apply_result_dec_ref(c: Z3_context, r: Z3_apply_result);

    /// Convert the `Z3_apply_result` object returned by [`Z3_tactic_apply`] into a string.
    pub fn Z3_apply_result_to_string(c: Z3_context, r: Z3_apply_result) -> Z3_string;

    /// Return the number of subgoals in the `Z3_apply_result` object returned by [`Z3_tactic_apply`].
    ///
    /// # See also:
    ///
    /// - [`Z3_apply_result_get_subgoal`]
    pub fn Z3_apply_result_get_num_subgoals(
        c: Z3_context,
        r: Z3_apply_result,
    ) -> ::core::ffi::c_uint;

    /// Return one of the subgoals in the `Z3_apply_result` object returned by [`Z3_tactic_apply`].
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_apply_result_get_num_subgoals(c, r)`
    ///
    /// # See also:
    ///
    /// - [`Z3_apply_result_get_num_subgoals`]
    pub fn Z3_apply_result_get_subgoal(
        c: Z3_context,
        r: Z3_apply_result,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_goal>;

    /// Create a new solver. This solver is a "combined solver" (see
    /// `combined_solver` module) that internally uses a non-incremental (solver1) and an
    /// incremental solver (solver2). This combined solver changes its behaviour based
    /// on how it is used and how its parameters are set.
    ///
    /// If the solver is used in a non incremental way (i.e. no calls to
    /// [`Z3_solver_push`] or [`Z3_solver_pop`], and no calls to
    /// [`Z3_solver_assert`] or [`Z3_solver_assert_and_track`] after checking
    /// satisfiability without an intervening [`Z3_solver_reset`]) then solver1
    /// will be used. This solver will apply Z3's "default" tactic.
    ///
    /// The "default" tactic will attempt to probe the logic used by the
    /// assertions and will apply a specialized tactic if one is supported.
    /// Otherwise the general `(and-then simplify smt)` tactic will be used.
    ///
    /// If the solver is used in an incremental way then the combined solver
    /// will switch to using solver2 (which behaves similarly to the general
    /// "smt" tactic).
    ///
    /// Note however it is possible to set the `solver2_timeout`,
    /// `solver2_unknown`, and `ignore_solver1` parameters of the combined
    /// solver to change its behaviour.
    ///
    /// The function [`Z3_solver_get_model`] retrieves a model if the
    /// assertions is satisfiable (i.e., the result is
    /// `Z3_L_TRUE`) and model construction is enabled.
    /// The function [`Z3_solver_get_model`] can also be used even
    /// if the result is `Z3_L_UNDEF`, but the returned model
    /// is not guaranteed to satisfy quantified assertions.
    ///
    /// NOTE: User must use [`Z3_solver_inc_ref`] and [`Z3_solver_dec_ref`] to manage solver objects.
    /// Even if the context was created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_simple_solver`]
    /// - [`Z3_mk_solver_for_logic`]
    /// - [`Z3_mk_solver_from_tactic`]
    pub fn Z3_mk_solver(c: Z3_context) -> Option<Z3_solver>;

    /// Create a new incremental solver.
    ///
    /// This is equivalent to applying the "smt" tactic.
    ///
    /// Unlike [`Z3_mk_solver`] this solver
    /// - Does not attempt to apply any logic specific tactics.
    /// - Does not change its behaviour based on whether it used
    ///   incrementally/non-incrementally.
    ///
    /// Note that these differences can result in very different performance
    /// compared to `Z3_mk_solver()`.
    ///
    /// The function [`Z3_solver_get_model`] retrieves a model if the
    /// assertions is satisfiable (i.e., the result is
    /// `Z3_L_TRUE`) and model construction is enabled.
    /// The function [`Z3_solver_get_model`] can also be used even
    /// if the result is `Z3_L_UNDEF`, but the returned model
    /// is not guaranteed to satisfy quantified assertions.
    ///
    /// NOTE: User must use [`Z3_solver_inc_ref`] and [`Z3_solver_dec_ref`] to manage solver objects.
    /// Even if the context was created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_solver`]
    /// - [`Z3_mk_solver_for_logic`]
    /// - [`Z3_mk_solver_from_tactic`]
    pub fn Z3_mk_simple_solver(c: Z3_context) -> Option<Z3_solver>;

    /// Create a new solver customized for the given logic.
    /// It behaves like [`Z3_mk_solver`] if the logic is unknown or unsupported.
    ///
    /// NOTE: User must use [`Z3_solver_inc_ref`] and [`Z3_solver_dec_ref`] to manage solver objects.
    /// Even if the context was created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_solver`]
    /// - [`Z3_mk_simple_solver`]
    /// - [`Z3_mk_solver_from_tactic`]
    pub fn Z3_mk_solver_for_logic(c: Z3_context, logic: Z3_symbol) -> Option<Z3_solver>;

    /// Create a new solver that is implemented using the given tactic.
    /// The solver supports the commands [`Z3_solver_push`] and [`Z3_solver_pop`], but it
    /// will always solve each [`Z3_solver_check`] from scratch.
    ///
    /// NOTE: User must use [`Z3_solver_inc_ref`] and [`Z3_solver_dec_ref`] to manage solver objects.
    /// Even if the context was created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_solver`]
    /// - [`Z3_mk_simple_solver`]
    /// - [`Z3_mk_solver_for_logic`]
    pub fn Z3_mk_solver_from_tactic(c: Z3_context, t: Z3_tactic) -> Option<Z3_solver>;

    /// Copy a solver `s` from the context `source` to the context `target`.
    pub fn Z3_solver_translate(
        source: Z3_context,
        s: Z3_solver,
        target: Z3_context,
    ) -> Option<Z3_solver>;

    /// Ad-hoc method for importing model conversion from solver.
    pub fn Z3_solver_import_model_converter(ctx: Z3_context, src: Z3_solver, dst: Z3_solver);

    /// Return a string describing all solver available parameters.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_get_param_descrs`]
    /// - [`Z3_solver_set_params`]
    pub fn Z3_solver_get_help(c: Z3_context, s: Z3_solver) -> Z3_string;

    /// Return the parameter description set for the given solver object.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_get_help`]
    /// - [`Z3_solver_set_params`]
    pub fn Z3_solver_get_param_descrs(c: Z3_context, s: Z3_solver) -> Option<Z3_param_descrs>;

    /// Set the given solver using the given parameters.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_get_help`]
    /// - [`Z3_solver_get_param_descrs`]
    pub fn Z3_solver_set_params(c: Z3_context, s: Z3_solver, p: Z3_params);

    /// Increment the reference counter of the given solver.
    pub fn Z3_solver_inc_ref(c: Z3_context, s: Z3_solver);

    /// Decrement the reference counter of the given solver.
    pub fn Z3_solver_dec_ref(c: Z3_context, s: Z3_solver);

    /// Create a backtracking point.
    ///
    /// The solver contains a stack of assertions.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_pop`]
    pub fn Z3_solver_push(c: Z3_context, s: Z3_solver);

    /// Backtrack `n` backtracking points.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_push`]
    ///
    /// # Preconditions:
    ///
    /// - `n <= Z3_solver_get_num_scopes(c, s)`
    pub fn Z3_solver_pop(c: Z3_context, s: Z3_solver, n: ::core::ffi::c_uint);

    /// Remove all assertions from the solver.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_assert`]
    /// - [`Z3_solver_assert_and_track`]
    pub fn Z3_solver_reset(c: Z3_context, s: Z3_solver);

    /// Return the number of backtracking points.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_push`]
    /// - [`Z3_solver_pop`]
    pub fn Z3_solver_get_num_scopes(c: Z3_context, s: Z3_solver) -> ::core::ffi::c_uint;

    /// Assert a constraint into the solver.
    ///
    /// The functions [`Z3_solver_check`] and [`Z3_solver_check_assumptions`] should be
    /// used to check whether the logical context is consistent or not.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_assert_and_track`]
    /// - [`Z3_solver_reset`]
    pub fn Z3_solver_assert(c: Z3_context, s: Z3_solver, a: Z3_ast);

    /// Assert a constraint `a` into the solver, and track it (in the
    /// unsat) core using the Boolean constant `p`.
    ///
    /// This API is an alternative to [`Z3_solver_check_assumptions`]
    /// for extracting unsat cores. Both APIs can be used in the same solver.
    /// The unsat core will contain a combination of the Boolean variables
    /// provided using [`Z3_solver_assert_and_track`]
    /// and the Boolean literals provided using
    /// [`Z3_solver_check_assumptions`].
    ///
    /// # Preconditions:
    ///
    /// * `a` must be a Boolean expression
    /// * `p` must be a Boolean constant (aka variable).
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_assert`]
    /// - [`Z3_solver_reset`]
    pub fn Z3_solver_assert_and_track(c: Z3_context, s: Z3_solver, a: Z3_ast, p: Z3_ast);

    /// load solver assertions from a file.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_from_string`]
    /// - [`Z3_solver_to_string`]
    pub fn Z3_solver_from_file(c: Z3_context, s: Z3_solver, file_name: Z3_string);

    /// load solver assertions from a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_from_file`]
    /// - [`Z3_solver_to_string`]
    pub fn Z3_solver_from_string(c: Z3_context, s: Z3_solver, c_str: Z3_string);

    /// Return the set of asserted formulas on the solver.
    pub fn Z3_solver_get_assertions(c: Z3_context, s: Z3_solver) -> Option<Z3_ast_vector>;

    /// Return the set of units modulo model conversion.
    pub fn Z3_solver_get_units(c: Z3_context, s: Z3_solver) -> Option<Z3_ast_vector>;

    /// Return the set of non units in the solver state.
    pub fn Z3_solver_get_non_units(c: Z3_context, s: Z3_solver) -> Option<Z3_ast_vector>;

    /// Check whether the assertions in a given solver are consistent or not.
    ///
    /// The function [`Z3_solver_get_model`]
    /// retrieves a model if the assertions is satisfiable (i.e., the
    /// result is `Z3_L_TRUE`) and model construction is enabled.
    /// Note that if the call returns `Z3_L_UNDEF`, Z3 does not
    /// ensure that calls to [`Z3_solver_get_model`]
    /// succeed and any models produced in this case are not guaranteed
    /// to satisfy the assertions.
    ///
    /// The function [`Z3_solver_get_proof`]
    /// retrieves a proof if proof generation was enabled when the context
    /// was created, and the assertions are unsatisfiable (i.e., the result
    /// is `Z3_L_FALSE`).
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_check_assumptions`]
    pub fn Z3_solver_check(c: Z3_context, s: Z3_solver) -> Z3_lbool;

    /// Check whether the assertions in the given solver and
    /// optional assumptions are consistent or not.
    ///
    /// The function
    /// [`Z3_solver_get_unsat_core`]
    /// retrieves the subset of the assumptions used in the
    /// unsatisfiability proof produced by Z3.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_check`]
    pub fn Z3_solver_check_assumptions(
        c: Z3_context,
        s: Z3_solver,
        num_assumptions: ::core::ffi::c_uint,
        assumptions: *const Z3_ast,
    ) -> Z3_lbool;

    /// Retrieve congruence class representatives for terms.
    ///
    /// The function can be used for relying on Z3 to identify equal terms under the current
    /// set of assumptions. The array of terms and array of class identifiers should have
    /// the same length. The class identifiers are numerals that are assigned to the same
    /// value for their corresponding terms if the current context forces the terms to be
    /// equal. You cannot deduce that terms corresponding to different numerals must be all different,
    /// (especially when using non-convex theories).
    /// All implied equalities are returned by this call.
    /// This means that two terms map to the same class identifier if and only if
    /// the current context implies that they are equal.
    ///
    /// A side-effect of the function is a satisfiability check on the assertions on the solver that is passed in.
    /// The function return `Z3_L_FALSE` if the current assertions are not satisfiable.
    pub fn Z3_get_implied_equalities(
        c: Z3_context,
        s: Z3_solver,
        num_terms: ::core::ffi::c_uint,
        terms: *const Z3_ast,
        class_ids: *mut ::core::ffi::c_uint,
    ) -> Z3_lbool;

    /// retrieve consequences from solver that determine values of the supplied function symbols.
    pub fn Z3_solver_get_consequences(
        c: Z3_context,
        s: Z3_solver,
        assumptions: Z3_ast_vector,
        variables: Z3_ast_vector,
        consequences: Z3_ast_vector,
    ) -> Z3_lbool;

    /// Extract a next cube for a solver. The last cube is the constant `true` or `false`.
    /// The number of (non-constant) cubes is by default 1. For the sat solver cubing is controlled
    /// using parameters sat.lookahead.cube.cutoff and sat.lookahead.cube.fraction.
    ///
    /// The third argument is a vector of variables that may be used for cubing.
    /// The contents of the vector is only used in the first call. The initial list of variables
    /// is used in subsequent calls until it returns the unsatisfiable cube.
    /// The vector is modified to contain a set of Autarky variables that occur in clauses that
    /// are affected by the (last literal in the) cube. These variables could be used by a different
    /// cuber (on a different solver object) for further recursive cubing.
    ///
    /// The last argument is a backtracking level. It instructs the cube process to backtrack below
    /// the indicated level for the next cube.
    pub fn Z3_solver_cube(
        c: Z3_context,
        s: Z3_solver,
        vars: Z3_ast_vector,
        backtrack_level: ::core::ffi::c_uint,
    ) -> Option<Z3_ast_vector>;

    /// Retrieve the model for the last [`Z3_solver_check`]
    ///
    /// The error handler is invoked if a model is not available because
    /// the commands above were not invoked for the given solver, or if the result was `Z3_L_FALSE`.
    pub fn Z3_solver_get_model(c: Z3_context, s: Z3_solver) -> Option<Z3_model>;

    /// Retrieve the proof for the last [`Z3_solver_check`]
    ///
    /// The error handler is invoked if proof generation is not enabled,
    /// or if the commands above were not invoked for the given solver,
    /// or if the result was different from `Z3_L_FALSE`.
    pub fn Z3_solver_get_proof(c: Z3_context, s: Z3_solver) -> Option<Z3_ast>;

    /// Retrieve the unsat core for the last [`Z3_solver_check_assumptions`]
    /// The unsat core is a subset of the assumptions `a`.
    ///
    /// By default, the unsat core will not be minimized. Generation of a minimized
    /// unsat core can be enabled via the `"sat.core.minimize"` and `"smt.core.minimize"`
    /// settings for SAT and SMT cores respectively. Generation of minimized unsat cores
    /// will be more expensive.
    pub fn Z3_solver_get_unsat_core(c: Z3_context, s: Z3_solver) -> Option<Z3_ast_vector>;

    /// Return a brief justification for an "unknown" result (i.e., `Z3_L_UNDEF`) for
    /// the commands [`Z3_solver_check`]
    pub fn Z3_solver_get_reason_unknown(c: Z3_context, s: Z3_solver) -> Z3_string;

    /// Return statistics for the given solver.
    ///
    /// NOTE: User must use [`Z3_stats_inc_ref`] and [`Z3_stats_dec_ref`] to manage [`Z3_stats`] objects.
    pub fn Z3_solver_get_statistics(c: Z3_context, s: Z3_solver) -> Option<Z3_stats>;

    /// Convert a solver into a string.
    ///
    /// # See also:
    ///
    /// - [`Z3_solver_from_file`]
    /// - [`Z3_solver_from_string`]
    pub fn Z3_solver_to_string(c: Z3_context, s: Z3_solver) -> Z3_string;

    /// Convert a statistics into a string.
    pub fn Z3_stats_to_string(c: Z3_context, s: Z3_stats) -> Z3_string;

    /// Increment the reference counter of the given statistics object.
    pub fn Z3_stats_inc_ref(c: Z3_context, s: Z3_stats);

    /// Decrement the reference counter of the given statistics object.
    pub fn Z3_stats_dec_ref(c: Z3_context, s: Z3_stats);

    /// Return the number of statistical data in `s`.
    pub fn Z3_stats_size(c: Z3_context, s: Z3_stats) -> ::core::ffi::c_uint;

    /// Return the key (a string) for a particular statistical data.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_stats_size(c, s)`
    pub fn Z3_stats_get_key(c: Z3_context, s: Z3_stats, idx: ::core::ffi::c_uint) -> Z3_string;

    /// Return `true` if the given statistical data is a unsigned integer.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_stats_size(c, s)`
    pub fn Z3_stats_is_uint(c: Z3_context, s: Z3_stats, idx: ::core::ffi::c_uint) -> bool;

    /// Return `true` if the given statistical data is a double.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_stats_size(c, s)`
    pub fn Z3_stats_is_double(c: Z3_context, s: Z3_stats, idx: ::core::ffi::c_uint) -> bool;

    /// Return the unsigned value of the given statistical data.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_stats_size(c, s) && Z3_stats_is_uint(c, s)`
    pub fn Z3_stats_get_uint_value(
        c: Z3_context,
        s: Z3_stats,
        idx: ::core::ffi::c_uint,
    ) -> ::core::ffi::c_uint;

    /// Return the double value of the given statistical data.
    ///
    /// # Preconditions:
    ///
    /// - `idx < Z3_stats_size(c, s) && Z3_stats_is_double(c, s)`
    pub fn Z3_stats_get_double_value(c: Z3_context, s: Z3_stats, idx: ::core::ffi::c_uint) -> f64;

    /// Return the estimated allocated memory in bytes.
    pub fn Z3_get_estimated_alloc_size() -> u64;

    /// Return an empty AST vector.
    ///
    /// NOTE: Reference counting must be used to manage AST vectors, even when the `Z3_context` was
    /// created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_ast_vector(c: Z3_context) -> Option<Z3_ast_vector>;

    /// Increment the reference counter of the given AST vector.
    pub fn Z3_ast_vector_inc_ref(c: Z3_context, v: Z3_ast_vector);

    /// Decrement the reference counter of the given AST vector.
    pub fn Z3_ast_vector_dec_ref(c: Z3_context, v: Z3_ast_vector);

    /// Return the size of the given AST vector.
    pub fn Z3_ast_vector_size(c: Z3_context, v: Z3_ast_vector) -> ::core::ffi::c_uint;

    /// Return the AST at position `i` in the AST vector `v`.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_ast_vector_size(c, v)`
    pub fn Z3_ast_vector_get(
        c: Z3_context,
        v: Z3_ast_vector,
        i: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Update position `i` of the AST vector `v` with the AST `a`.
    ///
    /// # Preconditions:
    ///
    /// - `i < Z3_ast_vector_size(c, v)`
    pub fn Z3_ast_vector_set(c: Z3_context, v: Z3_ast_vector, i: ::core::ffi::c_uint, a: Z3_ast);

    /// Resize the AST vector `v`.
    pub fn Z3_ast_vector_resize(c: Z3_context, v: Z3_ast_vector, n: ::core::ffi::c_uint);

    /// Add the AST `a` in the end of the AST vector `v`. The size of `v` is increased by one.
    pub fn Z3_ast_vector_push(c: Z3_context, v: Z3_ast_vector, a: Z3_ast);

    /// Translate the AST vector `v` from context `s` into an AST vector in context `t`.
    pub fn Z3_ast_vector_translate(
        s: Z3_context,
        v: Z3_ast_vector,
        t: Z3_context,
    ) -> Option<Z3_ast_vector>;

    /// Convert AST vector into a string.
    pub fn Z3_ast_vector_to_string(c: Z3_context, v: Z3_ast_vector) -> Z3_string;

    /// Return an empty mapping from AST to AST
    ///
    /// NOTE: Reference counting must be used to manage AST maps, even when the `Z3_context` was
    /// created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_ast_map(c: Z3_context) -> Option<Z3_ast_map>;

    /// Increment the reference counter of the given AST map.
    pub fn Z3_ast_map_inc_ref(c: Z3_context, m: Z3_ast_map);

    /// Decrement the reference counter of the given AST map.
    pub fn Z3_ast_map_dec_ref(c: Z3_context, m: Z3_ast_map);

    /// Return true if the map `m` contains the AST key `k`.
    pub fn Z3_ast_map_contains(c: Z3_context, m: Z3_ast_map, k: Z3_ast) -> bool;

    /// Return the value associated with the key `k`.
    ///
    /// The procedure invokes the error handler if `k` is not in the map.
    pub fn Z3_ast_map_find(c: Z3_context, m: Z3_ast_map, k: Z3_ast) -> Option<Z3_ast>;

    /// Store/Replace a new key, value pair in the given map.
    pub fn Z3_ast_map_insert(c: Z3_context, m: Z3_ast_map, k: Z3_ast, v: Z3_ast);

    /// Erase a key from the map.
    pub fn Z3_ast_map_erase(c: Z3_context, m: Z3_ast_map, k: Z3_ast);

    /// Remove all keys from the given map.
    pub fn Z3_ast_map_reset(c: Z3_context, m: Z3_ast_map);

    /// Return the size of the given map.
    pub fn Z3_ast_map_size(c: Z3_context, m: Z3_ast_map) -> ::core::ffi::c_uint;

    /// Return the keys stored in the given map.
    pub fn Z3_ast_map_keys(c: Z3_context, m: Z3_ast_map) -> Option<Z3_ast_vector>;

    /// Convert the given map into a string.
    pub fn Z3_ast_map_to_string(c: Z3_context, m: Z3_ast_map) -> Z3_string;

    /// Return `true` if `a` can be used as value in the Z3 real algebraic
    /// number package.
    pub fn Z3_algebraic_is_value(c: Z3_context, a: Z3_ast) -> bool;

    /// Return `true` if `a` is positive, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_is_pos(c: Z3_context, a: Z3_ast) -> bool;

    /// Return `true` if `a` is negative, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_is_neg(c: Z3_context, a: Z3_ast) -> bool;

    /// Return `true` if `a` is zero, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_is_zero(c: Z3_context, a: Z3_ast) -> bool;

    /// Return 1 if `a` is positive, 0 if `a` is zero, and -1 if `a` is negative.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_sign(c: Z3_context, a: Z3_ast) -> ::core::ffi::c_int;

    /// Return the value `a + b`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_add(c: Z3_context, a: Z3_ast, b: Z3_ast) -> Option<Z3_ast>;

    /// Return the value `a - b`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_sub(c: Z3_context, a: Z3_ast, b: Z3_ast) -> Option<Z3_ast>;

    /// Return the value `a * b`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_mul(c: Z3_context, a: Z3_ast, b: Z3_ast) -> Option<Z3_ast>;

    /// Return the value `a / b`.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    /// - `!Z3_algebraic_is_zero(c, b)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    /// - [`Z3_algebraic_is_zero`]
    pub fn Z3_algebraic_div(c: Z3_context, a: Z3_ast, b: Z3_ast) -> Option<Z3_ast>;

    /// Return the `a^(1/k)`
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - k is even => `!Z3_algebraic_is_neg(c, a)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_neg`]
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_root(c: Z3_context, a: Z3_ast, k: ::core::ffi::c_uint) -> Option<Z3_ast>;

    /// Return the `a^k`
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    ///
    /// # Postconditions:
    ///
    /// - `Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_power(c: Z3_context, a: Z3_ast, k: ::core::ffi::c_uint) -> Option<Z3_ast>;

    /// Return `true` if `a < b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_lt(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Return `true` if `a > b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_gt(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Return `true` if `a <= b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_le(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Return `true` if `a >= b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_ge(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Return `true` if `a == b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_eq(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Return `true` if `a != b`, and `false` otherwise.
    ///
    /// # Preconditions:
    ///
    /// - `Z3_algebraic_is_value(c, a)`
    /// - `Z3_algebraic_is_value(c, b)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_neq(c: Z3_context, a: Z3_ast, b: Z3_ast) -> bool;

    /// Given a multivariate polynomial `p(x_0, ..., x_{n-1}, x_n)`, returns the
    /// roots of the univariate polynomial `p(a[0], ..., a[n-1], x_n)`.
    ///
    /// # Preconditions:
    ///
    /// - `p` is a Z3 expression that contains only arithmetic terms and free variables.
    /// - `forall i in [0, n) Z3_algebraic_is_value(c, a[i])`
    ///
    /// # Postconditions:
    ///
    /// - `forall r in result Z3_algebraic_is_value(c, result)`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_roots(
        c: Z3_context,
        p: Z3_ast,
        n: ::core::ffi::c_uint,
        a: *mut Z3_ast,
    ) -> Option<Z3_ast_vector>;

    /// Given a multivariate polynomial `p(x_0, ..., x_{n-1})`, return the
    /// sign of `p(a[0], ..., a[n-1])`.
    ///
    /// # Preconditions:
    ///
    /// - `p` is a Z3 expression that contains only arithmetic terms and free variables.
    /// - `forall i in [0, n) Z3_algebraic_is_value(c, a[i])`
    ///
    /// # See also:
    ///
    /// - [`Z3_algebraic_is_value`]
    pub fn Z3_algebraic_eval(
        c: Z3_context,
        p: Z3_ast,
        n: ::core::ffi::c_uint,
        a: *mut Z3_ast,
    ) -> ::core::ffi::c_int;

    /// Return the nonzero subresultants of `p` and `q` with respect to the "variable" `x`.
    ///
    /// # Preconditions:
    ///
    /// - `p`, `q` and `x` are Z3 expressions where `p` and `q` are arithmetic terms.
    ///
    /// Note that, any subterm that cannot be viewed as a polynomial is assumed to be a variable.
    /// Example: `f(a)` is a considered to be a variable in the polynomial
    /// `f(a)*f(a) + 2*f(a) + 1`
    pub fn Z3_polynomial_subresultants(
        c: Z3_context,
        p: Z3_ast,
        q: Z3_ast,
        x: Z3_ast,
    ) -> Option<Z3_ast_vector>;

    /// Delete a RCF numeral created using the RCF API.
    pub fn Z3_rcf_del(c: Z3_context, a: Z3_rcf_num);

    /// Return a RCF rational using the given string.
    pub fn Z3_rcf_mk_rational(c: Z3_context, val: Z3_string) -> Option<Z3_rcf_num>;

    /// Return a RCF small integer.
    pub fn Z3_rcf_mk_small_int(c: Z3_context, val: ::core::ffi::c_int) -> Option<Z3_rcf_num>;

    /// Return Pi
    pub fn Z3_rcf_mk_pi(c: Z3_context) -> Option<Z3_rcf_num>;

    /// Return e (Euler's constant)
    pub fn Z3_rcf_mk_e(c: Z3_context) -> Option<Z3_rcf_num>;

    /// Return a new infinitesimal that is smaller than all elements in the Z3 field.
    pub fn Z3_rcf_mk_infinitesimal(c: Z3_context) -> Option<Z3_rcf_num>;

    /// Store in roots the roots of the polynomial `a[n-1]*x^{n-1} + ... + a[0]`.
    /// The output vector `roots` must have size `n`.
    /// It returns the number of roots of the polynomial.
    ///
    /// # Preconditions:
    ///
    /// - The input polynomial is not the zero polynomial.
    pub fn Z3_rcf_mk_roots(
        c: Z3_context,
        n: ::core::ffi::c_uint,
        a: *const Z3_rcf_num,
        roots: *mut Z3_rcf_num,
    ) -> ::core::ffi::c_uint;

    /// Return the value `a + b`.
    pub fn Z3_rcf_add(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `a - b`.
    pub fn Z3_rcf_sub(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `a * b`.
    pub fn Z3_rcf_mul(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `a / b`.
    pub fn Z3_rcf_div(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `-a`.
    pub fn Z3_rcf_neg(c: Z3_context, a: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `1/a`.
    pub fn Z3_rcf_inv(c: Z3_context, a: Z3_rcf_num) -> Option<Z3_rcf_num>;

    /// Return the value `a^k`.
    pub fn Z3_rcf_power(c: Z3_context, a: Z3_rcf_num, k: ::core::ffi::c_uint)
    -> Option<Z3_rcf_num>;

    /// Return `true` if `a < b`.
    pub fn Z3_rcf_lt(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Return `true` if `a > b`.
    pub fn Z3_rcf_gt(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Return `true` if `a <= b`.
    pub fn Z3_rcf_le(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Return `true` if `a >= b`.
    pub fn Z3_rcf_ge(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Return `true` if `a == b`.
    pub fn Z3_rcf_eq(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Return `true` if `a != b`.
    pub fn Z3_rcf_neq(c: Z3_context, a: Z3_rcf_num, b: Z3_rcf_num) -> bool;

    /// Convert the RCF numeral into a string.
    pub fn Z3_rcf_num_to_string(
        c: Z3_context,
        a: Z3_rcf_num,
        compact: bool,
        html: bool,
    ) -> Z3_string;

    /// Convert the RCF numeral into a string in decimal notation.
    pub fn Z3_rcf_num_to_decimal_string(
        c: Z3_context,
        a: Z3_rcf_num,
        prec: ::core::ffi::c_uint,
    ) -> Z3_string;

    /// Extract the "numerator" and "denominator" of the given RCF numeral.
    ///
    /// We have that `a = n/d`, moreover `n` and `d` are not represented using rational functions.
    pub fn Z3_rcf_get_numerator_denominator(
        c: Z3_context,
        a: Z3_rcf_num,
        n: *mut Z3_rcf_num,
        d: *mut Z3_rcf_num,
    );

    /// Create a new fixedpoint context.
    ///
    /// NOTE: User must use [`Z3_fixedpoint_inc_ref`] and [`Z3_fixedpoint_dec_ref`] to manage fixedpoint objects.
    /// Even if the context was created using [`Z3_mk_context`] instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_fixedpoint(c: Z3_context) -> Option<Z3_fixedpoint>;

    /// Increment the reference counter of the given fixedpoint context
    pub fn Z3_fixedpoint_inc_ref(c: Z3_context, d: Z3_fixedpoint);

    /// Decrement the reference counter of the given fixedpoint context.
    pub fn Z3_fixedpoint_dec_ref(c: Z3_context, d: Z3_fixedpoint);

    /// Add a universal Horn clause as a named rule.
    /// The `horn_rule` should be of the form:
    ///
    /// ```text
    /// horn_rule ::= (forall (bound-vars) horn_rule)
    /// |  (=> atoms horn_rule)
    /// |  atom
    /// ```
    pub fn Z3_fixedpoint_add_rule(
        c: Z3_context,
        d: Z3_fixedpoint,
        rule: Z3_ast,
        name: Option<Z3_symbol>,
    );

    /// Add a Database fact.
    ///
    /// - `c`: - context
    /// - `d`: - fixed point context
    /// - `r`: - relation signature for the row.
    /// - `num_args`: - number of columns for the given row.
    /// - `args`: - array of the row elements.
    ///
    /// The number of arguments `num_args` should be equal to the number
    /// of sorts in the domain of `r`. Each sort in the domain should be an integral
    /// (bit-vector, Boolean or or finite domain sort).
    ///
    /// The call has the same effect as adding a rule where `r` is applied to the arguments.
    pub fn Z3_fixedpoint_add_fact(
        c: Z3_context,
        d: Z3_fixedpoint,
        r: Z3_func_decl,
        num_args: ::core::ffi::c_uint,
        args: *mut ::core::ffi::c_uint,
    );

    /// Assert a constraint to the fixedpoint context.
    ///
    /// The constraints are used as background axioms when the fixedpoint engine uses the PDR mode.
    /// They are ignored for standard Datalog mode.
    pub fn Z3_fixedpoint_assert(c: Z3_context, d: Z3_fixedpoint, axiom: Z3_ast);

    /// Pose a query against the asserted rules.
    ///
    /// ```text
    /// query ::= (exists (bound-vars) query)
    /// |  literals
    /// ```
    ///
    /// query returns
    /// - `Z3_L_FALSE` if the query is unsatisfiable.
    /// - `Z3_L_TRUE` if the query is satisfiable. Obtain the answer by calling [`Z3_fixedpoint_get_answer`].
    /// - `Z3_L_UNDEF` if the query was interrupted, timed out or otherwise failed.
    pub fn Z3_fixedpoint_query(c: Z3_context, d: Z3_fixedpoint, query: Z3_ast) -> Z3_lbool;

    /// Pose multiple queries against the asserted rules.
    ///
    /// The queries are encoded as relations (function declarations).
    ///
    /// query returns
    /// - `Z3_L_FALSE` if the query is unsatisfiable.
    /// - `Z3_L_TRUE` if the query is satisfiable. Obtain the answer by calling [`Z3_fixedpoint_get_answer`].
    /// - `Z3_L_UNDEF` if the query was interrupted, timed out or otherwise failed.
    pub fn Z3_fixedpoint_query_relations(
        c: Z3_context,
        d: Z3_fixedpoint,
        num_relations: ::core::ffi::c_uint,
        relations: *const Z3_func_decl,
    ) -> Z3_lbool;

    /// Retrieve a formula that encodes satisfying answers to the query.
    ///
    ///
    /// When used in Datalog mode, the returned answer is a disjunction of conjuncts.
    /// Each conjunct encodes values of the bound variables of the query that are satisfied.
    /// In PDR mode, the returned answer is a single conjunction.
    ///
    /// When used in Datalog mode the previous call to `Z3_fixedpoint_query` must have returned `Z3_L_TRUE`.
    /// When used with the PDR engine, the previous call must have been either `Z3_L_TRUE` or `Z3_L_FALSE`.
    pub fn Z3_fixedpoint_get_answer(c: Z3_context, d: Z3_fixedpoint) -> Option<Z3_ast>;

    /// Retrieve a string that describes the last status returned by [`Z3_fixedpoint_query`].
    ///
    /// Use this method when [`Z3_fixedpoint_query`] returns `Z3_L_UNDEF`.
    pub fn Z3_fixedpoint_get_reason_unknown(c: Z3_context, d: Z3_fixedpoint) -> Z3_string;

    /// Update a named rule.
    /// A rule with the same name must have been previously created.
    pub fn Z3_fixedpoint_update_rule(c: Z3_context, d: Z3_fixedpoint, a: Z3_ast, name: Z3_symbol);

    /// Query the PDR engine for the maximal levels properties are known about predicate.
    ///
    /// This call retrieves the maximal number of relevant unfoldings
    /// of `pred` with respect to the current exploration state.
    /// Note: this functionality is PDR specific.
    pub fn Z3_fixedpoint_get_num_levels(
        c: Z3_context,
        d: Z3_fixedpoint,
        pred: Z3_func_decl,
    ) -> ::core::ffi::c_uint;

    /// Retrieve the current cover of `pred` up to `level` unfoldings.
    /// Return just the delta that is known at `level`. To
    /// obtain the full set of properties of `pred` one should query
    /// at `level`+1 , `level`+2 etc, and include `level`=-1.
    ///
    /// Note: this functionality is PDR specific.
    pub fn Z3_fixedpoint_get_cover_delta(
        c: Z3_context,
        d: Z3_fixedpoint,
        level: ::core::ffi::c_int,
        pred: Z3_func_decl,
    ) -> Option<Z3_ast>;

    /// Add property about the predicate `pred`.
    /// Add a property of predicate `pred` at `level`.
    /// It gets pushed forward when possible.
    ///
    /// Note: level = -1 is treated as the fixedpoint. So passing -1 for the `level`
    /// means that the property is true of the fixed-point unfolding with respect to `pred`.
    ///
    /// Note: this functionality is PDR specific.
    pub fn Z3_fixedpoint_add_cover(
        c: Z3_context,
        d: Z3_fixedpoint,
        level: ::core::ffi::c_int,
        pred: Z3_func_decl,
        property: Z3_ast,
    );

    /// Retrieve statistics information from the last call to [`Z3_fixedpoint_query`].
    pub fn Z3_fixedpoint_get_statistics(c: Z3_context, d: Z3_fixedpoint) -> Option<Z3_stats>;

    /// Register relation as Fixedpoint defined.
    /// Fixedpoint defined relations have least-fixedpoint semantics.
    /// For example, the relation is empty if it does not occur
    /// in a head or a fact.
    pub fn Z3_fixedpoint_register_relation(c: Z3_context, d: Z3_fixedpoint, f: Z3_func_decl);

    /// Configure the predicate representation.
    ///
    /// It sets the predicate to use a set of domains given by the list of symbols.
    /// The domains given by the list of symbols must belong to a set
    /// of built-in domains.
    pub fn Z3_fixedpoint_set_predicate_representation(
        c: Z3_context,
        d: Z3_fixedpoint,
        f: Z3_func_decl,
        num_relations: ::core::ffi::c_uint,
        relation_kinds: *const Z3_symbol,
    );

    /// Retrieve set of rules from fixedpoint context.
    pub fn Z3_fixedpoint_get_rules(c: Z3_context, f: Z3_fixedpoint) -> Option<Z3_ast_vector>;

    /// Retrieve set of background assertions from fixedpoint context.
    pub fn Z3_fixedpoint_get_assertions(c: Z3_context, f: Z3_fixedpoint) -> Option<Z3_ast_vector>;

    /// Set parameters on fixedpoint context.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_get_help`]
    /// - [`Z3_fixedpoint_get_param_descrs`]
    pub fn Z3_fixedpoint_set_params(c: Z3_context, f: Z3_fixedpoint, p: Z3_params);

    /// Return a string describing all fixedpoint available parameters.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_get_param_descrs`]
    /// - [`Z3_fixedpoint_set_params`]
    pub fn Z3_fixedpoint_get_help(c: Z3_context, f: Z3_fixedpoint) -> Z3_string;

    /// Return the parameter description set for the given fixedpoint object.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_get_help`]
    /// - [`Z3_fixedpoint_set_params`]
    pub fn Z3_fixedpoint_get_param_descrs(
        c: Z3_context,
        f: Z3_fixedpoint,
    ) -> Option<Z3_param_descrs>;

    /// Print the current rules and background axioms as a string.
    /// - `c`: - context.
    /// - `f`: - fixedpoint context.
    /// - `num_queries`: - number of additional queries to print.
    /// - `queries`: - additional queries.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_from_file`]
    /// - [`Z3_fixedpoint_from_string`]
    pub fn Z3_fixedpoint_to_string(
        c: Z3_context,
        f: Z3_fixedpoint,
        num_queries: ::core::ffi::c_uint,
        queries: *mut Z3_ast,
    ) -> Z3_string;

    /// Parse an SMT-LIB2 string with fixedpoint rules.
    /// Add the rules to the current fixedpoint context.
    /// Return the set of queries in the string.
    ///
    /// - `c`: - context.
    /// - `f`: - fixedpoint context.
    /// - `s`: - string containing SMT2 specification.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_from_file`]
    /// - [`Z3_fixedpoint_to_string`]
    pub fn Z3_fixedpoint_from_string(
        c: Z3_context,
        f: Z3_fixedpoint,
        s: Z3_string,
    ) -> Option<Z3_ast_vector>;

    /// Parse an SMT-LIB2 file with fixedpoint rules.
    /// Add the rules to the current fixedpoint context.
    /// Return the set of queries in the file.
    ///
    /// - `c`: - context.
    /// - `f`: - fixedpoint context.
    /// - `s`: - path to file containing SMT2 specification.
    ///
    /// # See also:
    ///
    /// - [`Z3_fixedpoint_from_string`]
    /// - [`Z3_fixedpoint_to_string`]
    pub fn Z3_fixedpoint_from_file(
        c: Z3_context,
        f: Z3_fixedpoint,
        s: Z3_string,
    ) -> Option<Z3_ast_vector>;

    /// String less-than lexicographic comparison operation.
    /// Return a new AST node `Bool`.
    pub fn Z3_mk_str_lt(c: Z3_context, lhs: Z3_ast, rhs: Z3_ast) -> Option<Z3_ast>;

    /// String less-than-or-equal lexicographic comparison operation.
    /// Return a new AST node `Bool`.
    pub fn Z3_mk_str_le(c: Z3_context, lhs: Z3_ast, rhs: Z3_ast) -> Option<Z3_ast>;
}
/// The following utilities allows adding user-defined domains.
pub type Z3_fixedpoint_reduce_assign_callback_fptr = ::core::option::Option<
    unsafe extern "C" fn(
        arg1: *mut ::core::ffi::c_void,
        arg2: Z3_func_decl,
        arg3: ::core::ffi::c_uint,
        arg4: *const Z3_ast,
        arg5: ::core::ffi::c_uint,
        arg6: *const Z3_ast,
    ),
>;
pub type Z3_fixedpoint_reduce_app_callback_fptr = ::core::option::Option<
    unsafe extern "C" fn(
        arg1: *mut ::core::ffi::c_void,
        arg2: Z3_func_decl,
        arg3: ::core::ffi::c_uint,
        arg4: *const Z3_ast,
        arg5: *mut Z3_ast,
    ),
>;
unsafe extern "C" {
    /// Initialize the context with a user-defined state.
    pub fn Z3_fixedpoint_init(c: Z3_context, d: Z3_fixedpoint, state: *mut ::core::ffi::c_void);

    /// Register a callback to destructive updates.
    ///
    /// Registers are identified with terms encoded as fresh constants,
    pub fn Z3_fixedpoint_set_reduce_assign_callback(
        c: Z3_context,
        d: Z3_fixedpoint,
        cb: Z3_fixedpoint_reduce_assign_callback_fptr,
    );

    /// Register a callback for building terms based on the relational operators.
    pub fn Z3_fixedpoint_set_reduce_app_callback(
        c: Z3_context,
        d: Z3_fixedpoint,
        cb: Z3_fixedpoint_reduce_app_callback_fptr,
    );
}

pub type Z3_fixedpoint_new_lemma_eh = ::core::option::Option<
    unsafe extern "C" fn(
        state: *mut ::core::ffi::c_void,
        lemma: Z3_ast,
        level: ::core::ffi::c_uint,
    ),
>;
pub type Z3_fixedpoint_predecessor_eh =
    ::core::option::Option<unsafe extern "C" fn(state: *mut ::core::ffi::c_void)>;
pub type Z3_fixedpoint_unfold_eh =
    ::core::option::Option<unsafe extern "C" fn(state: *mut ::core::ffi::c_void)>;

unsafe extern "C" {
    /// Set export callback for lemmas.
    pub fn Z3_fixedpoint_add_callback(
        ctx: Z3_context,
        f: Z3_fixedpoint,
        state: *mut ::core::ffi::c_void,
        new_lemma_eh: Z3_fixedpoint_new_lemma_eh,
        predecessor_eh: Z3_fixedpoint_predecessor_eh,
        unfold_eh: Z3_fixedpoint_unfold_eh,
    );

    pub fn Z3_fixedpoint_add_constraint(
        c: Z3_context,
        d: Z3_fixedpoint,
        e: Z3_ast,
        lvl: ::core::ffi::c_uint,
    );

    /// Create a new optimize context.
    ///
    /// NOTE: User must use [`Z3_optimize_inc_ref`]
    /// and [`Z3_optimize_dec_ref`] to manage optimize objects,
    /// even if the context was created using [`Z3_mk_context`]
    /// instead of [`Z3_mk_context_rc`].
    pub fn Z3_mk_optimize(c: Z3_context) -> Option<Z3_optimize>;

    /// Increment the reference counter of the given optimize context
    pub fn Z3_optimize_inc_ref(c: Z3_context, d: Z3_optimize);

    /// Decrement the reference counter of the given optimize context.
    pub fn Z3_optimize_dec_ref(c: Z3_context, d: Z3_optimize);

    /// Assert hard constraint to the optimization context.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_assert_and_track`]
    /// - [`Z3_optimize_assert_soft`]
    pub fn Z3_optimize_assert(c: Z3_context, o: Z3_optimize, a: Z3_ast);

    /// Assert tracked hard constraint to the optimization context.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_assert`]
    /// - [`Z3_optimize_assert_soft`]
    pub fn Z3_optimize_assert_and_track(c: Z3_context, o: Z3_optimize, a: Z3_ast, t: Z3_ast);

    /// Assert soft constraint to the optimization context.
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `a`: - formula
    /// - `weight`: - a positive weight, penalty for violating soft constraint
    /// - `id`: - optional identifier to group soft constraints
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_assert`]
    /// - [`Z3_optimize_assert_and_track`]
    pub fn Z3_optimize_assert_soft(
        c: Z3_context,
        o: Z3_optimize,
        a: Z3_ast,
        weight: Z3_string,
        id: Option<Z3_symbol>,
    ) -> ::core::ffi::c_uint;

    /// Add a maximization constraint.
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `t`: - arithmetical term
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_minimize`]
    pub fn Z3_optimize_maximize(c: Z3_context, o: Z3_optimize, t: Z3_ast) -> ::core::ffi::c_uint;

    /// Add a minimization constraint.
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `t`: - arithmetical term
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_maximize`]
    pub fn Z3_optimize_minimize(c: Z3_context, o: Z3_optimize, t: Z3_ast) -> ::core::ffi::c_uint;

    /// Create a backtracking point.
    ///
    /// The optimize solver contains a set of rules, added facts and assertions.
    /// The set of rules, facts and assertions are restored upon calling [`Z3_optimize_pop`].
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_pop`]
    pub fn Z3_optimize_push(c: Z3_context, d: Z3_optimize);

    /// Backtrack one level.
    ///
    /// # Preconditions:
    ///
    /// - The number of calls to pop cannot exceed calls to push.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_push`]
    pub fn Z3_optimize_pop(c: Z3_context, d: Z3_optimize);

    /// Check consistency and produce optimal values.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `num_assumptions`: - number of additional assumptions
    /// - `assumptions`: - the additional assumptions
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_reason_unknown`]
    /// - [`Z3_optimize_get_model`]
    /// - [`Z3_optimize_get_statistics`]
    /// - [`Z3_optimize_get_unsat_core`]
    pub fn Z3_optimize_check(
        c: Z3_context,
        o: Z3_optimize,
        num_assumptions: ::core::ffi::c_uint,
        assumptions: *const Z3_ast,
    ) -> Z3_lbool;

    /// Retrieve a string that describes the last status returned by [`Z3_optimize_check`].
    ///
    /// Use this method when [`Z3_optimize_check`] returns `Z3_L_UNDEF`.
    pub fn Z3_optimize_get_reason_unknown(c: Z3_context, d: Z3_optimize) -> Z3_string;

    /// Retrieve the model for the last [`Z3_optimize_check`].
    ///
    /// The error handler is invoked if a model is not available because
    /// the commands above were not invoked for the given optimization
    /// solver, or if the result was `Z3_L_FALSE`.
    pub fn Z3_optimize_get_model(c: Z3_context, o: Z3_optimize) -> Option<Z3_model>;

    /// Retrieve the unsat core for the last [`Z3_optimize_check`].
    ///
    /// The unsat core is a subset of the assumptions `a`.
    pub fn Z3_optimize_get_unsat_core(c: Z3_context, o: Z3_optimize) -> Option<Z3_ast_vector>;

    /// Set parameters on optimization context.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `p`: - parameters
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_help`]
    /// - [`Z3_optimize_get_param_descrs`]
    pub fn Z3_optimize_set_params(c: Z3_context, o: Z3_optimize, p: Z3_params);

    /// Return the parameter description set for the given optimize object.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_help`]
    /// - [`Z3_optimize_set_params`]
    pub fn Z3_optimize_get_param_descrs(c: Z3_context, o: Z3_optimize) -> Option<Z3_param_descrs>;

    /// Retrieve lower bound value or approximation for the i'th optimization objective.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `idx`: - index of optimization objective
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_upper`]
    /// - [`Z3_optimize_get_lower_as_vector`]
    /// - [`Z3_optimize_get_upper_as_vector`]
    pub fn Z3_optimize_get_lower(
        c: Z3_context,
        o: Z3_optimize,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Retrieve upper bound value or approximation for the i'th optimization objective.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `idx`: - index of optimization objective
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_lower`]
    /// - [`Z3_optimize_get_lower_as_vector`]
    /// - [`Z3_optimize_get_upper_as_vector`]
    pub fn Z3_optimize_get_upper(
        c: Z3_context,
        o: Z3_optimize,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Retrieve lower bound value or approximation for the i'th optimization objective.
    /// The returned vector is of length 3. It always contains numerals.
    /// The three numerals are coefficients a, b, c and encode the result of [`Z3_optimize_get_lower`]
    /// a * infinity + b + c * epsilon.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `idx`: - index of optimization objective
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_lower`]
    /// - [`Z3_optimize_get_upper`]
    /// - [`Z3_optimize_get_upper_as_vector`]
    pub fn Z3_optimize_get_lower_as_vector(
        c: Z3_context,
        o: Z3_optimize,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_ast_vector>;

    /// Retrieve upper bound value or approximation for the i'th optimization objective.
    ///
    /// - `c`: - context
    /// - `o`: - optimization context
    /// - `idx`: - index of optimization objective
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_lower`]
    /// - [`Z3_optimize_get_upper`]
    /// - [`Z3_optimize_get_lower_as_vector`]
    pub fn Z3_optimize_get_upper_as_vector(
        c: Z3_context,
        o: Z3_optimize,
        idx: ::core::ffi::c_uint,
    ) -> Option<Z3_ast_vector>;

    /// Print the current context as a string.
    /// - `c`: - context.
    /// - `o`: - optimization context.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_from_file`]
    /// - [`Z3_optimize_from_string`]
    pub fn Z3_optimize_to_string(c: Z3_context, o: Z3_optimize) -> Z3_string;

    /// Parse an SMT-LIB2 string with assertions,
    /// soft constraints and optimization objectives.
    /// Add the parsed constraints and objectives to the optimization context.
    ///
    /// - `c`: - context.
    /// - `o`: - optimize context.
    /// - `s`: - string containing SMT2 specification.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_from_file`]
    /// - [`Z3_optimize_to_string`]
    pub fn Z3_optimize_from_string(c: Z3_context, o: Z3_optimize, s: Z3_string);

    /// Parse an SMT-LIB2 file with assertions,
    /// soft constraints and optimization objectives.
    /// Add the parsed constraints and objectives to the optimization context.
    ///
    /// - `c`: - context.
    /// - `o`: - optimize context.
    /// - `s`: - string containing SMT2 specification.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_from_string`]
    /// - [`Z3_optimize_to_string`]
    pub fn Z3_optimize_from_file(c: Z3_context, o: Z3_optimize, s: Z3_string);

    /// Return a string containing a description of parameters accepted by optimize.
    ///
    /// # See also:
    ///
    /// - [`Z3_optimize_get_param_descrs`]
    /// - [`Z3_optimize_set_params`]
    pub fn Z3_optimize_get_help(c: Z3_context, t: Z3_optimize) -> Z3_string;

    /// Retrieve statistics information from the last call to [`Z3_optimize_check`]
    pub fn Z3_optimize_get_statistics(c: Z3_context, d: Z3_optimize) -> Option<Z3_stats>;

    /// Return the set of asserted formulas on the optimization context.
    pub fn Z3_optimize_get_assertions(c: Z3_context, o: Z3_optimize) -> Option<Z3_ast_vector>;

    /// Return objectives on the optimization context.
    /// If the objective function is a max-sat objective it is returned
    /// as a Pseudo-Boolean (minimization) sum of the form (+ (if f1 w1 0) (if f2 w2 0) ...)
    /// If the objective function is entered as a maximization objective, then return
    /// the corresponding minimization objective. In this way the resulting objective
    /// function is always returned as a minimization objective.
    pub fn Z3_optimize_get_objectives(c: Z3_context, o: Z3_optimize) -> Option<Z3_ast_vector>;

    /// Create the `RoundingMode` sort.
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_away`] or [`Z3_mk_fpa_rna`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_even`] or [`Z3_mk_fpa_rne`]
    /// - [`Z3_mk_fpa_round_toward_negative`] or [`Z3_mk_fpa_rtn`]
    /// - [`Z3_mk_fpa_round_toward_positive`] or [`Z3_mk_fpa_rtp`]
    /// - [`Z3_mk_fpa_round_toward_zero`] or [`Z3_mk_fpa_rtz`]
    pub fn Z3_mk_fpa_rounding_mode_sort(c: Z3_context) -> Option<Z3_sort>;

    /// Create a numeral of `RoundingMode` sort which represents the `NearestTiesToEven` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_rne`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_away`]
    /// - [`Z3_mk_fpa_round_toward_negative`]
    /// - [`Z3_mk_fpa_round_toward_positive`]
    /// - [`Z3_mk_fpa_round_toward_zero`]
    pub fn Z3_mk_fpa_round_nearest_ties_to_even(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `NearestTiesToEven` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_round_nearest_ties_to_even`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_rna`]
    /// - [`Z3_mk_fpa_rtn`]
    /// - [`Z3_mk_fpa_rtp`]
    /// - [`Z3_mk_fpa_rtz`]
    pub fn Z3_mk_fpa_rne(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `NearestTiesToAway` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_rna`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_even`]
    /// - [`Z3_mk_fpa_round_toward_negative`]
    /// - [`Z3_mk_fpa_round_toward_positive`]
    /// - [`Z3_mk_fpa_round_toward_zero`]
    pub fn Z3_mk_fpa_round_nearest_ties_to_away(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `NearestTiesToAway` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_round_nearest_ties_to_away`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_rne`]
    /// - [`Z3_mk_fpa_rtn`]
    /// - [`Z3_mk_fpa_rtp`]
    /// - [`Z3_mk_fpa_rtz`]
    pub fn Z3_mk_fpa_rna(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardPositive` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_rtp`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_away`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_even`]
    /// - [`Z3_mk_fpa_round_toward_negative`]
    /// - [`Z3_mk_fpa_round_toward_zero`]
    pub fn Z3_mk_fpa_round_toward_positive(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardPositive` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_round_toward_positive`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_rna`]
    /// - [`Z3_mk_fpa_rne`]
    /// - [`Z3_mk_fpa_rtn`]
    /// - [`Z3_mk_fpa_rtz`]
    pub fn Z3_mk_fpa_rtp(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardNegative` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_rtn`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_away`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_even`]
    /// - [`Z3_mk_fpa_round_toward_positive`]
    /// - [`Z3_mk_fpa_round_toward_zero`]
    pub fn Z3_mk_fpa_round_toward_negative(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardNegative` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_round_toward_negative`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_rna`]
    /// - [`Z3_mk_fpa_rne`]
    /// - [`Z3_mk_fpa_rtp`]
    /// - [`Z3_mk_fpa_rtz`]
    pub fn Z3_mk_fpa_rtn(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardZero` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_rtz`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_away`]
    /// - [`Z3_mk_fpa_round_nearest_ties_to_even`]
    /// - [`Z3_mk_fpa_round_toward_negative`]
    /// - [`Z3_mk_fpa_round_toward_positive`]
    pub fn Z3_mk_fpa_round_toward_zero(c: Z3_context) -> Option<Z3_ast>;

    /// Create a numeral of `RoundingMode` sort which represents the `TowardZero` rounding mode.
    ///
    /// This is the same as [`Z3_mk_fpa_round_toward_zero`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_rounding_mode_sort`]
    /// - [`Z3_mk_fpa_rna`]
    /// - [`Z3_mk_fpa_rne`]
    /// - [`Z3_mk_fpa_rtn`]
    /// - [`Z3_mk_fpa_rtp`]
    pub fn Z3_mk_fpa_rtz(c: Z3_context) -> Option<Z3_ast>;

    /// Create a `FloatingPoint` sort.
    ///
    /// - `c`: logical context
    /// - `ebits`: number of exponent bits
    /// - `sbits`: number of significand bits
    ///
    /// NOTE: ebits must be larger than 1 and sbits must be larger than 2.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_half`] or [`Z3_mk_fpa_sort_16`]
    /// - [`Z3_mk_fpa_sort_single`] or [`Z3_mk_fpa_sort_32`]
    /// - [`Z3_mk_fpa_sort_double`] or [`Z3_mk_fpa_sort_64`]
    /// - [`Z3_mk_fpa_sort_quadruple`] or [`Z3_mk_fpa_sort_128`]
    pub fn Z3_mk_fpa_sort(
        c: Z3_context,
        ebits: ::core::ffi::c_uint,
        sbits: ::core::ffi::c_uint,
    ) -> Option<Z3_sort>;

    /// Create the half-precision (16-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_16`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_single`]
    /// - [`Z3_mk_fpa_sort_double`]
    /// - [`Z3_mk_fpa_sort_quadruple`]
    pub fn Z3_mk_fpa_sort_half(c: Z3_context) -> Option<Z3_sort>;

    /// Create the half-precision (16-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_half`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_32`]
    /// - [`Z3_mk_fpa_sort_64`]
    /// - [`Z3_mk_fpa_sort_128`]
    pub fn Z3_mk_fpa_sort_16(c: Z3_context) -> Option<Z3_sort>;

    /// Create the single-precision (32-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_32`].
    ///
    /// - `c`: logical context.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_half`]
    /// - [`Z3_mk_fpa_sort_double`]
    /// - [`Z3_mk_fpa_sort_quadruple`]
    pub fn Z3_mk_fpa_sort_single(c: Z3_context) -> Option<Z3_sort>;

    /// Create the single-precision (32-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_single`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_16`]
    /// - [`Z3_mk_fpa_sort_64`]
    /// - [`Z3_mk_fpa_sort_128`]
    pub fn Z3_mk_fpa_sort_32(c: Z3_context) -> Option<Z3_sort>;

    /// Create the double-precision (64-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_64`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_half`]
    /// - [`Z3_mk_fpa_sort_single`]
    /// - [`Z3_mk_fpa_sort_quadruple`]
    pub fn Z3_mk_fpa_sort_double(c: Z3_context) -> Option<Z3_sort>;

    /// Create the double-precision (64-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_double`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_16`]
    /// - [`Z3_mk_fpa_sort_32`]
    /// - [`Z3_mk_fpa_sort_128`]
    pub fn Z3_mk_fpa_sort_64(c: Z3_context) -> Option<Z3_sort>;

    /// Create the quadruple-precision (128-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_128`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_half`]
    /// - [`Z3_mk_fpa_sort_single`]
    /// - [`Z3_mk_fpa_sort_double`]
    pub fn Z3_mk_fpa_sort_quadruple(c: Z3_context) -> Option<Z3_sort>;

    /// Create the quadruple-precision (128-bit) `FloatingPoint` sort.
    ///
    /// This is the same as [`Z3_mk_fpa_sort_quadruple`].
    ///
    /// - `c`: logical context
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_sort_16`]
    /// - [`Z3_mk_fpa_sort_32`]
    /// - [`Z3_mk_fpa_sort_64`]
    pub fn Z3_mk_fpa_sort_128(c: Z3_context) -> Option<Z3_sort>;

    /// Create a floating-point NaN of sort `s`.
    ///
    /// - `c`: logical context
    /// - `s`: target sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_inf`]
    /// - [`Z3_mk_fpa_is_nan`]
    /// - [`Z3_mk_fpa_zero`]
    pub fn Z3_mk_fpa_nan(c: Z3_context, s: Z3_sort) -> Option<Z3_ast>;

    /// Create a floating-point infinity of sort `s`.
    ///
    /// - `c`: logical context
    /// - `s`: target sort
    /// - `negative`: indicates whether the result should be negative
    ///
    /// When `negative` is true, -oo will be generated instead of +oo.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_nan`]
    /// - [`Z3_mk_fpa_zero`]
    pub fn Z3_mk_fpa_inf(c: Z3_context, s: Z3_sort, negative: bool) -> Option<Z3_ast>;

    /// Create a floating-point zero of sort `s`.
    ///
    /// - `c`: logical context
    /// - `s`: target sort
    /// - `negative`: indicates whether the result should be negative
    ///
    /// When `negative` is true, -zero will be generated instead of +zero.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_inf`]
    /// - [`Z3_mk_fpa_is_zero`]
    /// - [`Z3_mk_fpa_nan`]
    pub fn Z3_mk_fpa_zero(c: Z3_context, s: Z3_sort, negative: bool) -> Option<Z3_ast>;

    /// Create an expression of `FloatingPoint` sort from three bit-vector expressions.
    ///
    /// This is the operator named `fp` in the SMT FP theory definition.
    /// Note that `sign` is required to be a bit-vector of size 1. Significand and exponent
    /// are required to be longer than 1 and 2 respectively. The `FloatingPoint` sort
    /// of the resulting expression is automatically determined from the bit-vector sizes
    /// of the arguments. The exponent is assumed to be in IEEE-754 biased representation.
    ///
    /// - `c`: logical context
    /// - `sgn`: sign
    /// - `exp`: exponent
    /// - `sig`: significand
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_numeral_double`]
    /// - [`Z3_mk_fpa_numeral_float`]
    /// - [`Z3_mk_fpa_numeral_int`]
    /// - [`Z3_mk_fpa_numeral_int_uint`]
    /// - [`Z3_mk_fpa_numeral_int64_uint64`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_fp(c: Z3_context, sgn: Z3_ast, exp: Z3_ast, sig: Z3_ast) -> Option<Z3_ast>;

    /// Create a numeral of `FloatingPoint` sort from a float.
    ///
    /// This function is used to create numerals that fit in a float value.
    /// It is slightly faster than [`Z3_mk_numeral`] since it is not necessary to parse a string.
    ///
    /// - `c`: logical context
    /// - `v`: value
    /// - `ty`: sort
    ///
    /// `ty` must be a `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_fp`]
    /// - [`Z3_mk_fpa_numeral_double`]
    /// - [`Z3_mk_fpa_numeral_int`]
    /// - [`Z3_mk_fpa_numeral_int_uint`]
    /// - [`Z3_mk_fpa_numeral_int64_uint64`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_numeral_float(c: Z3_context, v: f32, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a numeral of `FloatingPoint` sort from a double.
    ///
    /// This function is used to create numerals that fit in a double value.
    /// It is slightly faster than [`Z3_mk_numeral`]
    ///
    /// - `c`: logical context
    /// - `v`: value
    /// - `ty`: sort
    ///
    /// `ty` must be a `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_fp`]
    /// - [`Z3_mk_fpa_numeral_float`]
    /// - [`Z3_mk_fpa_numeral_int`]
    /// - [`Z3_mk_fpa_numeral_int_uint`]
    /// - [`Z3_mk_fpa_numeral_int64_uint64`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_numeral_double(c: Z3_context, v: f64, ty: Z3_sort) -> Option<Z3_ast>;

    /// Create a numeral of `FloatingPoint` sort from a signed integer.
    ///
    /// - `c`: logical context
    /// - `v`: value
    /// - `ty`: result sort
    ///
    /// `ty` must be a `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_fp`]
    /// - [`Z3_mk_fpa_numeral_double`]
    /// - [`Z3_mk_fpa_numeral_float`]
    /// - [`Z3_mk_fpa_numeral_int_uint`]
    /// - [`Z3_mk_fpa_numeral_int64_uint64`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_numeral_int(
        c: Z3_context,
        v: ::core::ffi::c_int,
        ty: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Create a numeral of `FloatingPoint` sort from a sign bit and two integers.
    ///
    /// - `c`: logical context
    /// - `sgn`: sign bit (true == negative)
    /// - `sig`: significand
    /// - `exp`: exponent
    /// - `ty`: result sort
    ///
    /// `ty` must be a `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_fp`]
    /// - [`Z3_mk_fpa_numeral_double`]
    /// - [`Z3_mk_fpa_numeral_float`]
    /// - [`Z3_mk_fpa_numeral_int`]
    /// - [`Z3_mk_fpa_numeral_int64_uint64`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_numeral_int_uint(
        c: Z3_context,
        sgn: bool,
        exp: ::core::ffi::c_int,
        sig: ::core::ffi::c_uint,
        ty: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Create a numeral of `FloatingPoint` sort from a sign bit and two 64-bit integers.
    ///
    /// - `c`: logical context
    /// - `sgn`: sign bit (true == negative)
    /// - `sig`: significand
    /// - `exp`: exponent
    /// - `ty`: result sort
    ///
    /// `ty` must be a `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_fp`]
    /// - [`Z3_mk_fpa_numeral_double`]
    /// - [`Z3_mk_fpa_numeral_float`]
    /// - [`Z3_mk_fpa_numeral_int`]
    /// - [`Z3_mk_fpa_numeral_int_uint`]
    /// - [`Z3_mk_numeral`]
    pub fn Z3_mk_fpa_numeral_int64_uint64(
        c: Z3_context,
        sgn: bool,
        exp: i64,
        sig: u64,
        ty: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Floating-point absolute value
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_negative`]
    /// - [`Z3_mk_fpa_is_positive`]
    /// - [`Z3_mk_fpa_neg`]
    pub fn Z3_mk_fpa_abs(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point negation
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_abs`]
    /// - [`Z3_mk_fpa_is_negative`]
    /// - [`Z3_mk_fpa_is_positive`]
    pub fn Z3_mk_fpa_neg(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point addition
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `rm` must be of `RoundingMode` sort, `t1` and `t2` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_add(c: Z3_context, rm: Z3_ast, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point subtraction
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `rm` must be of `RoundingMode` sort, `t1` and `t2` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_sub(c: Z3_context, rm: Z3_ast, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point multiplication
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `rm` must be of `RoundingMode` sort, `t1` and `t2` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_mul(c: Z3_context, rm: Z3_ast, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point division
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t1`: term of `FloatingPoint` sort.
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// The nodes `rm` must be of `RoundingMode` sort, `t1` and `t2` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_div(c: Z3_context, rm: Z3_ast, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point fused multiply-add.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    /// - `t3`: term of `FloatingPoint` sort
    ///
    /// The result is round((t1 * t2) + t3)
    ///
    /// `rm` must be of `RoundingMode` sort, `t1`, `t2`, and `t3` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_fma(
        c: Z3_context,
        rm: Z3_ast,
        t1: Z3_ast,
        t2: Z3_ast,
        t3: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Floating-point square root
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `rm` must be of `RoundingMode` sort, `t` must have `FloatingPoint` sort.
    pub fn Z3_mk_fpa_sqrt(c: Z3_context, rm: Z3_ast, t: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point remainder
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    pub fn Z3_mk_fpa_rem(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point roundToIntegral. Rounds a floating-point number to
    /// the closest integer, again represented as a floating-point number.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must be of `FloatingPoint` sort.
    pub fn Z3_mk_fpa_round_to_integral(c: Z3_context, rm: Z3_ast, t: Z3_ast) -> Option<Z3_ast>;

    /// Minimum of floating-point numbers.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_max`]
    pub fn Z3_mk_fpa_min(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Maximum of floating-point numbers.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_min`]
    pub fn Z3_mk_fpa_max(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point less than or equal.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_eq`]
    /// - [`Z3_mk_fpa_geq`]
    /// - [`Z3_mk_fpa_gt`]
    /// - [`Z3_mk_fpa_lt`]
    pub fn Z3_mk_fpa_leq(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point less than.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_eq`]
    /// - [`Z3_mk_fpa_geq`]
    /// - [`Z3_mk_fpa_gt`]
    /// - [`Z3_mk_fpa_leq`]
    pub fn Z3_mk_fpa_lt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point greater than or equal.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_eq`]
    /// - [`Z3_mk_fpa_gt`]
    /// - [`Z3_mk_fpa_leq`]
    /// - [`Z3_mk_fpa_lt`]
    pub fn Z3_mk_fpa_geq(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point greater than.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_eq`]
    /// - [`Z3_mk_fpa_geq`]
    /// - [`Z3_mk_fpa_leq`]
    /// - [`Z3_mk_fpa_lt`]
    pub fn Z3_mk_fpa_gt(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Floating-point equality.
    ///
    /// - `c`: logical context
    /// - `t1`: term of `FloatingPoint` sort
    /// - `t2`: term of `FloatingPoint` sort
    ///
    /// Note that this is IEEE 754 equality (as opposed to SMT-LIB =).
    ///
    /// `t1` and `t2` must have the same `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_geq`]
    /// - [`Z3_mk_fpa_gt`]
    /// - [`Z3_mk_fpa_leq`]
    /// - [`Z3_mk_fpa_lt`]
    pub fn Z3_mk_fpa_eq(c: Z3_context, t1: Z3_ast, t2: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a normal floating-point number.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_is_nan`]
    /// - [`Z3_mk_fpa_is_subnormal`]
    /// - [`Z3_mk_fpa_is_zero`]
    pub fn Z3_mk_fpa_is_normal(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a subnormal floating-point number.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_is_nan`]
    /// - [`Z3_mk_fpa_is_normal`]
    /// - [`Z3_mk_fpa_is_zero`]
    pub fn Z3_mk_fpa_is_subnormal(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a floating-point number with zero value, i.e., +zero or -zero.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_is_nan`]
    /// - [`Z3_mk_fpa_is_normal`]
    /// - [`Z3_mk_fpa_is_subnormal`]
    /// - [`Z3_mk_fpa_is_zero`]
    /// - [`Z3_mk_fpa_zero`]
    pub fn Z3_mk_fpa_is_zero(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a floating-point number representing +oo or -oo.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_inf`]
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_is_nan`]
    /// - [`Z3_mk_fpa_is_normal`]
    /// - [`Z3_mk_fpa_is_subnormal`]
    /// - [`Z3_mk_fpa_is_zero`]
    pub fn Z3_mk_fpa_is_infinite(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a NaN.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_is_infinite`]
    /// - [`Z3_mk_fpa_is_normal`]
    /// - [`Z3_mk_fpa_is_subnormal`]
    /// - [`Z3_mk_fpa_is_zero`]
    /// - [`Z3_mk_fpa_nan`]
    pub fn Z3_mk_fpa_is_nan(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a negative floating-point number.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_abs`]
    /// - [`Z3_mk_fpa_is_positive`]
    /// - [`Z3_mk_fpa_neg`]
    pub fn Z3_mk_fpa_is_negative(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Predicate indicating whether `t` is a positive floating-point number.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort.
    ///
    /// # See also:
    ///
    /// - [`Z3_mk_fpa_abs`]
    /// - [`Z3_mk_fpa_is_negative`]
    /// - [`Z3_mk_fpa_neg`]
    pub fn Z3_mk_fpa_is_positive(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Conversion of a single IEEE 754-2008 bit-vector into a floating-point number.
    ///
    /// Produces a term that represents the conversion of a bit-vector term `bv` to a
    /// floating-point term of sort `s`.
    ///
    /// - `c`: logical context
    /// - `bv`: a bit-vector term
    /// - `s`: floating-point sort
    ///
    /// `s` must be a `FloatingPoint` sort, `t` must be of bit-vector sort, and the bit-vector
    /// size of `bv` must be equal to ebits+sbits of `s`. The format of the bit-vector is
    /// as defined by the IEEE 754-2008 interchange format.
    pub fn Z3_mk_fpa_to_fp_bv(c: Z3_context, bv: Z3_ast, s: Z3_sort) -> Option<Z3_ast>;

    /// Conversion of a `FloatingPoint` term into another term of different `FloatingPoint` sort.
    ///
    /// Produces a term that represents the conversion of a floating-point term `t` to a
    /// floating-point term of sort `s`. If necessary, the result will be rounded according
    /// to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of `FloatingPoint` sort
    /// - `s`: floating-point sort
    ///
    /// `s` must be a `FloatingPoint` sort, `rm` must be of `RoundingMode` sort, `t` must be
    /// of floating-point sort.
    pub fn Z3_mk_fpa_to_fp_float(
        c: Z3_context,
        rm: Z3_ast,
        t: Z3_ast,
        s: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Conversion of a term of real sort into a term of `FloatingPoint` sort.
    ///
    /// Produces a term that represents the conversion of term `t` of real sort into a
    /// floating-point term of sort `s`. If necessary, the result will be rounded according
    /// to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of Real sort
    /// - `s`: floating-point sort
    ///
    /// `s` must be a `FloatingPoint` sort, `rm` must be of `RoundingMode` sort, `t` must be of
    /// Real sort.
    pub fn Z3_mk_fpa_to_fp_real(c: Z3_context, rm: Z3_ast, t: Z3_ast, s: Z3_sort)
    -> Option<Z3_ast>;

    /// Conversion of a 2's complement signed bit-vector term into a term of `FloatingPoint` sort.
    ///
    /// Produces a term that represents the conversion of the bit-vector term `t` into a
    /// floating-point term of sort `s`. The bit-vector `t` is taken to be in signed
    /// 2's complement format. If necessary, the result will be rounded according
    /// to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of bit-vector sort
    /// - `s`: floating-point sort
    ///
    /// `s` must be a `FloatingPoint` sort, `rm` must be of `RoundingMode` sort, `t` must be
    /// of bit-vector sort.
    pub fn Z3_mk_fpa_to_fp_signed(
        c: Z3_context,
        rm: Z3_ast,
        t: Z3_ast,
        s: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Conversion of a 2's complement unsigned bit-vector term into a term of `FloatingPoint` sort.
    ///
    /// Produces a term that represents the conversion of the bit-vector term `t` into a
    /// floating-point term of sort `s`. The bit-vector `t` is taken to be in unsigned
    /// 2's complement format. If necessary, the result will be rounded according
    /// to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of bit-vector sort
    /// - `s`: floating-point sort
    ///
    /// `s` must be a `FloatingPoint` sort, `rm` must be of `RoundingMode` sort, `t` must be
    /// of bit-vector sort.
    pub fn Z3_mk_fpa_to_fp_unsigned(
        c: Z3_context,
        rm: Z3_ast,
        t: Z3_ast,
        s: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Conversion of a floating-point term into an unsigned bit-vector.
    ///
    /// Produces a term that represents the conversion of the floating-point term `t` into a
    /// bit-vector term of size `sz` in unsigned 2's complement format. If necessary, the result
    /// will be rounded according to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of `FloatingPoint` sort
    /// - `sz`: size of the resulting bit-vector
    pub fn Z3_mk_fpa_to_ubv(
        c: Z3_context,
        rm: Z3_ast,
        t: Z3_ast,
        sz: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Conversion of a floating-point term into a signed bit-vector.
    ///
    /// Produces a term that represents the conversion of the floating-point term `t` into a
    /// bit-vector term of size `sz` in signed 2's complement format. If necessary, the result
    /// will be rounded according to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `t`: term of `FloatingPoint` sort
    /// - `sz`: size of the resulting bit-vector
    pub fn Z3_mk_fpa_to_sbv(
        c: Z3_context,
        rm: Z3_ast,
        t: Z3_ast,
        sz: ::core::ffi::c_uint,
    ) -> Option<Z3_ast>;

    /// Conversion of a floating-point term into a real-numbered term.
    ///
    /// Produces a term that represents the conversion of the floating-point term `t` into a
    /// real number. Note that this type of conversion will often result in non-linear
    /// constraints over real terms.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    pub fn Z3_mk_fpa_to_real(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Retrieves the number of bits reserved for the exponent in a `FloatingPoint` sort.
    ///
    /// - `c`: logical context
    /// - `s`: `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_get_sbits`]
    pub fn Z3_fpa_get_ebits(c: Z3_context, s: Z3_sort) -> ::core::ffi::c_uint;

    /// Retrieves the number of bits reserved for the significand in a `FloatingPoint` sort.
    ///
    /// - `c`: logical context
    /// - `s`: `FloatingPoint` sort
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_get_ebits`]
    pub fn Z3_fpa_get_sbits(c: Z3_context, s: Z3_sort) -> ::core::ffi::c_uint;

    /// Checks whether a given floating-point numeral is a NaN.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_inf`]
    /// - [`Z3_fpa_is_numeral_normal`]
    /// - [`Z3_fpa_is_numeral_subnormal`]
    /// - [`Z3_fpa_is_numeral_zero`]
    pub fn Z3_fpa_is_numeral_nan(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is a +oo or -oo.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_nan`]
    /// - [`Z3_fpa_is_numeral_normal`]
    /// - [`Z3_fpa_is_numeral_subnormal`]
    /// - [`Z3_fpa_is_numeral_zero`]
    pub fn Z3_fpa_is_numeral_inf(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is +zero or -zero.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_inf`]
    /// - [`Z3_fpa_is_numeral_nan`]
    /// - [`Z3_fpa_is_numeral_normal`]
    /// - [`Z3_fpa_is_numeral_subnormal`]
    pub fn Z3_fpa_is_numeral_zero(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is normal.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_inf`]
    /// - [`Z3_fpa_is_numeral_nan`]
    /// - [`Z3_fpa_is_numeral_subnormal`]
    /// - [`Z3_fpa_is_numeral_zero`]
    pub fn Z3_fpa_is_numeral_normal(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is subnormal.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_inf`]
    /// - [`Z3_fpa_is_numeral_nan`]
    /// - [`Z3_fpa_is_numeral_normal`]
    /// - [`Z3_fpa_is_numeral_zero`]
    pub fn Z3_fpa_is_numeral_subnormal(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is positive.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_negative`]
    pub fn Z3_fpa_is_numeral_positive(c: Z3_context, t: Z3_ast) -> bool;

    /// Checks whether a given floating-point numeral is negative.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// # See also:
    ///
    /// - [`Z3_fpa_is_numeral_positive`]
    pub fn Z3_fpa_is_numeral_negative(c: Z3_context, t: Z3_ast) -> bool;

    /// Retrieves the sign of a floating-point literal as a bit-vector expression.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// Remarks: NaN is an invalid argument.
    pub fn Z3_fpa_get_numeral_sign_bv(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Retrieves the significand of a floating-point literal as a bit-vector expression.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// Remarks: NaN is an invalid argument.
    pub fn Z3_fpa_get_numeral_significand_bv(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Retrieves the sign of a floating-point literal.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    /// - `sgn`: sign
    ///
    /// Remarks: sets `sgn` to 0 if `t` is positive and to 1 otherwise, except for
    /// NaN, which is an invalid argument.
    pub fn Z3_fpa_get_numeral_sign(c: Z3_context, t: Z3_ast, sgn: *mut ::core::ffi::c_int) -> bool;

    /// Return the significand value of a floating-point numeral as a string.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    ///
    /// Remarks: The significand `s` is always `0.0 <= s < 2.0`; the resulting string is
    /// long enough to represent the real significand precisely.
    pub fn Z3_fpa_get_numeral_significand_string(c: Z3_context, t: Z3_ast) -> Z3_string;

    /// Return the significand value of a floating-point numeral as a uint64.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    /// - `n`: pointer to output uint64
    ///
    /// Remarks: This function extracts the significand bits in `t`, without the
    /// hidden bit or normalization. Sets the `ErrorCode::InvalidArg` error code if the
    /// significand does not fit into a uint64. NaN is an invalid argument.
    pub fn Z3_fpa_get_numeral_significand_uint64(c: Z3_context, t: Z3_ast, n: *mut u64) -> bool;

    /// Return the exponent value of a floating-point numeral as a string.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    /// - `biased`: flag to indicate whether the result is in biased representation
    ///
    /// Remarks: This function extracts the exponent in `t`, without normalization.
    /// NaN is an invalid argument.
    pub fn Z3_fpa_get_numeral_exponent_string(c: Z3_context, t: Z3_ast, biased: bool) -> Z3_string;

    /// Return the exponent value of a floating-point numeral as a signed 64-bit integer
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    /// - `n`: exponent
    /// - `biased`: flag to indicate whether the result is in biased representation
    ///
    /// Remarks: This function extracts the exponent in `t`, without normalization.
    /// NaN is an invalid argument.
    pub fn Z3_fpa_get_numeral_exponent_int64(
        c: Z3_context,
        t: Z3_ast,
        n: *mut i64,
        biased: bool,
    ) -> bool;

    /// Retrieves the exponent of a floating-point literal as a bit-vector expression.
    ///
    /// - `c`: logical context
    /// - `t`: a floating-point numeral
    /// - `biased`: flag to indicate whether the result is in biased representation
    ///
    /// Remarks: This function extracts the exponent in `t`, without normalization.
    /// NaN is an invalid arguments.
    pub fn Z3_fpa_get_numeral_exponent_bv(c: Z3_context, t: Z3_ast, biased: bool)
    -> Option<Z3_ast>;

    /// Conversion of a floating-point term into a bit-vector term in IEEE 754-2008 format.
    ///
    /// - `c`: logical context
    /// - `t`: term of `FloatingPoint` sort
    ///
    /// `t` must have `FloatingPoint` sort. The size of the resulting bit-vector is automatically
    /// determined.
    ///
    /// Note that IEEE 754-2008 allows multiple different representations of NaN. This conversion
    /// knows only one NaN and it will always produce the same bit-vector representation of
    /// that NaN.
    pub fn Z3_mk_fpa_to_ieee_bv(c: Z3_context, t: Z3_ast) -> Option<Z3_ast>;

    /// Conversion of a real-sorted significand and an integer-sorted exponent into a term of `FloatingPoint` sort.
    ///
    /// Produces a term that represents the conversion of `sig * 2^exp` into a
    /// floating-point term of sort `s`. If necessary, the result will be rounded
    /// according to rounding mode `rm`.
    ///
    /// - `c`: logical context
    /// - `rm`: term of `RoundingMode` sort
    /// - `exp`: exponent term of Int sort
    /// - `sig`: significand term of Real sort
    /// - `s`: `FloatingPoint` sort
    ///
    /// `s` must be a `FloatingPoint` sort, `rm` must be of `RoundingMode` sort,
    /// `exp` must be of int sort, `sig` must be of real sort.
    pub fn Z3_mk_fpa_to_fp_int_real(
        c: Z3_context,
        rm: Z3_ast,
        exp: Z3_ast,
        sig: Z3_ast,
        s: Z3_sort,
    ) -> Option<Z3_ast>;

    /// Pose a query against the asserted rules at the given level.
    ///
    /// ```text
    /// query ::= (exists (bound-vars) query)
    /// |  literals
    /// ```
    ///
    /// query returns
    /// - `Z3_L_FALSE` if the query is unsatisfiable.
    /// - `Z3_L_TRUE` if the query is satisfiable. Obtain the answer by
    ///   calling [`Z3_fixedpoint_get_answer`].
    /// - `Z3_L_UNDEF` if the query was interrupted, timed out or otherwise failed.
    pub fn Z3_fixedpoint_query_from_lvl(
        c: Z3_context,
        d: Z3_fixedpoint,
        query: Z3_ast,
        lvl: ::core::ffi::c_uint,
    ) -> Z3_lbool;

    /// Retrieve a bottom-up (from query) sequence of ground facts
    ///
    /// The previous call to [`Z3_fixedpoint_query`]
    /// must have returned `Z3_L_TRUE`.
    pub fn Z3_fixedpoint_get_ground_sat_answer(c: Z3_context, d: Z3_fixedpoint) -> Option<Z3_ast>;

    /// Obtain the list of rules along the counterexample trace.
    pub fn Z3_fixedpoint_get_rules_along_trace(
        c: Z3_context,
        d: Z3_fixedpoint,
    ) -> Option<Z3_ast_vector>;

    /// Obtain the list of rules along the counterexample trace.
    pub fn Z3_fixedpoint_get_rule_names_along_trace(
        c: Z3_context,
        d: Z3_fixedpoint,
    ) -> Option<Z3_symbol>;

    /// Add an assumed invariant of predicate `pred`.
    ///
    /// Note: this functionality is Spacer specific.
    pub fn Z3_fixedpoint_add_invariant(
        c: Z3_context,
        d: Z3_fixedpoint,
        pred: Z3_func_decl,
        property: Z3_ast,
    );

    /// Retrieve reachable states of a predicate.
    ///
    /// Note: this functionality is Spacer specific.
    pub fn Z3_fixedpoint_get_reachable(
        c: Z3_context,
        d: Z3_fixedpoint,
        pred: Z3_func_decl,
    ) -> Option<Z3_ast>;

    /// Project variables given a model
    pub fn Z3_qe_model_project(
        c: Z3_context,
        m: Z3_model,
        num_bounds: ::core::ffi::c_uint,
        bound: *const Z3_app,
        body: Z3_ast,
    ) -> Option<Z3_ast>;

    /// Project variables given a model
    pub fn Z3_qe_model_project_skolem(
        c: Z3_context,
        m: Z3_model,
        num_bounds: ::core::ffi::c_uint,
        bound: *const Z3_app,
        body: Z3_ast,
        map: Z3_ast_map,
    ) -> Option<Z3_ast>;

    /// Extrapolates a model of a formula
    pub fn Z3_model_extrapolate(c: Z3_context, m: Z3_model, fml: Z3_ast) -> Option<Z3_ast>;

    /// Best-effort quantifier elimination
    pub fn Z3_qe_lite(c: Z3_context, vars: Z3_ast_vector, body: Z3_ast) -> Option<Z3_ast>;
}

#[cfg(not(windows))]
#[link(name = "z3")]
unsafe extern "C" {}

#[cfg(windows)]
#[link(name = "libz3")]
unsafe extern "C" {}
