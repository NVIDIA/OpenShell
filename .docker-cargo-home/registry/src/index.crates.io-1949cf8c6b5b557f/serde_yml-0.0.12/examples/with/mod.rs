/// This module contains the `singleton_map` example.
pub(crate) mod singleton_map;

/// This module contains the `singleton_map_recursive`
pub(crate) mod singleton_map_recursive;

/// This module contains the `singleton_map_enum_variants` example.
pub(crate) mod singleton_map_enum_variants;

/// This module contains the `singleton_map_recursive_deep_nesting` example.
pub(crate) mod singleton_map_recursive_deep_nesting;

/// This module contains the `singleton_map_recursive_serialize_deserialize` example.
pub(crate) mod singleton_map_recursive_serialize_deserialize;

/// This module contains the `singleton_map_optional` example.
pub(crate) mod singleton_map_optional;

/// This module contains the `singleton_map_with` example.
pub(crate) mod singleton_map_with;

/// This module contains the `singleton_map_recursive_optional` example.
pub(crate) mod singleton_map_recursive_optional;

/// This module contains the `singleton_map_recursive_with` example.
pub(crate) mod singleton_map_recursive_with;

/// This module contains the `singleton_map_with_custom_serialize` example.
pub(crate) mod singleton_map_with_custom_serialize;

/// This module contains the `singleton_map_custom_serialize_deserialize` example.
pub(crate) mod singleton_map_custom_serialize_deserialize;

/// This module contains the `nested_singleton_map` example.
pub(crate) mod nested_singleton_map;

/// The main function that runs all the example modules.
pub(crate) fn main() {
    // Run the example module `loader_anchors_and_aliases`.
    singleton_map::main();

    // Run the example module `singleton_map_recursive`.
    singleton_map_recursive::main();

    // Run the example module `singleton_map_enum_variants`.
    singleton_map_enum_variants::main();

    // Run the example module `singleton_map_recursive_deep_nesting`.
    singleton_map_recursive_deep_nesting::main();

    // Run the example module `singleton_map_recursive_serialize_deserialize`.
    singleton_map_recursive_serialize_deserialize::main();

    // Run the example module `singleton_map_optional`.
    singleton_map_optional::main();

    // Run the example module `singleton_map_with`.
    singleton_map_with::main();

    // Run the example module `singleton_map_recursive_optional`.
    singleton_map_recursive_optional::main();

    // Run the example module `singleton_map_recursive_with`.
    singleton_map_recursive_with::main();

    // Run the example module `singleton_map_with_custom_serialize`.
    singleton_map_with_custom_serialize::main();

    // Run the example module `singleton_map_custom_serialize_deserialize`.
    singleton_map_custom_serialize_deserialize::main();

    // Run the example module `nested_singleton_map`.
    nested_singleton_map::main();
}
