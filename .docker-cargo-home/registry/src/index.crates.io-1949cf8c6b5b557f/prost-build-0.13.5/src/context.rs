use std::borrow::Cow;

use prost_types::{
    field_descriptor_proto::{Label, Type},
    FieldDescriptorProto,
};

use crate::extern_paths::ExternPaths;
use crate::message_graph::MessageGraph;
use crate::{BytesType, Config, MapType, ServiceGenerator};

/// The context providing all the global information needed to generate code.
/// It also provides a more disciplined access to Config
/// and its mutable instance of ServiceGenerator.
///
/// A `Context` is built once in the generation process and is reused by
/// `CodeGenerator` instances created to generate code for each input file.
pub struct Context<'a> {
    config: &'a mut Config,
    message_graph: MessageGraph,
    extern_paths: ExternPaths,
}

impl<'a> Context<'a> {
    pub fn new(
        config: &'a mut Config,
        message_graph: MessageGraph,
        extern_paths: ExternPaths,
    ) -> Self {
        Self {
            config,
            message_graph,
            extern_paths,
        }
    }

    pub fn config(&self) -> &Config {
        self.config
    }

    pub fn service_generator_mut(&mut self) -> Option<&mut (dyn ServiceGenerator + 'static)> {
        self.config.service_generator.as_deref_mut()
    }

    pub fn prost_path(&self) -> &str {
        self.config.prost_path.as_deref().unwrap_or("::prost")
    }

    pub fn resolve_extern_ident(&self, pb_ident: &str) -> Option<String> {
        self.extern_paths.resolve_ident(pb_ident)
    }

    /// Returns an iterator over the additional attributes configured
    /// for the named type.
    pub fn type_attributes(&self, fq_type_name: &str) -> impl Iterator<Item = &str> {
        self.config
            .type_attributes
            .get(fq_type_name)
            .map(|s| s.as_str())
    }

    /// Returns an iterator over the additional attributes configured
    /// for the named message.
    pub fn message_attributes(&self, fq_message_name: &str) -> impl Iterator<Item = &str> {
        self.config
            .message_attributes
            .get(fq_message_name)
            .map(|s| s.as_str())
    }

    /// Returns an iterator over the additional attributes configured
    /// for the named enum.
    pub fn enum_attributes(&self, fq_enum_name: &str) -> impl Iterator<Item = &str> {
        self.config
            .enum_attributes
            .get(fq_enum_name)
            .map(|s| s.as_str())
    }

    /// Returns an iterator over the additional attributes configured
    /// for the named message field.
    pub fn field_attributes(
        &self,
        fq_message_name: &str,
        field_name: &str,
    ) -> impl Iterator<Item = &str> {
        self.config
            .field_attributes
            .get_field(fq_message_name, field_name)
            .map(|s| s.as_str())
    }

    /// Returns the bytes type configured for the named message field.
    pub(crate) fn bytes_type(&self, fq_message_name: &str, field_name: &str) -> BytesType {
        self.config
            .bytes_type
            .get_first_field(fq_message_name, field_name)
            .copied()
            .unwrap_or_default()
    }

    /// Returns the map type configured for the named message field.
    pub(crate) fn map_type(&self, fq_message_name: &str, field_name: &str) -> MapType {
        self.config
            .map_type
            .get_first_field(fq_message_name, field_name)
            .copied()
            .unwrap_or_default()
    }

    /// Returns whether the Rust type for this message field needs to be `Box<_>`.
    ///
    /// This can be explicitly configured with `Config::boxed`, or necessary
    /// to prevent an infinitely sized type definition in case when the type of
    /// a non-repeated message field transitively contains the message itself.
    pub fn should_box_message_field(
        &self,
        fq_message_name: &str,
        field: &FieldDescriptorProto,
    ) -> bool {
        self.should_box_impl(fq_message_name, None, field)
    }

    /// Returns whether the Rust type for this field in the oneof needs to be `Box<_>`.
    ///
    /// This can be explicitly configured with `Config::boxed`, or necessary
    /// to prevent an infinitely sized type definition in case when the type of
    /// a non-repeated message field transitively contains the message itself.
    pub fn should_box_oneof_field(
        &self,
        fq_message_name: &str,
        oneof_name: &str,
        field: &FieldDescriptorProto,
    ) -> bool {
        self.should_box_impl(fq_message_name, Some(oneof_name), field)
    }

    fn should_box_impl(
        &self,
        fq_message_name: &str,
        oneof: Option<&str>,
        field: &FieldDescriptorProto,
    ) -> bool {
        let repeated = field.label() == Label::Repeated;
        let fd_type = field.r#type();
        if !repeated
            && (fd_type == Type::Message || fd_type == Type::Group)
            && self
                .message_graph
                .is_nested(field.type_name(), fq_message_name)
        {
            return true;
        }
        let config_path = match oneof {
            None => Cow::Borrowed(fq_message_name),
            Some(oneof_name) => Cow::Owned(format!("{fq_message_name}.{oneof_name}")),
        };
        if self
            .config
            .boxed
            .get_first_field(&config_path, field.name())
            .is_some()
        {
            if repeated {
                println!(
                    "cargo:warning=\
                    Field X is repeated and manually marked as boxed. \
                    This is deprecated and support will be removed in a later release"
                );
            }
            return true;
        }
        false
    }

    /// Returns `true` if this message can automatically derive Copy trait.
    pub fn can_message_derive_copy(&self, fq_message_name: &str) -> bool {
        assert_eq!(".", &fq_message_name[..1]);
        self.message_graph
            .get_message(fq_message_name)
            .unwrap()
            .field
            .iter()
            .all(|field| self.can_field_derive_copy(fq_message_name, field))
    }

    /// Returns `true` if the type of this message field allows deriving the Copy trait.
    pub fn can_field_derive_copy(
        &self,
        fq_message_name: &str,
        field: &FieldDescriptorProto,
    ) -> bool {
        assert_eq!(".", &fq_message_name[..1]);

        // repeated field cannot derive Copy
        if field.label() == Label::Repeated {
            false
        } else if field.r#type() == Type::Message {
            // nested and boxed messages cannot derive Copy
            if self
                .message_graph
                .is_nested(field.type_name(), fq_message_name)
            {
                return false;
            }
            if self
                .config
                .boxed
                .get_first_field(fq_message_name, field.name())
                .is_some()
            {
                false
            } else {
                self.can_message_derive_copy(field.type_name())
            }
        } else {
            matches!(
                field.r#type(),
                Type::Float
                    | Type::Double
                    | Type::Int32
                    | Type::Int64
                    | Type::Uint32
                    | Type::Uint64
                    | Type::Sint32
                    | Type::Sint64
                    | Type::Fixed32
                    | Type::Fixed64
                    | Type::Sfixed32
                    | Type::Sfixed64
                    | Type::Bool
                    | Type::Enum
            )
        }
    }

    pub fn should_disable_comments(&self, fq_message_name: &str, field_name: Option<&str>) -> bool {
        if let Some(field_name) = field_name {
            self.config
                .disable_comments
                .get_first_field(fq_message_name, field_name)
                .is_some()
        } else {
            self.config
                .disable_comments
                .get(fq_message_name)
                .next()
                .is_some()
        }
    }

    /// Returns whether the named message should skip generating the `Debug` implementation.
    pub fn should_skip_debug(&self, fq_message_name: &str) -> bool {
        assert_eq!(b'.', fq_message_name.as_bytes()[0]);
        self.config.skip_debug.get(fq_message_name).next().is_some()
    }

    /// Returns the type name domain URL for the named message,
    /// or an empty string if such is not configured.
    pub fn type_name_domain(&self, fq_message_name: &str) -> &str {
        self.config
            .type_name_domains
            .get_first(fq_message_name)
            .map_or("", |name| name.as_str())
    }
}
