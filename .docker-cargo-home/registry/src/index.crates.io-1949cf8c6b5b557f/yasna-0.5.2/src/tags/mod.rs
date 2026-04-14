// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides universal tag constants.

use super::{Tag,TagClass};

/// A special tag representing "end of contents".
pub const TAG_EOC : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 0,
};

/// A universal tag for BOOLEAN.
pub const TAG_BOOLEAN : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 1,
};

/// A universal tag for INTEGER.
pub const TAG_INTEGER : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 2,
};

/// A universal tag for BITSTRING.
pub const TAG_BITSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 3,
};

/// A universal tag for OCTETSTRING.
pub const TAG_OCTETSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 4,
};

/// A universal tag for NULL.
pub const TAG_NULL : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 5,
};

/// A universal tag for object identifiers.
pub const TAG_OID : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 6,
};

/// A universal tag for object descriptors.
pub const TAG_OBJECT_DESCRIPTOR : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 7,
};

/// A universal tag for external/instance-of types.
pub const TAG_EXT : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 8,
};

/// A universal tag for REAL.
pub const TAG_REAL : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 9,
};

/// A universal tag for enumerated types.
pub const TAG_ENUM : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 10,
};

/// A universal tag for embedded-pdv types.
pub const TAG_EMBEDDED_PDV : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 11,
};

/// A universal tag for UTF8String.
pub const TAG_UTF8STRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 12,
};

/// A universal tag for relative object identifiers.
pub const TAG_RELATIVE_OID : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 13,
};

/// A universal tag for TIME.
pub const TAG_TIME : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 14,
};

/// A universal tag for SEQUENCE/SEQUENCE OF.
pub const TAG_SEQUENCE : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 16,
};

/// A universal tag for SET/SET OF.
pub const TAG_SET : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 17,
};

/// A universal tag for NumericString.
pub const TAG_NUMERICSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 18,
};

/// A universal tag for PrintableString.
pub const TAG_PRINTABLESTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 19,
};

/// A universal tag for TeletexString.
pub const TAG_TELETEXSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 20,
};

/// A universal tag for VideotexString.
pub const TAG_VIDEOTEXSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 21,
};

/// A universal tag for IA5String.
pub const TAG_IA5STRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 22,
};

/// A universal tag for UTCTime.
pub const TAG_UTCTIME : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 23,
};

/// A universal tag for GeneralizedTime.
pub const TAG_GENERALIZEDTIME : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 24,
};

/// A universal tag for GraphicString.
pub const TAG_GRAPHICSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 25,
};

/// A universal tag for VisibleString.
pub const TAG_VISIBLESTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 26,
};

/// A universal tag for GeneralString.
pub const TAG_GENERALSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 27,
};

/// A universal tag for UniversalString.
pub const TAG_UNIVERSALSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 28,
};

/// A universal tag for BMPString.
pub const TAG_BMPSTRING : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 30,
};

/// A universal tag for DATE.
pub const TAG_DATE : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 31,
};

/// A universal tag for TIME-OF-DAY.
pub const TAG_TIME_OF_DAY : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 32,
};

/// A universal tag for DATE-TIME.
pub const TAG_DATE_TIME : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 33,
};

/// A universal tag for DURATION.
pub const TAG_DURATION : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 34,
};

/// A universal tag for OID internationalized resource identifiers.
pub const TAG_OID_INTL_RESID : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 35,
};

/// A universal tag for relative OID internationalized resource identifiers.
pub const TAG_RELATIVE_OID_INTL_RESID : Tag = Tag {
    tag_class: TagClass::Universal,
    tag_number: 36,
};
