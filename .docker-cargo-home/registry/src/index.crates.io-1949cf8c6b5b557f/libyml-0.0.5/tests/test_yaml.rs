#![no_std]
#![cfg(test)]

use libyml::yaml::*;

// Default value tests

/// Tests the default values of YamlVersionDirectiveT
#[test]
fn test_default_yaml_version_directive() {
    let version_directive = YamlVersionDirectiveT::default();
    assert_eq!(version_directive.major, 0);
    assert_eq!(version_directive.minor, 0);
}

/// Tests the default values of YamlMarkT
#[test]
fn test_default_yaml_mark() {
    let mark = YamlMarkT::default();
    assert_eq!(mark.index, 0);
    assert_eq!(mark.line, 0);
    assert_eq!(mark.column, 0);
}

/// Tests the default values of YamlEncodingT
#[test]
fn test_default_yaml_encoding() {
    let encoding = YamlEncodingT::default();
    assert_eq!(encoding, YamlEncodingT::YamlAnyEncoding);
}

/// Tests the default values of YamlScalarStyleT
#[test]
fn test_default_yaml_scalar_style() {
    let scalar_style = YamlScalarStyleT::default();
    assert_eq!(scalar_style, YamlScalarStyleT::YamlAnyScalarStyle);
}

/// Tests the default values of YamlSequenceStyleT
#[test]
fn test_default_yaml_sequence_style() {
    let sequence_style = YamlSequenceStyleT::default();
    assert_eq!(
        sequence_style,
        YamlSequenceStyleT::YamlAnySequenceStyle
    );
}

/// Tests the default values of YamlMappingStyleT
#[test]
fn test_default_yaml_mapping_style() {
    let mapping_style = YamlMappingStyleT::default();
    assert_eq!(mapping_style, YamlMappingStyleT::YamlAnyMappingStyle);
}

/// Tests the default values of YamlTagDirectiveT
#[test]
fn test_default_yaml_tag_directive() {
    let tag_directive = YamlTagDirectiveT::default();
    assert!(tag_directive.handle.is_null());
    assert!(tag_directive.prefix.is_null());
}

/// Tests the default values of YamlBreakT
#[test]
fn test_default_yaml_break() {
    let line_break = YamlBreakT::default();
    assert_eq!(line_break, YamlBreakT::YamlAnyBreak);
}

/// Tests the default values of YamlErrorTypeT
#[test]
fn test_default_yaml_error_type() {
    let error_type = YamlErrorTypeT::default();
    assert_eq!(error_type, YamlErrorTypeT::YamlNoError);
}

/// Tests the default values of YamlSimpleKeyT
#[test]
fn test_default_yaml_simple_key() {
    let simple_key = YamlSimpleKeyT::default();
    assert!(!simple_key.possible);
    assert!(!simple_key.required);
    assert_eq!(simple_key.token_number, 0);
    assert_eq!(simple_key.mark.index, 0);
    assert_eq!(simple_key.mark.line, 0);
    assert_eq!(simple_key.mark.column, 0);
}

/// Tests the default values of YamlEventTypeT
#[test]
fn test_default_yaml_event_type() {
    let event_type = YamlEventTypeT::default();
    assert_eq!(event_type, YamlEventTypeT::YamlNoEvent);
}

/// Tests the default values of YamlNodeTypeT
#[test]
fn test_default_yaml_node_type() {
    let node_type = YamlNodeTypeT::default();
    assert_eq!(node_type, YamlNodeTypeT::YamlNoNode);
}

/// Tests the default values of YamlParserStateT
#[test]
fn test_default_yaml_parser_state() {
    let parser_state = YamlParserStateT::default();
    assert_eq!(
        parser_state,
        YamlParserStateT::YamlParseStreamStartState
    );
}

/// Tests the default values of YamlAliasDataT
#[test]
fn test_default_yaml_anchor_data() {
    let anchor_data = YamlAliasDataT::default();
    assert!(anchor_data.anchor.is_null());
    assert_eq!(anchor_data.index, 0);
    assert_eq!(anchor_data.mark.index, 0);
    assert_eq!(anchor_data.mark.line, 0);
    assert_eq!(anchor_data.mark.column, 0);
}

/// Tests the default values of YamlTokenT
#[test]
fn test_default_yaml_token() {
    let token = YamlTokenT::default();
    assert_eq!(token.type_, YamlTokenTypeT::YamlNoToken);
    assert_eq!(token.start_mark.index, 0);
    assert_eq!(token.start_mark.line, 0);
    assert_eq!(token.start_mark.column, 0);
    assert_eq!(token.end_mark.index, 0);
    assert_eq!(token.end_mark.line, 0);
    assert_eq!(token.end_mark.column, 0);
}

/// Tests the default values of YamlEmitterStateT
#[test]
fn test_default_yaml_emitter_state() {
    let emitter_state = YamlEmitterStateT::default();
    assert_eq!(
        emitter_state,
        YamlEmitterStateT::YamlEmitStreamStartState
    );
}

// Enum value tests

/// Tests the values of YamlEncodingT enum variants
#[test]
fn test_yaml_encoding_values() {
    assert_eq!(YamlEncodingT::YamlAnyEncoding as u32, 0);
    assert_eq!(YamlEncodingT::YamlUtf8Encoding as u32, 1);
    assert_eq!(YamlEncodingT::YamlUtf16leEncoding as u32, 2);
    assert_eq!(YamlEncodingT::YamlUtf16beEncoding as u32, 3);
}

/// Tests the values of YamlEventTypeT enum variants
#[test]
fn test_yaml_event_type_values() {
    assert_eq!(YamlEventTypeT::YamlNoEvent as u32, 0);
    assert_eq!(YamlEventTypeT::YamlStreamStartEvent as u32, 1);
    assert_eq!(YamlEventTypeT::YamlStreamEndEvent as u32, 2);
    assert_eq!(YamlEventTypeT::YamlDocumentStartEvent as u32, 3);
    assert_eq!(YamlEventTypeT::YamlDocumentEndEvent as u32, 4);
    assert_eq!(YamlEventTypeT::YamlAliasEvent as u32, 5);
    assert_eq!(YamlEventTypeT::YamlScalarEvent as u32, 6);
    assert_eq!(YamlEventTypeT::YamlSequenceStartEvent as u32, 7);
    assert_eq!(YamlEventTypeT::YamlSequenceEndEvent as u32, 8);
    assert_eq!(YamlEventTypeT::YamlMappingStartEvent as u32, 9);
    assert_eq!(YamlEventTypeT::YamlMappingEndEvent as u32, 10);
}

/// Tests the values of YamlScalarStyleT enum variants
#[test]
fn test_yaml_scalar_style_values() {
    assert_eq!(YamlScalarStyleT::YamlAnyScalarStyle as u32, 0);
    assert_eq!(YamlScalarStyleT::YamlPlainScalarStyle as u32, 1);
    assert_eq!(YamlScalarStyleT::YamlSingleQuotedScalarStyle as u32, 2);
    assert_eq!(YamlScalarStyleT::YamlDoubleQuotedScalarStyle as u32, 3);
    assert_eq!(YamlScalarStyleT::YamlLiteralScalarStyle as u32, 4);
    assert_eq!(YamlScalarStyleT::YamlFoldedScalarStyle as u32, 5);
}

/// Tests the values of YamlSequenceStyleT enum variants
#[test]
fn test_yaml_sequence_style_values() {
    assert_eq!(YamlSequenceStyleT::YamlAnySequenceStyle as u32, 0);
    assert_eq!(YamlSequenceStyleT::YamlBlockSequenceStyle as u32, 1);
    assert_eq!(YamlSequenceStyleT::YamlFlowSequenceStyle as u32, 2);
}

/// Tests the values of YamlMappingStyleT enum variants
#[test]
fn test_yaml_mapping_style_values() {
    assert_eq!(YamlMappingStyleT::YamlAnyMappingStyle as u32, 0);
    assert_eq!(YamlMappingStyleT::YamlBlockMappingStyle as u32, 1);
    assert_eq!(YamlMappingStyleT::YamlFlowMappingStyle as u32, 2);
}

/// Tests the values of YamlErrorTypeT enum variants
#[test]
fn test_yaml_error_type_values() {
    assert_eq!(YamlErrorTypeT::YamlNoError as u32, 0);
    assert_eq!(YamlErrorTypeT::YamlMemoryError as u32, 1);
    assert_eq!(YamlErrorTypeT::YamlReaderError as u32, 2);
    assert_eq!(YamlErrorTypeT::YamlScannerError as u32, 3);
    assert_eq!(YamlErrorTypeT::YamlParserError as u32, 4);
    assert_eq!(YamlErrorTypeT::YamlComposerError as u32, 5);
    assert_eq!(YamlErrorTypeT::YamlWriterError as u32, 6);
    assert_eq!(YamlErrorTypeT::YamlEmitterError as u32, 7);
}

/// Tests the values of YamlNodeTypeT enum variants
#[test]
fn test_yaml_node_type_values() {
    assert_eq!(YamlNodeTypeT::YamlNoNode as u32, 0);
    assert_eq!(YamlNodeTypeT::YamlScalarNode as u32, 1);
    assert_eq!(YamlNodeTypeT::YamlSequenceNode as u32, 2);
    assert_eq!(YamlNodeTypeT::YamlMappingNode as u32, 3);
}

/// Tests the values of YamlBreakT enum variants
#[test]
fn test_yaml_break_type_values() {
    assert_eq!(YamlBreakT::YamlAnyBreak as u32, 0);
    assert_eq!(YamlBreakT::YamlCrBreak as u32, 1);
    assert_eq!(YamlBreakT::YamlLnBreak as u32, 2);
    assert_eq!(YamlBreakT::YamlCrlnBreak as u32, 3);
}

/// Tests the values of YamlParserStateT enum variants
#[test]
fn test_yaml_parser_state_values() {
    assert_eq!(YamlParserStateT::YamlParseStreamStartState as u32, 0);
    assert_eq!(
        YamlParserStateT::YamlParseImplicitDocumentStartState as u32,
        1
    );
    assert_eq!(YamlParserStateT::YamlParseDocumentStartState as u32, 2);
    assert_eq!(
        YamlParserStateT::YamlParseDocumentContentState as u32,
        3
    );
    assert_eq!(YamlParserStateT::YamlParseDocumentEndState as u32, 4);
    assert_eq!(YamlParserStateT::YamlParseBlockNodeState as u32, 5);
    assert_eq!(
        YamlParserStateT::YamlParseBlockNodeOrIndentlessSequenceState
            as u32,
        6
    );
    assert_eq!(YamlParserStateT::YamlParseFlowNodeState as u32, 7);
    assert_eq!(
        YamlParserStateT::YamlParseBlockSequenceFirstEntryState as u32,
        8
    );
    assert_eq!(
        YamlParserStateT::YamlParseBlockSequenceEntryState as u32,
        9
    );
    assert_eq!(
        YamlParserStateT::YamlParseIndentlessSequenceEntryState as u32,
        10
    );
    assert_eq!(
        YamlParserStateT::YamlParseBlockMappingFirstKeyState as u32,
        11
    );
    assert_eq!(
        YamlParserStateT::YamlParseBlockMappingKeyState as u32,
        12
    );
    assert_eq!(
        YamlParserStateT::YamlParseBlockMappingValueState as u32,
        13
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowSequenceFirstEntryState as u32,
        14
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowSequenceEntryState as u32,
        15
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowSequenceEntryMappingKeyState
            as u32,
        16
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowSequenceEntryMappingValueState
            as u32,
        17
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowSequenceEntryMappingEndState
            as u32,
        18
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowMappingFirstKeyState as u32,
        19
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowMappingKeyState as u32,
        20
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowMappingValueState as u32,
        21
    );
    assert_eq!(
        YamlParserStateT::YamlParseFlowMappingEmptyValueState as u32,
        22
    );
    assert_eq!(YamlParserStateT::YamlParseEndState as u32, 23);
}

/// Tests the values of YamlEmitterStateT enum variants
#[test]
fn test_yaml_emitter_state_values() {
    assert_eq!(YamlEmitterStateT::YamlEmitStreamStartState as u32, 0);
    assert_eq!(
        YamlEmitterStateT::YamlEmitFirstDocumentStartState as u32,
        1
    );
    assert_eq!(YamlEmitterStateT::YamlEmitDocumentStartState as u32, 2);
    assert_eq!(
        YamlEmitterStateT::YamlEmitDocumentContentState as u32,
        3
    );
    assert_eq!(YamlEmitterStateT::YamlEmitDocumentEndState as u32, 4);
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowSequenceFirstItemState as u32,
        5
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowSequenceItemState as u32,
        6
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowMappingFirstKeyState as u32,
        7
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowMappingKeyState as u32,
        8
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowMappingSimpleValueState as u32,
        9
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitFlowMappingValueState as u32,
        10
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockSequenceFirstItemState as u32,
        11
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockSequenceItemState as u32,
        12
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockMappingFirstKeyState as u32,
        13
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockMappingKeyState as u32,
        14
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockMappingSimpleValueState as u32,
        15
    );
    assert_eq!(
        YamlEmitterStateT::YamlEmitBlockMappingValueState as u32,
        16
    );
    assert_eq!(YamlEmitterStateT::YamlEmitEndState as u32, 17);
}

/// Tests the constructor of YamlVersionDirectiveT
#[test]
fn test_yaml_version_directive() {
    let version_directive = YamlVersionDirectiveT::new(1, 2);
    assert_eq!(version_directive.major, 1);
    assert_eq!(version_directive.minor, 2);
}
