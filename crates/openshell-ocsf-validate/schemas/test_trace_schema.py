# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed and constraint-preservation checks for Trace schema composition."""

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from trace_schema import DRAFT, main, prepare_schema


def exported(class_name="http_activity", uid=4002, trace=True):
    schema = {
        "$schema": DRAFT,
        "$id": "https://schema.ocsf.io/schema/classes/" + class_name,
        "type": "object",
        "additionalProperties": False,
        "required": ["class_uid", "time"],
        "properties": {"class_uid": {"const": uid}, "time": {"type": "integer"}},
        "$defs": {"unrelated": {"enum": ["preserve"]}},
    }
    if trace:
        schema["properties"]["trace"] = {"$ref": "#/$defs/trace", "title": "Trace"}
        schema["$defs"].update(
            {
                "trace": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["uid"],
                    "properties": {
                        "uid": {"type": "string"},
                        "span": {"$ref": "#/$defs/span"},
                        "service": {"$ref": "#/$defs/service"},
                    },
                },
                "span": {
                    "properties": {
                        "tags": {"items": {"$ref": "#/$defs/key_value_object"}}
                    }
                },
                "service": {"type": "object", "additionalProperties": False},
                "key_value_object": {"type": "object", "required": ["key", "value"]},
            }
        )
    return schema


class TraceSchemaTests(unittest.TestCase):
    def compose(self, base, donor=None, **kwargs):
        return prepare_schema(
            base,
            donor if donor is not None else exported(),
            kwargs.get("class_name", "network_activity"),
            kwargs.get("version", "1.8.0"),
            kwargs.get(
                "profiles",
                ["container", "host", "network_proxy", "security_control", "trace"],
            ),
        )

    def test_extension_preserves_all_unrelated_constraints_and_inputs(self):
        base = exported("network_activity", 4001, False)
        donor = exported()
        original = copy.deepcopy(base)
        donor_original = copy.deepcopy(donor)
        result = self.compose(base, donor)
        self.assertIn("OpenShell extension", result.pop("$comment"))
        self.assertEqual(
            result["properties"].pop("trace"), donor["properties"]["trace"]
        )
        for name in ["trace", "span", "service", "key_value_object"]:
            self.assertEqual(result["$defs"].pop(name), donor["$defs"][name])
        self.assertEqual(result, original)
        self.assertEqual(base, original)
        self.assertEqual(donor, donor_original)

    def test_native_export_is_returned_without_extension(self):
        native = exported("api_activity", 6003)
        result = self.compose(
            native, class_name="api_activity", profiles=["host", "trace"]
        )
        self.assertEqual(result, native)
        self.assertNotIn("$comment", result)

    def test_conflicting_shared_definition_is_rejected(self):
        base = exported("network_activity", 4001, False)
        base["$defs"]["service"] = {"type": "string"}
        with self.assertRaisesRegex(ValueError, "conflicting shared definition"):
            self.compose(base)

    def test_missing_or_widened_trace_definition_is_rejected(self):
        for change in [
            "missing_uid",
            "allow_extra",
            "missing_span",
            "external_reference",
        ]:
            with self.subTest(change=change):
                donor = exported()
                if change == "missing_uid":
                    donor["$defs"]["trace"]["required"] = []
                elif change == "allow_extra":
                    donor["$defs"]["trace"]["additionalProperties"] = True
                elif change == "missing_span":
                    del donor["$defs"]["span"]
                else:
                    donor["properties"]["trace"]["$ref"] = (
                        "https://example.invalid/trace"
                    )
                with self.assertRaises(ValueError):
                    self.compose(exported("network_activity", 4001, False), donor)

    def test_wrong_class_version_and_profiles_are_rejected(self):
        cases = [
            {"version": "1.9.0"},
            {"profiles": ["host", "invented", "trace"]},
            {"profiles": ["trace", "host"]},
            {"profiles": ["host", "trace", "trace"]},
            {"profiles": ["host"]},
            {"class_name": "base_event"},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.compose(exported("network_activity", 4001, False), **case)

    def test_native_class_without_trace_and_changed_extension_applicability_fail(self):
        with self.assertRaisesRegex(ValueError, "missing official Trace"):
            self.compose(
                exported("http_activity", 4002, False), class_name="http_activity"
            )
        with self.assertRaisesRegex(ValueError, "now exports Trace natively"):
            self.compose(exported("network_activity", 4001))

    def test_cached_donor_requires_recorded_hash_and_matching_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / "v1.8.0"
            version.mkdir()
            plain = version / "network_activity@host.json"
            plain.write_text(json.dumps(exported("network_activity", 4001, False)))
            target = version / "network_activity@host+trace.json"
            donor = Path(directory) / "http.json"
            donor.write_text(json.dumps(exported()))
            argv = ["trace_schema.py", str(target), str(plain), str(donor)]
            for expected in ["", "0" * 64]:
                with (
                    self.subTest(expected=expected),
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.dict(
                        "os.environ",
                        {
                            "OCSF_TRACE_SCHEMA_EXPORT": str(donor),
                            "OCSF_TRACE_SCHEMA_SHA256": expected,
                        },
                    ),
                    self.assertRaisesRegex(ValueError, "SHA-256|SHA256"),
                ):
                    main()
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(output),
                mock.patch.dict(
                    "os.environ",
                    {
                        "OCSF_TRACE_SCHEMA_EXPORT": str(donor),
                        "OCSF_TRACE_SCHEMA_SHA256": hashlib.sha256(
                            donor.read_bytes()
                        ).hexdigest(),
                    },
                ),
            ):
                main()
            self.assertIn(
                "OpenShell extension", json.loads(output.getvalue())["$comment"]
            )


if __name__ == "__main__":
    unittest.main()
