# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Checkpoint proof tests: fake GitHub boundary only, no model or mutations."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from label_issue_checkpoint import (
    IncompleteMaterial,
    checkpoint_matches,
    collect_label_events,
    decode_checkpoint,
    encode_checkpoint,
    find_checkpoint,
    fingerprint,
    latest_label_event,
    operation_digest,
)


def source(kind, content, **extra):
    raw = json.dumps(content, sort_keys=True).encode()
    return dict(
        kind=kind,
        content=content,
        inspected=True,
        coverage="complete",
        source_digest=hashlib.sha256(raw).hexdigest(),
        source_bytes=len(raw),
        **extra,
    )


def material(kind="issue"):
    index = dict(
        body=source("body", {"body": "Proxy policy"}),
        labels=source("reconciliation", ["area:gateway"]),
        comments=source("comments", ["comment:1"], members=["comment:1"]),
        **{
            "comment:1": source(
                "comment", {"id": 1, "body": "Real evidence"}, _raw_text="Real evidence"
            )
        },
        timeline=source("timeline", None),
    )
    index["timeline"].update(coverage="not_inspected", inspected=False)
    if kind == "pull_request":
        index.update(
            files=source("files", ["patch:proxy"], members=["patch:proxy"]),
            reviews=source("reviews", [], members=[]),
            review_comments=source("review_comments", [], members=[]),
        )
        index["patch:proxy"] = source("patch", {"patch": "@@ -1 +1 @@\n-old\n+new"})
    return {
        "repository": "NVIDIA/OpenShell",
        "number": 12,
        "kind": kind,
        "item_id": "I_12",
        "item_material": {"body": "Proxy policy", "state": "open"},
        "policy_version": "policy1",
        "taxonomy": {
            "areas": {"area:runtime": "Execution"},
            "definitions": {
                "area:runtime": {"name": "area:runtime", "id": "LA_runtime"}
            },
        },
        "eligibility": {"accepted": True, "lifecycle": "eligible"},
        "existing_labels": ["area:gateway"],
        "malformed_classification_labels": [],
        "evidence_index": index,
        "relevant_timeline": source("relevant_timeline", []),
    }


def event(identity, action="add", label="LA_runtime", actor="labeler", rationale=None):
    node = {
        "id": identity,
        "__typename": "LabeledEvent" if action == "add" else "UnlabeledEvent",
        "actor": {"login": actor},
        "label": {"id": label, "name": label},
        "createdAt": "2026-11-07T12:00:00Z",
    }
    if action == "add":
        node["intent"] = {"rationale": rationale}
    return node


def response(nodes, *, previous=False, cursor=None):
    return {
        "data": {
            "node": {
                "__typename": "Issue",
                "timelineItems": {
                    "nodes": nodes,
                    "pageInfo": {"hasPreviousPage": previous, "startCursor": cursor},
                },
            }
        }
    }


class FakeGitHub:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def __call__(self, path, *, method="GET", data=None, pages=False):
        self.calls.append((path, method, data))
        if path != "graphql" or method != "POST" or pages:
            raise AssertionError("Checkpoint helper may only query GraphQL")
        if data is None or "mutation" in data["query"]:
            raise AssertionError("No mutations permitted")
        return self.pages.pop(0)


def proof_fixture():
    state = material()
    final = {"area:runtime"}
    operations = [
        {"actor": "labeler", "action": "add", "label_id": "LA_runtime"},
        {"actor": "labeler", "action": "remove", "label_id": "LA_gateway"},
    ]
    rationale = encode_checkpoint(
        fingerprint(state, final, "policy1"),
        boundary_id="B_0",
        operations_digest=operation_digest(operations),
        event_count=2,
    )
    addition = event("C_1", rationale=rationale)
    removal = event("C_2", "remove", "LA_gateway")
    api = FakeGitHub([response([addition])])
    candidate = find_checkpoint("I_12", api=api, trusted_actors={"labeler"})[
        "checkpoint"
    ]
    current = copy.deepcopy(state)
    current["existing_labels"] = ["area:runtime"]
    current["evidence_index"]["labels"] = source("reconciliation", ["area:runtime"])
    proof = {
        "status": "complete",
        "boundary_id": "B_0",
        "item_id": "I_12",
        "events": [addition, removal],
    }
    return candidate, current, final, proof


class CheckpointTests(unittest.TestCase):
    def test_v1_round_trip_is_audit_only(self):
        digest = "a" * 64
        rationale = "openshell-labeler:v1:" + digest
        self.assertEqual(rationale, "openshell-labeler:v1:" + digest)
        self.assertEqual(
            decode_checkpoint(rationale), {"version": 1, "fingerprint": digest}
        )
        self.assertFalse(
            checkpoint_matches(
                decode_checkpoint(rationale), material(), {"area:runtime"}, "policy1"
            )
        )

    def test_v2_round_trip_and_280_character_limit(self):
        rationale = encode_checkpoint(
            "a" * 64,
            boundary_id="node:opaque/with=padding",
            operations_digest="b" * 64,
            event_count=3,
        )
        self.assertLessEqual(len(rationale), 280)
        self.assertEqual(
            decode_checkpoint(rationale),
            {
                "version": 2,
                "fingerprint": "a" * 64,
                "boundary_id": "node:opaque/with=padding",
                "operations_digest": "b" * 64,
                "event_count": 3,
            },
        )
        with self.assertRaises(ValueError):
            encode_checkpoint(
                "a" * 64,
                boundary_id="x" * 200,
                operations_digest="b" * 64,
                event_count=3,
            )

    def test_invalid_metadata_and_partial_encoder_arguments_rejected(self):
        for value in [
            None,
            "",
            "openshell-labeler:v3:" + "a" * 64,
            "openshell-labeler:v1:" + "x" * 64,
            "openshell-labeler:v1:" + "a" * 65,
            "openshell-labeler:v1:" + "a" * 64 + "\n",
        ]:
            self.assertIsNone(decode_checkpoint(value))
        invalid_options: list[dict] = [
            {"boundary_id": "B"},
            {"boundary_id": "B", "operations_digest": "b" * 64, "event_count": 0},
            {"boundary_id": "B", "operations_digest": "b" * 64, "event_count": True},
        ]
        for kwargs in invalid_options:
            with self.assertRaises((TypeError, ValueError)):
                encode_checkpoint("a" * 64, **kwargs)

    def test_operation_digest_is_canonical_ordered_and_casefolds_actor(self):
        ops = [{"actor": "Labeler", "action": "add", "label_id": "LA_1"}]
        expected = hashlib.sha256(
            b'[{"action":"add","actor":"labeler","label_id":"LA_1"}]'
        ).hexdigest()
        self.assertEqual(operation_digest(ops), expected)
        with self.assertRaises(ValueError):
            operation_digest(
                [{"actor": "labeler", "action": "comment", "label_id": "LA_1"}]
            )

    def test_fingerprint_is_deterministic_and_normalizes_only_local_read_state(self):
        first, second = material(), material()
        second["evidence_index"]["comment:1"].pop("content")
        second["evidence_index"]["comment:1"].update(
            inspected=False, artifact_path="/tmp/different"
        )
        second["evidence_index"]["comments"]["inspected"] = False
        parent_digest = second["evidence_index"]["comment:1"]["source_digest"]
        text_id = f"text:comment:1:{parent_digest}:0:4"
        second["evidence_index"][text_id] = source(
            "text_slice",
            "Real",
            parent_id="comment:1",
            parent_digest=parent_digest,
            start=0,
            end=4,
        )
        second["evidence_index"][text_id]["coverage"] = "slice"
        second["existing_labels"] = ["area:runtime"]
        second["malformed_classification_labels"] = ["areaa:runtime"]
        second["evidence_index"]["labels"] = source("reconciliation", ["area:runtime"])
        self.assertEqual(
            fingerprint(first, {"area:runtime"}, "policy1"),
            fingerprint(second, {"area:runtime"}, "policy1"),
        )

    def test_old_comment_edits_and_deletions_new_reviews_and_diffs_invalidate(self):
        original = material("pull_request")
        before = fingerprint(original, {"area:runtime"}, "policy1")
        for artifact, changed in [
            ("comment:1", source("comment", {"id": 1, "body": "Edited old comment"})),
            ("patch:proxy", source("patch", {"patch": "different"})),
            ("reviews", source("reviews", ["review:2"], members=["review:2"])),
        ]:
            state = copy.deepcopy(original)
            state["evidence_index"][artifact] = changed
            if artifact == "reviews":
                state["evidence_index"]["review:2"] = source(
                    "review", {"id": 2, "body": "New review"}
                )
            self.assertNotEqual(before, fingerprint(state, {"area:runtime"}, "policy1"))
        deleted = copy.deepcopy(original)
        del deleted["evidence_index"]["comment:1"]
        deleted["evidence_index"]["comments"] = source("comments", [], members=[])
        self.assertNotEqual(before, fingerprint(deleted, {"area:runtime"}, "policy1"))

    def test_policy_definitions_labels_and_real_lifecycle_are_bound(self):
        state = material()
        before = fingerprint(state, {"area:runtime"}, "policy1")
        self.assertNotEqual(before, fingerprint(state, {"area:platform"}, "policy1"))
        self.assertNotEqual(before, fingerprint(state, {"area:runtime"}, "policy2"))
        for key, value in [
            ("taxonomy", {"changed": "definitions"}),
            (
                "relevant_timeline",
                source("relevant_timeline", [{"id": "closed1", "actor": "maintainer"}]),
            ),
        ]:
            changed = copy.deepcopy(state)
            changed[key] = value
            self.assertNotEqual(
                before, fingerprint(changed, {"area:runtime"}, "policy1")
            )

    def test_unresolved_or_partial_collections_cannot_establish_unchanged(self):
        for kind in ["issue", "pull_request"]:
            for artifact in ["comments", "body", "relevant_timeline"] + (
                ["reviews", "review_comments", "files"]
                if kind == "pull_request"
                else []
            ):
                with self.subTest(kind=kind, artifact=artifact):
                    state = material(kind)
                    target = (
                        state[artifact]
                        if artifact == "relevant_timeline"
                        else state["evidence_index"][artifact]
                    )
                    target["coverage"] = "not_inspected"
                    with self.assertRaises(IncompleteMaterial):
                        fingerprint(state, {"area:runtime"}, "policy1")
        state = material()
        del state["relevant_timeline"]
        with self.assertRaises(IncompleteMaterial):
            fingerprint(state, {"area:runtime"}, "policy1")

    def test_command_looking_comment_invalidates_as_ordinary_evidence(self):
        before, after = material(), material()
        after["evidence_index"]["comment:2"] = source(
            "comment", {"id": 2, "body": "/label-issue"}
        )
        after["evidence_index"]["comments"] = source(
            "comments", ["comment:1", "comment:2"], members=["comment:1", "comment:2"]
        )
        self.assertNotEqual(
            fingerprint(before, {"area:runtime"}, "policy1"),
            fingerprint(after, {"area:runtime"}, "policy1"),
        )

    def test_fetched_uninspected_source_is_change_detector_not_read_claim(self):
        state = material()
        state["evidence_index"]["comment:1"]["inspected"] = False
        first = fingerprint(state, {"area:runtime"}, "policy1")
        changed = copy.deepcopy(state)
        changed["evidence_index"]["comment:1"] = source(
            "comment", {"body": "New evidence"}
        )
        changed["evidence_index"]["comment:1"]["inspected"] = False
        self.assertNotEqual(first, fingerprint(changed, {"area:runtime"}, "policy1"))
        self.assertFalse(state["evidence_index"]["comment:1"]["inspected"])

    def test_discovery_paginates_backwards_finds_removed_label_and_trusted_actor_only(
        self,
    ):
        rationale = "openshell-labeler:v1:" + "a" * 64
        api = FakeGitHub(
            [
                response(
                    [event("untrusted", actor="stranger", rationale=rationale)],
                    previous=True,
                    cursor="cursor1",
                ),
                response(
                    [
                        event(
                            "found",
                            label="removed-label",
                            actor="LABELER",
                            rationale=rationale,
                        )
                    ]
                ),
            ]
        )
        result = find_checkpoint("I_12", api=api, trusted_actors={"labeler"})
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["checkpoint"]["event_id"], "found")
        self.assertEqual(result["diagnostics"]["checkpoint_pages"], 2)
        self.assertEqual(api.calls[1][2]["variables"]["before"], "cursor1")
        self.assertIn("last: 100", api.calls[0][2]["query"])
        self.assertIn("LABELED_EVENT", api.calls[0][2]["query"])
        self.assertNotIn("UNLABELED_EVENT", api.calls[0][2]["query"])

    def test_discovery_chooses_newest_valid_event_and_trust_has_no_default(self):
        rationale = "openshell-labeler:v1:" + "a" * 64
        api = FakeGitHub(
            [
                response(
                    [
                        event("old", rationale=rationale),
                        event("new", rationale=rationale),
                    ]
                )
            ]
        )
        self.assertEqual(
            find_checkpoint("I_12", api=api, trusted_actors={"labeler"})["checkpoint"][
                "event_id"
            ],
            "new",
        )
        api = FakeGitHub([response([event("new", rationale=rationale)])])
        self.assertEqual(
            find_checkpoint("I_12", api=api, trusted_actors=set())["status"],
            "not_found",
        )

    def test_nullable_deleted_actor_or_label_cannot_hide_older_valid_checkpoint(self):
        rationale = "openshell-labeler:v1:" + "a" * 64
        api = FakeGitHub(
            [
                response(
                    [
                        event("valid", rationale=rationale),
                        event("deleted-actor", rationale=rationale) | {"actor": None},
                        event("deleted-label", rationale=rationale) | {"label": None},
                    ]
                )
            ]
        )
        found = find_checkpoint("I_12", api=api, trusted_actors={"labeler"})
        self.assertEqual(found["checkpoint"]["event_id"], "valid")

    def test_discovery_distinguishes_not_found_and_exhausted_budget(self):
        self.assertEqual(
            find_checkpoint(
                "I_12", api=FakeGitHub([response([])]), trusted_actors={"labeler"}
            )["status"],
            "not_found",
        )
        api = FakeGitHub(
            [response([event(str(i))], previous=True, cursor=str(i)) for i in range(10)]
        )
        result = find_checkpoint("I_12", api=api, trusted_actors={"labeler"})
        self.assertEqual(result["status"], "exhausted")
        self.assertEqual(len(api.calls), 10)

    def test_repeated_cursors_graphql_errors_and_malformed_payload_fail_closed(self):
        for pages in [
            [{"data": {"node": None}, "errors": [{"message": "denied"}]}],
            [{"data": {"node": None}}],
            [
                response([event("1")], previous=True, cursor="same"),
                response([event("2")], previous=True, cursor="same"),
            ],
        ]:
            with self.subTest(pages=pages), self.assertRaises(ValueError):
                find_checkpoint(
                    "I_12", api=FakeGitHub(pages), trusted_actors={"labeler"}
                )

    def test_latest_label_boundary_requires_one_filtered_read_not_full_history(self):
        api = FakeGitHub(
            [response([event("latest", "remove")], previous=True, cursor="older")]
        )
        self.assertEqual(latest_label_event("I_12", api=api)["boundary_id"], "latest")
        self.assertEqual(len(api.calls), 1)
        self.assertIn("last: 1", api.calls[0][2]["query"])
        self.assertIn("UNLABELED_EVENT", api.calls[0][2]["query"])
        self.assertEqual(
            latest_label_event("I_12", api=FakeGitHub([response([])]))["boundary_id"],
            "",
        )

    def test_event_proof_collects_both_actions_chronologically_and_stops_at_boundary(
        self,
    ):
        api = FakeGitHub(
            [
                response(
                    [event("C2", "remove"), event("external")],
                    previous=True,
                    cursor="p1",
                ),
                response([event("older"), event("B0"), event("C1")]),
            ]
        )
        result = collect_label_events("I_12", "B0", api=api)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [entry["id"] for entry in result["events"]], ["C1", "C2", "external"]
        )
        self.assertIn("UNLABELED_EVENT", api.calls[0][2]["query"])
        self.assertEqual(result["diagnostics"]["event_proof_pages"], 2)

    def test_missing_boundary_or_exhausted_event_proof_is_not_complete(self):
        result = collect_label_events(
            "I_12", "missing", api=FakeGitHub([response([event("other")])])
        )
        self.assertEqual(result["status"], "not_found")
        api = FakeGitHub(
            [response([event(str(i))], previous=True, cursor=str(i)) for i in range(2)]
        )
        result = collect_label_events("I_12", "missing", api=api, max_pages=2)
        self.assertEqual(result["status"], "exhausted")
        self.assertEqual(len(api.calls), 2)

    def test_verified_complete_protocol_operations_match_separate_live_final_state(
        self,
    ):
        candidate, state, final, proof = proof_fixture()
        self.assertTrue(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )
        before = copy.deepcopy((candidate, state, proof))
        checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        self.assertEqual((candidate, state, proof), before)

    def test_candidate_before_removal_is_not_success_and_lingering_bookkeeping_fails(
        self,
    ):
        candidate, state, final, proof = proof_fixture()
        proof["events"].pop()
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )
        candidate, state, final, proof = proof_fixture()
        state["existing_labels"].append("meta:labeler-checkpoint")
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )

    def test_external_remove_readd_even_same_trusted_actor_invalidates(self):
        candidate, state, final, proof = proof_fixture()
        for actor in ["human", "labeler"]:
            extra = copy.deepcopy(proof)
            extra["events"] += [
                event("external-remove", "remove", actor=actor),
                event("external-add", actor=actor),
            ]
            self.assertFalse(
                checkpoint_matches(
                    candidate, state, final, "policy1", label_events=extra
                )
            )

    def test_wrong_actor_order_boundary_item_and_candidate_identity_rejected(self):
        candidate, state, final, proof = proof_fixture()
        for field, value in [("actor", {"login": "human"}), ("id", "different")]:
            changed = copy.deepcopy(proof)
            changed["events"][0][field] = value
            self.assertFalse(
                checkpoint_matches(
                    candidate, state, final, "policy1", label_events=changed
                )
            )
        changed = copy.deepcopy(proof)
        changed["events"].reverse()
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=changed)
        )
        for field, value in [
            ("boundary_id", "wrong"),
            ("item_id", "wrong"),
            ("status", "exhausted"),
        ]:
            self.assertFalse(
                checkpoint_matches(
                    candidate,
                    state,
                    final,
                    "policy1",
                    label_events=proof | {field: value},
                )
            )
        self.assertFalse(
            checkpoint_matches(
                candidate | {"trusted": False},
                state,
                final,
                "policy1",
                label_events=proof,
            )
        )
        self.assertFalse(checkpoint_matches(candidate, state, final, "policy1"))

    def test_material_changed_after_candidate_is_not_marked_examined(self):
        candidate, state, final, proof = proof_fixture()
        state["evidence_index"]["comment:1"] = source(
            "comment", {"body": "Concurrent evidence"}
        )
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )

    def test_encoder_requires_all_v2_fields_instead_of_emitting_unmatchable_v1(self):
        with self.assertRaises(TypeError):
            missing_fields: dict = {}
            encode_checkpoint("a" * 64, **missing_fields)

    def test_parent_id_cannot_bypass_required_body_or_collection_member_coverage(self):
        for identity in ["body", "comments", "comment:1"]:
            with self.subTest(identity=identity):
                state = material()
                state["evidence_index"][identity].update(
                    parent_id="something", coverage="partial"
                )
                with self.assertRaises(IncompleteMaterial):
                    fingerprint(state, {"area:runtime"}, "policy1")

    def test_edited_required_member_with_parent_id_still_changes_fingerprint(self):
        before, after = material(), material()
        before["evidence_index"]["comment:1"]["parent_id"] = "body"
        after["evidence_index"]["comment:1"] = source(
            "comment", {"body": "Changed evidence"}, parent_id="body"
        )
        self.assertNotEqual(
            fingerprint(before, {"area:runtime"}, "policy1"),
            fingerprint(after, {"area:runtime"}, "policy1"),
        )

    def test_arbitrary_parent_id_or_derivative_prefix_cannot_hide_source_facts(self):
        before, after = material(), material()
        before["evidence_index"]["text:fake"] = source(
            "comment", {"body": "First"}, parent_id="body"
        )
        after["evidence_index"]["text:fake"] = source(
            "comment", {"body": "Edited"}, parent_id="body"
        )
        self.assertNotEqual(
            fingerprint(before, {"area:runtime"}, "policy1"),
            fingerprint(after, {"area:runtime"}, "policy1"),
        )

    def test_actual_evidence_producer_satisfies_hydrated_child_contract(self):
        from label_issue_evidence import (
            expand_evidence,
            material_state,
            prepare_snapshot,
        )
        from label_issue_evidence_test import API

        for pull in [False, True]:
            with self.subTest(pull=pull), tempfile.TemporaryDirectory() as directory:
                api = API(pull=pull)
                api.collections["comments"] = [
                    {"id": 7, "body": "Policy context", "user": {"login": "reader"}}
                ]
                if pull:
                    api.collections["files"] = [
                        {
                            "filename": "src/a",
                            "status": "modified",
                            "additions": 1,
                            "deletions": 1,
                            "patch": "@@ -1 +1 @@\n-old\n+new",
                        }
                    ]
                    api.collections["reviews"] = [
                        {"id": 8, "body": "Policy review", "user": {"login": "reader"}}
                    ]
                    api.collections["review_comments"] = [
                        {"id": 9, "body": "Inline context", "user": {"login": "reader"}}
                    ]
                snapshot = prepare_snapshot("Owner/Repo", 3, Path(directory), api=api)
                hydration = ["comments"] + (
                    ["files", "reviews", "review_comments"] if pull else []
                )
                expand_evidence(snapshot, hydration, api=api)
                current = material_state(snapshot)
                with self.assertRaises(IncompleteMaterial):
                    fingerprint(current, {"area:platform"}, snapshot["policy_version"])
                # Task 6 supplies this separately fetched complete filtered lifecycle envelope.
                current["relevant_timeline"] = source(
                    "relevant_timeline", api.lifecycle_events
                )
                before = fingerprint(
                    current, {"area:platform"}, snapshot["policy_version"]
                )
                self.assertEqual(len(before), 64)
                self.assertIn(
                    "comment:7", current["evidence_index"]["comments"]["members"]
                )
                api.collections["comments"][0]["body"] = "Edited old policy context"
                expand_evidence(snapshot, ["comments"], api=api)
                changed = material_state(snapshot)
                changed["relevant_timeline"] = current["relevant_timeline"]
                self.assertNotEqual(
                    before,
                    fingerprint(changed, {"area:platform"}, snapshot["policy_version"]),
                )

    def test_producer_timeline_mapping_order_does_not_change_fingerprint(self):
        from label_issue_evidence import _artifact

        state, reordered = material(), material()
        event = {
            "__typename": "ClosedEvent",
            "id": "C1",
            "createdAt": "t1",
            "closer": {"number": 1, "merged": True},
        }
        state["relevant_timeline"] = _artifact("relevant_timeline", [event])
        event["closer"] = {"merged": True, "number": 1}
        reordered["relevant_timeline"] = _artifact("relevant_timeline", [event])
        self.assertEqual(
            fingerprint(state, {"area:runtime"}, "policy1"),
            fingerprint(reordered, {"area:runtime"}, "policy1"),
        )

    def test_fingerprint_canonicalizes_mapping_order_without_mutating_inputs(self):
        state = material()
        reordered = dict(reversed(list(state.items())))
        reordered["evidence_index"] = dict(
            reversed(list(state["evidence_index"].items()))
        )
        before = copy.deepcopy(state)
        self.assertEqual(
            fingerprint(state, {"topic:policy", "area:runtime"}, "policy1"),
            fingerprint(reordered, {"area:runtime", "topic:policy"}, "policy1"),
        )
        self.assertEqual(state, before)

    def test_missing_hydrated_child_and_partial_patch_fail_closed(self):
        for missing in [True, False]:
            state = material("pull_request")
            if missing:
                del state["evidence_index"]["comment:1"]
            else:
                state["evidence_index"]["patch:proxy"]["coverage"] = "partial"
            with self.assertRaises(IncompleteMaterial):
                fingerprint(state, {"area:runtime"}, "policy1")

    def test_malformed_graphql_json_shapes_are_explicit_lookup_errors(self):
        for payload in [
            {"data": ["not-an-object"]},
            response([None]),
            response([event("bad") | {"__typename": []}]),
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                find_checkpoint(
                    "I_12", api=FakeGitHub([payload]), trusted_actors={"labeler"}
                )

    def test_transcript_cannot_normalize_a_different_actor_as_protocol_owned(self):
        state, final = material(), {"area:runtime"}
        ops = [
            {"actor": "labeler", "action": "add", "label_id": "LA_runtime"},
            {"actor": "human", "action": "remove", "label_id": "LA_gateway"},
        ]
        rationale = encode_checkpoint(
            fingerprint(state, final, "policy1"),
            boundary_id="B0",
            operations_digest=operation_digest(ops),
            event_count=2,
        )
        addition = event("C1", rationale=rationale)
        candidate = find_checkpoint(
            "I_12", api=FakeGitHub([response([addition])]), trusted_actors={"labeler"}
        )["checkpoint"]
        state["existing_labels"] = ["area:runtime"]
        proof = {
            "status": "complete",
            "boundary_id": "B0",
            "item_id": "I_12",
            "events": [addition, event("C2", "remove", "LA_gateway", actor="human")],
        }
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )

    def test_actual_checkpoint_bookkeeping_transcript_normalizes_own_events_only(self):
        state, final = material(), {"area:gateway"}
        ops = [
            {"actor": "labeler", "action": "add", "label_id": "LA_meta"},
            {"actor": "labeler", "action": "remove", "label_id": "LA_meta"},
        ]
        rationale = encode_checkpoint(
            fingerprint(state, final, "policy1"),
            boundary_id="",
            operations_digest=operation_digest(ops),
            event_count=2,
        )
        addition = event("C1", label="LA_meta", rationale=rationale)
        candidate = find_checkpoint(
            "I_12", api=FakeGitHub([response([addition])]), trusted_actors={"labeler"}
        )["checkpoint"]
        proof = {
            "status": "complete",
            "boundary_id": "",
            "item_id": "I_12",
            "events": [addition, event("C2", "remove", "LA_meta")],
        }
        self.assertTrue(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )
        proof["events"][1]["label"]["id"] = "other"
        self.assertFalse(
            checkpoint_matches(candidate, state, final, "policy1", label_events=proof)
        )


if __name__ == "__main__":
    unittest.main()
