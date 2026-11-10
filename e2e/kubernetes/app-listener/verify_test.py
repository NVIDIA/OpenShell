# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Ensure listener E2E rejects app Services in both supervisor topologies."""

import unittest

from verify import check_app_service_count


class AppServiceCountTest(unittest.TestCase):
    def test_both_topologies_reject_app_services(self):
        for topology in ("dedicated", "shared"):
            for services in ([{}], [{}, {}]):
                with (
                    self.subTest(topology=topology, count=len(services)),
                    self.assertRaisesRegex(AssertionError, "expected 0"),
                ):
                    check_app_service_count(services, topology)

    def test_both_topologies_accept_no_app_services(self):
        for topology in ("dedicated", "shared"):
            with self.subTest(topology=topology):
                check_app_service_count([], topology)


if __name__ == "__main__":
    unittest.main()
