# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Evidence adapters.

An adapter's only job is to turn an evidence format into a list of mappings
the property checks can read. It never fetches, never executes, and never
reaches the network. :mod:`ambit_grader.adapters.normalise` recognises record
shapes; :mod:`ambit_grader.adapters.foreign` holds the third-party profiles.
"""

from ambit_grader.adapters import foreign, normalise

__all__ = ["foreign", "normalise"]
