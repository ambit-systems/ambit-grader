# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Evidence adapters.

An adapter's only job is to turn a foreign evidence format into a list of
mappings the property checks can read. It never fetches, never executes, and
never reaches the network.
"""

from ambit_grader.adapters import ambit_receipts

__all__ = ["ambit_receipts"]
