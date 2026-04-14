"""
DELETE-ME file. Cycle 7 sanity check that GitHub Actions CI actually
fails loudly on a red test. After CI confirms red on branch
`ci-sanity-check-delete-me`, this file is removed and the branch is
deleted without merging to main.

If you see this file on main, something went wrong — the cycle 7 cleanup
step was missed. Delete it and file a retro note about the workflow.
"""

def test_deliberate_failure_for_ci_sanity_check():
    """
    This assertion MUST fail. Cycle 7 uses this to verify that a CI red
    is actually produced when a test breaks, closing the 'two cycles of
    green means converging OR blind spot' concern from the cycle 6 review.
    """
    assert False, "deliberate CI sanity-check failure — cycle 7"
