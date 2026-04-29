"""
SumTree — Iterating Sum Composition into a Binary Tree (MMM Section 7)

SumTree(scheme_factory, depth) builds a balanced binary tree of Sum nodes
with 2^depth leaves, each leaf being an independent instance of the base
scheme. This gives a forward-secure scheme with 2^depth time periods.

Construction (depth=3 example):

    Level 0 (leaves):  S  S  S  S  S  S  S  S     (each handles 1 period)
    Level 1:           Sum(S,S)  Sum(S,S)  ...     (2 periods each)
    Level 2:           Sum(Sum,Sum)  Sum(Sum,Sum)   (4 periods each)
    Level 3 (root):    Sum(level2_L, level2_R)      (8 periods)

The scheme_factory is a callable that returns a fresh AbstractSignature
instance (e.g., lambda: MLDSA() or lambda: MLDSA("ML-DSA-44")).

Convention: update(t) prepares the scheme for signing at time t.
Called BEFORE sign(t), matching the existing SumCompose convention.
"""

from typing import Callable
from interfaces.signature import AbstractSignature
from signers.sum_compose import SumCompose


def build_sum_tree(
    scheme_factory: Callable[[], AbstractSignature],
    depth: int,
) -> AbstractSignature:
    """
    Recursively build a SumTree of the given depth.

    - depth=0: returns a single base scheme instance (1 time period)
    - depth=d: returns Sum(SumTree(d-1), SumTree(d-1)) with 2^d time periods

    Args:
        scheme_factory: callable returning a fresh AbstractSignature instance
        depth: tree depth (total periods = 2^depth)

    Returns:
        An AbstractSignature with 2^depth time periods
    """
    if depth == 0:
        return scheme_factory()

    left = build_sum_tree(scheme_factory, depth - 1)
    right = build_sum_tree(scheme_factory, depth - 1)
    return SumCompose(left, right)
