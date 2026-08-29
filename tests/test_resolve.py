# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from conda.base.context import reset_context
from conda.common.compat import on_win
from conda.core.index import Index
from conda.exceptions import UnsatisfiableError
from conda.models.match_spec import MatchSpec
from conda.resolve import Resolve
from conda.testing import helpers

if TYPE_CHECKING:
    from pytest import MonkeyPatch
    from pytest_mock import MockerFixture


def test_Resolve_make_channel_priorities():
    channels = ["conda-canary", "defaults", "conda-forge"]
    names = (
        "conda-canary",
        "pkgs/main",
        "pkgs/r",
        *(["pkgs/msys2"] if on_win else []),
        "conda-forge",
    )
    assert Resolve._make_channel_priorities(channels) == {
        name: weight for weight, name in enumerate(names)
    }


def test_specs_by_name_copy_is_independent() -> None:
    """Copying specs_by_name with a dict comprehension must yield independent lists."""
    seed = {
        "numpy": [MatchSpec("numpy>=1.20")],
        "scipy": [MatchSpec("scipy")],
    }
    copy = {k: list(v) for k, v in seed.items()}

    assert copy["numpy"] is not seed["numpy"], "values must be distinct list objects"
    copy["numpy"].append(MatchSpec("numpy<2"))
    assert len(seed["numpy"]) == 1, "seed must not be mutated by changes to the copy"
    assert len(copy["numpy"]) == 2


def test_solve_wrong_version_calls_find_conflicts(
    mocker: MockerFixture,
) -> None:
    """Wrong-version specs route through find_conflicts without crashing.

    build_conflict_map cannot derive chains when no package matches the spec,
    so bad_deps has the classified shape but empty category sets.
    """
    rec = helpers.record(name="foo", version="1.0")
    resolve = Resolve({rec: rec})
    spec = MatchSpec("foo=99.0")

    mocker.patch("conda.resolve.Resolve.get_reduced_index", return_value={})
    find_conflicts = mocker.spy(resolve, "find_conflicts")
    unsatisfiable_init = mocker.spy(UnsatisfiableError, "__init__")

    with pytest.raises(UnsatisfiableError):
        resolve.solve([spec])

    find_conflicts.assert_called_once_with({spec}, None, None)
    bad_deps = unsatisfiable_init.call_args.args[1]
    assert bad_deps == {
        "python": set(),
        "request_conflict_with_history": set(),
        "direct": set(),
        "virtual_package": set(),
    }


@pytest.mark.usefixtures("reset_conda_context")
class TestPrereleaseHandling:
    """Uses the on-disk test channel `channel-one`, where `foo-5.0.0rc1` depends
    on the `__prerelease` virtual package, to exercise the `prerelease` context
    setting against a real solve. `__prerelease` is only exposed by the
    `prerelease` virtual package plugin when prereleases are not disallowed.
    """

    channel = os.path.join(helpers.TEST_DATA_DIR, "channel-one")

    def _solve(self, specs: list[str]):
        index = dict(
            Index(
                channels=[self.channel],
                prepend=False,
                platform="noarch",
                use_system=True,
            )
        )
        return Resolve(index).solve(specs)

    @pytest.mark.parametrize(
        "prerelease,expected_version",
        [
            ("allow", "5.0.0rc1"),
            ("disallow", "4.0.2"),
            ("if-necessary", "4.0.2"),
        ],
    )
    def test_prerelease_setting(
        self, monkeypatch: MonkeyPatch, prerelease: str, expected_version: str
    ):
        monkeypatch.setenv("CONDA_PRERELEASE", prerelease)
        reset_context()
        result = self._solve(["foo"])
        assert [str(prec.version) for prec in result] == [expected_version]


    @pytest.mark.parametrize(
        "solve_specs,expected_version",
        [
            ("foo>=4.99", "5.0.0rc1"),
            ("foo>=4.0", "4.0.2"),
            ("foo", "4.0.2"),
        ],
    )
    def test_prerelease_if_necessary(
        self, monkeypatch: MonkeyPatch, solve_specs: str, expected_version: str
    ):
        monkeypatch.setenv("CONDA_PRERELEASE", "if-necessary")
        reset_context()
        result = self._solve([solve_specs])
        assert [str(prec.version) for prec in result] == [expected_version]
