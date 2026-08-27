# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from conda.base.context import reset_context, context
from conda.common.compat import on_win
from conda.exceptions import UnsatisfiableError
from conda.exports import get_index
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord, PrefixRecord
from conda.resolve import Resolve
from conda.testing import helpers
from conda.testing.helpers import TEST_DATA_DIR

from conda.common.configuration import DefaultValueRawParameter

if TYPE_CHECKING:
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
    def _index(self, versions, installed_version=None):
        index = {}
        for version in versions:
            rec = helpers.record(name="foo", version=version)
            if version == installed_version:
                rec = PrefixRecord.from_objects(rec)
            index[rec] = rec
        return index

    def test_allow_prefers_latest_including_prerelease(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "allow")
        reset_context()
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_disallow_skips_prerelease(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.1.0"]

    def test_disallow_raises_when_only_prerelease_available(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        resolve = Resolve(self._index(["1.2.0rc1"]))
        with pytest.raises(UnsatisfiableError):
            resolve.solve(["foo"])

    def test_disallow_keeps_already_installed_prerelease(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        resolve = Resolve(
            self._index(["1.0.0", "1.2.0rc1"], installed_version="1.2.0rc1")
        )
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_if_necessary_prefers_stable(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "if-necessary")
        reset_context()
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.1.0"]

    def test_if_necessary_falls_back_to_prerelease(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "if-necessary")
        reset_context()
        resolve = Resolve(self._index(["1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_disallow_does_not_exclude_virtual_packages(self, monkeypatch):
        """Regression test: conda's own __conda virtual package uses a
        placeholder dev version (e.g. 0.0.0.dev0+placeholder), which is not a
        stable version. Disallowing prereleases must not exclude it, or every
        solve becomes unsatisfiable.
        """
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        index = self._index(["1.0.0", "1.1.0"])
        vpkg = PackageRecord.virtual_package("__conda", "0.0.0.dev0+placeholder")
        index[vpkg] = vpkg
        resolve = Resolve(index)
        # core/solve.py adds a bare MatchSpec for every virtual package present
        # in the index so the solver accounts for it; reproduce that here.
        result = resolve.solve(["foo", "__conda"])
        assert [str(prec.version) for prec in result] == ["1.1.0"]

    def test_prerelease_package_allow(self):
        reset_context()
        raw_data = {"prerelease_package": {"foo": "allow"}}
        rd = {
            "testdata": DefaultValueRawParameter.make_raw_parameters("testdata", raw_data)
        }
        context._set_raw_data(rd)
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_prerelease_package_disallow(self):
        reset_context()
        raw_data = {"prerelease_package": {"foo": "disallow"}}
        rd = {
            "testdata": DefaultValueRawParameter.make_raw_parameters("testdata", raw_data)
        }
        context._set_raw_data(rd)
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.1.0"]

    def test_prerelease_package_only_effects_package(self):
        reset_context()
        raw_data = {"prerelease_package": {"bob": "disallow"}}
        rd = {
            "testdata": DefaultValueRawParameter.make_raw_parameters("testdata", raw_data)
        }
        context._set_raw_data(rd)
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_prerelease_package_higher_priority_than_prerelease_one(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        raw_data = {"prerelease_package": {"foo": "allow"}}
        rd = {
            "testdata": DefaultValueRawParameter.make_raw_parameters("testdata", raw_data)
        }
        context._set_raw_data(rd)

        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.2.0rc1"]

    def test_prerelease_package_higher_priority_than_prerelease_two(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "allow")
        reset_context()
        raw_data = {"prerelease_package": {"foo": "disallow"}}
        rd = {
            "testdata": DefaultValueRawParameter.make_raw_parameters("testdata", raw_data)
        }
        context._set_raw_data(rd)
    
        resolve = Resolve(self._index(["1.0.0", "1.1.0", "1.2.0rc1"]))
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["1.1.0"]


@pytest.mark.usefixtures("reset_conda_context")
class TestPrereleaseHandlingWithRealChannels:
    """Uses the on-disk test channels channel-one (foo 3.0.2, 4.0.2) and
    channel-one-prerelease (foo 3.0.2rc1, 4.0.2rc1, 5.0.0rc1) to exercise the
    prerelease config option against real repodata.
    """

    stable_channel = f"file://{TEST_DATA_DIR}/channel-one"
    prerelease_channel = f"file://{TEST_DATA_DIR}/channel-one-prerelease"

    def _resolve(self, channels):
        index = get_index(
            channel_urls=channels, prepend=False, platform="noarch", use_cache=False
        )
        return Resolve(index)

    @pytest.mark.parametrize(
        "prerelease,expected_version",
        [
            ("allow", "5.0.0rc1"),
            ("disallow", "4.0.2"),
            ("if-necessary", "4.0.2"),
        ],
    )
    def test_prerelease_setting(self, monkeypatch, prerelease, expected_version):
        monkeypatch.setenv("CONDA_PRERELEASE", prerelease)
        reset_context()
        resolve = self._resolve([self.stable_channel, self.prerelease_channel])
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == [expected_version]

    def test_if_necessary_falls_back_when_only_prerelease_channel(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "if-necessary")
        reset_context()
        resolve = self._resolve([self.prerelease_channel])
        result = resolve.solve(["foo"])
        assert [str(prec.version) for prec in result] == ["5.0.0rc1"]

    def test_disallow_raises_when_only_prerelease_channel(self, monkeypatch):
        monkeypatch.setenv("CONDA_PRERELEASE", "disallow")
        reset_context()
        resolve = self._resolve([self.prerelease_channel])
        with pytest.raises(UnsatisfiableError):
            resolve.solve(["foo"])
