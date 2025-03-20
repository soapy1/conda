# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda package installation logic.

Core logic for `conda [create|install|update|remove]` commands.

See conda.cli.main_create, conda.cli.main_install, conda.cli.main_update, and
conda.cli.main_remove for the entry points into this module.
"""

from __future__ import annotations

import os
from logging import getLogger
from os.path import abspath, basename, exists, isdir, isfile, join
from pathlib import Path

from boltons.setutils import IndexedSet

from .. import CondaError
from ..auxlib.ish import dals
from ..base.constants import REPODATA_FN, ROOT_ENV_NAME, DepsModifier, UpdateModifier
from ..base.context import context, locate_prefix_by_name
from ..common.constants import NULL
from ..common.path import is_package_file, paths_equal
from ..core.index import (
    _supplement_index_with_prefix,
    calculate_channel_urls,
    get_index,
)
from ..core.link import PrefixSetup, UnlinkLinkTransaction
from ..core.prefix_data import PrefixData
from ..core.solve import diff_for_unlink_link_precs
from ..exceptions import (
    CondaEnvException,
    CondaExitZero,
    CondaImportError,
    CondaIndexError,
    CondaSystemExit,
    CondaValueError,
    DirectoryNotACondaEnvironmentError,
    DirectoryNotFoundError,
    DryRunExit,
    EnvironmentLocationNotFound,
    NoBaseEnvironmentError,
    OperationNotAllowed,
    PackageNotInstalledError,
    PackagesNotFoundError,
    ResolvePackageNotFound,
    SpecsConfigurationConflictError,
    TooManyArgumentsError,
    UnsatisfiableError,
)
from ..gateways.disk.delete import delete_trash, path_is_clean
from ..history import History
from ..misc import _get_best_prec_match, clone_env, explicit, touch_nonadmin
from ..models.match_spec import MatchSpec
from ..models.prefix_graph import PrefixGraph
from ..reporters import confirm_yn, get_spinner
from . import common
from .common import check_non_admin
from .main_config import set_keys

log = getLogger(__name__)
stderrlog = getLogger("conda.stderr")


def validate_prefix_exists(prefix: str | Path) -> None:
    """
    Validate that we are receiving at least one valid value for --name or --prefix.
    """
    prefix = Path(prefix)
    if not prefix.exists():
        raise CondaEnvException("The environment you have specified does not exist.")


def validate_new_prefix(dest: str, force: bool = False) -> str:
    """Ensure that the new prefix does not exist."""
    from ..base.context import context, validate_prefix_name
    from ..common.path import expand

    if os.sep in dest:
        dest = expand(dest)
    else:
        dest = validate_prefix_name(dest, ctx=context, allow_base=False)

    if not force and os.path.exists(dest):
        env_name = os.path.basename(os.path.normpath(dest))
        raise CondaEnvException(
            f"The environment '{env_name}' already exists. Override with --yes."
        )

    return dest


def check_prefix(prefix: str, json=False):
    if os.pathsep in prefix:
        raise CondaValueError(
            f"Cannot create a conda environment with '{os.pathsep}' in the prefix. Aborting."
        )
    name = basename(prefix)
    error = None
    if name == ROOT_ENV_NAME:
        error = f"'{name}' is a reserved environment name"
    if exists(prefix):
        if isdir(prefix) and "conda-meta" not in tuple(
            entry.name for entry in os.scandir(prefix)
        ):
            return None
        error = f"prefix already exists: {prefix}"

    if error:
        raise CondaValueError(error, json)

    if " " in prefix:
        stderrlog.warning(
            "WARNING: A space was detected in your requested environment path:\n"
            f"'{prefix}'\n"
            "Spaces in paths can sometimes be problematic. To minimize issues,\n"
            "make sure you activate your environment before running any executables!\n"
        )


def clone(src_arg, dst_prefix, json=False, quiet=False, index_args=None):
    if os.sep in src_arg:
        src_prefix = abspath(src_arg)
        if not isdir(src_prefix):
            raise DirectoryNotFoundError(src_arg)
    else:
        src_prefix = locate_prefix_by_name(src_arg)

    if not json:
        print(f"Source:      {src_prefix}")
        print(f"Destination: {dst_prefix}")

    actions, untracked_files = clone_env(
        src_prefix, dst_prefix, verbose=not json, quiet=quiet, index_args=index_args
    )

    if json:
        common.stdout_json_success(
            actions=actions,
            untracked_files=list(untracked_files),
            src_prefix=src_prefix,
            dst_prefix=dst_prefix,
        )


def print_activate(env_name_or_prefix):  # pragma: no cover
    if not context.quiet and not context.json:
        if " " in env_name_or_prefix:
            env_name_or_prefix = f'"{env_name_or_prefix}"'
        message = dals(
            f"""
        #
        # To activate this environment, use
        #
        #     $ conda activate {env_name_or_prefix}
        #
        # To deactivate an active environment, use
        #
        #     $ conda deactivate
        """
        )
        print(message)  # TODO: use logger


def get_revision(arg, json=False):
    try:
        return int(arg)
    except ValueError:
        raise CondaValueError(f"expected revision number, not: '{arg}'", json)


def install(args, parser, command="install"):
    """Logic for `conda install`, `conda update`, and `conda create`."""
    context.validate_configuration()
    check_non_admin()
    # this is sort of a hack.  current_repodata.json may not have any .tar.bz2 files,
    #    because it deduplicates records that exist as both formats.  Forcing this to
    #    repodata.json ensures that .tar.bz2 files are available
    if context.use_only_tar_bz2:
        args.repodata_fns = ("repodata.json",)

    newenv = bool(command == "create")
    isupdate = bool(command == "update")
    isinstall = bool(command == "install")
    isremove = bool(command == "remove")
    prefix = context.target_prefix
    if context.force_32bit and prefix == context.root_prefix:
        raise CondaValueError("cannot use CONDA_FORCE_32BIT=1 in base env")
    if isupdate and not (
        args.file
        or args.packages
        or context.update_modifier == UpdateModifier.UPDATE_ALL
    ):
        raise CondaValueError(
            """no package names supplied
# Example: conda update -n myenv scipy
"""
        )

    if newenv:
        check_prefix(prefix, json=context.json)
        if context.subdir != context._native_subdir():
            # We will only allow a different subdir if it's specified by global
            # configuration, environment variable or command line argument. IOW,
            # prevent a non-base env configured for a non-native subdir from leaking
            # its subdir to a newer env.
            context_sources = context.collect_all()
            if context_sources.get("cmd_line", {}).get("subdir") == context.subdir:
                pass  # this is ok
            elif context_sources.get("envvars", {}).get("subdir") == context.subdir:
                pass  # this is ok too
            # config does not come from envvars or cmd_line, it must be a file
            # that's ok as long as it's a base env or a global file
            elif not paths_equal(context.active_prefix, context.root_prefix):
                # this is only ok as long as it's base environment
                active_env_config = next(
                    (
                        config
                        for path, config in context_sources.items()
                        if paths_equal(context.active_prefix, path.parent)
                    ),
                    None,
                )
                if active_env_config.get("subdir") == context.subdir:
                    # In practice this never happens; the subdir info is not even
                    # loaded from the active env for conda create :shrug:
                    msg = dals(
                        f"""
                        Active environment configuration ({context.active_prefix}) is
                        implicitly requesting a non-native platform ({context.subdir}).
                        Please deactivate first or explicitly request the platform via
                        the --platform=[value] command line flag.
                        """
                    )
                    raise OperationNotAllowed(msg)
            log.info(
                "Creating new environment for a non-native platform %s",
                context.subdir,
            )
    elif isdir(prefix):
        delete_trash(prefix)
        if not isfile(join(prefix, "conda-meta", "history")):
            if paths_equal(prefix, context.conda_prefix):
                raise NoBaseEnvironmentError()
            else:
                if not path_is_clean(prefix):
                    raise DirectoryNotACondaEnvironmentError(prefix)
        else:
            # fall-through expected under normal operation
            pass
    else:
        raise EnvironmentLocationNotFound(prefix)

    args_packages = [s.strip("\"'") for s in args.packages]
    if newenv and not args.no_default_packages:
        # Override defaults if they are specified at the command line
        names = [MatchSpec(pkg).name for pkg in args_packages]
        for default_package in context.create_default_packages:
            if MatchSpec(default_package).name not in names:
                args_packages.append(default_package)

    context_channels = context.channels
    index_args = {
        # TODO: deprecate --use-index-cache
        # "use_cache": args.use_index_cache,  # --use-index-cache
        "channel_urls": context_channels,
        # TODO: deprecate --unknown
        # "unknown": args.unknown,  # --unknown
        "prepend": not args.override_channels,  # --override-channels
        "use_local": args.use_local,  # --use-local
    }

    num_cp = sum(is_package_file(s) for s in args_packages)
    if num_cp:
        if num_cp == len(args_packages):
            explicit(args_packages, prefix, verbose=not context.quiet)
            if newenv:
                touch_nonadmin(prefix)
                print_activate(args.name or prefix)
            return
        else:
            raise CondaValueError(
                "cannot mix specifications with conda package filenames"
            )

    specs = []
    if args.file:
        for fpath in args.file:
            try:
                specs.extend(common.specs_from_url(fpath, json=context.json))
            except UnicodeError:
                raise CondaError(
                    "Error reading file, file should be a text file containing"
                    " packages \nconda create --help for details"
                )
        if "@EXPLICIT" in specs:
            explicit(specs, prefix, verbose=not context.quiet)
            if newenv:
                touch_nonadmin(prefix)
                print_activate(args.name or prefix)
            return
    specs.extend(common.specs_from_args(args_packages, json=context.json))

    if isinstall and args.revision:
        get_revision(args.revision, json=context.json)
    elif isinstall and not (args.file or args_packages):
        raise CondaValueError(
            "too few arguments, must supply command line package specs or --file"
        )

    # for 'conda update', make sure the requested specs actually exist in the prefix
    # and that they are name-only specs
    if isupdate and context.update_modifier != UpdateModifier.UPDATE_ALL:
        prefix_data = PrefixData(prefix)
        for spec in specs:
            spec = MatchSpec(spec)
            if not spec.is_name_only_spec:
                raise CondaError(
                    f"Invalid spec for 'conda update': {spec}\n"
                    "Use 'conda install' instead."
                )
            if not prefix_data.get(spec.name, None):
                raise PackageNotInstalledError(prefix, spec.name)

    if newenv and args.clone:
        if args.packages:
            raise TooManyArgumentsError(
                0,
                len(args.packages),
                list(args.packages),
                "did not expect any arguments for --clone",
            )

        clone(
            args.clone,
            prefix,
            json=context.json,
            quiet=context.quiet,
            index_args=index_args,
        )
        touch_nonadmin(prefix)
        print_activate(args.name or prefix)
        return

    installer = context.plugin_manager.get_env_installer("conda")
    result = installer.install(prefix, specs)
    if newenv:
        if context.subdir != context._native_subdir():
            set_keys(
                ("subdir", context.subdir),
                path=Path(prefix, ".condarc"),
            )
        print_activate(args.name or prefix)

    if context.json:
        common.stdout_json_success(prefix=prefix, actions=result)
    elif context.dry_run:
        common.stdout_json_success(prefix=prefix, actions=result, dry_run=True)
        raise DryRunExit()



def revert_actions(prefix, revision=-1, index=None):
    # TODO: If revision raise a revision error, should always go back to a safe revision
    h = History(prefix)
    # TODO: need a History method to get user-requested specs for revision number
    #       Doing a revert right now messes up user-requested spec history.
    #       Either need to wipe out history after ``revision``, or add the correct
    #       history information to the new entry about to be created.
    # TODO: This is wrong!!!!!!!!!!
    user_requested_specs = h.get_requested_specs_map().values()
    try:
        target_state = {
            MatchSpec.from_dist_str(dist_str) for dist_str in h.get_state(revision)
        }
    except IndexError:
        raise CondaIndexError("no such revision: %d" % revision)

    _supplement_index_with_prefix(index, prefix)

    not_found_in_index_specs = set()
    link_precs = set()
    for spec in target_state:
        precs = tuple(prec for prec in index.values() if spec.match(prec))
        if not precs:
            not_found_in_index_specs.add(spec)
        elif len(precs) > 1:
            link_precs.add(_get_best_prec_match(precs))
        else:
            link_precs.add(precs[0])

    if not_found_in_index_specs:
        raise PackagesNotFoundError(not_found_in_index_specs)

    final_precs = IndexedSet(PrefixGraph(link_precs).graph)  # toposort
    unlink_precs, link_precs = diff_for_unlink_link_precs(prefix, final_precs)
    setup = PrefixSetup(prefix, unlink_precs, link_precs, (), user_requested_specs, ())
    return UnlinkLinkTransaction(setup)


def handle_txn(unlink_link_transaction, prefix, args, newenv, remove_op=False):
    if unlink_link_transaction.nothing_to_do:
        if remove_op:
            # No packages found to remove from environment
            raise PackagesNotFoundError(args.package_names)
        elif not newenv:
            if context.json:
                common.stdout_json_success(
                    message="All requested packages already installed."
                )
            else:
                print("\n# All requested packages already installed.\n")
            return

    if not context.json:
        unlink_link_transaction.print_transaction_summary()
        confirm_yn()

    elif context.dry_run:
        actions = unlink_link_transaction._make_legacy_action_groups()[0]
        common.stdout_json_success(prefix=prefix, actions=actions, dry_run=True)
        raise DryRunExit()

    try:
        unlink_link_transaction.download_and_extract()
        if context.download_only:
            raise CondaExitZero(
                "Package caches prepared. UnlinkLinkTransaction cancelled with "
                "--download-only option."
            )
        unlink_link_transaction.execute()

    except SystemExit as e:
        raise CondaSystemExit("Exiting", e)

    if newenv:
        touch_nonadmin(prefix)
        if context.subdir != context._native_subdir():
            set_keys(
                ("subdir", context.subdir),
                path=Path(prefix, ".condarc"),
            )
        print_activate(args.name or prefix)

    if context.json:
        actions = unlink_link_transaction._make_legacy_action_groups()[0]
        common.stdout_json_success(prefix=prefix, actions=actions)
