# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""CLI implementation for `conda create`.

Creates new conda environments with the specified packages.
"""

from __future__ import annotations

from logging import getLogger
from os.path import isdir
from typing import TYPE_CHECKING

from ..auxlib.ish import dals
from ..notices import notices
from ..misc import touch_nonadmin


if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace, _SubParsersAction

log = getLogger(__name__)


def configure_parser(sub_parsers: _SubParsersAction, **kwargs) -> ArgumentParser:
    from ..auxlib.ish import dals
    from ..common.constants import NULL
    from .actions import NullCountAction
    from .helpers import (
        add_parser_create_install_update,
        add_parser_default_packages,
        add_parser_platform,
        add_parser_solver,
    )

    summary = "Create a new conda environment from a list of specified packages. "
    description = dals(
        f"""
        {summary}

        To use the newly-created environment, use 'conda activate envname'.
        This command requires either the -n NAME or -p PREFIX option.
        """
    )
    epilog = dals(
        """
        Examples:

        Create an environment containing the package 'sqlite'::

            conda create -n myenv sqlite

        Create an environment (env2) as a clone of an existing environment (env1)::

            conda create -n env2 --clone path/to/file/env1

        """
    )
    p = sub_parsers.add_parser(
        "create",
        help=summary,
        description=description,
        epilog=epilog,
        **kwargs,
    )
    p.add_argument(
        "--clone",
        action="store",
        help="Create a new environment as a copy of an existing local environment.",
        metavar="ENV",
    )
    solver_mode_options, _, channel_options = add_parser_create_install_update(p)
    add_parser_default_packages(solver_mode_options)
    add_parser_platform(channel_options)
    add_parser_solver(solver_mode_options)
    p.add_argument(
        "--dev",
        action=NullCountAction,
        help="Use `sys.executable -m conda` in wrapper scripts instead of CONDA_EXE. "
        "This is mainly for use during tests where we test new conda sources "
        "against old Python versions.",
        dest="dev",
        default=NULL,
    )
    p.set_defaults(func="conda.cli.main_create.execute")

    return p


@notices
def execute(args: Namespace, parser: ArgumentParser) -> int:
    import os
    from tempfile import mktemp

    from ..base.constants import UNUSED_ENV_NAME
    from ..base.context import context
    from ..cli.main_rename import check_protected_dirs
    from ..common.path import paths_equal
    from ..exceptions import ArgumentError, CondaValueError, OperationNotAllowed, TooManyArgumentsError
    from ..gateways.disk.delete import rm_rf
    from ..gateways.disk.test import is_conda_environment
    from ..reporters import confirm_yn
    from .install import check_prefix, install, clone, common_index_args, print_activate

    if not args.name and not args.prefix:
        if context.dry_run:
            args.prefix = os.path.join(mktemp(), UNUSED_ENV_NAME)
            context.__init__(argparse_args=args)
        else:
            # TODO: check if a environment.yaml file is provided. If
            # so, then no need to specify -n/-p
            raise ArgumentError(
                "one of the arguments -n/--name -p/--prefix is required"
            )

    check_protected_dirs(context.target_prefix)
    check_prefix(context.target_prefix, json=context.json)

    if is_conda_environment(context.target_prefix):
        if paths_equal(context.target_prefix, context.root_prefix):
            raise CondaValueError("The target prefix is the base prefix. Aborting.")
        if context.dry_run:
            # Taking the "easy" way out, rather than trying to fake removing
            # the existing environment before creating a new one.
            raise CondaValueError(
                "Cannot `create --dry-run` with an existing conda environment"
            )
        confirm_yn(
            f"WARNING: A conda environment already exists at '{context.target_prefix}'\n\n"
            "Remove existing environment?\nThis will remove ALL directories contained within "
            "this specified prefix directory, including any other conda environments.\n\n",
            default="no",
            dry_run=False,
        )
        log.info("Removing existing environment %s", context.target_prefix)
        rm_rf(context.target_prefix)
    elif isdir(context.target_prefix):
        check_prefix(context.target_prefix)

        confirm_yn(
            f"WARNING: A directory already exists at the target location '{context.target_prefix}'\n"
            "but it is not a conda environment.\n"
            "Continue creating environment",
            default="no",
            dry_run=False,
        )

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

    # TODO: maybe there is a better way to handle mutually exclusive args
    if args.clone and args.package:
         raise TooManyArgumentsError(
                0,
                len(args.packages),
                list(args.packages),
                "did not expect any arguments for --clone",
            )

    if args.clone:
        prefix = context.target_prefix
        index_args = common_index_args(args)
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


    return install(args, parser, "create")
