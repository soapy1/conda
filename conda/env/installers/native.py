# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda-flavored installer."""

import tempfile
from typing import Iterable
from os.path import basename
from functools import wraps

from boltons.setutils import IndexedSet

from ...base.constants import UpdateModifier
from ...base.context import context
from ...exceptions import (
    CondaSystemExit,
    CondaExitZero,
    PackagesNotFoundError,
    ResolvePackageNotFound,
    SpecsConfigurationConflictError,
    UnsatisfiableError,
)
from ...reporters import confirm_yn
from ...models.channel import Channel, prioritize_channels


def _solve(prefix, specs):
    """Solve the environment"""
    channel_urls = context.channels
    _channel_priority_map = prioritize_channels(channel_urls)

    channels = IndexedSet(Channel(url) for url in _channel_priority_map)
    subdirs = IndexedSet(basename(url) for url in _channel_priority_map)

    solver_backend = context.plugin_manager.get_cached_solver_backend()
    solver = solver_backend(prefix, channels, subdirs, specs_to_add=specs)
    return solver


def dry_run(specs: Iterable[str], *args, **kwargs) -> Iterable[str]:
    """Do a dry run of the environment solve"""
    solver = _solve(tempfile.mkdtemp(), specs)
    pkgs = solver.solve_final_state()
    return [str(p) for p in pkgs]


def retry_package_not_found(repodata_fns: list[str], index_args: dict[str, any], retry_extra_errors: tuple[Exception] = ()):
    """Decorator to retry running a (conda solving) function 
    The function being decorated should accept a repodata as an input 'repodata'.
    
    :param repodata_fns: a list of the repodatas
    :param index_args: a dict of arguments for describing the index
    :param retry_extra_errors: a tuple of exceptions to catch and retry with the next repodata file 
    :raises Excption: if the package is not found in any of the provided repodata_fns, or one of the provided retry_extra_errors occurs
    """
    from ...core.index import calculate_channel_urls

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for repodata_fn in repodata_fns:
                try:
                    return func(repodata=repodata_fn, *args, **kwargs)
                except (ResolvePackageNotFound, PackagesNotFoundError) as e:
                    if not getattr(e, "allow_retry", True):
                        # TODO: This is a temporary workaround to allow downstream libraries
                        # to inject this attribute set to False and skip the retry logic
                        # Other solvers might implement their own internal retry logic without
                        # depending --freeze-install implicitly like conda classic does. Example
                        # retry loop in conda-libmamba-solver:
                        # https://github.com/conda-incubator/conda-libmamba-solver/blob/da5b1ba/conda_libmamba_solver/solver.py#L254-L299
                        # If we end up raising UnsatisfiableError, we annotate it with `allow_retry`
                        # so we don't have go through all the repodatas and freeze-installed logic
                        # unnecessarily (see https://github.com/conda/conda/issues/11294). see also:
                        # https://github.com/conda-incubator/conda-libmamba-solver/blob/7c698209/conda_libmamba_solver/solver.py#L617
                        raise e

                    if repodata_fn == repodata_fns[-1]:
                        # PackagesNotFoundError is the only exception type we want to raise.
                        #    Over time, we should try to get rid of ResolvePackageNotFound
                        if isinstance(e, PackagesNotFoundError):
                            raise e
                        else:
                            channels_urls = tuple(
                                calculate_channel_urls(
                                    channel_urls=index_args["channel_urls"],
                                    prepend=index_args["prepend"],
                                    platform=None,
                                    use_local=index_args["use_local"],
                                )
                            )
                            # convert the ResolvePackageNotFound into PackagesNotFoundError
                            raise PackagesNotFoundError(e._formatted_chains, channels_urls)
                except Exception as e:
                     # If the exception is:
                     # 1. not in the list of exceptions that should be retried OR
                     # 2. their are no more repodata files to try, 
                     # then we must raise the exception
                     if (type(e) not in retry_extra_errors 
                         or repodata_fn == repodata_fns[-1]):
                         raise e

        return wrapper
    return decorator


def handle_txn(unlink_link_transaction, prefix, args, remove_op=False):
    if unlink_link_transaction.nothing_to_do or context.dry_run:
        return

    if not context.json:
        unlink_link_transaction.print_transaction_summary()
        confirm_yn()

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


def install(prefix: str, specs: Iterable[str], *args, **kwargs) -> Iterable[str]:
    """Install packages into an environment"""
    channel_urls = context.channels
    _channel_priority_map = prioritize_channels(channel_urls)
    repodata_fns = list(context.repodata_fns)
    index_args = {
        "channel_urls": channel_urls,
        # TODO: how to get override_channels
        #"prepend": not args.override_channels,  # --override-channels
        "use_local": context.use_local,  # --use-local
    }

    channels = IndexedSet(Channel(url) for url in _channel_priority_map)

    # This helps us differentiate between an update, the --freeze-installed option, and the retry
    # behavior in our initial fast frozen solve
    _should_retry_unfrozen = (
        context.update_modifier not in (UpdateModifier.FREEZE_INSTALLED, UpdateModifier.UPDATE_SPECS)
    )

    @retry_package_not_found(repodata_fns=repodata_fns, index_args=index_args, retry_extra_errors=(UnsatisfiableError, SpecsConfigurationConflictError, SystemExit))
    def get_solve_transaction(repodata):
        solver_backend = context.plugin_manager.get_cached_solver_backend()
        solver = solver_backend(
            prefix,
            channels,
            context.subdirs,
            specs_to_add=specs,
            repodata_fn=repodata,
        )
        
        try:
            return solver.solve_for_transaction(
                deps_modifier=context.deps_modifier,
                update_modifier=context.update_modifier,
                force_reinstall=context.force_reinstall or context.force,
                should_retry_solve=(
                     _should_retry_unfrozen or repodata != repodata_fns[-1]
                ),
            )
        except (UnsatisfiableError, SpecsConfigurationConflictError) as e:
            if not getattr(e, "allow_retry", True):
                # TODO: This is a temporary workaround to allow downstream libraries
                # to inject this attribute set to False and skip the retry logic
                # Other solvers might implement their own internal retry logic without
                # depending --freeze-install implicitly like conda classic does. Example
                # retry loop in conda-libmamba-solver:
                # https://github.com/conda-incubator/conda-libmamba-solver/blob/da5b1ba/conda_libmamba_solver/solver.py#L254-L299
                # If we end up raising UnsatisfiableError, we annotate it with `allow_retry`
                # so we don't have go through all the repodatas and freeze-installed logic
                # unnecessarily (see https://github.com/conda/conda/issues/11294). see also:
                # https://github.com/conda-incubator/conda-libmamba-solver/blob/7c698209/conda_libmamba_solver/solver.py#L617
                raise e
            if _should_retry_unfrozen:
                return solver.solve_for_transaction(
                    deps_modifier=context.deps_modifier,
                    update_modifier=UpdateModifier.UPDATE_SPECS,
                    force_reinstall=context.force_reinstall or context.force,
                    should_retry_solve=(repodata != repodata_fns[-1]),
                )
            else:
                raise e

    unlink_link_transaction = get_solve_transaction()
    if unlink_link_transaction.nothing_to_do:
        return None
    
    handle_txn(unlink_link_transaction, prefix, args)
    return unlink_link_transaction._make_legacy_action_groups()[0]
