#
# TEE Attestation Service - KBM Plugin Contract Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Contract tests to verify that all KBM plugins adhere to the expected interface
# and properly declare their host-provided dependencies via KBM_HOST_KWARGS.

import importlib
import inspect
import os
import pkgutil
import sys
from pathlib import Path

import pytest

# Add plugins directory to path
PLUGINS_DIR = Path(__file__).parent.parent / "plugins"
if str(PLUGINS_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGINS_DIR))


def discover_kbm_plugins():
    """Discover all KBM plugins (modules starting with tas_kbm_)."""
    plugins = {}
    for importer, modname, ispkg in pkgutil.iter_modules([str(PLUGINS_DIR)]):
        if modname.startswith("tas_kbm_"):
            module = importlib.import_module(modname)
            plugins[modname] = module
    return plugins


class TestKBMPluginContract:
    """Test that all discovered KBM plugins adhere to the contract."""

    @pytest.fixture(scope="class")
    def kbm_plugins(self):
        """Discover all KBM plugins."""
        return discover_kbm_plugins()

    def test_all_plugins_discoverable(self, kbm_plugins):
        """Verify that at least some KBM plugins are discoverable."""
        assert len(kbm_plugins) > 0, "No KBM plugins discovered; check PLUGINS_DIR"

    def test_plugin_has_required_functions(self, kbm_plugins):
        """Each KBM plugin must have the three required functions."""
        required = [
            "kbm_open_client_connection",
            "kbm_get_secret",
            "kbm_close_client_connection",
        ]
        for plugin_name, module in kbm_plugins.items():
            for func_name in required:
                assert hasattr(
                    module, func_name
                ), f"Plugin {plugin_name} is missing required function '{func_name}'"
                func = getattr(module, func_name)
                assert callable(
                    func
                ), f"Plugin {plugin_name}.{func_name} is not callable"

    def test_plugin_declares_host_kwargs_if_present(self, kbm_plugins):
        """If a plugin declares KBM_HOST_KWARGS it must be a set. A missing declaration
        is treated as set() (no extra dependencies) and is valid."""
        for plugin_name, module in kbm_plugins.items():
            declared = getattr(module, "KBM_HOST_KWARGS", None)
            if declared is not None:
                assert isinstance(declared, set), (
                    f"Plugin {plugin_name}.KBM_HOST_KWARGS must be a set, "
                    f"got {type(declared).__name__}"
                )

    def test_plugin_signature_matches_declared_kwargs(self, kbm_plugins):
        """Verify that kbm_open_client_connection signature accepts declared kwargs."""
        # Known supported kwargs that the host can provide
        supported_kwargs = {"redis_client"}

        for plugin_name, module in kbm_plugins.items():
            declared_kwargs = getattr(module, "KBM_HOST_KWARGS", set())

            # Verify that declared kwargs are from the supported set
            unsupported = declared_kwargs - supported_kwargs
            assert not unsupported, (
                f"Plugin {plugin_name} declares unsupported kwargs: {unsupported}; "
                f"supported: {supported_kwargs}"
            )

            # Get the function signature
            func = module.kbm_open_client_connection
            sig = inspect.signature(func)
            param_names = set(sig.parameters.keys())

            # Build the call kwargs that app.py would attempt
            call_kwargs = {"config_file": None}  # always required
            for kwarg in declared_kwargs:
                call_kwargs[kwarg] = None

            # Verify the signature can accept these kwargs
            try:
                sig.bind(**call_kwargs)
            except TypeError as e:
                pytest.fail(
                    f"Plugin {plugin_name} cannot accept declared kwargs. "
                    f"Declared: {declared_kwargs}, Parameters: {param_names}, "
                    f"Error: {e}"
                )

            # Verify that declared kwargs are actually in the signature
            for kwarg in declared_kwargs:
                assert kwarg in param_names, (
                    f"Plugin {plugin_name} declares {kwarg!r} in KBM_HOST_KWARGS "
                    f"but the function parameter {kwarg!r} is missing. "
                    f"Available parameters: {list(param_names)}"
                )

    def test_plugin_functions_have_reasonable_signatures(self, kbm_plugins):
        """Verify that plugin functions have expected parameter patterns."""
        for plugin_name, module in kbm_plugins.items():
            # kbm_open_client_connection: should have config_file and optionally other kwargs
            open_sig = inspect.signature(module.kbm_open_client_connection)
            assert (
                "config_file" in open_sig.parameters
            ), f"Plugin {plugin_name}: kbm_open_client_connection must have 'config_file' parameter"

            # kbm_get_secret: should have (client, key_id, wrapping_key)
            get_sig = inspect.signature(module.kbm_get_secret)
            get_params = list(get_sig.parameters.keys())
            assert len(get_params) >= 3, (
                f"Plugin {plugin_name}: kbm_get_secret must have at least 3 parameters "
                f"(client, key_id, wrapping_key), got {get_params}"
            )

            # kbm_close_client_connection: should have at least one parameter (client handle)
            close_sig = inspect.signature(module.kbm_close_client_connection)
            close_params = list(close_sig.parameters.keys())
            assert len(close_params) >= 1, (
                f"Plugin {plugin_name}: kbm_close_client_connection must have "
                f"at least one parameter (the client handle), got {close_params}"
            )

    def test_standard_plugins_have_expected_declarations(self, kbm_plugins):
        """Verify that built-in plugins have expected declarations."""
        # tas_kbm_mock: should declare empty set
        if "tas_kbm_mock" in kbm_plugins:
            mock = kbm_plugins["tas_kbm_mock"]
            assert (
                getattr(mock, "KBM_HOST_KWARGS", set()) == set()
            ), "tas_kbm_mock should not declare any host kwargs"

        # tas_kbm_thales_ctm: should declare redis_client
        if "tas_kbm_thales_ctm" in kbm_plugins:
            ctm = kbm_plugins["tas_kbm_thales_ctm"]
            assert "redis_client" in getattr(
                ctm, "KBM_HOST_KWARGS", set()
            ), "tas_kbm_thales_ctm should declare redis_client in KBM_HOST_KWARGS"

        # tas_kbm_kmip_json: should declare empty set
        if "tas_kbm_kmip_json" in kbm_plugins:
            kmip = kbm_plugins["tas_kbm_kmip_json"]
            assert (
                getattr(kmip, "KBM_HOST_KWARGS", set()) == set()
            ), "tas_kbm_kmip_json should not declare any host kwargs"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
