"""Compatibility namespace for installed SentinelForge integrations."""

import importlib
import pkgutil
import sys

import riswan_ir

for module in pkgutil.walk_packages(riswan_ir.__path__, "riswan_ir."):
    if module.name == "riswan_ir.__main__":
        continue
    alias = "sentinelforge" + module.name.removeprefix("riswan_ir")
    sys.modules[alias] = imported = importlib.import_module(module.name)
    if module.name.count(".") == 1:
        globals()[module.name.rsplit(".", 1)[1]] = imported
