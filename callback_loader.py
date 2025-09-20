import importlib.util
import os
import threading
from types import ModuleType
from typing import Callable

_MODULE_CACHE: dict[str, ModuleType] = {}
_MODULE_LOCK = threading.RLock()


def load_func(path: str, func_name: str) -> Callable:
    """
    Load (with thread-safe cache) a Python module from `path`
    and return the callable attribute `func_name`.
    """
    abs_path = os.path.abspath(path)

    with _MODULE_LOCK:
        mod = _MODULE_CACHE.get(abs_path)
        if mod is None:
            spec = importlib.util.spec_from_file_location(f"cb_{hash(abs_path)}", abs_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Impossible de charger le module: {path}")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            _MODULE_CACHE[abs_path] = mod

        func = getattr(mod, func_name, None)
        if not callable(func):
            raise AttributeError(f"La fonction '{func_name}' est introuvable/callable dans {path}")

        return func

