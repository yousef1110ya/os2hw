import pkgutil
import importlib
import inspect

from detectors.base import BaseDetector


def load_detectors():

    import detectors

    loaded = []
    seen_classes = set()

    for module_info in pkgutil.walk_packages(
        detectors.__path__,
        detectors.__name__ + "."
    ):

        module_name = module_info.name

        if module_name.endswith("base"):
            continue

        module = importlib.import_module(module_name)

        for _, cls in inspect.getmembers(module, inspect.isclass):

            if (
                issubclass(cls, BaseDetector)
                and cls is not BaseDetector
                and cls not in seen_classes
            ):
                seen_classes.add(cls)
                loaded.append(cls())

    return loaded
