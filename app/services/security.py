import os


class PathTraversalError(ValueError):
    pass


def sanitise_path(path: str, base_path: str) -> str:
    base_real = os.path.realpath(base_path)
    candidate = path if os.path.isabs(path) else os.path.join(base_real, path)
    resolved = os.path.realpath(candidate)
    if resolved != base_real and not resolved.startswith(base_real + os.sep):
        raise PathTraversalError("Path traversal detected")
    return resolved
