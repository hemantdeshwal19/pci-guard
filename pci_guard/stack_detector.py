import os


def detect(target_dir: str) -> set:
    signals = set()

    if os.path.exists(os.path.join(target_dir, "Dockerfile")):
        signals.add("has_dockerfile")

    if any(
        os.path.exists(os.path.join(target_dir, f))
        for f in ["requirements.txt", "Pipfile", "pyproject.toml"]
    ):
        signals.add("has_python_deps")

    if any(
        os.path.exists(os.path.join(target_dir, f))
        for f in ["package.json", "yarn.lock"]
    ):
        signals.add("has_node_deps")

    return signals
