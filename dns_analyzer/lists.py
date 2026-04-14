import fnmatch
import os


def load_list(filepath):
  
    try:
        with open(filepath, "r") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except FileNotFoundError:
        return []


def save_list(filepath, patterns):
    """Writes a list of patterns back to a text file on disk."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w") as f:
        f.write("\n".join(patterns))


def is_match(query, patterns):

    # Strip trailing dot DNS always adds, and lowercase for case-insensitivity
    q = query.rstrip(".").lower()

    # Guard: empty query after stripping cannot match anything
    if not q:
        return False, None

    for pattern in patterns:
        p = pattern.lower().rstrip(".")
        # fnmatch handles wildcards: * = any sequence of characters
        if fnmatch.fnmatch(q, p):
            return True, pattern

    return False, None


def get_wildcard_pattern(domain):
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return "*." + ".".join(parts[-2:])
    return domain
