"""In-memory registry implementing the backend interface used by pirate_monitor.registry.model."""

import threading
import time


def _now_filetime():
    return int(time.time() * 10_000_000) + 116444736000000000


class FakeKey:
    def __init__(self, name):
        self.name = name
        self.children = {}  # lower -> FakeKey
        self.values = {}  # lower -> (name, data, type)
        self.last_write = _now_filetime()
        self.deleted = False


class FakeRegistry:
    def __init__(self):
        self.lock = threading.RLock()
        self.hives = {h: FakeKey(h) for h in ("HKLM", "HKCU", "HKU")}

    # -- mutation helpers used by tests ---------------------------------------------------------
    def _resolve(self, path, create=False):
        parts = path.split("\\")
        key = self.hives[parts[0]]
        for part in parts[1:]:
            child = key.children.get(part.lower())
            if child is None:
                if not create:
                    raise OSError(2, f"not found: {path}")
                child = FakeKey(part)
                key.children[part.lower()] = child
                key.last_write = _now_filetime()
            key = child
        return key

    def create(self, path):
        with self.lock:
            return self._resolve(path, create=True)

    def set_value(self, path, name, data, vtype=1):
        with self.lock:
            key = self._resolve(path, create=True)
            key.values[name.lower()] = (name, data, vtype)
            key.last_write = _now_filetime()

    def delete_value(self, path, name):
        with self.lock:
            key = self._resolve(path)
            del key.values[name.lower()]
            key.last_write = _now_filetime()

    def delete_key(self, path):
        with self.lock:
            parent_path, _, name = path.rpartition("\\")
            parent = self._resolve(parent_path)
            child = parent.children.pop(name.lower())
            parent.last_write = _now_filetime()

            def mark(k):
                k.deleted = True
                for c in k.children.values():
                    mark(c)

            mark(child)

    def age(self, path, seconds):
        """Pretend a key (and its subtree) was last written ``seconds`` ago."""
        with self.lock:
            def walk(k):
                k.last_write -= int(seconds * 10_000_000)
                for c in k.children.values():
                    walk(c)

            walk(self._resolve(path))

    # -- backend interface ----------------------------------------------------------------------
    def open(self, path):
        with self.lock:
            return self._resolve(path)

    def open_child(self, handle, name):
        with self.lock:
            if handle.deleted:
                raise OSError(1018, "key deleted")
            child = handle.children.get(name.lower())
            if child is None:
                raise OSError(2, "not found")
            return child

    def close(self, handle):
        pass

    def last_write(self, handle):
        return handle.last_write

    def subkeys(self, handle):
        with self.lock:
            return [c.name for c in handle.children.values()]

    def values(self, handle):
        with self.lock:
            return list(handle.values.values())
