r"""An in-memory stand-in for `winreg`, for tests that must not touch the real
registry and must also run off Windows.

Only what MinerSentry calls is implemented. Key paths and value names are
case-insensitive, as they are in the real registry, and a missing key or
value raises FileNotFoundError, as `winreg` does.

    reg = FakeWinreg()
    reg.set("HKCU", r"Software\X\Run", "name", "value")
    monkeypatch.setitem(sys.modules, "winreg", reg)
"""

from __future__ import annotations


class _Key:
    def __init__(self, reg: "FakeWinreg", hive: int, path: str):
        self.reg, self.hive, self.path = reg, hive, path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def Close(self):
        pass


class FakeWinreg:
    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_MULTI_SZ = 7

    _HIVES = {"HKCU": 1, "HKLM": 2}

    def __init__(self):
        # (hive, lower path) -> {lower name: (name, value, type)}
        self.keys: dict[tuple[int, str], dict[str, tuple[str, object, int]]] = {}
        self.paths: dict[tuple[int, str], str] = {}

    # -- test-side helpers -------------------------------------------------
    def set(self, hive: str, path: str, name: str, value, value_type: int = 1):
        h = self._HIVES[hive]
        self._ensure(h, path)
        self.keys[(h, path.lower())][name.lower()] = (name, value, value_type)

    def get(self, hive: str, path: str, name: str):
        values = self.keys.get((self._HIVES[hive], path.lower()), {})
        found = values.get(name.lower())
        return None if found is None else (found[1], found[2])

    def _ensure(self, hive: int, path: str):
        parts = path.split("\\")
        for i in range(1, len(parts) + 1):
            sub = "\\".join(parts[:i])
            self.keys.setdefault((hive, sub.lower()), {})
            self.paths.setdefault((hive, sub.lower()), sub)

    # -- the winreg surface ------------------------------------------------
    def _resolve(self, key, sub: str) -> tuple[int, str]:
        if isinstance(key, _Key):
            hive = key.hive
            path = f"{key.path}\\{sub}" if sub else key.path
        else:
            hive, path = key, sub
        return hive, path

    def OpenKey(self, key, sub_key, reserved=0, access=0):
        hive, path = self._resolve(key, sub_key)
        if (hive, path.lower()) not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return _Key(self, hive, path)

    def CreateKey(self, key, sub_key):
        hive, path = self._resolve(key, sub_key)
        self._ensure(hive, path)
        return _Key(self, hive, path)

    def _values(self, key: _Key):
        return self.keys[(key.hive, key.path.lower())]

    def QueryValueEx(self, key: _Key, name: str):
        found = self._values(key).get((name or "").lower())
        if found is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return found[1], found[2]

    def SetValueEx(self, key: _Key, name: str, reserved, value_type, value):
        self._values(key)[(name or "").lower()] = (name, value, value_type)

    def DeleteValue(self, key: _Key, name: str):
        values = self._values(key)
        if (name or "").lower() not in values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        del values[(name or "").lower()]

    def _subkeys(self, key: _Key) -> list[str]:
        prefix = key.path.lower() + "\\"
        out = []
        for (hive, low), _values in self.keys.items():
            if hive == key.hive and low.startswith(prefix) \
                    and "\\" not in low[len(prefix):]:
                out.append(self.paths[(hive, low)].rsplit("\\", 1)[-1])
        return out

    def QueryInfoKey(self, key: _Key):
        return len(self._subkeys(key)), len(self._values(key)), 0

    def EnumKey(self, key: _Key, index: int) -> str:
        subs = self._subkeys(key)
        if index >= len(subs):
            raise OSError(259, "No more data is available")
        return subs[index]

    def EnumValue(self, key: _Key, index: int):
        values = list(self._values(key).values())
        if index >= len(values):
            raise OSError(259, "No more data is available")
        return values[index]
