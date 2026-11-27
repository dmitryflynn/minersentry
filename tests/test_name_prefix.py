"""The short-name check matches whole path components (#65).

`score_name` used `exe.startswith(trusted_dirs)`, so C:\\Program Files2 (which
any user can create) counted as Program Files, and /optx as /opt.
"""

import pytest

from minersentry.config import Config
from minersentry.scoring import score_name

WIN = ("c:\\program files", "c:\\program files (x86)",
       "c:\\windows\\system32", "c:\\windows\\syswow64")
POSIX = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/usr/libexec", "/opt")


def _cfg(dirs):
    return Config(trusted_dirs=dirs, suspicious_dir_hints=())


@pytest.mark.parametrize("dirs,exe", [
    (WIN, r"C:\Program Files2\abc.exe"),
    (WIN, r"C:\Program Filesx\abc.exe"),
    (WIN, r"C:\Windows\System32x\abc.exe"),
    (POSIX, "/optx/abc"),
    (POSIX, "/binx/abc"),
])
def test_a_lookalike_folder_is_outside_the_standard_dirs(dirs, exe):
    sig = score_name("abc", exe, _cfg(dirs))
    assert sig.score == Config().name_score_short, sig.detail


@pytest.mark.parametrize("dirs,exe", [
    (WIN, r"C:\Program Files\Vendor\abc.exe"),
    (WIN, r"C:\Windows\System32\abc.exe"),
    (POSIX, "/opt/vendor/abc"),
    (POSIX, "/usr/bin/abc"),
])
def test_a_real_standard_dir_still_exempts_a_short_name(dirs, exe):
    assert score_name("abc", exe, _cfg(dirs)).score == 0
