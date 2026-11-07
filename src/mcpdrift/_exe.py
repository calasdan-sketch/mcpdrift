"""Find a helper program (ssh-keygen, taskkill) without trusting the
current folder. On Windows ``shutil.which`` and CreateProcess look in the
working directory first, so a checked-out repository containing its own
``ssh-keygen.exe`` could fake a "Good signature". Here the current folder is
never searched."""
from __future__ import annotations

import os
import shutil
from typing import Optional


def find_exe(name: str, path: Optional[str] = None, windows: Optional[bool] = None,
             pathext: Optional[str] = None) -> Optional[str]:
    win = (os.name == "nt") if windows is None else windows
    if not win:
        return shutil.which(name, path=path)
    cwd = os.path.normcase(os.path.abspath(os.getcwd()))
    exts = ["", *[e for e in (pathext if pathext is not None else os.environ.get("PATHEXT", ".EXE;.CMD;.BAT")).split(";") if e]]
    for entry in (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if not entry or entry == os.curdir:
            continue
        d = entry.strip('"')
        if os.path.normcase(os.path.abspath(d)) == cwd:
            continue
        for ext in exts:
            cand = os.path.join(d, name + ext)
            if os.path.isfile(cand):
                return cand
    return None
