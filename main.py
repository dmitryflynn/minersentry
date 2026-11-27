"""MinerSentry entry point, and the packaged exe's.

With no arguments this is the GUI. `--service` is how the scheduled task that
`minersentry-service --install` registers from the packaged exe starts it
again (see `service._run_target`), so it has to run the watcher: ignoring it
opened the GUI as SYSTEM at boot, and nothing watched.
"""
import os
import sys


def _ensure_streams() -> None:
    """A --windowed PyInstaller build has no console, so sys.stdout and
    sys.stderr are None and the first print raises."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def launch(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--service"]:
        _ensure_streams()
        from minersentry import service
        return service.main(["--run", *argv[1:]])
    from minersentry.gui import main
    main()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
