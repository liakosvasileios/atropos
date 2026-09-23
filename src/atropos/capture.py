"""Host-side driver for the Frida capture agent.

``frida`` is an optional dependency: everything offline — replay, slicing,
output, the whole test suite — works on a bundle produced anywhere, on any
platform.  Only this module needs a live target, and it is the only place that
imports ``frida``.

    python -m atropos.capture --spawn target.exe --out run.atrace \\
        --mark-export advapi32.dll:CryptEncrypt=1 --duration 30

    python -m atropos.capture --attach 4242 --out run.atrace
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

AGENT_PATH = Path(__file__).resolve().parents[2] / "agent" / "atropos-agent.js"


class CaptureError(RuntimeError):
    pass


def _load_frida():
    try:
        import frida  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CaptureError(
            "capture needs the `frida` package: pip install frida\n"
            "Offline analysis of an existing bundle does not."
        ) from exc
    return frida


def _read_agent(path: Path | None = None) -> str:
    path = path or AGENT_PATH
    if not path.exists():
        raise CaptureError(f"agent script not found at {path}")
    return path.read_text(encoding="utf-8")


class Capture:
    """Attaches or spawns, drives the agent, and leaves a bundle on disk."""

    def __init__(self, output: str, agent_path: Path | None = None) -> None:
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.agent_source = _read_agent(agent_path)
        self.messages: list[dict] = []
        self._frida = _load_frida()
        self._session = None
        self._script = None
        self._pid: int | None = None
        self._detached: str | None = None
        self._spawned = False
        self._final_stats: dict | None = None

    # -- lifecycle --------------------------------------------------------

    def spawn(self, program: str, argv: list[str] | None = None) -> "Capture":
        device = self._frida.get_local_device()
        self._spawned = True
        self._pid = device.spawn([program] + list(argv or []))
        self._session = device.attach(self._pid)
        self._inject()
        return self

    def attach(self, target: int | str) -> "Capture":
        self._session = self._frida.attach(target)
        self._inject()
        return self

    def _inject(self) -> None:
        self._session.on("detached", self._on_detached)
        self._script = self._create_script()
        self._script.on("message", self._on_message)
        self._script.load()

    def _create_script(self):
        """Create the agent script, pinned to the V8 runtime.

        Frida 17 runs agents on QuickJS by default, and on QuickJS the memory
        callout this agent puts on every memory-touching instruction wedges the
        target: the stalked thread spins, the agent's JS runtime stops
        answering RPC, and ``stop()`` never returns.  The same agent on V8
        traces the same binary to completion in well under a second.  V8 ships
        with frida on the desktop platforms; fall back to the default runtime
        where it does not, so a build without it still runs.
        """
        try:
            return self._session.create_script(self.agent_source, runtime="v8")
        except (self._frida.NotSupportedError,
                self._frida.InvalidArgumentError,
                ValueError,
                TypeError):
            print(
                "[atropos] V8 runtime unavailable; falling back to QuickJS, "
                "where tracing a memory-heavy target is known to hang",
                file=sys.stderr,
            )
            return self._session.create_script(self.agent_source)

    def _on_detached(self, reason, *_) -> None:
        self._detached = str(reason)

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") == "error":
            print(f"agent error: {message.get('description')}", file=sys.stderr)
            if message.get("stack"):
                print(message["stack"], file=sys.stderr)
        payload = message.get("payload")
        if payload is not None:
            self.messages.append(payload)
            kind = payload.get("type")
            if kind == "stopped":
                # The agent drains itself when the target calls ExitProcess, so
                # a one-shot target still leaves a bundle behind.
                self._final_stats = payload.get("stats")
                if payload.get("reason") == "process-exit":
                    print("[atropos] target exiting; trace flushed")
                    # The agent is blocked in recv().wait() so this message
                    # cannot be lost to the race with process teardown.
                    self._script.post({"type": "drain-ack"})
            elif kind == "drain-failed":
                print(f"[atropos] drain failed: {payload.get('error')}",
                      file=sys.stderr)
            elif kind == "arm-failed":
                # The target ran past its entry point untraced; whatever is
                # drained at exit is an empty trace, not a short one.
                print(f"[atropos] could not start tracing at the entry point "
                      f"{payload.get('entry')}: {payload.get('error')}",
                      file=sys.stderr)
            elif kind == "thread":
                print(f"[atropos] following thread {payload['tid']}")
            elif kind == "code-version":
                print(
                    f"[atropos] code rewritten at {payload['base']} "
                    f"-> version {payload['version']}"
                )
            elif kind == "mark":
                print(f"[atropos] mark {payload['id']} at {payload.get('export')}")

    # -- control ----------------------------------------------------------

    @property
    def api(self):
        if self._script is None:
            raise CaptureError("not attached")
        return self._script.exports_sync if hasattr(self._script, "exports_sync") else self._script.exports

    def configure(self, **options) -> dict:
        options.setdefault("output", str(self.output).replace("\\", "/"))
        options.setdefault("spawned", self._spawned)
        return self.api.configure(options)

    def mark_export(self, module: str, export: str, mark_id: int) -> str:
        return self.api.mark_export(module, export, mark_id)

    def start(self) -> dict:
        stats = self.api.start()
        if self._pid is not None:
            self._frida.get_local_device().resume(self._pid)
        return stats

    @property
    def alive(self) -> bool:
        """False once the target has gone away and the script with it."""
        return self._detached is None

    def stop(self) -> dict:
        """Stop tracing, tolerating a target that has already exited.

        The trace lives in the agent's buffers until it drains, so a dead
        script means the bundle was either already written by the agent's
        exit hook or lost entirely.  Either way there is nothing left to ask
        for, and raising ``InvalidOperationError`` here would bury that.
        """
        if self._detached is not None:
            if self._final_stats is None:
                raise CaptureError(
                    f"target went away before the trace was flushed "
                    f"({self._detached}); no bundle was written"
                )
            return self._final_stats
        try:
            return self.api.stop()
        except self._frida.InvalidOperationError as exc:
            if self._final_stats is not None:
                return self._final_stats
            raise CaptureError(
                f"target went away before the trace was flushed; "
                f"no bundle was written ({exc})"
            ) from exc

    def close(self) -> None:
        if self._session is not None and self._detached is None:
            try:
                self._session.detach()
            except self._frida.InvalidOperationError:
                pass

    def __enter__(self) -> "Capture":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="atropos.capture",
        description="Record an execution trace with Frida Stalker.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--spawn", metavar="PROGRAM")
    group.add_argument("--attach", metavar="PID_OR_NAME")
    parser.add_argument("--out", required=True, help="bundle directory to create")
    parser.add_argument("--arg", action="append", default=[],
                        help="argument for the spawned program; repeatable")
    parser.add_argument(
        "--mark-export", action="append", default=[], metavar="MOD:EXPORT=ID",
        help="hook an export and place a mark at every call, so the slice "
             "criterion can be `--at mark=ID` (design v0.2 section 8.1)",
    )
    parser.add_argument(
        "--thread", action="append", default=[], type=int, metavar="TID",
        help="thread to follow; repeatable. Required when attaching to a "
             "running process, where the target's threads cannot be "
             "distinguished from Frida's own.",
    )
    parser.add_argument(
        "--exclude", action="append", default=[],
        help="additional module to exclude from tracing; repeatable",
    )
    parser.add_argument("--duration", type=float, default=None,
                        help="stop after this many seconds")
    parser.add_argument(
        "--paranoid", action="store_true",
        help="never trust instrumented code (design v0.2 section 4.7). Correct "
             "for hostile self-modifying targets and one to two orders of "
             "magnitude slower on loops.",
    )
    parser.add_argument("--capture-values", action="store_true")
    args = parser.parse_args(argv)

    try:
        capture = Capture(args.out)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with capture:
        if args.spawn:
            capture.spawn(args.spawn, args.arg)
        else:
            target = int(args.attach) if args.attach.isdigit() else args.attach
            capture.attach(target)

        options: dict = {"captureValues": args.capture_values}
        if args.thread:
            options["threads"] = args.thread
        if args.paranoid:
            options["trustThreshold"] = -1
        if args.exclude:
            options["excludeModules"] = None  # replaced below
        config = capture.configure(**options)
        if args.exclude:
            merged = list(config.get("excludeModules") or []) + args.exclude
            capture.configure(excludeModules=merged)

        for spec in args.mark_export:
            location, _, mark_id = spec.partition("=")
            module, _, export = location.partition(":")
            capture.mark_export(module, export, int(mark_id))
            print(f"[atropos] marking {module}!{export} as mark={mark_id}")

        capture.start()
        print(f"[atropos] tracing; bundle will be written to {capture.output}")

        deadline = time.monotonic() + args.duration if args.duration else None
        if deadline is None:
            print("[atropos] press Ctrl-C to stop")
        try:
            while capture.alive:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            print()

        try:
            stats = capture.stop()
        except CaptureError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        print(f"[atropos] captured {json.dumps(stats)}")
        print(f"[atropos] now run:  atropos info {capture.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
