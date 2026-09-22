# API and syscall summaries

Implementation-level companion to design v0.2 §4.5. Code:
[`src/atropos/summaries.py`](../src/atropos/summaries.py); the agent-side hook table is at the bottom of
[`agent/atropos-agent.js`](../agent/atropos-agent.js).

---

## 1. The hole a summary fills

Tracing into `ntdll`, `kernel32` and the CRT is expensive and almost never the answer, so those modules
are excluded (`Stalker.exclude`). But an untraced `memcpy` is a **hole in the dependence graph**: the
destination bytes acquire no last writer, so a slice through them bottoms out in a spurious live-in leaf
and the analyst is told the data came from nowhere.

That failure is quiet and it is worse than it sounds, because the live-in report is the *deliverable*
for the crypto workflow. "The key came from unwritten memory" is not merely unhelpful; it is wrong, and
it looks like an answer.

A summary is a hand-written statement of what an API does to storage, in the same vocabulary as the
effect model: these byte ranges are read, these are written, this register is defined. The agent hooks
the export and records the concrete argument values; replay expands the record into a synthetic node
with real edges.

---

## 2. The four kinds

The `kind` field is not decoration — it is what the input report keys off.

### `transform`
Output is a function of input. `memcpy`, `CryptEncrypt`, `NtReadVirtualMemory`. The edge crosses the
call, and the node is an ordinary interior node of the slice.

### `source`
Output comes from **outside the process**. `ReadFile`, `GetVolumeInformationW`, `GetUserNameW`,
`BCryptGenRandom`. The node is a *leaf*, and it is the interesting kind — "the key depends on the volume
serial number" is exactly what the crypto workflow is asking.

### `alloc`
`VirtualAlloc`, `HeapAlloc`. Defines a fresh region, so bytes read out of it before anything writes them
are attributable to the allocation rather than to unknown initial state.

### `free`
`VirtualFree`. Releases shadow pages so peak memory tracks the live working set rather than everything
the process ever touched. Only fully covered pages are released — a page straddling the edge of a freed
allocation may still hold live neighbours, and inventing `LIVE_IN` for them would turn a real dependence
into a spurious input leaf.

---

## 3. Writing one

```python
Summary(
    id=30,
    name="CryptEncrypt",
    kind="transform",
    reads=[Ref(3, 4)],    # buffer at arg3, length at arg4
    writes=[Ref(3, 4)],   # encrypted in place
)
```

`Ref(ptr, length)` names a buffer: `ptr` is an argument index, and `length` is either another argument
index or a literal byte count. `Ref(1, 8)` means "the buffer at arg1, eight bytes long".

Every summary also emits **address** edges on the argument registers it consumed (`RCX`, `RDX`, `R8`,
`R9` under the Microsoft x64 convention). Whatever computed the destination pointer is part of how the
buffer came to be there, and `--mode value+addr` reaches it.

### Adding a summary

1. Add the `Summary` to `SummaryTable.default()` with a **new** id.
2. Add the matching hook to `SUMMARIES` in the agent, with the same id and the argument count to
   capture.
3. Add a fixture, ideally in [`examples.py`](../src/atropos/examples.py), so the behaviour is asserted
   rather than assumed.

### Ids are permanent

`summary_id` values are baked into captured bundles. Renumbering one silently reinterprets every
existing trace — a `ReadFile` becomes a `memcpy` and the slice changes shape with no error anywhere. The
table is **append-only**. Deleting an entry is also forbidden; mark it obsolete instead.

---

## 4. Unknown calls

`UnknownCall` is the default for an unrecognised external call. It defines `RAX`, emits value edges on
the argument registers, marks the node `imprecise`, and records a note.

It is deliberately weak. The alternative — inventing byte ranges for pointer arguments whose lengths we
do not know — either misses real dependences (guessing too small) or invents them wholesale (guessing
too large), and in both cases does so invisibly. Reporting "we crossed an unmodelled call here" is the
honest answer, and the precision banner surfaces the count so the analyst knows how much of the graph
rests on it.

If a slice bottoms out at an `UnknownCall`, that is the signal to write a real summary for it.

---

## 5. Direct syscalls

Malware routinely bypasses the hooked `ntdll` stubs by executing `syscall` directly. The effect model
flags these (`is_syscall`), and the agent keys a summary off the syscall number in `EAX`.

Only the syscalls that *move data* need summaries: `NtReadFile`, `NtAllocateVirtualMemory`,
`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`. The rest can be crossed as
unknown calls without losing anything a slice cares about.

Syscall numbers are **version-specific** — they change between Windows builds. A summary table keyed by
number is therefore only valid for the build the trace was captured on, which is why `meta.json` records
the capture environment. This is a real limitation and it is not currently checked; a bundle captured on
one build and sliced with another build's table would mis-attribute.

---

## 6. Where summaries are structurally imprecise

- **Length arguments that are pointers.** `ReadFile`'s `lpNumberOfBytesRead` is an out-parameter, so the
  count is not known at call time. The current summary uses the *requested* size, which
  over-approximates a short read.
- **Optional and variadic arguments.** A `Ref` naming an argument the caller did not pass resolves to
  nothing and is skipped silently.
- **Callbacks.** An API that invokes a callback into traced code produces two disjoint regions of trace
  with a summary node between them; the data flow through the callback is captured, the control
  relationship is not.
- **Size caps.** A hooked call with a garbage length would otherwise allocate shadow pages until the
  process dies, so writes are capped at 64 MB per summary and the truncation is noted.

Each of these is an over- or under-approximation that shows up as a note rather than as an error,
because the alternative is refusing to cross the call at all — which loses more than it protects.
