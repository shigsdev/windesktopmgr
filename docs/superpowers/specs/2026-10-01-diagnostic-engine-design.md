# Diagnostic Engine — Design Spec

**Date:** 2026-10-01
**Status:** Awaiting review
**Scope of this spec:** PR 1 — the engine plus the Network & DNS bundle.
Bundles for crashes, storage, and performance are follow-up PRs against a
frozen engine (see [Decomposition](#decomposition)).

---

## 1. Problem

When something breaks on this machine, the app can already *display* a
hundred facts about it — but it cannot answer "why is this happening, and
what should I do?" The user has to know which tab to open, which number
matters, and what the combination of numbers means.

The motivating case: `hynote.ai` would not load, with Chrome reporting
`ERR_NAME_NOT_RESOLVED`. The user's first move was flushing the DNS cache,
which was structurally incapable of helping. The real answer took two waves
of probing:

1. **Broad sweep** — resolve against three resolvers, check the hosts file,
   confirm a control domain works. All three resolvers returned NXDOMAIN.
2. **Targeted escalation** — query the domain's own authoritative nameserver
   directly, then sweep every record type. This found `MX`, `SPF`, and
   `google-site-verification` records present while `A`/`AAAA`/`CNAME` were
   absent.

Wave one alone supports a confident but misleading verdict ("the domain is
dead"). Only wave two distinguishes *"someone edited this zone and dropped
the web records"* from *"this domain does not exist"* — and only that
distinction tells the user there is no local fix.

Two requirements fall directly out of that:

- The engine must support **adaptive escalation**, not a single fixed sweep.
- The verdict vocabulary must include **"the cause is not on this machine"**,
  or the tool will suggest `flush_dns` into exactly the dead end the user
  already walked down.

## 2. Intent and success criteria

**Intent:** the user describes a symptom in plain language and gets a
diagnosis grounded in probes actually run on this machine, plus — only when
warranted — a suggested action drawn from the existing vetted remediation
set.

**Success criteria:**

| | Criterion |
|---|---|
| S1 | Pasting the verbatim Chrome error for `hynote.ai` yields an `external_cause` verdict naming the missing `A` record, and does **not** suggest `flush_dns`. |
| S2 | The user sees exactly what will leave the machine, before it leaves. |
| S3 | With no API key, the tool still produces a useful structured report. |
| S4 | The model can never run a probe or an action outside a closed registry. |
| S5 | "Inconclusive" is never rendered as a diagnosis. |

**Non-goals** (explicit YAGNI): no autonomous repair, no scheduled/background
diagnosis, no history analytics, no multi-machine support, no chat interface
(`nlq.py` already owns free-form Q&A).

## 3. Architecture

New module `diagnose.py` + blueprint `diagnose_bp`, registered in
`windesktopmgr.py` alongside `disk_bp` / `maintenance_bp`. New tab
**🔍 Diagnose**, JS prefix `dx` (unused; `doc`, `dk`, `db`, `drv` taken).

Its own module rather than more weight in `windesktopmgr.py`, which is
already 5,422 lines, consistent with the blueprint-extraction direction of
`plan_prod_file_splits_2026-05-30.md`.

Four parts, each independently testable:

```
  symptom text
       │
       ▼
  ┌──────────────┐   deterministic first; one model call only if low-confidence
  │  Classifier  │──▶ (symptom_class, slots{target_host: "hynote.ai"})
  └──────────────┘
       │
       ▼
  ┌──────────────┐   wave-one bundle for that class, run in parallel
  │ Probe runner │──▶ [{key, ok, data|error, elapsed_ms}, ...]
  └──────────────┘
       │
       ▼
  ┌──────────────┐   redact → PREVIEW GATE → send
  │ Egress gate  │──▶ user sees the exact payload and confirms
  └──────────────┘
       │
       ▼
  ┌──────────────┐   verdict, or need_probes[] → loop (max 2 extra rounds)
  │    Engine    │──▶ {status, cause, confidence, evidence_refs, actions[]}
  └──────────────┘
```

## 4. Probe registry

A closed, declarative registry. The model may only ever name a key from it.

```python
@dataclass(frozen=True)
class Probe:
    key: str                       # "dns.authoritative"
    label: str                     # shown in the UI and the payload preview
    category: str                  # "network" | "crash" | "storage" | "perf"
    fn: Callable[[dict], dict]     # (slots) -> JSON-serialisable evidence
    needs: tuple[str, ...] = ()    # required slot names
    redact: tuple[str, ...] = ()   # redaction classes to apply to the output
    timeout_s: float = 8.0
```

**Invariants, each enforced by a test:**

- Every probe is read-only. No probe function is reachable from
  `remediation._REMEDIATION_DISPATCH`, and no probe runs a mutating command.
  Asserted by name-set intersection plus a review checklist item.
- Every bundle references only keys present in the registry.
- Every probe declares its required slots; the runner refuses to call a probe
  whose slots are unfilled rather than passing `None` through.
- A probe that raises returns `{ok: False, error: str}`; it never propagates.

### 4.1 Network & DNS wave-one bundle

`dnspython` is a new dependency (`dnspython>=2.6` in `requirements.txt`).
Rationale: stdlib `socket` cannot target a specific resolver or request a
record type, so the Python-first ladder in CLAUDE.md lands on the pip package
(step 2) rather than a `nslookup` subprocess (step 3).

| Probe key | What it does | Why it earns its place |
|---|---|---|
| `dns.resolve_cached` | Resolve via the Windows resolver (`socket.getaddrinfo`) — goes **through** the OS cache | Half of the cache comparison |
| `dns.resolve_direct` | Query the configured resolver, Cloudflare, and Google directly over UDP/53 via `dnspython` — **bypasses** the OS cache | Other half; disagreement with the above is the stale-cache signal |
| `dns.authoritative` | Find the zone's NS from the parent, then query those nameservers directly | The wave-two probe that cracked the hynote case |
| `dns.record_sweep` | `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SOA`, `NS` for the target | "MX present, A absent" ⇒ zone edited, not expired |
| `dns.hosts_file` | Grep `drivers/etc/hosts` for the target | Cheap, and a real cause when it hits |
| `dns.client_config` | Per-adapter DNS servers, suffix search list, DoH state | Finds VPN/adapter-ordering causes |
| `net.control_domain` | Resolve + TCP-connect a known-good domain | Separates "this name" from "all DNS" |
| `net.gateway` | Ping/ARP the default gateway | Separates DNS from link-layer |
| `net.proxy_config` | WinINET/WinHTTP proxy + PAC settings | A PAC file can produce resolution-shaped failures |

**The cache-comparison insight is the centrepiece.** `dns.resolve_cached`
agreeing with `dns.resolve_direct` proves the OS cache is not the problem,
making `flush_dns` provably useless. Them disagreeing proves it is. This
converts the user's opening guess into a measurement.

Escalation probes available to the model but not in wave one:
`dns.trace_delegation`, `dns.dnssec_check`, `net.tcp_connect`,
`net.tls_handshake`, `net.traceroute`.

## 5. Symptom classes and the classifier

```python
SYMPTOM_CLASSES = {
    "network_dns": {
        "label": "Website or network unreachable",
        "slots": ("target_host",),
        "wave1": ("dns.resolve_cached", "dns.resolve_direct", ...),
    },
    # crash_instability / storage_health / performance → follow-up PRs
}
```

**Classifier is deterministic first.** Keyword match plus slot extraction:
pull a hostname out of a pasted URL or a verbatim browser error blob
(`ERR_NAME_NOT_RESOLVED`, `DNS_PROBE_FINISHED_NXDOMAIN`, …). Only when that
scores low-confidence does one model call classify and extract. The common
case is free, instant, and table-testable.

**A missing required slot is a question, not a guess.** If the user types
"the internet is broken" with no host, the UI asks which address to test. The
engine never substitutes a default target.

## 6. Engine

Follows the established background-thread + poll pattern from
`maintenance.start_or_get` (single-flight under a lock, state in a bounded
dict, TTL eviction). A diagnosis takes 10–60s, so the route must not block.

State machine: `classifying → awaiting_slots? → probing_wave1 →
awaiting_consent → interpreting → (probing_waveN → interpreting)* → done |
evidence_only | error`

**Escalation is hard-bounded at 2 extra rounds** and at a total probe count.
Round 3 forces a conclusion; the model is told so in its prompt, so it spends
its escalations deliberately.

### 6.1 Verdict schema

The model must return exactly this shape (validated server-side; a parse
failure degrades to evidence-only, never a 500):

```json
{
  "status": "confident" | "likely" | "inconclusive",
  "locus": "local" | "external_cause" | "unknown",
  "headline": "hynote.ai has no DNS address record",
  "reasoning": "Prose citing probe keys.",
  "evidence_refs": ["dns.record_sweep", "dns.authoritative"],
  "suggested_actions": ["flush_dns"],
  "no_local_fix_reason": "The zone is served correctly; the A record is absent at the source."
}
```

- `locus: "external_cause"` exists specifically so the engine can say *there
  is nothing to fix here*. When `locus` is `external_cause`,
  `suggested_actions` **must** be empty — enforced server-side, not left to
  the model's discretion.
- `status: "inconclusive"` renders as "couldn't determine this" with the
  evidence shown. It is never styled as a diagnosis. This encodes the
  standing project rule that *cannot verify ≠ problem found*.

## 7. Privacy and the egress gate

**The gate.** After wave one, the UI renders the exact redacted JSON payload
with a Send button. Default on; a per-session "don't ask again" checkbox.
A test asserts the Anthropic client is **not called** before confirmation.

**Redaction classes**, applied per the probe's `redact` tuple:

| Class | Rule |
|---|---|
| `username` | `%USERNAME%` and its occurrences inside paths → `<user>` |
| `serial` | Disk/BIOS/board serials → `<serial>` |
| `mac` | MAC addresses → `<mac>` |
| `local_ip` | RFC1918 addresses → `<private-ip>` (off by default for the network class, where they are the evidence) |

Hostnames and public IPs are deliberately **not** redacted — in a DNS
diagnosis they *are* the subject, and redacting them would make the tool
useless. The preview gate is the protection, not blanket scrubbing. This is a
conscious departure from `ai_identify.py`'s "never send telemetry" stance,
which is viable there because it only ever sends an entity name; a diagnoser
cannot work that way. Recording the departure here so it is a decision rather
than a drift.

**Audit trail.** Every diagnosis appends to `diagnose_history.json` (atomic
write, capped length) including the payload that was sent, so "what did this
thing tell Anthropic about my machine" is answerable after the fact.

## 8. Remediation handoff

The model returns action **keys only**. The server then:

1. Validates each key against `remediation.REMEDIATION_REGISTRY`; unknown
   keys are dropped silently and logged.
2. Drops all actions when `locus == "external_cause"`.
3. Renders the registry's own `label` / `description` / `risk` / `reboot`
   metadata — never model-authored action text.

The user clicks; the existing `POST /api/remediation/run` executes it, with
its existing logging. **Nothing auto-executes.** The model cannot invent an
action, cannot pass arguments, and cannot reach anything outside the ten
vetted entries.

## 9. Evidence-only mode

No API key, no `anthropic` SDK, model timeout, or unparseable reply ⇒ the tab
renders the full structured probe report with a banner explaining why there
is no AI verdict, plus any deterministic rule hits. Still genuinely useful:
readable directly, or copy-pasteable into a Claude session. Mirrors the
degradation already proven in `ai_identify.py`.

## 10. Routes

| Route | Purpose |
|---|---|
| `GET  /api/diagnose/classes` | Symptom classes + their slots, for the UI |
| `POST /api/diagnose/start` | `{symptom, slots?}` → `{session_id, status}` |
| `GET  /api/diagnose/status/<session_id>` | Poll; returns state + payload preview when `awaiting_consent` |
| `POST /api/diagnose/consent` | `{session_id, approved}` → releases or aborts the send |
| `GET  /api/diagnose/history` | Past diagnoses + what was sent |

`POST` bodies use non-silent `get_json()` (the standing rule — it is what
blocks cross-site form posts). All inputs validated; `session_id` is a
server-generated opaque token, never a path.

## 11. Cost and concurrency

- Per-process model-call cap, following `ai_identify.MAX_AI_LOOKUPS`.
- At most 3 interpretation calls per diagnosis (the initial one, plus one after each of the 2 permitted escalation rounds), plus at most
  1 classifier call.
- Model id from env (`DIAGNOSE_MODEL`, default Sonnet 5) — matching
  `ai_identify.py`'s env-override pattern rather than `nlq.py`'s hardcoding.
- Single-flight per session; bounded session dict with TTL eviction.
- Diagnoses are **not** cached: each is a point-in-time system read, and
  serving a stale verdict would be a correctness bug, not an optimisation.

## 12. Error handling

| Failure | Behaviour |
|---|---|
| Probe raises / times out | `{ok: False, error}` in the payload — a failed probe is evidence |
| Required slot missing | Ask the user; never guess |
| Model unreachable / timeout | Evidence-only mode + banner |
| Model returns unparseable JSON | One reformat retry, then evidence-only |
| Model names an unknown probe | Dropped, logged; loop continues |
| `dnspython` missing | DNS probes degrade to `getaddrinfo` only, with an explicit capability note in the payload |

## 13. Testing

Per CLAUDE.md's three layers, plus:

- **Probe level:** happy / empty / malformed / timeout per probe.
- **Registry invariants:** bundle keys exist; no write-capable probes; all
  probes declare slots.
- **Classifier:** one JSON fixture per scenario in a new
  `tests/fixtures/diagnose/` directory. Each file holds a synthetic
  evidence bundle plus the verdict it must produce; a single parametrized
  test discovers the directory and asserts fixture-by-fixture, so adding a
  scenario means adding a file, not writing a test function.

  ```
  tests/fixtures/diagnose/
    hynote_zone_missing_a.json        -> external_cause, no flush_dns (S1)
    stale_cache_direct_resolves.json  -> local, flush_dns
    hosts_file_override.json          -> local, edit_hosts
  ```

  Each fixture is `{"symptom": ..., "evidence": {<probe key>: ...},
  "expect": {"locus": ..., "must_include": [...], "must_exclude":
  [...]}}`. The test asserts on `locus` and on action keys present and
  absent — never on `headline` or `reasoning` prose, which the model is
  free to word however it likes.

  Scenarios to add as the probes land: NXDOMAIN vs NODATA, captive portal,
  proxy misconfig, dead gateway. The S1 fixture carries the user's
  verbatim Chrome error string as its `symptom` input.
- **Engine:** mocked model — escalation capped at 2 rounds; unknown probe
  keys rejected; unknown action keys dropped; `external_cause` forces empty
  actions.
- **Redaction:** fixture with planted username/serial/MAC; assert absent from
  the payload.
- **Egress gate:** assert the client is not called pre-consent.
- **Routes:** 200 / 400 / missing-field per endpoint.
- **Playwright:** tab renders; submit → preview appears; `inconclusive` does
  not render as a verdict.

**Golden regression case (S1).** `hynote_zone_missing_a.json` above, built
from today's real evidence — `MX` + `SPF` + `google-site-verification`
present, `A`/`AAAA`/`CNAME` absent,
`SOA` answering, all resolvers agreeing — asserting `locus ==
"external_cause"` and `"flush_dns" not in suggested_actions`. This is the
test that would have prevented the hour the user spent flushing a cache.

## 14. Decomposition

| PR | Contents |
|---|---|
| **1** | Engine, probe registry, redaction, egress gate, evidence-only mode, Network & DNS bundle, tab, tests, `architecture.html` |
| 2 | Crashes & instability bundle |
| 3 | Storage & disk bundle |
| 4 | Performance & thermals bundle |

PRs 2–4 are "add probes, add a bundle, add tests" against a frozen engine. If
the abstraction is wrong, that surfaces on bundle two rather than after four
half-built ones have landed together.

## 15. Architecture.html triggers fired

New root file (`diagnose.py`), new routes, new tab, new test file, new
dependency, test-count change. `architecture.html` update is mandatory for
PR 1.

---

**Review note:** §7 (not redacting hostnames/IPs) and §4.1 (adding
`dnspython`) are the two decisions most worth a second look — the first is a
deliberate privacy trade-off, the second a new runtime dependency.
