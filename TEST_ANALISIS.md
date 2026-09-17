# Functional tests bottleneck analysis

Date: 2026-09-17 · commit `6bfbfb70` (local) / `2c540cc` (CI) · macOS 14 cores
and GitHub Actions `ubuntu-latest` (4 vCPU).

Line numbers for `tests/` refer to the tree **with** the timing instrumentation
applied (see [Instrumentation](#instrumentation)).

## TL;DR

**The bottleneck is not the same on macOS and on CI**, and CI is what matters
for the project. Measured on both:

| | macOS (14 cores, `-n 4`) | CI (ubuntu-latest, 4 vCPU, `-n 4`) |
|---|---:|---:|
| wall time | 322s | **135s** |
| florestad start | 9.17s | **1.04s** |
| florestad stop | 9.47s | **3.35s** |
| florestad CPU per lifetime | 20.38s | **0.88s** |

1. **On macOS**, the dominant cost is the XXH3 checksum over the 2 GiB
   `headers.bin` mmap (Finding 1a). Hashing a sparse mmap costs ~8s per call on
   APFS and is essentially free on the CI filesystem (0.88s of CPU for a whole
   florestad lifetime, against 20.4s here). **This is a local-only problem** —
   real, worth fixing, but it does not slow CI down.
2. **On CI**, what is left is the `florestad` shutdown loop polling its stop
   signal every **5s** (Finding 1b): mean 3.35s, p50 3.5s, p95 5.0s per stop,
   **35% of all worker time**.
3. **On CI**, the framework's own fixed costs are now proportionally the
   largest: ~110s per run of unconditional `time.sleep(1)` after each spawn
   (Finding 2), plus the 0.5s polling intervals.
4. **On CI only**, some daemon starts fail and get retried, including bitcoind
   starts that burn the full 30s RPC timeout (Finding 5): ~41s per run.

In the macOS reference run, **68% of the summed test time was setup + teardown**
(439s of 643s). On CI setup + teardown is 55% (261s of 470s) — smaller, but
still the biggest single bucket.

## Methodology

1. Reference run: `nix develop -c bash tests/run.sh --durations=0` with the
   default config (`-n 4 --dist=loadscope -x`).
2. Per-test log timestamps (`$FLORESTA_TEMP_DIR/logs/<version>/<test>/`) cross
   checked against `florestad0.log`.
3. The binary measured on its own, outside pytest (`/tmp/fl-probe.sh`): time
   until the RPC port opens, and from the `stop` RPC until the process exits.
4. Full instrumented runs, once the instrumentation described below was in
   place. Every number attributed to "the instrumented run" comes from there.
5. Three instrumented CI runs on one `ubuntu-latest` runner
   (`functional-timings.yml`, artifact `functional-timings-35259332933`).

## Reference run

```
1 failed, 43 passed, 2 skipped in 222.86s (0:03:42)
real 3m46s   user 9m12s   sys 0m13s
```

⚠️ **Incomplete run.** `-x` stopped everything at the first failure, after
roughly 70% of the suite. The numbers below cover only that ~70%.

The failure is unrelated to performance:
```
tests/floresta-cli/getblockchaininfo.py:40
AssertionError: Float mismatch: candidate=0.9999999756580423, reference=1, tolerance=1e-08
```
The verification progress field comes back as a float just under 1 and the test
compares it with a 1e-8 tolerance. Treated as flaky. While it exists, `-x`
lets any single failure hide the timing of the rest of the suite; pass
`--maxfail=0` to override it.

### Summed time per phase (all workers)

| Phase | Seconds | % |
|---|---:|---:|
| setup | 205.7 | 32% |
| call | 204.4 | 32% |
| teardown | 233.4 | 36% |
| **total** | **643.5** | |

Nodes started in that run: **28 florestad**, 17 bitcoind, 9 utreexod.

Pattern: nearly every test that uses florestad has ~9–11s of setup and ~9–10s
of teardown, **including single-node tests** whose body runs in milliseconds.
For example `floresta-cli/getmemoryinfo.py`: setup 9.10s, call ~0s,
teardown 9.09s.

### Slowest tests

| Time | Phase | Test | Why |
|---:|---|---|---|
| 57.6s | call | `florestad/wallet.py::test_wallet_conf` | 5 florestad starts + 5 stops |
| 46.5s | call | `florestad/wallet.py::test_wallet_flags` | 4 florestad starts + 4 stops |
| 27.3s | teardown | `florestad/wallet.py::test_wallet_conf` | |
| 23.4s | setup | `floresta-cli/gettxoutproof.py::TestGetTxOutProof` | 3 nodes + 3s+1s of `conftest` sleeps |
| 18.7s | teardown | `florestad/wallet.py::test_wallet_flags` | |
| 16.1s | call | `floresta-cli/getblockchaininfo.py` | 3 nodes |
| 16.1s | call | `floresta-cli/getdeploymentinfo.py` | |
| 15.3s | call | `electrum/blockchain_block_header.py` | |
| 13.3s | call | `floresta-cli/addnode.py::test_add_node_v1` | 4 bitcoind starts + florestad |
| 13.1s | call | `floresta-cli/addnode.py::test_add_node_v2` | |

Tests that only use bitcoind/utreexod (`example/bitcoin.py`,
`example/utreexod.py`) have ~1s of setup and ~0.1s of teardown, confirming the
cost is specific to florestad.

## Finding 1 (main): the `florestad` lifecycle

### Measured on its own (outside pytest)

| Scenario | start → RPC open | `stop` RPC → process exits |
|---|---:|---:|
| new datadir | **8.11s** | **8.82s** |
| existing datadir (empty chain) | **0.19s** | **9.00s** |
| new datadir (repeat) | 8.28s | 9.03s |

The `florestad0.log` timeline from `test_get_memory_info` shows where it goes:
```
14:03:14 INFO node: Loading blockchain database
14:03:22 INFO node: Loaded compact filters store at height 0     <- 8s
...
14:03:23 INFO wire: Shutting down node...                          <- stop RPC
14:03:31 INFO florestad: Stopping Floresta                         <- 8s
```

### 1a. The 2 GiB checksum (macOS-dominant)

`crates/floresta-chain/src/pruned_utreexo/flat_chain_store.rs`

- `FlatChainStore::new` (l. 729–745): if `metadata.bin` does not exist, it
  creates the store and calls `store.flush()` right away.
- `do_flush` (l. 1153–1165) calls `compute_checksum()`.
- `check_integrity` (l. 837–846) calls the same `compute_checksum()`.
- `compute_checksum` (l. 849–867) runs `XxHash3_64::oneshot` over the **entire
  mmap** of `headers.bin`, `blocks_index.bin` and `fork_headers.bin`.
- On-disk sizes in regtest:
  - `headers.bin`: 2,147,483,648 bytes (2 GiB, sparse file; `du` reports ~1 MB)
  - `blocks_index.bin`: 64 MiB
  - `fork_headers.bin`: 2 MiB

Hashing 2 GiB of a sparse mmap faults in every zero page. On macOS/APFS that
is ~8s per call; on the CI runner the same code costs almost nothing (a whole
florestad lifetime uses 0.88s of CPU there, against 20.38s here), so this
finding is **local-only in practice**. It still runs on four occasions:

1. **Startup with a new datadir**, which is nearly every test, since `run.sh`
   and the framework create a clean datadir per test.
2. **Startup with an existing chain store that has a saved height:**
   `ChainState::open` → `load_chain_state` → `check_chain_integrity`
   (`chain_state.rs:810`) → `check_db_integrity` → `compute_checksum`.
3. **Shutdown:** `UtreexoNode::shutdown`
   (`crates/floresta-wire/src/p2p_wire/node/mod.rs:413-421`) calls
   `self.chain.flush()`.
4. **Every block connected outside IBD:** `connect_block` calls `self.flush()`
   when `!self.is_in_ibd()` (`chain_state.rs:1420`), holding the chain state
   write lock while hashing.

Evidence, from the instrumented run and the standalone probe:

- With an existing datadir and an empty chain there is no `flush()` on
  creation and startup drops from 8s to 0.19s; shutdown stays at ~9s either way.
- Startup has three modes: new chain ~9s, existing chain without a saved
  height ~1s, existing chain with a saved height ~9s. The restart in
  `p2p_dynamic_tips.py::test_dynamic_chain_tips_derivation_restart` took
  **8.57s** despite reusing the chain store, while restarts with no blocks
  (`restart.py`, `wallet.py`) took ~1s.
- Case 4 shows up as stalled florestad RPCs: `addnode` peaking at 8.00s (mean
  798ms), `getblockcount` at 8.32s, bitcoind's `generatetoaddress` at 8.29s and
  `wait_for_sync_nodes` up to 15s. So in regtest **each mined block can cost
  ~8s of CPU**.
- Each florestad averaged **20.4s** of CPU (p95 33.9s, max 71.8s) in the full
  run, more than the ~16s of a bare start+stop — consistent with the extra
  per-block checksums.

Cases 1–3 are confirmed by measurement; case 4 is read from the code and
matches the RPC stalls, but has not been confirmed with a profiler.

**Scope:** every number above is from macOS. On CI, florestad start is 1.04s
(`wait RPC socket open` p50 of 0.2ms) and no RPC stalls of this shape appear,
so the hashing cost does not materialize there. Worth fixing for local
developer experience and for slower filesystems, not as a CI win.

`FlatChainStoreConfig` already accepts `headers_file_size`, `block_index_size`
and `fork_file_size` (l. 141–180), but `Florestad::load_chain_state`
(`crates/floresta-node/src/florestad.rs:724-736`) only uses
`FlatChainStoreConfig::new(path)`, with the defaults.

### 1b. Shutdown loop polling every 5s (CI-dominant)

`bin/florestad/src/main.rs:146-160`:
```rust
loop {
    if florestad.should_stop().await || *_signal.read().await {
        info!("Stopping Floresta");
        florestad.stop().await;
        let _ = timeout(Duration::from_secs(10), florestad.wait_shutdown()).await;
        break;
    }
    sleep(Duration::from_secs(5)).await;
}
```
After the `stop` RPC the process takes up to 5s just to notice the signal, and
only then waits on `wait_shutdown` (10s timeout).

On CI this is **the** florestad cost, and the distribution matches a uniform
0–5s wait exactly: mean 3.35s, p50 3.51s, p95 5.01s, max 5.05s over 147 stops.
At 49 florestad stops per run that is **164s of worker time per run, 35% of all
test time**, for a signal the process already has. On macOS the same stop takes
9.47s because the checksum runs on top of this wait.

### Estimated impact

28 florestad starts × (~8s startup + ~9s shutdown) ≈ **~450 worker-seconds**,
essentially all of the measured setup + teardown (439s). In `wallet.py`, which
restarts florestad several times, the cost multiplies (57s + 46s of call time).

### Suggestions

1. **Checksum:** do not hash regions that were never written. Options: hash
   only up to the last occupied header/index slot, keep the checksum
   incremental, or skip the checksum on the creation `flush` (an empty store
   has a known checksum).
2. **File sizes:** on regtest/signet, or behind a flag, pass a smaller
   `headers_file_size` to `FlatChainStoreConfig`. 2 GiB of headers is pointless
   in regtest.
3. **Flush cadence:** reconsider flushing on every block outside IBD, or make
   that flush cheap (item 1).
4. **Shutdown loop:** replace `sleep(5s)` with a notification
   (`tokio::sync::Notify` / `watch`), or at least a short interval (100ms).

Items 1+4, or 2+4, should take setup and teardown from ~9s to under 1s per test.

## CI results (3 runs, ubuntu-latest, 4 vCPU, `-n 4`)

`64 passed, 2 skipped` in all three runs — the `getblockchaininfo` float
failure does not reproduce there. Wall time: mean **134.9s**, stdev 10.5s
(124.2 / 135.4 / 145.1). For reference, the same suite on this Mac at `-n 4`
takes ~322s, so **CI is ~2.4× faster than the Mac**.

| bucket | worker time/run | % of test time |
|---|---:|---:|
| test setup | 118.2s | 25% |
| test call | 208.9s | 44% |
| test teardown | 143.4s | 30% |
| **all test phases** | **470.5s** | 100% |
| node stop: florestad | 164.3s | 35% |
| node start: bitcoind | 70.5s | 15% |
| node start: florestad | 65.5s | 14% |
| node start: utreexod | 16.1s | 3% |
| `time.sleep` inside `test_framework` | 401.5s | 85% |
| `time.sleep` in tests/fixtures | 45.7s | 10% |

florestad per stage (150 starts, 147 stops over 3 runs):

| stage | mean | p50 | p95 | total/run |
|---|---:|---:|---:|---:|
| start (new chain state) | 1.04s | 1.00s | 1.07s | 44.2s |
| ↳ fixed sleep after spawn | 1.00s | 1.00s | 1.00s | 63.7s |
| ↳ wait RPC socket open | 27.0ms | 0.2ms | 0.6ms | 1.4s |
| stop | 3.35s | 3.51s | 5.01s | 164.3s |
| ↳ wait shutdown | 3.35s | 3.50s | 5.00s | 164.1s |
| daemon lifetime CPU | 880ms | 674ms | 1.19s | 43.1s |

Reading of these numbers:

- **The florestad binary is fast on CI, except for shutdown.** Startup is
  1.04s, of which 1.00s is the framework's own fixed sleep — the binary itself
  is ready in ~0.2ms of socket wait. The checksum cost that dominates macOS
  simply does not show up.
- **Shutdown is pure waiting on the 5s poll loop** (Finding 1b), and it is the
  single largest bucket at 35% of worker time.
- **The framework's fixed sleep is now the second largest**: 63.7s/run for
  florestad plus 30.3s/run for bitcoind plus utreexod, ~110s/run of `sleep(1)`
  that buys nothing.
- **Polling at 0.5s is visible**: the top sleep site is `rpc/base.py:247`
  (socket polling) at 132.4s/run from teardown alone.
- `wait_for_peers_connections` is worse on CI: mean 2.2 attempts (max 20), and
  **13 calls per 3 runs went past 10 attempts**, where each extra attempt adds
  a 1s sleep — 61.8s/run total.

## Local `-n` sweep (macOS, 3 rounds each)

`-n` 2/4/8/12/14, three full runs each, interleaved so noise spreads evenly.

| `-n` | wall (mean) | stdev | speedup vs `-n 2` | florestad start | florestad stop | florestad CPU | total phase time |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 603.3s | 2.3s | 1.00× | 8.78s | 9.24s | 19.79s | 1151.8s |
| 4 | 326.1s | 6.1s | 1.85× | 9.15s | 9.38s | 19.96s | 1166.9s |
| 8 | 215.5s | 17.7s | 2.80× | 9.30s | 9.55s | 20.65s | 1200.1s |
| 12 | **179.2s** | 3.1s | **3.37×** | 10.34s | 10.35s | 22.28s | 1296.8s |
| 14 | 198.9s | 0.9s | 3.03× | 11.08s | 10.91s | 23.04s | 1360.8s |

- **Scaling is near-linear only from `-n 2` to `-n 4`** (1.85× for 2× the
  workers). After that it flattens: 8→12 buys just 1.2×.
- **The optimum is `-n 12`, and `-n 14` is worse** (+20s). This is a 14-core
  machine, so with 14 workers the daemons compete with the workers themselves.
- **The per-node cost degrades as `-n` grows**: florestad start goes from 8.78s
  to 11.08s (+26%) and its CPU from 19.79s to 23.04s (+16%), while total worker
  time grows 18%. That is the signature of CPU contention, and it confirms the
  macOS checksum cost is CPU bound rather than I/O wait.
- At `-n 12`, 49 florestads × ~22s of CPU ≈ 1090s of CPU over a 179s wall
  clock — about 6 cores busy on nothing but the checksum.
- `-n 8` has by far the widest spread (stdev 17.7s), so it sits right at the
  point where contention starts to bite.

**Conclusion:** bumping `-n` locally is worth it (`-n 4` → `-n 12` cuts the
suite almost in half), but it is a workaround. On the 4-vCPU CI runner there is
no room to do this, which is why the fixes in the priority table matter more.

## Finding 5: daemon starts that fail and get retried (CI only)

`run_node` retries a failed start up to 3 times, and the instrumentation tags
the attempts that raised. On CI, beyond the 13.7/run expected failures from
`wallet.py` (which are intentional, under `pytest.raises`), there are starts
that fail for no test reason:

- **bitcoind, 4 occurrences over 3 runs, 31.02s each** (~41s/run): the RPC
  socket wait runs to the full `BaseRPC.TIMEOUT` of 30s
  (`tests/test_framework/rpc/base.py:43`) and only then retries, successfully.
  Seen in `getconnectioncount.py`, `ping.py` and `gettxout.py`.
- **florestad, 5 occurrences over 3 runs, ~1s each**: the process is already
  dead when the fixed sleep ends, so the retry is quick. Seen in
  `blockchain_block_header.py`, `uptime.py`, `getrpcinfo.py`, `getblock.py`
  and `disconnectnode.py`.

None of these failed the suite, so they are invisible today — the tests just
get slower and noisier. `getconnectioncount.py` is the slowest CI test at
35.1s with a **20.2s stdev**, entirely from this.

Likely cause: the framework assigns random ports and the daemon loses the race
against another worker (`Node.update_configs` re-rolls them on retry, which is
why the retry works). Worth confirming by logging the chosen ports and the
daemon stderr on a failed attempt.

## Finding 2: fixed cost in the Python framework

Smaller than Finding 1, but it applies to every test.

| Location | What it does | Cost |
|---|---|---|
| `tests/test_framework/daemon/base.py:180` | unconditional `time.sleep(1)` after `Popen` | 1s per node started: ~54s/run on macOS, **~110s/run on CI** (the single largest framework cost there) |
| `tests/test_framework/rpc/base.py:228-250` (`try_wait_on_socket`) | polls the RPC port every 0.5s, on both startup and shutdown | up to 0.5s × 2 per node |
| `tests/test_framework/node.py:319-352` (`Node.stop`) | `stop` RPC → `process.wait()` → wait for the socket to close | serial |
| `tests/test_framework/__init__.py:282-291` (`FlorestaTestFramework.stop`) | stops nodes **one at a time** | with 3 nodes, sums 3 shutdowns (~9s for florestad alone) |
| `tests/test_framework/util.py:172` (`wait_until`) | default interval of **0.5s** | every sync/connection point |
| `tests/test_framework/util.py:128` (`wait_until_helper_internal`) | Core-style variant, 0.05s interval | (reference: 10× faster) |
| `tests/test_framework/__init__.py:330-360` (`wait_for_peers_connections`) | after 10 attempts adds an extra `sleep(1)`; every attempt sends RPC pings to both peers | 4 calls went past 10 attempts in the instrumented run, max 14 |

**Suggestions**
- Replace the `daemon.start` `sleep(1)` with short `process.poll()` polling
  alongside `wait_on_socket`.
- Use ~50–100ms polling intervals.
- Stop nodes in parallel: send `stop` to all of them, then wait for all.

## Finding 3: fixed sleeps in tests and fixtures

| Location | Sleep | Note |
|---|---|---|
| `tests/conftest.py:390,392` | 3s + 1s | three-node fixture, right after `connect_nodes`, which already waits for the connection |
| `tests/conftest.py:430,432` | 3s + 1s | same thing in the class-scoped variant |
| `tests/floresta-cli/getrawtransaction.py:123,126` | 5s + 5s | largest sleep in the suite; also right after `connect_nodes` |
| `tests/floresta-cli/getblock.py:39` | 1s | between two `generate` calls |
| `tests/floresta-cli/getblockheader.py:60` | 1s | needs distinct timestamps; `setmocktime` would do |
| `tests/floresta-cli/getblockheader.py:71` | 0.5s in a loop | hand-rolled polling, should be `wait_until` |
| `tests/floresta-cli/ping.py:25` | 1s | |
| `tests/floresta-cli/uptime.py:28` | `SLEEP_TIME` | inherent to the test |
| `tests/p2p/p2p_dynamic_tips.py:116` | 0.1s per header | scales with the fork |
| `tests/expensive/p2p_resilience.py` | 1 occurrence | only with `--run-expensive` |

**Suggestion:** replace the sleeps that follow `connect_nodes` with a
`wait_until` on the real condition (synced height/tip).

## Finding 4: parallelism and pytest configuration

- `-n 4` is hardcoded on a 14-core machine. `user 9m12s` against `real 3m46s`
  means ~2.4 cores busy on average — and that `user` time is mostly the
  florestad checksum (28 florestads × ~16s of CPU ≈ 450s), not idle waiting.
  So raising `-n` only helps while there are free cores. On the 4-vCPU CI
  runner `-n 4` is already at the hardware limit. Locally the sweep (below)
  shows it keeps paying up to `-n 12`.
- `--dist=loadscope`: one slow module (e.g. `wallet.py`, >2min across its two
  tests) occupies a whole worker.
- `-x`: one failure aborts the suite and hides the rest of the timings (which
  is what happened in the reference run).
- `--log-cli-level=DEBUG`: does not look significant, but was not measured
  in isolation.

## Suggested priority

Ordered by what it buys **on CI**, which is where the suite actually costs
time for the project.

| # | Change | Expected gain on CI | Effort |
|---|---|---|---|
| 1 | florestad: shutdown loop without `sleep(5s)` | 164s→~0 of worker time/run (35% of test time) | low |
| 2 | framework: drop the `sleep(1)` after spawn, poll the process instead | ~110s of worker time/run | low |
| 3 | framework: lower polling intervals to ~50–100ms (`try_wait_on_socket`, `wait_until`) | tens of seconds/run; also shrinks the `wait_for_peers_connections` tail | low |
| 4 | framework: stop nodes in parallel | proportional to multi-node tests; ~9s per extra florestad on macOS | low |
| 5 | investigate the failed starts (Finding 5) | ~41s/run plus most of the run-to-run variance | medium |
| 6 | tests: drop the fixed sleeps (`conftest`, `getrawtransaction`) | 45.7s/run of test-side sleeps | low |
| 7 | florestad: checksum/flush that does not walk the 2 GiB | no measurable CI gain; ~8s per start/stop **locally on macOS** | medium |
| 8 | pytest: higher `-n` | nothing on a 4-vCPU runner (`-n 4` is the limit); **locally `-n 12` cuts the suite from 326s to 179s** | trivial |

## Instrumentation

Every test records timing spans as JSONL, and a Markdown report aggregates
several runs (mean, stdev, p50/p95/max), so the numbers are stable both
locally and on CI.

### Usage

```bash
# N runs back to back, without stopping at failures, then a report
nix develop -c just test-functional-timing 5 local

# Report only (all recorded runs, or a filtered subset)
nix develop -c just test-functional-timing-report "--label local --last 5"
nix develop -c uv run python tests/test_framework/timing_report.py /path/to/runs --output report.md
```

- Data lands in `$FLORESTA_TEMP_DIR/timings/<run-id>/`, which `run.sh` does
  **not** delete. Override with `FLORESTA_TIMINGS_DIR`.
- `FLORESTA_TIMINGS_LABEL=<name>` tags a run (useful to compare before/after a
  change). `FLORESTA_TIMINGS=0` disables recording.
- Each run has `meta.json` (commit, florestad version, host, CPUs, `-n`,
  loadavg, CI variables), `session.json` (wall time, failures) and one
  `<worker>.jsonl` per xdist worker.
- `--maxfail=0` overrides the `-x` in `pyproject.toml`, so a flaky test does
  not cut the run in half.

### On CI

`.github/workflows/functional-timings.yml` builds once and runs the suite N
times on the same runner, then publishes the report to the job summary and
uploads the JSONL as an artifact (`functional-timings-<run_id>`). Triggered by
`workflow_dispatch` (inputs `runs` and `pytest_args`; only listed once the
workflow is on the default branch) or by pushing to a `timings/**` branch.

To combine CI runs with local ones: download the artifacts and pass the
directories to `timing_report.py`.

### What is measured

| Event | Where | What it exposes |
|---|---|---|
| `test.phase` | `conftest.py` (`pytest_runtest_makereport`) | setup/call/teardown per test, outcome and 1min loadavg |
| `node.start` | `node.py` | full start, with `existing_chain_state` (chain store already there: `metadata.bin` for florestad, `chainstate` for bitcoind, `blocks_ffldb` for utreexod) |
| ↳ `daemon.spawn` | `daemon/base.py` | `Popen` |
| ↳ `daemon.start_fixed_sleep` | `daemon/base.py` | the fixed `sleep(1)` |
| ↳ `rpc.wait_socket_open` | `rpc/base.py` | until the RPC port opens (= binary startup), with the poll count |
| ↳ `node.first_rpc`, `node.electrum_ping` | `node.py` | first calls |
| `node.stop` | `node.py` | full stop, with `method` (rpc/terminate), `returncode` and **the daemon's user/sys CPU over its whole lifetime** (`getrusage(RUSAGE_CHILDREN)`) |
| ↳ `rpc.stop_call` | `rpc/base.py` | the `stop` RPC call |
| ↳ `rpc.stop_wait_shutdown` | `rpc/base.py` | until the port closes (= binary shutdown) |
| ↳ `node.process_exit` | `node.py` | `process.wait()` |
| `framework.run_node_attempt` | `__init__.py` | each start attempt (`attempt > 0` = retry; an `error` field marks attempts that raised) |
| `framework.stop_all` | `__init__.py` | teardown of all nodes (serial) |
| `framework.connect_nodes`, `wait_for_peers_connections` (with `attempts`), `wait_for_sync_nodes`, `generate_blocks_and_sync`, `add_p2p_connection` | `__init__.py` | helpers that wait on nodes |
| `wait_until` (aggregated) | `util.py` | all polling, by call site, origin and interval |
| `sleep` (aggregated) | `time.sleep` patched in `pytest_configure` | **every** `time.sleep` during tests, with `site` (who called) and `origin` (test/fixture that caused it) |
| `rpc.request` (aggregated) | `rpc/base.py` | client-side RPC latency, per daemon and method |

High frequency events are aggregated in memory and written once per test
phase, so the instrumentation does not become a bottleneck itself.

### The report

Sections: runs (with wall time mean and stdev); where the time goes; start/stop
per daemon broken into stages; slowest tests (with how many nodes each starts);
sleeps by call site; waits and helpers; RPC; and loadavg per run (to spot noisy
runs).

### Full instrumented run (macOS, 1 run, `-n 4`)

`1 failed (getblockchaininfo, flaky), 63 passed, 2 skipped`, wall 339.9s.

| | worker time | % of phase time |
|---|---|---|
| florestad start | 430.5s | 36% |
| florestad stop | 464.2s | 39% |
| bitcoind/utreexod start+stop | 56.4s | 5% |
| total florestad CPU | 998.5s | — |

florestad stages (n=50 starts, 49 stops):

| stage | mean | stdev | p95 |
|---|---|---|---|
| start (new chain state) | 9.17s | 0.53s | 9.60s |
| ↳ wait RPC socket open | 7.36s | 2.53s | 9.06s |
| ↳ fixed sleep | 1.00s | 0.00s | 1.01s |
| stop | 9.47s | 1.29s | 9.60s |
| ↳ wait shutdown | 9.41s | 0.97s | 9.60s |
| daemon lifetime CPU | **20.38s** | 9.96s | 33.87s |

For comparison, bitcoind: start 1.01s (almost entirely the fixed sleep), stop
319ms, lifetime CPU 177ms.

Other things the instrumentation surfaced:

- florestad starts that fail on purpose (`wallet.py`, under `pytest.raises`)
  cost 3 attempts × 1s of fixed sleep each: 12s per run.
- `wait_for_peers_connections`: 4 calls went past 10 attempts (1s extra per
  attempt), max 14.
- bitcoind `stop`: p50 of 502ms, which is just the 0.5s polling interval — the
  process exits in ~50ms.

## Open items

- [x] Local `-n` sweep — done, see [Local `-n` sweep](#local--n-sweep-macos-3-rounds-each).
      Optimum at `-n 12` (179s, 3.37× over `-n 2`); `-n 14` regresses.
- [x] Run `functional-timings.yml` on CI and compare against the Mac — done,
      see [CI results](#ci-results-3-runs-ubuntu-latest-4-vcpu--n-4). There is
      no single local↔CI ratio: the dominant cost differs per platform.
- [ ] Investigate the failed daemon starts on CI (Finding 5), starting with
      port collisions between xdist workers.
- [ ] Fix `compare_fields` in `tests/test_framework/util.py:223` to propagate
      `float_tol` through its recursive calls — that is why
      `getblockchaininfo.py` fails locally with a 1e-8 tolerance even though
      the test asks for 1e-3. It only triggers on slow machines, where ~12s
      elapse between mining and the RPC call (the field is wall-clock based).
- [ ] Confirm the checksum cost with a profiler (e.g. `samply` / `Instruments`)
      on florestad startup and shutdown.
- [ ] Confirm the per-block flush outside IBD (case 4 of Finding 1a).
- [ ] Measure `--dist=load` against `loadscope`.
- [ ] Apply changes 1, 3 and 4 and measure the real gain.
