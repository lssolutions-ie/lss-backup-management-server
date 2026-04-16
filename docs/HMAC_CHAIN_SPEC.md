# HMAC Chain for Audit Events — Contract Proposal

**Status:** SHIPPED — Server v1.14.4 + CLI v2.5.0. Verified on all 3 nodes, zero chain breaks.  
**Participants:** Server (v1.14.0+) · CLI (v2.5.0+)  
**Key fix:** v1.14.4 — prev_hmac uses raw hex string bytes, not hex-decoded (confirmed via CLI test vector).

---

## Problem

Today's audit pipeline is tamper-evident only relative to a **trusted CLI**. A node with a compromised PSK can:

- Forge any audit event with any `actor`, including `user:admin`
- Inject `mgmt_console_cleared` or `ssh_credentials_configured` events that appear legitimate on `/audit`
- Silently drop or reorder events since the server has no continuity proof

The server detects gaps (via contiguous-seq reconcile) but cannot distinguish "network loss" from "attacker selectively deleted evidence."

## Solution

Per-event HMAC chain. Each audit event carries a signature over itself + the previous signature, keyed with the node's PSK. The server verifies the chain on every batch and refuses to advance the ack pointer on a break.

## Wire format

### Event shape (extends existing AuditEvent)

```json
{
  "seq": 42,
  "ts": 1776300000,
  "category": "job_modified",
  "severity": "info",
  "actor": "user:root",
  "message": "...",
  "details": {"job_id": "001"},
  "hmac": "a1b2c3d4e5f6..."
}
```

New field: `hmac` (string, hex-encoded, 64 chars = SHA-256).

### Computation

```
canonical = json_canon(event_without_hmac_field)
hmac_value = HMAC-SHA256(psk, prev_hmac || canonical)
```

Where:
- `json_canon()` = deterministic JSON serialization (keys sorted, no whitespace, UTF-8). Go: `json.Marshal` with struct field ordering (stable by spec).
- `prev_hmac` = the `hmac` field of the immediately preceding event (seq - 1). For seq=1 (first event ever), `prev_hmac` = 64 zero bytes (`"0000...0000"`).
- `psk` = the node's pre-shared key (same one used for AES-256-GCM payload encryption + HMAC tunnel auth).
- `||` = byte concatenation.

### Server verification

On each batch of `audit_events[]`:

1. Load `nodes.audit_chain_head` for the node (the `hmac` of the last verified event, or `""` if none).
2. For each event in seq order:
   a. Compute expected HMAC using `chain_head` as `prev_hmac`.
   b. Compare with event's `hmac` field (constant-time).
   c. On match: advance `chain_head` to this event's `hmac`. Continue.
   d. On mismatch: **stop**. Log `CRITICAL chain_break` with details. Do NOT advance `audit_ack_seq`. Return `audit_ack_seq` = last good seq. CLI will re-send from there.
3. After the batch, persist `chain_head` to `nodes.audit_chain_head`.

### Server DB changes (migration 037 or wherever we are)

```sql
ALTER TABLE nodes
    ADD COLUMN audit_chain_head VARCHAR(64) NOT NULL DEFAULT '';
```

### What a chain break means

A chain break is one of:
- **Event was modified after signing** (tampering)
- **Event was dropped** (seq gap + chain break together = evidence destruction)
- **PSK was rotated** without resetting the chain (operational — not an attack)

The server should:
- Insert an audit_log row: `category=audit_chain_break, severity=critical, source=server`
- Include both expected and received HMACs in details
- NOT silently skip — the break must be visible on `/audit`
- NOT auto-advance past the break. Operator must manually investigate and reset `audit_chain_head` + `audit_ack_seq` after verification.

### PSK rotation interaction

When a node's PSK is regenerated (via HandleNodeRegeneratePSK), the chain must restart:
- Server sets `audit_chain_head = ''` and `audit_ack_seq = 0` for that node.
- CLI detects PSK change, resets its local chain state, starts from seq=1 with the new PSK.
- First event after rotation uses `prev_hmac = "0000...0000"`.

### Backward compatibility

- Server accepts events WITHOUT `hmac` field (v2.3.x / v2.4.x CLIs). When `hmac` is absent, chain verification is skipped for that event; `chain_head` is NOT advanced. The chain only engages once the CLI starts sending `hmac`.
- Payload version stays at `"3"` — the `hmac` field is additive/optional. No bump needed.
- Old events re-shipped from a v2.3.x queue (pre-HMAC) will lack the field. Server ingests them normally; chain starts from the first event that carries `hmac`.

### CLI implementation notes

- `audit.Emit()` computes HMAC after assigning seq, before writing to `audit.jsonl`.
- `prev_hmac` loaded from a new `state/audit_chain` file (single hex string). Updated after each emit. Crash-safe: written BEFORE the event is appended to the queue.
- On first boot / after PSK rotation: `audit_chain` file is absent → `prev_hmac = "0000...0000"`.
- `canonical_json(event)` must exclude the `hmac` field itself to avoid circular dependency. Easiest: marshal a copy with `HMAC: ""` or use a shadow struct without the field.

### Testing

Server-side unit test: construct a 5-event chain with known PSK, verify the chain verifier accepts it. Mutate one event in the middle, verify chain breaks at the right index.

CLI-side unit test: emit 3 events, verify each `hmac` chains correctly. Simulate a PSK rotation, verify the chain restarts from zero.

Integration: ship a batch from a real node, verify `audit_chain_head` advances on the server. Force a gap, verify chain break is logged.

---

## Open questions

1. **Canonical JSON implementation.** Go's `json.Marshal` produces deterministic output for structs (field order is declaration order). Is that sufficient, or do we need a formal canonicalization spec (e.g. RFC 8785 JCS)? Proposal: use `json.Marshal` on a struct with fields in a locked order. Both sides use the same Go struct → same byte output. If we ever have a non-Go client, revisit.

2. **Chain head storage.** Single column on `nodes` vs separate table. Proposal: column on `nodes` (same pattern as `audit_ack_seq`). One fewer join.

3. **Operator reset UX.** When a chain break happens, the operator needs a "reset chain" button on the node detail page that:
   - Sets `audit_chain_head = ''`
   - Sets `audit_ack_seq` to current max seq for that node
   - Logs an audit row `audit_chain_reset, severity=critical`
   - Requires superadmin

---

**To CLI session:** review this spec. If the shape is acceptable, confirm and I'll write the migration + server verifier. You write the emitter + chain file. Coordinate on the canonical-JSON question before coding.
