BlackRose 0.9.22 — automatic backups, and no more hung AI calls.

Automatic encrypted backups
Your BlackRose memory is finally protected on its own schedule. Once
`BLACKROSE_STATE_PASSWORD` is set, BlackRose takes a full encrypted snapshot of
its entire state about 20 seconds after startup, then every hour, keeping the
newest 14 in `~/.blackrose/backups/`. `/backup` takes one on demand.

These are complete snapshots, not incremental deltas — any one of them restores
on its own. Rotation only ever deletes a snapshot after a newer full one exists.

Nothing is uploaded anywhere. No LLM, no network, no API key needed. The
password is only used to encrypt and decrypt the snapshot itself.

To enable: set the environment variable, restart BlackRose, run `/backup`, then
see `docs/07-BACKUP.md` for restore instructions. The variable may already be
set from an earlier setup — note that 0.9.21 could not act on it, because the
backup feature is new in this release.

Please also copy snapshots to external storage periodically. These protect
against accidental deletion, not against losing the disk.

No more hung AI calls
The OpenAI and Gemini adapters had no request deadline of their own, so a
provider that accepted a connection and then went quiet would hang the agent
indefinitely instead of failing. Both now carry their own timeout and surface a
normal error.

Verification
- Installer sha256: 7f197f45481ca906... (25,774,040 bytes)
- Signed with your existing Tauri updater key; `latest.json` carries this build's
  signature, confirmed byte-identical to the .sig on disk
- Payload extracted and inspected: the backup code is genuinely inside it