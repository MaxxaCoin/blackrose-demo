BlackRose 0.9.23 — fixes three real faults in 0.9.22, one of them serious.

Past sessions could not be reopened
If you updated to 0.9.22, your conversation history appeared but would not open.
Your data was never lost and nothing was deleted — the list was on screen the
whole time. Clicking a session silently did nothing.

The cause was a JavaScript error in the web interface. A helper function was
declared roughly 110 lines below where it was first used, which JavaScript
treats as a hard error rather than a harmless ordering quirk. Every attempt to
load your session list threw, and a `catch` block written to handle "you are
offline" swallowed the message entirely. There was no error, no failed
request, and nothing to report. The server was working perfectly the whole
time; only the interface could not ask it for anything.

Both halves are fixed: the ordering, and the error-swallowing that hid it.
Errors in that path now appear in the browser console.

Asking for a backup in chat created an unencrypted archive
Typing /backup into the chat produced a real file, in the wrong place, with the
wrong protections:

    C:\Users\pc\backups\blackrose_backup_20261005.zip   (102 MB)

/app has a /backup command that writes an encrypted snapshot, but the chat
window had no handler for it. So the text was treated as an ordinary question,
and the assistant wrote its own version instead: a plain zip of the entire
BlackRose data folder, with no encryption whatsoever.

Worse, that folder contains keys.enc and vault.key — the sealed key material
the encrypted export deliberately leaves out, because those two only work on
this computer and shipping them together undoes the protection that made
copying your data safe in the first place.

Two fixes. The chat now handles /backup directly and calls the real encrypted
backup, and reports a failure honestly rather than falling through to the
assistant. And the shell tool now refuses commands that would bundle the sealed
vault into a plaintext archive, pointing you at the built-in commands instead.

You deleted that file, which was the right call. Nothing of value was lost: it
contained no memories of its own, only copies.

Full-backup trust
The hourly encrypted backup introduced in 0.9.22 continues to work unchanged.

Verification
- Installer sha256: c8b909c2fb24f0220be1546bab391b2d1ae7f890a26451e9ab86b5f741609216
- Signed with your existing Tauri updater key; latest.json carries this build's
  signature, confirmed identical to the .sig on disk
- Payload extracted and inspected: the backup feature, the new /backup endpoint,
  the chat command handler, the archive guard and the corrected declaration
  order were each confirmed present in the shipped file