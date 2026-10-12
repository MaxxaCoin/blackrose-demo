import readline from 'node:readline';

import fs from 'node:fs';

import path from 'node:path';

import os from 'node:os';

import crypto from 'node:crypto';

import zlib from 'node:zlib';

import { execFileSync } from 'node:child_process';

import { spawn } from 'node:child_process';

import http from 'node:http';

const __mod = {};

function M1() {
/**
 * Secret Vault (B1) — encryption at rest for the API key store.
 *
 * WHY: `keys.json` used to be plain JSON. Its `mode: 0o600` is a NO-OP on NTFS
 * (ACLs govern Windows permissions), so every key was readable by anything that
 * could read the file: a directory copy, a cloud backup, a git commit, a laptop
 * shared with another account.
 *
 * HOW: two layers, both zero-dependency.
 *  1. `keys.enc`  — AES-256-GCM over gzipped JSON, the envelope style already
 *     proven in `.aistate`:  BRVAULT1 | iv(12) | authTag(16) | gzip(JSON)
 *     GCM makes tampering fail closed (an edited file decrypts to nothing rather
 *     than to attacker-controlled key material).
 *  2. `vault.key` — the 32 random bytes that key layer 1. Stored DPAPI-wrapped
 *     (CURRENTUSER scope + our entropy) whenever Windows is reachable, so the
 *     master key is bound to THIS machine and THIS Windows account: copying
 *     ~/.blackrose to another machine or account yields an unusable key.
 *     Where DPAPI is unavailable the key file is plain hex instead and every
 *     status surface reports `protection: "keyfile"` instead of `"dpapi"`.
 *     NTFS ACLs on both files are hardened with icacls — the honest replacement
 *     for the no-op 0o600.
 *
 * HONEST LIMIT: the desktop app boots unattended, so nobody types a passphrase.
 * A process running as THIS user on THIS machine can still ask the OS to unwrap
 * the key. What vaulting DOES buy: no plaintext at rest, no keys travelling in
 * backups/copies/git/other accounts, integrity-checked reads, and one place to
 * point a future passphrase or Credential-Manager upgrade at.
 *
 * Opt out of DPAPI (e.g. while debugging): BLACKROSE_VAULT_DPAPI=0
 */
const VAULT_MAGIC = Buffer.from('BRVAULT1');
const KEY_MAGIC = 'BRVKEY1';
const DPAPI_ENTROPY = 'BlackRose.vault.v1';
const IV_LEN = 12;
const TAG_LEN = 16;
function vaultFilePath(dataDir) {
    return path.join(dataDir, 'keys.enc');
}
function vaultKeyPath(dataDir) {
    return path.join(dataDir, 'vault.key');
}
/* ────────────────────────── windows helpers ───────────────────────── */
/** Run a one-shot PowerShell command and return stdout, whitespace-stripped. */
function runPs(script) {
    return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
        encoding: 'utf8',
        timeout: 10_000,
        windowsHide: true,
        maxBuffer: 2 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
    }).replace(/\s+/g, '');
}
const PS_PRELUDE = "$ErrorActionPreference='Stop';" +
    'try { Add-Type -AssemblyName System.Security } ' +
    'catch { Add-Type -AssemblyName System.Security.Cryptography.ProtectedData };' +
    `$e = [Text.Encoding]::UTF8.GetBytes('${DPAPI_ENTROPY}');`;
/** DPAPI (user scope + our entropy). Input and output travel as base64. */
function dpapiProtect(b64) {
    return runPs(PS_PRELUDE +
        `$b = [Convert]::FromBase64String('${b64}');` +
        "$p = [Security.Cryptography.ProtectedData]::Protect($b, $e, 'CurrentUser');" +
        '[Console]::Out.Write([Convert]::ToBase64String($p))');
}
function dpapiUnprotect(b64) {
    return runPs(PS_PRELUDE +
        `$b = [Convert]::FromBase64String('${b64}');` +
        "$p = [Security.Cryptography.ProtectedData]::Unprotect($b, $e, 'CurrentUser');" +
        '[Console]::Out.Write([Convert]::ToBase64String($p))');
}
/** null = untested this process; true/false = cached verdict. */
let dpapiOk = null;
function dpapiAvailable() {
    if (dpapiOk !== null)
        return dpapiOk;
    dpapiOk = false;
    if (process.platform === 'win32' && (process.env.BLACKROSE_VAULT_DPAPI ?? '1') !== '0') {
        try {
            const probe = crypto.randomBytes(8).toString('base64');
            dpapiOk = Buffer.from(dpapiUnprotect(dpapiProtect(probe)), 'base64').length === 8;
        }
        catch {
            dpapiOk = false;
        }
    }
    return dpapiOk;
}
const aclHardened = new Set();
/**
 * The real Windows equivalent of `mode: 0o600`: strip inherited ACLs and grant
 * only the current account. Best effort — never fatal, never retried per file.
 */
function hardenAtRest(file) {
    if (aclHardened.has(file))
        return;
    aclHardened.add(file);
    try {
        fs.chmodSync(file, 0o600); // meaningful on POSIX
    }
    catch {
        /* advisory only */
    }
    if (process.platform !== 'win32')
        return;
    const domain = process.env.USERDOMAIN ?? '';
    const user = process.env.USERNAME ?? '';
    if (!user)
        return;
    const principal = domain ? `${domain}\\${user}` : user;
    try {
        execFileSync('icacls', [file, '/quiet', '/inheritance:r', '/grant:r', `${principal}:F`], {
            stdio: 'ignore',
            timeout: 8_000,
            windowsHide: true,
        });
    }
    catch {
        /* ACL hardening is a bonus, not a requirement */
    }
}
/** Write owner-only-intent content atomically (tmp + rename). */
function writePrivate(file, bytes) {
    const tmp = `${file}.tmp-${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(tmp, bytes);
    hardenAtRest(tmp);
    fs.renameSync(tmp, file);
    hardenAtRest(file);
}
/* ─────────────────────────── master key ───────────────────────────── */
let cachedDir = null;
let cachedKey = null;
let cachedProtection = 'none';
let cachedError = '';
/** Memoise the master key for the dir it belongs to (see `masterKey`). */
function rememberKey(dir, key, protection) {
    cachedDir = dir;
    cachedKey = key;
    cachedProtection = protection;
    return { key, protection };
}
/**
 * Load — or, on first write, create — the vault master key. Never throws: an
 * unreadable key file is reported through `vaultError()` and reads return null.
 */
function masterKey(dataDir, create) {
    const dir = path.resolve(dataDir);
    // The cache holds the key for ONE data dir. A different dir (tests, an
    // alternate profile, the remote bridge's own store) must never reuse it —
    // that would seal one vault with another vault's key.
    if (cachedKey && cachedDir === dir)
        return { key: cachedKey, protection: cachedProtection === 'none' ? 'keyfile' : cachedProtection };
    if (cachedKey)
        resetVaultCache();
    const file = vaultKeyPath(dataDir);
    cachedError = '';
    if (fs.existsSync(file)) {
        try {
            const raw = fs.readFileSync(file, 'utf8').trim();
            if (raw.startsWith(KEY_MAGIC)) {
                const key = Buffer.from(dpapiUnprotect(raw.slice(KEY_MAGIC.length).trim()), 'base64');
                if (key.length !== 32)
                    throw new Error('decoded master key has the wrong length');
                return rememberKey(dir, key, 'dpapi');
            }
            if (/^[0-9a-f]{64}$/i.test(raw)) {
                hardenAtRest(file);
                return rememberKey(dir, Buffer.from(raw, 'hex'), 'keyfile');
            }
            throw new Error('unrecognised vault key format');
        }
        catch (e) {
            cachedError = e instanceof Error ? e.message : String(e);
            return null;
        }
    }
    if (!create)
        return null;
    const key = crypto.randomBytes(32);
    try {
        fs.mkdirSync(dataDir, { recursive: true });
        if (dpapiAvailable()) {
            writePrivate(file, KEY_MAGIC + dpapiProtect(key.toString('base64')));
            return rememberKey(dir, key, 'dpapi');
        }
        writePrivate(file, key.toString('hex'));
        return rememberKey(dir, key, 'keyfile');
    }
    catch (e) {
        cachedError = e instanceof Error ? e.message : String(e);
        return null;
    }
}
/** Why the vault could not be opened (empty when healthy). */
function vaultError() {
    return cachedError;
}
/* ─────────────────────────── envelope ─────────────────────────────── */
function seal(key, data) {
    const payload = zlib.gzipSync(Buffer.from(JSON.stringify(data), 'utf8'));
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
    return Buffer.concat([VAULT_MAGIC, iv, cipher.getAuthTag(), encrypted]);
}
function unseal(key, blob) {
    if (blob.length < VAULT_MAGIC.length + IV_LEN + TAG_LEN)
        throw new Error('vault file is truncated');
    if (!blob.subarray(0, VAULT_MAGIC.length).equals(VAULT_MAGIC))
        throw new Error('not a BlackRose vault file');
    let offset = VAULT_MAGIC.length;
    const iv = blob.subarray(offset, offset + IV_LEN);
    offset += IV_LEN;
    const tag = blob.subarray(offset, offset + TAG_LEN);
    offset += TAG_LEN;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag); // tampered file → final() throws, the read fails closed
    const payload = Buffer.concat([decipher.update(blob.subarray(offset)), decipher.final()]);
    const parsed = JSON.parse(zlib.gunzipSync(payload).toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('vault content is not a key map');
    }
    const out = {};
    for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string')
            out[k] = v.trim();
    }
    return out;
}
/* ─────────────────────────── public API ───────────────────────────── */
/** Read the sealed vault. Absent/unreadable → found:false; never throws. */
function readVault(dataDir) {
    const file = vaultFilePath(dataDir);
    if (!fs.existsSync(file))
        return { found: false, data: {}, protection: cachedProtection };
    const mk = masterKey(dataDir, false);
    if (!mk)
        return { found: false, data: {}, protection: cachedProtection, error: cachedError };
    try {
        return { found: true, data: unseal(mk.key, fs.readFileSync(file)), protection: mk.protection };
    }
    catch (e) {
        return {
            found: false,
            data: {},
            protection: mk.protection,
            error: e instanceof Error ? e.message : String(e),
        };
    }
}
/** Write the sealed vault. Throws only when no master key can be created. */
function writeVault(dataDir, data) {
    const mk = masterKey(dataDir, true);
    if (!mk)
        throw new Error(`Cannot create the secret vault: ${cachedError || 'no master key'}`);
    writePrivate(vaultFilePath(dataDir), seal(mk.key, data));
}
function vaultStatus(dataDir) {
    const read = readVault(dataDir);
    return {
        sealed: read.found,
        protection: read.found ? read.protection : cachedProtection,
        dpapi: dpapiAvailable(),
        encFile: vaultFilePath(dataDir),
        keyFile: vaultKeyPath(dataDir),
        entries: Object.keys(read.data).length,
        error: read.error ?? cachedError,
    };
}
/** Test seam: forget cached key/DPAPI state for this process. Touches no data. */
function resetVaultCache() {
    cachedDir = null;
    cachedKey = null;
    cachedProtection = 'none';
    cachedError = '';
}
return { vaultFilePath,vaultKeyPath,vaultError,readVault,writeVault,vaultStatus,resetVaultCache };
}

__mod['core/vault.js'] = M1();

function M2() {
const { readVault, vaultFilePath, writeVault } = __mod['core/vault.js'];
/**
 * Read-modify-write access to the sealed store, shared by keys.ts and
 * providers.ts.
 *
 * WHY A SEPARATE MODULE (2026-10-01): keys.ts needs the provider registry (to
 * list and validate keys for providers added from the UI) and the registry needs
 * to store itself in the same vault. That is a genuine two-way dependency.
 *
 * Two wrong turns, both worth recording:
 *
 * 1. The registry imported keys.ts directly. Typecheck was perfectly happy — it
 *    ignores evaluation order — but the single-file bundler evaluates modules in
 *    dependency order and the shipped bundle died at startup with
 *    "Cannot destructure property 'readStoredKeys' of '__mod.core/keys.js'".
 *    A cycle here is a RUNTIME failure the type-checker cannot see, and it only
 *    appears once the code is bundled.
 *
 * 2. So the registry was pointed at vault.ts directly instead. That fixed the
 *    crash and introduced a worse bug: readVault skips the legacy plaintext
 *    migration, so writing a vault containing only `__PROVIDERS__` made
 *    readStoredKeys() conclude a vault existed, skip the migration, and hand
 *    back a store with NONE of the user's API keys in it. The plaintext file was
 *    still on disk, but the app could no longer see those keys — which from the
 *    user's side is identical to losing them.
 *
 * The way out is both: this module owns the migrating read, the write, and the
 * legacy-path helpers, and it imports only vault.ts. keys.ts and providers.ts
 * both depend on it, so the graph is acyclic AND every write still goes through
 * the migration.
 */



/** Legacy plaintext store path (kept for migration + diagnostics only). */
function keysFilePath(dataDir) {
    return path.join(dataDir, 'keys.json');
}
/** Sealed vault path (the live store). */
function keyVaultPath(dataDir) {
    return vaultFilePath(dataDir);
}
/** Read the legacy plaintext store; {} when absent or malformed. */
function readPlaintextKeys(dataDir) {
    const file = keysFilePath(dataDir);
    if (!fs.existsSync(file))
        return {};
    try {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
            const res = {};
            for (const [k, v] of Object.entries(parsed)) {
                if (typeof v === 'string')
                    res[k] = v.trim();
            }
            return res;
        }
    }
    catch {
        /* malformed legacy file: ignore it rather than crash the app */
    }
    return {};
}
/**
 * One-time upgrade: plaintext keys.json → sealed keys.enc.
 * Returns the migrated map (or {} when there was nothing to migrate). The
 * plaintext file is deleted ONLY after the sealed copy has been read back and
 * matched, so a failed seal can never lose keys. When the vault itself is
 * unavailable the plaintext file is left untouched rather than destroyed.
 */
function migratePlaintextKeys(dataDir) {
    const legacy = readPlaintextKeys(dataDir);
    if (Object.keys(legacy).length === 0)
        return {};
    try {
        writeVault(dataDir, legacy);
        const back = readVault(dataDir);
        if (!back.found)
            return {}; // sealed copy unverified → keep the plaintext file
        let same = true;
        for (const [k, v] of Object.entries(legacy)) {
            if (back.data[k] !== v)
                same = false;
        }
        if (!same)
            return {};
        fs.rmSync(keysFilePath(dataDir), { force: true });
        return legacy;
    }
    catch {
        return {};
    }
}
/**
 * Read the stored keys: vault first, transparently migrating a legacy
 * plaintext file when one is still lying around.
 */
function readStoredKeys(dataDir) {
    const vault = readVault(dataDir);
    if (vault.found)
        return vault.data;
    const migrated = migratePlaintextKeys(dataDir);
    if (Object.keys(migrated).length > 0)
        return migrated;
    return {};
}
function writeStoredKeys(dataDir, keys) {
    fs.mkdirSync(dataDir, { recursive: true });
    writeVault(dataDir, keys);
    fs.rmSync(keysFilePath(dataDir), { force: true }); // never leave a plaintext twin
}
/**
 * Cross-process guard for the read-modify-write in updateStoredKeys().
 *
 * WHY THIS EXISTS: updateStoredKeys() is the only write path shared by
 * keys.ts and providers.ts, and a plain read → mutate → write has a window
 * between the two file operations. Two writers (the desktop app and the CLI
 * both touch the same store) interleave as
 *
 *   A reads store            → {x}
 *   B reads store            → {x}
 *   B writes {x, y}
 *   A writes {x}            ← y is GONE, and nothing anywhere reported an error
 *
 * The atomic write already in vault.ts prevents a TORN file; it cannot prevent
 * this LOST UPDATE, because each writer's file is individually perfect. So the
 * critical section needs a lock, and the read has to happen INSIDE it —
 * re-reading after acquiring is what makes the snapshot provably newer than
 * every other writer's.
 *
 * Cross-process, because that is the case that actually loses data: within one
 * process these functions are synchronous and cannot interleave at all.
 */
const LOCK_FILE = 'keys.enc.lock';
/** How long to wait for the other process before giving up on the lock. */
const LOCK_WAIT_MS = 3_000;
/**
 * A crashed holder leaves its lock file behind forever, so a stale lock is
 * broken. Generous relative to LOCK_WAIT_MS: the critical section is one read
 * plus one small sealed write, so anything older than this died holding it.
 */
const LOCK_STALE_MS = 10_000;
/** Synchronous sleep — this whole module is sync, so there is nothing to await. */
function sleepSync(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
/**
 * Exclusive-create the lock file, waiting (and stealing it if stale). Returns a
 * release function, or null when the lock could not be taken in time.
 */
function acquireLock(dataDir) {
    const lock = path.join(dataDir, LOCK_FILE);
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
        try {
            // 'wx' fails with EEXIST rather than truncating — the exclusive create IS
            // the test, so there is no stat/open TOCTOU window (see the 'wx' note in
            // cline's keybindings.ts for the same reasoning).
            fs.closeSync(fs.openSync(lock, 'wx'));
            return () => {
                try {
                    fs.rmSync(lock, { force: true });
                }
                catch {
                    /* best effort — a stale lock is broken after LOCK_STALE_MS anyway */
                }
            };
        }
        catch (e) {
            if (e.code !== 'EEXIST')
                return null; // unwritable dir → run unlocked rather than fail the write
            try {
                if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) {
                    fs.rmSync(lock, { force: true });
                    continue;
                }
            }
            catch {
                continue; // holder released it between our open and our stat
            }
            if (Date.now() > deadline)
                return null;
            sleepSync(15);
        }
    }
}
/**
 * Read-modify-write the sealed store.
 *
 * The point of this helper is that the READ migrates first. Any writer that
 * went straight to the vault would seal a store containing only its own field,
 * and the next readStoredKeys() would then see "a vault exists", skip the
 * migration, and hand back a store missing everything the user already had —
 * the file still on disk, but invisible to the app. That is exactly what the
 * provider registry did on its first attempt; see providers.ts.
 *
 * The read and the write are one critical section (see acquireLock) so a second
 * writer's key is never dropped on the floor without an error. If the lock
 * cannot be taken the write still happens — a lost update is worse than a
 * contended one, and the caller gets no way to report a lock timeout anyway.
 */
function updateStoredKeys(dataDir, mutate) {
    fs.mkdirSync(dataDir, { recursive: true });
    const release = acquireLock(dataDir);
    try {
        // Read INSIDE the critical section: a store snapshot taken before the lock
        // is exactly the stale snapshot that loses another writer's key.
        const stored = readStoredKeys(dataDir);
        mutate(stored);
        writeStoredKeys(dataDir, stored);
    }
    finally {
        release?.();
    }
}
return { keysFilePath,keyVaultPath,migratePlaintextKeys,readStoredKeys,writeStoredKeys,updateStoredKeys };
}

__mod['core/keystore.js'] = M2();

function M3() {
/**
 * The built-in route specs.
 *
 * Extracted from keys.ts on 2026-10-01 to break an import CYCLE. keys.ts needs
 * the provider registry (B27) to list and validate keys for providers added from
 * the UI, and the registry needs these specs to reject a custom route whose name
 * collides with a built-in. Left in keys.ts, that pair imports each other: the
 * TS type-checker is perfectly happy, but the single-file bundler evaluates
 * modules in dependency order and failed at runtime with
 * "Cannot destructure property 'readStoredKeys' of '__mod.core/keys.js'" —
 * a break that only appeared once the code was bundled, which is exactly the
 * kind of thing typecheck cannot catch.
 *
 * This module imports nothing, so both sides can depend on it safely.
 */
const ROUTE_KEY_SPECS = [
    { route: 'openai2', envVar: 'BLACKROSE_OPENAI2_API_KEY', label: 'OmniRoute / OpenAI #2' },
    { route: 'gemini', envVar: 'BLACKROSE_GEMINI_API_KEY', label: 'Google Gemini' },
    { route: 'openai3', envVar: 'BLACKROSE_OPENAI3_API_KEY', label: 'NVIDIA NIM / OpenAI #3' },
    { route: 'onemin', envVar: 'BLACKROSE_ONEMIN_API_KEY', label: '1min.ai' },
    { route: 'openai', envVar: 'BLACKROSE_OPENAI_API_KEY', label: 'OpenRouter / OpenAI #0' },
    { route: 'openai1', envVar: 'BLACKROSE_OPENAI1_API_KEY', label: 'Groq / OpenAI #1' },
    { route: 'openai4', envVar: 'BLACKROSE_OPENAI4_API_KEY', label: 'Hugging Face / OpenAI #4' },
    { route: 'openai5', envVar: 'BLACKROSE_OPENAI5_API_KEY', label: 'Cloudflare Workers AI / OpenAI #5' },
    { route: 'openai6', envVar: 'BLACKROSE_OPENAI6_API_KEY', label: 'GonkaRouter / OpenAI #6' },
    { route: 'anthropic', envVar: 'ANTHROPIC_API_KEY', label: 'Anthropic Claude' },
];
return { ROUTE_KEY_SPECS };
}

__mod['core/routespecs.js'] = M3();

function M4() {
const { readStoredKeys, updateStoredKeys } = __mod['core/keystore.js'];
const { ROUTE_KEY_SPECS } = __mod['core/routespecs.js'];
/**
 * Provider registry (B27) — add a gateway without a code change.
 *
 * THE PROBLEM THIS SOLVES
 * Until now a new gateway meant editing `ROUTE_KEY_SPECS` in core/keys.ts,
 * adding a branch in `singleProvider()`, and rebuilding. That is a code change
 * and a restart to add one row to a config table — the UI could show and change
 * KEYS but not PROVIDERS.
 *
 * WHAT IS STORED
 * A small JSON document listing the user's own OpenAI-compatible gateways:
 * route name, label, base URL, model, and whether a key is required. It is
 * sealed in the SAME encrypted vault as the keys (under one reserved entry), so
 * there is no new secret-handling path to get wrong, and a vault backup carries
 * the providers with it.
 *
 * WHAT IS DELIBERATELY NOT HERE
 * Built-in providers (gemini, anthropic, 1min, kilo, ovh) are NOT in the
 * registry. They are code, not configuration: each has its own adapter and wire
 * format. A registry entry means "another OpenAI-compatible endpoint", and
 * pretending otherwise would invite someone to register Gemini here and get a
 * confusing failure instead of a clear one.
 *
 * Compatibility: the registry only ever ADDS to `ROUTE_KEY_SPECS`. Every
 * existing reader, test and migration keeps working, and deleting the registry
 * returns the app to exactly its previous behaviour.
 */


/** Reserved vault entry holding the registry JSON. */
const REGISTRY_KEY = '__PROVIDERS__';
/**
 * Reserved vault entry holding the fallback chain, in order.
 *
 * The chain used to be readable only through the BLACKROSE_ROUTES environment
 * variable, which a desktop user has no natural way to set — so adding a
 * provider from the panel could never actually put it in the chain, and the UI
 * could only tell the user to go edit it elsewhere. Sealing the chain in the
 * same vault as everything else makes the panel the one place that decides it.
 *
 * The env var still wins when set, so an existing scripted launch keeps its
 * exact behaviour and nothing silently changes under someone mid-deploy.
 */
const CHAIN_KEY = '__ROUTE_CHAIN__';
/** Chain to use when neither the vault nor the environment says anything. */
const DEFAULT_ROUTE_CHAIN = ['anthropic', 'openai'];
function readRouteChain(dataDir) {
    // Environment first, deliberately: a launch script that sets BLACKROSE_ROUTES
    // is stating an intent that should not be second-guessed by stored state.
    const env = process.env.BLACKROSE_ROUTES;
    if (env != null && env.trim() !== '') {
        // ...but NOT one we published ourselves from the stored chain. makeClient()
        // and the save endpoint both set BLACKROSE_ROUTES so the rest of the process
        // sees the current chain; if that counted as "the environment", then simply
        // saving the chain once would flip it to read-only forever after. The UI
        // would grey itself out on the first successful edit.
        //
        // A stamp set alongside the value is the marker that distinguishes "the user
        // set this before launch" from "we mirrored our own stored chain".
        const fromVault = process.env.BLACKROSE_ROUTES_FROM_VAULT === '1';
        if (!fromVault) {
            return { routes: parseChain(env), source: 'env', editable: false };
        }
    }
    const raw = readStoredKeys(dataDir)[CHAIN_KEY];
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) {
                const routes = parsed.filter((r) => typeof r === 'string');
                if (routes.length)
                    return { routes, source: 'vault', editable: true };
            }
        }
        catch {
            // fall through to the default
        }
    }
    // The default is editable: nothing is stored yet, so the first save writes a
    // vault chain and takes over from here.
    return { routes: [...DEFAULT_ROUTE_CHAIN], source: 'default', editable: true };
}
function parseChain(raw) {
    return raw.split(',').map((s) => s.trim()).filter(Boolean);
}
/**
 * Replace the stored chain.
 *
 * Returns the routes actually stored. Duplicates are dropped (a repeated route
 * in the chain costs a wasted round trip on every single turn) and so are names
 * that cannot be routes at all. Unknown-but-well-formed names are KEPT: the
 * chain legitimately references providers that exist without holding a key
 * right now, and dropping those silently would make a key added later not take
 * effect until the user re-added the route by hand.
 */
function writeRouteChain(dataDir, routes) {
    const clean = [];
    for (const raw of routes) {
        const r = String(raw).trim().toLowerCase();
        if (!NAME_RE.test(r))
            throw new Error(`"${raw}" is not a usable route name`);
        if (!clean.includes(r))
            clean.push(r);
    }
    updateStoredKeys(dataDir, (stored) => {
        if (clean.length === 0)
            delete stored[CHAIN_KEY];
        else
            stored[CHAIN_KEY] = JSON.stringify(clean);
    });
    // Publish for this process AND mark it as ours, so readRouteChain() does not
    // mistake the mirror for a user-supplied environment variable and lock the UI
    // (see the fromVault check there).
    process.env.BLACKROSE_ROUTES = clean.join(',');
    process.env.BLACKROSE_ROUTES_FROM_VAULT = '1';
    return clean;
}
/**
 * Drop a route from the stored chain.
 *
 * Called when a provider is deleted. A chain still naming a deleted provider
 * is not fatal — the factory already skips an unusable route with a warning —
 * but it leaves a permanently red row in Connected routes and a warning on
 * every startup, which reads like something is broken when nothing is.
 */
function removeRouteFromChain(dataDir, name) {
    const chain = readRouteChain(dataDir);
    if (chain.source !== 'vault')
        return; // env/default is not ours to edit
    if (!chain.routes.includes(name))
        return;
    writeRouteChain(dataDir, chain.routes.filter((r) => r !== name));
}
/**
 * The built-in gateways, offered as starting points. Selecting one fills the
 * form; the user still confirms the model, because defaults go stale and a wrong
 * model looks exactly like a broken key.
 */
const PROVIDER_PRESETS = [
    { id: 'openrouter', label: 'OpenRouter', baseUrl: 'https://openrouter.ai/api/v1', model: 'nvidia/nemotron-3-super-120b-a12b:free', needsKey: true, note: 'large model catalogue, many free models' },
    { id: 'groq', label: 'Groq', baseUrl: 'https://api.groq.com/openai/v1', model: 'openai/gpt-oss-120b', needsKey: true, note: 'very fast inference' },
    { id: 'nvidia', label: 'NVIDIA NIM', baseUrl: 'https://integrate.api.nvidia.com/v1', model: 'nvidia/nemotron-3-super-120b-a12b', needsKey: true, note: 'open models, generous free tier' },
    { id: 'huggingface', label: 'Hugging Face', baseUrl: 'https://router.huggingface.co/v1', model: 'meta-llama/Llama-3.3-70B-Instruct', needsKey: true, note: 'inference providers' },
    { id: 'gonka', label: 'GonkaRouter', baseUrl: 'https://api.gonkarouter.io/v1', model: 'minimaxai/MiniMax-M2.7', needsKey: true, note: 'fast, OpenAI-compatible' },
    { id: 'openai', label: 'OpenAI (official)', baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini', needsKey: true, note: 'paid' },
    { id: 'deepseek', label: 'DeepSeek', baseUrl: 'https://api.deepseek.com/v1', model: 'deepseek-chat', needsKey: true, note: 'OpenAI-compatible' },
    { id: 'custom', label: 'Custom OpenAI-compatible', baseUrl: '', model: '', needsKey: true, note: 'any /v1 endpoint speaking the Chat Completions API' },
    { id: 'keyless', label: 'Keyless (no credential)', baseUrl: '', model: '', needsKey: false, note: 'a gateway that needs no Authorization header' },
];
/** Route names become env var names, so they must be safe and boring. */
const NAME_RE = /^[a-z][a-z0-9]{0,23}$/;
/** Only http(s): a `file:` or `javascript:` base URL would be a foot-gun. */
function validBaseUrl(u) {
    try {
        const parsed = new URL(u);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    }
    catch {
        return false;
    }
}
function readProviders(dataDir) {
    // readStoredKeys, not readVault: it transparently migrates a legacy plaintext
    // keys.json first. Reading the vault directly would report "no providers"
    // for such a user while their keys still sat un-migrated, and the next write
    // would then clobber them.
    const raw = readStoredKeys(dataDir)[REGISTRY_KEY];
    if (!raw)
        return [];
    try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed))
            return [];
        return parsed.filter((p) => !!p && typeof p === 'object' && typeof p.name === 'string' &&
            NAME_RE.test(p.name) && typeof p.baseUrl === 'string');
    }
    catch {
        // A corrupt registry must not break startup: the app keeps working with the
        // built-in providers, which is exactly the pre-B27 behaviour.
        return [];
    }
}
function writeProviders(dataDir, list) {
    // updateStoredKeys, not a raw vault write, for two reasons.
    //
    // 1. It merges into whatever else is sealed, so adding a provider never
    //    disturbs a stored key.
    // 2. Its read MIGRATES a legacy plaintext keys.json first. Reading the vault
    //    directly (the first attempt here, to dodge an import cycle) sealed a
    //    store containing only __PROVIDERS__, so readStoredKeys() then saw "a vault
    //    exists", skipped the migration, and returned NONE of the user's keys. The
    //    file was still on disk, but the app could no longer see those keys — from
    //    the user's side, identical to losing them. The cycle is broken at the
    //    module graph instead; see the header of keystore.ts.
    updateStoredKeys(dataDir, (stored) => {
        if (list.length === 0)
            delete stored[REGISTRY_KEY];
        else
            stored[REGISTRY_KEY] = JSON.stringify(list);
    });
}
/** Env var a provider's key lives under, matching the built-in convention. */
function providerKeyEnvVar(name) {
    return `BLACKROSE_${name.toUpperCase()}_API_KEY`;
}
function addProvider(dataDir, input) {
    const name = input.name.trim().toLowerCase();
    if (!NAME_RE.test(name)) {
        throw new Error(`"${input.name}" is not a usable route name — letters and digits only, starting with a letter, up to 24 characters`);
    }
    const baseUrl = input.baseUrl.trim().replace(/\/+$/, '');
    if (!validBaseUrl(baseUrl)) {
        throw new Error('base URL must be a full http(s) URL, e.g. https://api.example.com/v1');
    }
    const model = input.model.trim();
    if (!model)
        throw new Error('a model id is required');
    const list = readProviders(dataDir);
    if (list.some((p) => p.name === name))
        throw new Error(`route "${name}" already exists`);
    if (ROUTE_KEY_SPECS.some((s) => s.route === name))
        throw new Error(`"${name}" is a built-in route name`);
    const entry = {
        name,
        label: input.label.trim() || name,
        baseUrl,
        model,
        needsKey: input.needsKey !== false,
        created: new Date().toISOString(),
    };
    writeProviders(dataDir, [...list, entry]);
    // Publish to the environment so it takes effect on the NEXT turn rather than
    // after a restart — that is the entire point of the panel.
    const up = name.toUpperCase();
    process.env[`BLACKROSE_${up}_BASE_URL`] = baseUrl;
    process.env[`BLACKROSE_${up}_MODEL`] = model;
    return entry;
}
function removeProvider(dataDir, name) {
    const list = readProviders(dataDir);
    const next = list.filter((p) => p.name !== name);
    if (next.length === list.length)
        return false;
    writeProviders(dataDir, next);
    const up = name.toUpperCase();
    delete process.env[`BLACKROSE_${up}_BASE_URL`];
    delete process.env[`BLACKROSE_${up}_MODEL`];
    // A deleted provider must also leave the fallback chain. Leaving it behind is
    // not fatal — singleProvider() throws and makeClient() skips the route with a
    // warning — but it costs a warning on every single startup and paints a
    // permanently red row in Connected routes, which reads as a broken install
    // when the real cause is a name that no longer exists.
    //
    // Its KEYS are deliberately left in the vault: deleting a provider and losing
    // the keys attached to it would be a genuinely destructive surprise, and the
    // cost of keeping them is a few hundred bytes.
    removeRouteFromChain(dataDir, name);
    return true;
}
/**
 * Built-in specs merged with the user's own providers, in one list the UI and
 * the key validator can both read. Built-ins come first so their order — the
 * deliberate fallback priority — is never disturbed.
 */
function allProviderSpecs(dataDir) {
    const builtIn = ROUTE_KEY_SPECS.map((s) => {
        const up = s.route.toUpperCase();
        return {
            route: s.route,
            envVar: s.envVar,
            label: s.label,
            baseUrl: process.env[`BLACKROSE_${up}_BASE_URL`] ?? '',
            model: process.env[`BLACKROSE_${up}_MODEL`] ?? '',
            needsKey: true,
            custom: false,
        };
    });
    const custom = readProviders(dataDir).map((p) => ({
        route: p.name,
        envVar: providerKeyEnvVar(p.name),
        label: p.label,
        baseUrl: p.baseUrl,
        model: p.model,
        needsKey: p.needsKey,
        custom: true,
    }));
    return [...builtIn, ...custom];
}
/** Push every registered provider into the environment at startup. */
function applyProviders(dataDir) {
    for (const p of readProviders(dataDir)) {
        const up = p.name.toUpperCase();
        process.env[`BLACKROSE_${up}_BASE_URL`] = p.baseUrl;
        process.env[`BLACKROSE_${up}_MODEL`] = p.model;
    }
}
return { DEFAULT_ROUTE_CHAIN,readRouteChain,writeRouteChain,removeRouteFromChain,PROVIDER_PRESETS,validBaseUrl,readProviders,providerKeyEnvVar,addProvider,removeProvider,allProviderSpecs,applyProviders };
}

__mod['core/providers.js'] = M4();

function M5() {
const { vaultStatus } = __mod['core/vault.js'];
const { allProviderSpecs } = __mod['core/providers.js'];
const { ROUTE_KEY_SPECS } = __mod['core/routespecs.js'];
const { keysFilePath, keyVaultPath, migratePlaintextKeys, readStoredKeys, writeStoredKeys, updateStoredKeys, } = __mod['core/keystore.js'];
/**
 * Key store manager for BlackRose.
 *
 * Persists user API keys ENCRYPTED AT REST in `dataDir/keys.enc` (Secret Vault,
 * docs/07-BUILD-CHECKLIST B1 — see core/vault.ts for the crypto). At runtime the
 * keys are loaded into `process.env` so factory, router and diagnostics pick
 * them up seamlessly.
 *
 * Security principles:
 * 1. Raw keys are NEVER returned to the UI; only masked previews (e.g. `sk-...abcd`)
 *    and presence booleans (`hasKey: true|false`).
 * 2. At rest the store is AES-256-GCM sealed behind a DPAPI-wrapped machine key,
 *    with NTFS ACLs hardened (the old `mode: 0o600` was a no-op on Windows).
 * 3. Setting a key takes effect immediately in process memory and is saved to disk.
 * 4. A legacy plaintext `keys.json` is migrated into the vault on first read and
 *    then DELETED — but only after the sealed copy has been read back and verified.
 */



// Re-exported through the import above. Note the form: `export { x }` of a
// LOCAL binding, not `export { x } from './keystore.ts'`. The bundler flattens
// every module into one file, and a direct re-export emitted a second
// `const readStoredKeys` next to the imported one, failing the build with
// "Identifier 'readStoredKeys' has already been declared".

// The specs themselves now live in routespecs.ts (they are needed by BOTH
// keys.ts and providers.ts, and putting them here would make those two modules
// import each other). Re-exported so every existing
// `import { ROUTE_KEY_SPECS } from './keys.ts'` keeps working unchanged.

// The store accessors live in keystore.ts (see the note at the top of that
// file) so providers.ts can reach the vault without importing this module.
// Re-exported by NAME from the imports above, not with `export { x } from
// './keystore.ts'`: the bundler flattens every module into one file, and a direct
// re-export emitted a second `const readStoredKeys` next to the imported one,
// failing the build with "Identifier 'readStoredKeys' has already been declared".

/** How the key store is protected right now (for --doctor and the UI tray). */
function keystoreStatus(dataDir) {
    const s = vaultStatus(dataDir);
    return {
        encrypted: s.sealed,
        protection: s.protection,
        dpapi: s.dpapi,
        entries: s.entries,
        file: s.encFile,
        error: s.error ?? '',
    };
}
function maskSecret(val) {
    const t = val.trim();
    if (!t)
        return '';
    if (t.length <= 8)
        return '****';
    return `${t.slice(0, 3)}...${t.slice(-4)}`;
}
function loadAndApplyKeys(dataDir) {
    const stored = readStoredKeys(dataDir);
    for (const [envVar, val] of Object.entries(stored)) {
        if (val && !process.env[envVar]) {
            process.env[envVar] = val;
        }
    }
}
function listKeyStatuses(dataDir) {
    const stored = readStoredKeys(dataDir);
    // Built-ins first, then any provider added from the UI (B27), so the panel
    // lists everything the user can actually configure a key for.
    return allProviderSpecs(dataDir).map((spec) => {
        const val = process.env[spec.envVar] || stored[spec.envVar] || '';
        return {
            route: spec.route,
            envVar: spec.envVar,
            label: spec.label,
            hasKey: Boolean(val),
            preview: maskSecret(val),
        };
    });
}
/**
 * A key may be saved for a built-in route OR for a provider registered from the
 * UI (B27). The allowlist is what stops the API from being used as an arbitrary
 * "write any env var" primitive, so a custom provider has to be registered
 * first — which is the point.
 */
function isKnownProvider(dataDir, envVar) {
    return allProviderSpecs(dataDir).some((s) => s.envVar === envVar);
}
function saveKey(dataDir, envVar, val) {
    if (!isKnownProvider(dataDir, envVar)) {
        throw new Error(`Unsupported API key identifier: "${envVar}"`);
    }
    const cleanVal = val.trim();
    const stored = readStoredKeys(dataDir);
    if (!cleanVal) {
        delete stored[envVar];
        delete process.env[envVar];
    }
    else {
        stored[envVar] = cleanVal;
        process.env[envVar] = cleanVal;
    }
    writeStoredKeys(dataDir, stored);
}
/* ───────────────────── multi-key rotation (B26) ────────────────────────
 *
 * A provider can hold several keys so one being rate-limited or out of credit
 * does not fail the turn. Storage shape, chosen to stay backward compatible:
 *
 *   <ENV>            the PRIMARY key — exactly as before, so every existing
 *                    reader, migration and test keeps working untouched.
 *   <ENV>__KEYS      a JSON array of the ADDITIONAL keys, sealed in the same
 *                    vault. Absent means "just the primary".
 *
 * Keys are never concatenated, comma-joined or newline-joined into one value:
 * a real API key can contain any character, so a delimiter scheme is a
 * corruption risk. JSON is unambiguous.
 */
/** Env-var name holding the additional keys for `envVar`. */
function extraKeysEnvVar(envVar) {
    return `${envVar}__KEYS`;
}
/** All keys for a provider: the primary first, then the extras in order. */
function readProviderKeys(dataDir, envVar) {
    const stored = readStoredKeys(dataDir);
    const primary = (process.env[envVar] || stored[envVar] || '').trim();
    const keys = primary ? [primary] : [];
    const raw = stored[extraKeysEnvVar(envVar)];
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) {
                for (const k of parsed) {
                    if (typeof k !== 'string')
                        continue;
                    const clean = k.trim();
                    // A duplicate of the primary would burn a retry on the same dead key.
                    if (clean && !keys.includes(clean))
                        keys.push(clean);
                }
            }
        }
        catch {
            /* corrupt extras: fall back to the primary alone rather than failing the turn */
        }
    }
    return keys;
}
/** Replace the additional keys for a provider (the primary is set by saveKey). */
function saveExtraKeys(dataDir, envVar, extras) {
    const valid = ROUTE_KEY_SPECS.some((s) => s.envVar === envVar);
    if (!valid) {
        throw new Error(`Unsupported API key identifier: "${envVar}"`);
    }
    const stored = readStoredKeys(dataDir);
    const primary = (stored[envVar] || process.env[envVar] || '').trim();
    const cleaned = [...new Set(extras.map((k) => k.trim()).filter(Boolean))]
        .filter((k) => k !== primary);
    if (cleaned.length === 0)
        delete stored[extraKeysEnvVar(envVar)];
    else
        stored[extraKeysEnvVar(envVar)] = JSON.stringify(cleaned);
    writeStoredKeys(dataDir, stored);
}
/** Add one key to a provider. Returns the new total. */
function addProviderKey(dataDir, envVar, val) {
    const clean = val.trim();
    if (!clean)
        throw new Error('Empty API key');
    const existing = readProviderKeys(dataDir, envVar).filter((k) => k !== clean);
    const primary = existing[0] ?? clean;
    const rest = existing.slice(1);
    if (primary !== clean)
        rest.unshift(clean);
    const stored = readStoredKeys(dataDir);
    stored[envVar] = primary;
    process.env[envVar] = primary;
    saveExtraKeys(dataDir, envVar, rest);
    return readProviderKeys(dataDir, envVar).length;
}
/**
 * Parse a pasted or uploaded file of many keys for ONE provider.
 *
 * People keep their keys in whatever their provider's dashboard or a password
 * manager gave them, so the input is genuinely messy. Rather than demand one
 * format, this accepts the common ones and reports what it could not use:
 *
 *   - one key per line (blank lines and # or // comments ignored)
 *   - a JSON array of strings
 *   - `KEY=value` or `KEY: value` lines (.env / CSV / YAML style)
 *   - comma- or whitespace-separated runs on one line
 *   - a CSV-ish header row, which is skipped
 *
 * Two rules that matter more than the parsing:
 *  - Nothing is echoed back. A rejected line is reported by LINE NUMBER and a
 *    masked preview, never the content, so a bad paste cannot spill a real key
 *    into the UI, a log, or a screenshot.
 *  - A rejected line never aborts the import. A file with 50 good keys and one
 *    stray note should yield 50 keys, not an error.
 */
function parseBulkKeys(raw) {
    const keys = [];
    const rejected = [];
    let skipped = 0;
    const seen = new Set();
    const add = (candidate, line) => {
        const clean = candidate.trim().replace(/^["']|["']$/g, '').trim();
        if (!clean)
            return;
        if (clean.length < 16) {
            rejected.push({ line, reason: 'too short to be a key', preview: maskSecret(clean) });
            return;
        }
        if (/\s/.test(clean)) {
            rejected.push({ line, reason: 'contains whitespace', preview: maskSecret(clean.slice(0, 12)) });
            return;
        }
        if (seen.has(clean))
            return; // a duplicate is not an error, just nothing to add
        seen.add(clean);
        keys.push(clean);
    };
    const text = raw.replace(/\r\n/g, '\n').trim();
    if (!text)
        return { keys, rejected, skipped };
    // Whole-file JSON array — the clean case, handled first.
    if (text.startsWith('[')) {
        try {
            const arr = JSON.parse(text);
            if (Array.isArray(arr)) {
                arr.forEach((v, i) => {
                    if (typeof v === 'string')
                        add(v, i + 1);
                    else
                        rejected.push({ line: i + 1, reason: 'not a string', preview: typeof v });
                });
                return { keys, rejected, skipped };
            }
        }
        catch {
            /* not valid JSON — fall through to line handling */
        }
    }
    const lines = text.split('\n');
    lines.forEach((line, idx) => {
        const lineNo = idx + 1;
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';')) {
            skipped++;
            return;
        }
        // KEY=value / KEY: value — take the right-hand side only.
        const assigned = trimmed.match(/^[A-Za-z0-9_.-]+\s*[:=]\s*(.+)$/);
        if (assigned) {
            add(assigned[1], lineNo);
            return;
        }
        // A CSV/export header row is the one common non-key line.
        if (/^[A-Za-z_ ]+(,|\t)/.test(trimmed) && /name|key|token|email|id/i.test(trimmed)) {
            skipped++;
            return;
        }
        // Otherwise split a run of several keys on one line.
        for (const part of trimmed.split(/[,\s]+/)) {
            if (part)
                add(part, lineNo);
        }
    });
    return { keys, rejected, skipped };
}
/**
 * Add many keys to one provider at once. Existing keys are kept and duplicates
 * are ignored, so re-importing the same file is a no-op rather than a mess.
 */
function addProviderKeysBulk(dataDir, envVar, values) {
    for (const v of values)
        addProviderKey(dataDir, envVar, v);
    return readProviderKeys(dataDir, envVar).length;
}
/**
 * Check whether each key actually works, before trusting it.
 *
 * Why this exists: a key that is stored but dead is WORSE than no key. The
 * rotating-key client walks its list in order, so one dead key costs a wasted
 * round trip on every single turn until something notices — and nothing does,
 * because the router just falls through to the next route and the turn
 * succeeds anyway. The failure is invisible and permanent.
 *
 * The check is GET <base>/models, never a chat completion: validating must cost
 * no tokens and must not eat the provider's generation quota. Gateways that
 * hide /models (OmniRoute, Cloudflare) return 'unknown', not 'invalid' — we
 * genuinely do not know, and saying otherwise would be a lie that invites
 * someone to delete a working key.
 */
async function validateProviderKeys(envVar, baseUrl, keys, opts) {
    const base = baseUrl.replace(/\/+$/, '');
    const timeout = opts?.timeoutMs ?? 8000;
    return Promise.all(keys.map(async (key, index) => {
        const preview = maskSecret(key);
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), timeout);
        try {
            const res = await fetch(`${base}/models`, {
                headers: { authorization: `Bearer ${key}` },
                signal: ac.signal,
            });
            clearTimeout(timer);
            if (res.ok) {
                let n = 0;
                try {
                    const j = (await res.json());
                    n = Array.isArray(j.data) ? j.data.length : 0;
                }
                catch {
                    /* a 200 with an unparseable body still means the key authenticated */
                }
                return { index, preview, ok: true, reason: 'valid', detail: n > 0 ? `${n} model(s)` : 'authenticated' };
            }
            if (res.status === 401 || res.status === 403) {
                return { index, preview, ok: false, reason: 'unauthorized', detail: `HTTP ${res.status} — key rejected` };
            }
            if (res.status === 429) {
                // The key is GOOD; the account is just busy. Must not be reported as
                // a bad key, or a user would delete a working credential.
                return { index, preview, ok: true, reason: 'rate_limited', detail: 'HTTP 429 — key valid, quota busy' };
            }
            // 404/405 and friends: the endpoint is not exposed, which says nothing
            // about the key. Try a minimal generation to be sure? No — that spends
            // tokens. Report honestly as unknown.
            return { index, preview, ok: false, reason: 'unknown', detail: `HTTP ${res.status} — /models not exposed` };
        }
        catch (e) {
            clearTimeout(timer);
            const msg = e instanceof Error ? e.message : String(e);
            const timedOut = e instanceof Error && e.name === 'AbortError';
            return {
                index,
                preview,
                ok: false,
                reason: timedOut ? 'unreachable' : 'unknown',
                detail: timedOut ? `no response in ${timeout}ms` : msg.slice(0, 120),
            };
        }
    }));
}
/** One-line human summary of a validation run. */
function summarizeKeyValidation(v) {
    const valid = v.filter((x) => x.ok).length;
    const bad = v.filter((x) => !x.ok && (x.reason === 'unauthorized' || x.reason === 'unreachable')).length;
    const unknown = v.length - valid - bad;
    const parts = [`${valid}/${v.length} key(s) usable`];
    if (bad)
        parts.push(`${bad} rejected/unreachable`);
    if (unknown)
        parts.push(`${unknown} unconfirmed`);
    return parts.join(' · ');
}
/** Remove the key at `index` for a provider. Returns the new total. */
function removeProviderKey(dataDir, envVar, index) {
    const keys = readProviderKeys(dataDir, envVar);
    if (index < 0 || index >= keys.length)
        throw new Error(`No key at index ${index}`);
    const remaining = keys.filter((_, i) => i !== index);
    const stored = readStoredKeys(dataDir);
    if (remaining.length === 0) {
        delete stored[envVar];
        delete process.env[envVar];
        delete stored[extraKeysEnvVar(envVar)];
    }
    else {
        stored[envVar] = remaining[0];
        process.env[envVar] = remaining[0];
        if (remaining.length === 1)
            delete stored[extraKeysEnvVar(envVar)];
        else
            stored[extraKeysEnvVar(envVar)] = JSON.stringify(remaining.slice(1));
    }
    writeStoredKeys(dataDir, stored);
    return remaining.length;
}
/** Per-provider key roster for the UI: masked previews only, never values. */
function listProviderKeyStatuses(dataDir) {
    return ROUTE_KEY_SPECS.map((spec) => {
        const keys = readProviderKeys(dataDir, spec.envVar);
        return {
            route: spec.route,
            envVar: spec.envVar,
            label: spec.label,
            count: keys.length,
            previews: keys.map(maskSecret),
        };
    });
}
return { keystoreStatus,maskSecret,loadAndApplyKeys,listKeyStatuses,saveKey,extraKeysEnvVar,readProviderKeys,saveExtraKeys,addProviderKey,parseBulkKeys,addProviderKeysBulk,validateProviderKeys,summarizeKeyValidation,removeProviderKey,listProviderKeyStatuses,keysFilePath,keyVaultPath,ROUTE_KEY_SPECS,migratePlaintextKeys,readStoredKeys,writeStoredKeys,updateStoredKeys };
}

__mod['core/keys.js'] = M5();

function M6() {
const { loadAndApplyKeys } = __mod['core/keys.js'];
function defaultDataDir() {
    return process.env.BLACKROSE_DATA_DIR ?? path.join(os.homedir(), '.blackrose');
}
function ensureDataDirs(dataDir) {
    fs.mkdirSync(path.join(dataDir, 'memory'), { recursive: true });
    fs.mkdirSync(path.join(dataDir, 'sessions'), { recursive: true });
}
function loadConfig(cwd = process.cwd()) {
    const dataDir = defaultDataDir();
    ensureDataDirs(dataDir);
    loadAndApplyKeys(dataDir);
    const approveEnv = (process.env.BLACKROSE_APPROVE ?? 'ask').toLowerCase();
    const provider = (process.env.BLACKROSE_PROVIDER ?? 'anthropic').toLowerCase();
    return {
        apiKey: process.env.ANTHROPIC_API_KEY ?? process.env.BLACKROSE_API_KEY ?? null,
        model: process.env.BLACKROSE_MODEL ?? 'claude-sonnet-4-5',
        baseUrl: process.env.BLACKROSE_BASE_URL ?? 'https://api.anthropic.com',
        provider,
        dataDir,
        cwd,
        maxTurns: Number(process.env.BLACKROSE_MAX_TURNS ?? 24),
        approve: approveEnv === 'all' ? 'all' : 'ask',
    };
}
return { defaultDataDir,ensureDataDirs,loadConfig };
}

__mod['config.js'] = M6();

function M7() {
/**
 * Strip provider-passthrough fields that only one adapter understands (e.g. the
 * Gemini `thought_signature` carried on tool_use blocks) before sending history
 * to Anthropic, whose API would reject unknown fields on a mid-conversation
 * router failover.
 */
function toAnthropicContent(content) {
    if (typeof content === 'string')
        return content;
    return content.map((block) => {
        if (block.type !== 'tool_use')
            return block;
        const b = block;
        if (!('thought_signature' in b))
            return block;
        const { thought_signature: _omit, ...rest } = b;
        return rest;
    });
}
/** Anthropic Messages API client implemented with plain fetch (no SDK lock-in). */
function anthropicClient(opts) {
    const base = (opts.baseUrl ?? 'https://api.anthropic.com').replace(/\/+$/, '');
    return {
        name: 'anthropic',
        model: opts.model,
        async call(system, messages, tools, callOpts) {
            const res = await fetch(`${base}/v1/messages`, {
                method: 'POST',
                // Honour the caller's signal: without it the Stop button cannot cancel
                // an in-flight Anthropic request, and the tokens keep being billed after
                // the user decided to stop.
                signal: callOpts?.signal,
                headers: {
                    'content-type': 'application/json',
                    'x-api-key': opts.apiKey,
                    'anthropic-version': '2023-06-01',
                },
                body: JSON.stringify({
                    model: opts.model,
                    max_tokens: opts.maxTokens ?? 8192,
                    system,
                    messages: messages.map((m) => ({ role: m.role, content: toAnthropicContent(m.content) })),
                    tools,
                }),
            });
            const body = (await res.json());
            if (!res.ok || body.error) {
                const detail = body.error?.message ?? JSON.stringify(body).slice(0, 500);
                throw new Error(`LLM API error (HTTP ${res.status}): ${detail}`);
            }
            return {
                content: body.content ?? [],
                stop_reason: body.stop_reason ?? null,
                usage: body.usage,
            };
        },
    };
}
return { anthropicClient };
}

__mod['llm/client.js'] = M7();

function M8() {
/* ── schema conversion: lowercase types → Gemini's UPPERCASE types ── */
function toUpperTypes(value) {
    if (typeof value === 'string')
        return value;
    if (Array.isArray(value))
        return value.map(toUpperTypes);
    if (typeof value === 'object' && value !== null) {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = k === 'type' && typeof v === 'string' ? v.toUpperCase() : toUpperTypes(v);
        }
        return out;
    }
    return value;
}
function toGeminiDeclarations(tools) {
    if (tools.length === 0)
        return [];
    const decls = tools.map((t) => ({
        name: t.name,
        description: t.description,
        parameters: toUpperTypes(t.input_schema),
    }));
    return [{ functionDeclarations: decls }];
}
/** Map tool_use ids → function names (Gemini's functionResponse is keyed by name). */
function buildFunctionNameMap(messages) {
    const map = new Map();
    for (const m of messages) {
        if (typeof m.content === 'string')
            continue;
        for (const b of m.content) {
            if (b.type !== 'tool_use')
                continue;
            const tb = b;
            if (tb.id)
                map.set(tb.id, tb.name);
        }
    }
    return map;
}
function extractToolResultText(content) {
    if (typeof content === 'string')
        return content;
    if (Array.isArray(content)) {
        let out = '';
        for (const part of content) {
            if (part.type === 'text')
                out += (out ? '\n' : '') + (part.text ?? '');
            else if (part.type === 'image')
                out += (out ? '\n' : '') + '[image attached]';
        }
        return out;
    }
    return '';
}
/** Convert the internal message format → Gemini `contents[]`. */
function toGeminiContents(messages) {
    const nameMap = buildFunctionNameMap(messages);
    const contents = [];
    for (const m of messages) {
        if (typeof m.content === 'string') {
            contents.push({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] });
            continue;
        }
        const blocks = m.content;
        if (m.role === 'assistant') {
            const parts = [];
            const text = blocks.filter((b) => b.type === 'text').map((b) => b.text ?? '').join('\n');
            if (text)
                parts.push({ text });
            for (const b of blocks) {
                if (b.type !== 'tool_use')
                    continue;
                const tb = b;
                const part = {
                    functionCall: { name: tb.name, args: (tb.input ?? {}) },
                };
                // Gemini 3.x: the signature MUST be echoed back alongside the call
                if (tb.thought_signature)
                    part.thoughtSignature = tb.thought_signature;
                parts.push(part);
            }
            if (parts.length > 0)
                contents.push({ role: 'model', parts });
            continue;
        }
        // user turn: text parts + functionResponse parts
        const parts = [];
        const text = blocks.filter((b) => b.type === 'text').map((b) => b.text ?? '').join('\n');
        if (text)
            parts.push({ text });
        for (const b of blocks) {
            if (b.type !== 'tool_result')
                continue;
            const trb = b;
            parts.push({
                functionResponse: {
                    name: nameMap.get(trb.tool_use_id ?? '') ?? 'unknown_tool',
                    response: { result: extractToolResultText(trb.content) },
                },
            });
        }
        if (parts.length > 0)
            contents.push({ role: 'user', parts });
    }
    return contents;
}
/* ── the client ── */
function geminiClient(opts) {
    const base = (opts.baseUrl ?? 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, '');
    return {
        name: 'gemini',
        model: opts.model,
        async call(system, messages, tools, callOpts) {
            const body = {
                system_instruction: { parts: [{ text: system }] },
                contents: toGeminiContents(messages),
                generationConfig: { maxOutputTokens: opts.maxOutputTokens ?? 8192 },
            };
            if (tools.length > 0)
                body.tools = toGeminiDeclarations(tools);
            // Honour the abort signal. This adapter previously dropped it on the
            // floor, so pressing Stop while Gemini was mid-generation did nothing:
            // the request ran to completion and the tokens were spent anyway — the
            // exact outcome the signal exists to prevent (see LlmClient.call).
            // Already-aborted signals short-circuit before the request is sent.
            if (callOpts?.signal?.aborted)
                throw new Error('aborted');
            const res = await fetch(`${base}/models/${opts.model}:generateContent`, {
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    'x-goog-api-key': opts.apiKey,
                },
                body: JSON.stringify(body),
                signal: callOpts?.signal,
            });
            const data = (await res.json());
            if (!res.ok || data.error) {
                const detail = data.error?.message ?? JSON.stringify(data).slice(0, 500);
                throw new Error(`Gemini API error (HTTP ${res.status}): ${detail}`);
            }
            const parts = data.candidates?.[0]?.content?.parts ?? [];
            const content = [];
            let callIdx = 0;
            for (const part of parts) {
                if (typeof part.text === 'string' && part.text !== '') {
                    content.push({ type: 'text', text: part.text });
                    continue;
                }
                if (!part.functionCall)
                    continue;
                const block = {
                    type: 'tool_use',
                    id: `gemini_call_${callIdx++}`,
                    name: part.functionCall.name,
                    input: (part.functionCall.args ?? {}),
                };
                if (part.thoughtSignature) {
                    ;
                    block.thought_signature = part.thoughtSignature;
                }
                content.push(block);
            }
            if (content.length === 0)
                content.push({ type: 'text', text: '(empty response from Gemini model)' });
            return {
                content,
                stop_reason: content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn',
                usage: {
                    input_tokens: data.usageMetadata?.promptTokenCount,
                    output_tokens: data.usageMetadata?.candidatesTokenCount,
                },
            };
        },
    };
}
return { geminiClient };
}

__mod['llm/gemini.js'] = M8();

function M9() {
const DEFAULT_BASE = 'https://api.1min.ai';
/* ── transcript flattening: system + messages → one prompt ── */
function textOf(content) {
    if (typeof content === 'string')
        return content;
    if (!Array.isArray(content))
        return '';
    const parts = [];
    for (const block of content) {
        if (block.type === 'text')
            parts.push(block.text);
        else if (block.type === 'image')
            parts.push('[image omitted]');
        else if (block.type === 'tool_use') {
            parts.push(`[called tool ${block.name} with ${JSON.stringify(block.input)}]`);
        }
        else if (block.type === 'tool_result') {
            const body = typeof block.content === 'string'
                ? block.content
                : block.content.map((b) => (b.type === 'text' ? b.text : '[image]')).join('\n');
            parts.push(block.is_error ? `[tool error] ${body}` : `[tool result] ${body}`);
        }
    }
    return parts.join('\n');
}
function toolProtocol(tools) {
    const list = tools
        .map((t) => `- ${t.name}: ${t.description} — input: ${JSON.stringify(t.input_schema)}`)
        .join('\n');
    return [
        'TOOL PROTOCOL:',
        'You have access to tools listed below. When (and only when) a tool is needed,',
        'reply with EXACTLY one fenced block and no other text:',
        '',
        '```tool_call',
        '{"tool":"<tool name>","input":{...}}',
        '```',
        '',
        'Rules:',
        '- Call ONE tool at a time. Wait for the TOOL RESULT before continuing.',
        '- Never invent a tool name; use only the names listed below.',
        '- Put valid JSON inside the block (double quotes, no trailing commas).',
        '- If no tool is needed, answer normally as plain text with no block.',
        '',
        'Available tools:',
        list,
    ].join('\n');
}
function transcript(system, messages) {
    const lines = [];
    if (system.trim())
        lines.push(`SYSTEM:\n${system.trim()}`);
    for (const m of messages) {
        const body = textOf(m.content).trim();
        if (!body)
            continue;
        const who = m.role === 'user' ? 'USER' : 'ASSISTANT';
        lines.push(`${who}:\n${body}`);
    }
    return lines.join('\n\n');
}
/* ── tool-call parsing: fenced JSON → tool_use block ── */
function parseToolCall(text) {
    const fence = /```(?:tool_call|tool|json)?\s*([\s\S]*?)```/i.exec(text);
    const candidates = fence ? [fence[1]] : [];
    // tolerate an unterminated fence (truncated response): take the JSON object
    const brace = /\{[\s\S]*\}/.exec(fence ? '' : text);
    if (brace)
        candidates.push(brace[0]);
    for (const raw of candidates) {
        const start = raw.indexOf('{');
        if (start < 0)
            continue;
        try {
            const parsed = JSON.parse(raw.slice(start, raw.lastIndexOf('}') + 1));
            const name = typeof parsed.tool === 'string' ? parsed.tool : typeof parsed.name === 'string' ? parsed.name : null;
            if (!name)
                continue;
            const input = (typeof parsed.input === 'object' && parsed.input !== null ? parsed.input : undefined) ??
                (typeof parsed.arguments === 'object' && parsed.arguments !== null ? parsed.arguments : undefined) ??
                (typeof parsed.parameters === 'object' && parsed.parameters !== null ? parsed.parameters : {});
            return { name, input: input };
        }
        catch {
            // not valid JSON — try the next candidate
        }
    }
    return null;
}
/** 1min.ai client: flattens history, emulates tool calls, maps the response back. */
function oneMinClient(opts) {
    const base = (opts.baseUrl ?? DEFAULT_BASE).replace(/\/+$/, '');
    return {
        name: 'onemin',
        model: opts.model,
        async call(system, messages, tools, callOpts) {
            const sections = [transcript(system, messages)];
            if (tools.length > 0)
                sections.push(toolProtocol(tools));
            sections.push('ASSISTANT:');
            const prompt = sections.join('\n\n');
            // The 120s cap below is a TIMEOUT, not a cancellation channel: it fires on
            // its own schedule and the caller's Stop signal was never wired in, so
            // pressing Stop could not interrupt a request that then kept running to
            // completion (and kept spending 1min.ai credits) for up to two minutes.
            // Bridge the two: abort our controller when the caller aborts, and tell
            // the two causes apart below.
            if (callOpts?.signal?.aborted)
                throw new Error('aborted');
            const ac = new AbortController();
            const onCallerAbort = () => ac.abort();
            callOpts?.signal?.addEventListener('abort', onCallerAbort, { once: true });
            const timer = setTimeout(() => ac.abort(), 120_000);
            let res;
            try {
                res = await fetch(`${base}/api/chat-with-ai`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json', 'API-KEY': opts.apiKey },
                    body: JSON.stringify({
                        type: 'UNIFY_CHAT_WITH_AI',
                        model: opts.model,
                        promptObject: {
                            prompt,
                            settings: {
                                webSearchSettings: {
                                    webSearch: opts.webSearch ?? false,
                                    numOfSite: 3,
                                    maxWord: 1000,
                                },
                                historySettings: { isMixed: false, historyMessageLimit: 10 },
                            },
                        },
                    }),
                    signal: ac.signal,
                });
            }
            catch (e) {
                clearTimeout(timer);
                callOpts?.signal?.removeEventListener('abort', onCallerAbort);
                if (e instanceof Error && e.name === 'AbortError') {
                    // A user-requested stop must not be reported as a timeout: the caller
                    // needs to tell "I cancelled this" apart from "the provider hung".
                    if (callOpts?.signal?.aborted)
                        throw new Error('aborted');
                    throw new Error('1min.ai request timed out (120s)');
                }
                throw new Error(`1min.ai request failed: ${e instanceof Error ? e.message : String(e)}`);
            }
            clearTimeout(timer);
            callOpts?.signal?.removeEventListener('abort', onCallerAbort);
            const raw = await res.text();
            if (!res.ok) {
                // surface the API's own error shape so the tray classifies it (401/429…)
                let detail = raw.slice(0, 300);
                try {
                    const j = JSON.parse(raw);
                    detail = j.error?.message ?? j.error?.code ?? detail;
                }
                catch {
                    /* non-JSON error body (HTML from a proxy) — keep the raw text */
                }
                throw new Error(`1min.ai API error (HTTP ${res.status}): ${detail}`);
            }
            let body;
            try {
                body = JSON.parse(raw);
            }
            catch {
                throw new Error(`1min.ai returned non-JSON: ${raw.slice(0, 200)}`);
            }
            if (body.error) {
                throw new Error(`1min.ai API error: ${body.error.message ?? body.error.code ?? 'unknown'}`);
            }
            const record = body.aiRecord;
            if (!record)
                throw new Error('1min.ai response had no aiRecord');
            if (record.status && record.status !== 'SUCCESS') {
                throw new Error(`1min.ai job status ${record.status} (credits exhausted or request rejected)`);
            }
            const answer = (record.aiRecordDetail?.resultObject ?? []).join('\n').trim();
            const call = tools.length > 0 ? parseToolCall(answer) : null;
            const content = [];
            if (call) {
                // keep any prose outside the fenced block as a leading text block
                const prose = answer.replace(/```[\s\S]*?```/g, '').trim();
                if (prose)
                    content.push({ type: 'text', text: prose });
                const block = {
                    type: 'tool_use',
                    id: `onemin-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
                    name: call.name,
                    input: call.input,
                };
                content.push(block);
                return {
                    content,
                    stop_reason: 'tool_use',
                    usage: {
                        input_tokens: record.metadata?.inputToken,
                        output_tokens: record.metadata?.outputToken,
                    },
                };
            }
            if (!answer)
                throw new Error('1min.ai returned an empty answer');
            content.push({ type: 'text', text: answer });
            return {
                content,
                stop_reason: 'end_turn',
                usage: {
                    input_tokens: record.metadata?.inputToken,
                    output_tokens: record.metadata?.outputToken,
                },
            };
        },
    };
}
return { parseToolCall,oneMinClient };
}

__mod['llm/onemin.js'] = M9();

function M10() {
function toOpenAiMessages(messages) {
    const out = [];
    for (const m of messages) {
        if (typeof m.content === 'string') {
            out.push({ role: m.role, content: m.content });
            continue;
        }
        const blocks = m.content;
        if (m.role === 'assistant') {
            const text = blocks.filter((b) => b.type === 'text').map((b) => b.text ?? '').join('\n');
            const calls = blocks.filter((b) => b.type === 'tool_use');
            const msg = { role: 'assistant', content: text || null };
            if (calls.length > 0) {
                msg.tool_calls = calls.map((b, i) => {
                    const tb = b;
                    return {
                        id: tb.id ?? `call_${i}`,
                        type: 'function',
                        function: { name: tb.name, arguments: JSON.stringify(tb.input ?? {}) },
                    };
                });
            }
            out.push(msg);
            continue;
        }
        // user turn: plain text parts + tool_result blocks (OpenAI wants role:"tool")
        const text = blocks.filter((b) => b.type === 'text').map((b) => b.text ?? '').join('\n');
        if (text)
            out.push({ role: 'user', content: text });
        for (const b of blocks) {
            if (b.type === 'tool_result') {
                let contentText = '';
                if (typeof b.content === 'string') {
                    contentText = b.content;
                }
                else if (Array.isArray(b.content)) {
                    for (const part of b.content) {
                        if (part.type === 'text')
                            contentText += (contentText ? '\n' : '') + (part.text ?? '');
                        else if (part.type === 'image')
                            contentText += (contentText ? '\n' : '') + '[image attached]';
                    }
                }
                out.push({
                    role: 'tool',
                    tool_call_id: String(b.tool_use_id ?? ''),
                    content: contentText,
                });
            }
        }
    }
    return out;
}
function toOpenAiTools(tools) {
    return tools.map((t) => ({
        type: 'function',
        function: { name: t.name, description: t.description, parameters: t.input_schema },
    }));
}
/**
 * Some gateway models emit a tool call as plain-text JSON instead of a native
 * `tool_calls` entry (same failure mode observed with small local models).
 * Recover it ONLY when: no native tool_calls exist, the text embeds a JSON
 * object whose `name` matches one of the tools actually offered in THIS
 * request, and arguments parse to an object. Prose and unknown tool names
 * are left untouched.
 */
function recoverTextToolCall(text, tools) {
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start === -1 || end <= start)
        return null;
    let parsed;
    try {
        parsed = JSON.parse(text.slice(start, end + 1));
    }
    catch {
        return null;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
        return null;
    const record = parsed;
    const name = record.name;
    if (typeof name !== 'string' || !tools.some((t) => t.name === name))
        return null;
    let args = record.arguments ?? record.parameters ?? {};
    if (typeof args === 'string') {
        try {
            args = JSON.parse(args);
        }
        catch {
            return null;
        }
    }
    if (args === null || typeof args !== 'object' || Array.isArray(args))
        return null;
    const rest = (text.slice(0, start) + text.slice(end + 1)).trim();
    const content = [];
    if (rest)
        content.push({ type: 'text', text: rest });
    content.push({
        type: 'tool_use',
        id: `openai_tc_recovered_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        name,
        input: args,
    });
    return content;
}
/**
 * Map Anthropic-style image blocks to OpenAI data-URL parts. Chat Completions
 * only accepts image parts on user messages, so images arriving inside
 * tool_result blocks are re-emitted as a follow-up user message (the standard
 * workaround; vision-capable models like minimax-m3-free will see them).
 */
function collectImageParts(blocks) {
    const parts = [];
    for (const b of blocks) {
        if (b.type !== 'image')
            continue;
        const src = b.source;
        if (src?.data) {
            parts.push({
                type: 'image_url',
                image_url: { url: `data:${src.media_type ?? 'image/png'};base64,${src.data}` },
            });
        }
    }
    return parts;
}
function openaiClient(opts) {
    const base = (opts.baseUrl ?? 'https://api.openai.com/v1').replace(/\/+$/, '');
    return {
        name: opts.name ?? 'openai',
        model: opts.model,
        async call(system, messages, tools, callOpts) {
            const body = {
                model: opts.model,
                max_tokens: opts.maxTokens ?? 8192,
                messages: [{ role: 'system', content: system }, ...toOpenAiMessages(messages)],
                stream: false,
            };
            // Only send tool fields when tools exist — some gateways reject
            // tool_choice on plain chat requests.
            if (tools.length > 0) {
                body.tools = toOpenAiTools(tools);
                body.tool_choice = 'auto';
            }
            const res = await fetch(`${base}/chat/completions`, {
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    // Keyless free gateways (Kilo, OVHcloud) reject a bogus token with
                    // 401 rather than ignoring it, so omit the header entirely when no
                    // key is configured instead of sending an empty/placeholder one.
                    ...(opts.apiKey ? { authorization: `Bearer ${opts.apiKey}` } : {}),
                    ...(opts.attribution?.siteUrl ? { 'HTTP-Referer': opts.attribution.siteUrl } : {}),
                    ...(opts.attribution?.siteName ? { 'X-Title': opts.attribution.siteName } : {}),
                },
                body: JSON.stringify(body),
                // Stop button: cancelling the request here is what actually halts the
                // token spend, instead of waiting for this turn to finish.
                signal: callOpts?.signal,
            });
            const data = (await res.json());
            const errMsg = typeof data.error === 'string' ? data.error : data.error?.message;
            if (!res.ok || errMsg) {
                throw new Error(`OpenAI-protocol error (HTTP ${res.status}): ${errMsg ?? 'request failed'}`);
            }
            const msg = data.choices?.[0]?.message ?? { role: 'assistant', content: null };
            // Same recovery path as the other adapters: gateway models sometimes
            // print the tool call as text JSON instead of native tool_calls.
            const recovered = (!msg.tool_calls || msg.tool_calls.length === 0) && msg.content
                ? recoverTextToolCall(msg.content, tools)
                : null;
            const content = [];
            if (recovered)
                content.push(...recovered);
            else if (msg.content)
                content.push({ type: 'text', text: msg.content });
            const calls = msg.tool_calls ?? [];
            for (let i = 0; i < calls.length; i++) {
                const tc = calls[i];
                let input = {};
                try {
                    input = JSON.parse(tc.function.arguments || '{}');
                }
                catch {
                    input = {};
                }
                content.push({
                    type: 'tool_use',
                    id: tc.id || `openai_tc_${i}`,
                    name: tc.function.name,
                    input: input,
                });
            }
            if (content.length === 0)
                content.push({ type: 'text', text: '(empty response from model)' });
            return {
                content,
                stop_reason: content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn',
                usage: {
                    input_tokens: data.usage?.prompt_tokens,
                    output_tokens: data.usage?.completion_tokens,
                },
            };
        },
    };
}
return { openaiClient };
}

__mod['llm/openai.js'] = M10();

function M11() {
/**
 * Route health registry — the UI remodel's route-status-tray backend.
 *
 * The router records every success/failure per route name; /api/health reads
 * the aggregated states and the UI paints a box per route:
 *   ok      → GREEN  (the route currently answering)
 *   degraded→ RED    (quota-out / 429 / upstream overloaded — recovers on its own)
 *   down    → YELLOW (needs our attention: bad key 401/403, unreachable, 404 model)
 * Unknown routes start as 'unknown' until the first call.
 */
const registry = new Map();
// Several routes share a provider name (e.g. openai×5 with different models
// behind different gateways) — key on name+model so the tray shows all of them.
function keyOf(name, model) {
    return `${name}::${model ?? ''}`;
}
/** Classify a router failure message into a tray state. */
function classifyRouteFailure(message) {
    const msg = message.replace(/\s+/g, ' ').trim();
    if (/429|quota|rate.?limit|overloaded|temporarily|billing|credit/i.test(msg)) {
        return { state: 'degraded', detail: msg.slice(0, 160) };
    }
    if (/40[134]|unauthorized|forbidden|invalid.*(key|token)|auth|not found|no such model/i.test(msg)) {
        return { state: 'down', detail: msg.slice(0, 160) };
    }
    if (/fetch failed|timeout|ECONN|ENOTFOUND|refused|network/i.test(msg)) {
        return { state: 'down', detail: msg.slice(0, 160) };
    }
    return { state: 'degraded', detail: msg.slice(0, 160) };
}
function recordRouteSuccess(name, model) {
    registry.set(keyOf(name, model), {
        name,
        model: model ?? '',
        state: 'ok',
        detail: model ? `answering · model ${model}` : 'answering',
        lastChange: Date.now(),
    });
}
function recordRouteFailure(name, message, model) {
    const { state, detail } = classifyRouteFailure(message);
    registry.set(keyOf(name, model), { name, model: model ?? '', state, detail, lastChange: Date.now() });
}
/** Register a route that has never been called yet (so the tray shows it). */
function registerRoute(name, model) {
    const k = keyOf(name, model);
    if (!registry.has(k)) {
        registry.set(k, {
            name,
            model: model ?? '',
            state: 'unknown',
            detail: model ? `model ${model}` : 'no calls yet',
            lastChange: Date.now(),
        });
    }
}
/**
 * How long a 'down' verdict stays actionable for the router's skip list.
 * Long enough to survive a burst of turns, short enough that a gateway which
 * comes back is retried without anyone restarting the app.
 */
const DOWN_FRESH_MS = 5 * 60_000;
/**
 * True when the router may skip this route without spending a round trip on it.
 *
 * Only a FRESH 'down' record qualifies. 'unknown' (never called), 'degraded'
 * (quota/429 — it recovers on its own) and a 'down' verdict that has gone stale
 * are all still worth trying: skipping on anything weaker trades a few seconds
 * for silently routing around a route that would have answered.
 */
function routeIsKnownDown(name, model) {
    const r = registry.get(keyOf(name, model));
    if (!r || r.state !== 'down')
        return false;
    return Date.now() - r.lastChange < DOWN_FRESH_MS;
}
/** Snapshot for /api/health — insertion order preserved (matches router order). */
function getRouteStates() {
    return [...registry.values()].map((r) => ({ name: r.name, model: r.model, state: r.state, detail: r.detail }));
}
/** Test helper: clear the registry. */
function resetRouteHealth() {
    registry.clear();
}
/**
 * Classify a BACKGROUND PROBE result.
 *
 * Separate from classifyRouteFailure because a probe is weaker evidence in both
 * directions:
 *   - 404/405 from GET <base>/models means the gateway hides /models
 *     (OmniRoute, Cloudflare). That says NOTHING about whether the route works,
 *     so it must stay 'unknown'. Classifying it 'down' painted a yellow "needs
 *     attention" box on a route that was answering fine.
 *   - a missing key is a config gap we can state outright, so it reads as 'down'
 *     with the env var named rather than degrading into a vague message.
 */
function classifyRouteProbe(detail) {
    const msg = detail.replace(/\s+/g, ' ').trim();
    if (/missing api key|no api key|not set|unset/i.test(msg))
        return { state: 'down', detail: msg.slice(0, 160) };
    if (/^HTTP 40[45]\b/.test(msg)) {
        return { state: 'unknown', detail: `${msg} · gateway hides /models — unknown, not broken` };
    }
    return classifyRouteFailure(msg);
}
/**
 * Apply a probe result to a route.
 *
 * Separate from recordRouteSuccess/Failure because a background probe is a
 * different kind of evidence: it must never overwrite what a REAL user call
 * established. If the primary route answered a request 2 seconds ago, a probe
 * that times out says something about the probe, not about the route. An
 * INCONCLUSIVE probe ('unknown') is likewise not allowed to erase a state a real
 * call proved.
 */
function recordRouteProbe(name, ok, detail, model) {
    const k = keyOf(name, model);
    const prev = registry.get(k);
    // A real call is stronger evidence than a probe — keep it.
    if (prev && prev.state !== 'unknown' && prev.detail.startsWith('answering'))
        return;
    const { state, detail: classified } = ok ? { state: 'ok', detail } : classifyRouteProbe(detail);
    if (state === 'unknown' && prev && prev.state !== 'unknown')
        return;
    registry.set(k, {
        name,
        model: model ?? prev?.model ?? '',
        state,
        detail: classified.slice(0, 160),
        lastChange: Date.now(),
    });
}
/**
 * The (name, model) pairs a composed client represents, in the SAME pairing
 * startWebUi() registers with registerRoute().
 *
 * This is what stops the tray growing two rows per route: the prober used to
 * re-derive the model from BLACKROSE_<NAME>_MODEL ?? '' while registerRoute used
 * the router's real model, so one route produced two differently-keyed entries.
 * One derivation, used by both, cannot drift.
 */
function routeEntriesFromClient(name, model) {
    const m = /^router\((.+)\)$/.exec(name);
    if (!m)
        return [{ name, model }];
    const models = model.split(' → ');
    return m[1].split('→').map((n, i) => ({ name: n.trim(), model: (models[i] ?? '').trim() }));
}
return { classifyRouteFailure,recordRouteSuccess,recordRouteFailure,registerRoute,routeIsKnownDown,getRouteStates,resetRouteHealth,classifyRouteProbe,recordRouteProbe,routeEntriesFromClient };
}

__mod['llm/routeHealth.js'] = M11();

function M12() {
/**
 * Per-key health for multi-key rotation (B26).
 *
 * A provider can hold several keys. Which failure means "try the next key" and
 * which means "stop using this key" is the whole problem, so it is modelled here
 * once and tested directly:
 *
 *   ok      → healthy, use it.
 *   quota   → this key is rate-limited or out of credit (429 / quota / credit).
 *             Transient: cool down briefly, then eligible again. Try the next
 *             key NOW so one exhausted key does not fail the turn.
 *   parked  → this key is rejected (401 / 403 / invalid token). Permanent until
 *             a human changes it: a long cooldown, and it is never tried while
 *             parked. This is what stops a bad key from burning a request on
 *             every single turn.
 *   down    → the PROVIDER failed (network, 5xx), not the key. Do not blame or
 *             park any key; the provider is unavailable.
 *
 * State is in-memory only: it is a per-process health cache, not identity, and
 * must never be synced between machines (same rule as the undo journal).
 */
/** Cooldowns. Quota recovers on its own; a rejected key does not. */
const QUOTA_COOLDOWN_MS = 60_000;
const PARK_COOLDOWN_MS = 30 * 60_000;
const DOWN_COOLDOWN_MS = 15_000;
const registry = new Map();
/** Stable, non-secret identifier for a key: its masked preview + position. */
function keyId(envVar, index, masked) {
    return `${envVar}#${index} (${masked || 'empty'})`;
}
/**
 * Classify a failure into a key state. Deliberately separate from
 * `classifyRouteFailure` (which is about ROUTES for the tray): that one answers
 * "should the router move to the next provider", this one answers "what should
 * happen to THIS key".
 */
function classifyKeyFailure(message) {
    const msg = message.replace(/\s+/g, ' ').trim();
    // Permanent rejections first: 401/403 must never be treated as transient,
    // even if the text also mentions a limit.
    //
    // 413 is deliberately NOT here even though it looks like a 4xx. 413 is
    // "payload too large": it says something about ONE oversized request, not
    // about the credential, which is still perfectly valid. Parking the key for
    // 30 minutes because one message happened to be long would take a working
    // provider offline over a sentence length, so it falls through to 'quota'
    // (transient) and the next key is tried.
    if (/\b401\b|\b403\b|unauthorized|forbidden|invalid.*(key|token|auth)|authentication|token is invalid/i.test(msg)) {
        return 'parked';
    }
    if (/429|quota|rate.?limit|overloaded|billing|credit|insufficient/i.test(msg))
        return 'quota';
    if (/HTTP 5\d\d|fetch failed|timeout|ECONN|ENOTFOUND|refused|network|socket/i.test(msg))
        return 'down';
    // Unknown: treat as transient-quota rather than parking, so a new error shape
    // does not permanently disable a key. Parking on a guess is unrecoverable;
    // a wasted attempt is not.
    return 'quota';
}
function cooldownFor(state) {
    if (state === 'parked')
        return PARK_COOLDOWN_MS;
    if (state === 'down')
        return DOWN_COOLDOWN_MS;
    return QUOTA_COOLDOWN_MS;
}
function recordKeySuccess(id) {
    registry.set(id, { state: 'ok', until: 0, detail: 'answering', lastChange: Date.now() });
}
function recordKeyFailure(id, message) {
    const state = classifyKeyFailure(message);
    registry.set(id, {
        state,
        until: Date.now() + cooldownFor(state),
        detail: message.replace(/\s+/g, ' ').trim().slice(0, 160),
        lastChange: Date.now(),
    });
    return state;
}
/** True when the key may be used right now. */
function keyUsable(id) {
    const rec = registry.get(id);
    if (!rec)
        return true;
    if (rec.state === 'ok')
        return true;
    if (rec.until === 0)
        return true;
    return Date.now() >= rec.until;
}
/** True when a key is parked and still cooling down (for the UI). */
function isKeyParked(id) {
    const rec = registry.get(id);
    return !!rec && rec.state === 'parked' && Date.now() < rec.until;
}
/** Snapshot for the UI: masked id + state + remaining cooldown. Never a secret. */
function keyHealthSnapshot() {
    const now = Date.now();
    return [...registry.entries()].map(([id, r]) => ({
        id,
        state: r.state,
        detail: r.detail,
        cooldownMs: r.state === 'ok' || r.until <= now ? 0 : r.until - now,
        usable: r.state === 'ok' || r.until <= now,
    }));
}
/** Test seam. */
function resetKeyHealth() {
    registry.clear();
}
return { keyId,classifyKeyFailure,recordKeySuccess,recordKeyFailure,keyUsable,isKeyParked,keyHealthSnapshot,resetKeyHealth };
}

__mod['llm/keyHealth.js'] = M12();

function M13() {
const { recordRouteFailure, recordRouteSuccess, routeIsKnownDown } = __mod['llm/routeHealth.js'];
const { keyId, keyUsable, recordKeyFailure, recordKeySuccess } = __mod['llm/keyHealth.js'];
const { maskSecret } = __mod['core/keys.js'];
/**
 * Model router: tries routes in order; on failure falls back to the next.
 * This is the "brain engine is swappable" layer — API routes in order.
 * Every success/failure is recorded in the route-health registry so the UI
 * can paint a live status box per route (green/red/yellow tray).
 *
 * MULTI-KEY (B26): a route may hold several keys for the same gateway. Key
 * rotation is tried BEFORE the router gives up on a provider, so one
 * rate-limited or out-of-credit key does not cost the turn. A rejected key
 * (401/403) is parked by keyHealth and not retried while parked, so a dead
 * key cannot burn a request on every turn.
 */
function routerClient(routes, onNotice) {
    if (routes.length === 0)
        throw new Error('routerClient requires at least one route');
    return {
        name: `router(${routes.map((r) => r.name).join('→')})`,
        model: routes.map((r) => r.model).join(' → '),
        async call(system, messages, tools, callOpts) {
            const errors = [];
            // Skip routes we already KNOW are down, so a dead gateway does not cost a
            // full round trip (or a timeout) on every single turn. Deliberately
            // conservative: routeIsKnownDown only returns true for a FRESH 'down'
            // verdict, and the skip is abandoned entirely if it would leave no route
            // at all — there must always be something to try.
            const skipped = new Set();
            if (routes.length > 1) {
                routes.forEach((r, i) => {
                    if (routeIsKnownDown(r.name, r.model))
                        skipped.add(i);
                });
            }
            const candidates = routes.filter((_, i) => !skipped.has(i));
            for (const route of candidates.length > 0 ? candidates : routes) {
                try {
                    // Forward the signal: without this the Stop button would be ignored
                    // in the default (router) path, since every route sits behind here.
                    const res = await route.call(system, messages, tools, callOpts);
                    recordRouteSuccess(route.name, route.model);
                    return res;
                }
                catch (e) {
                    const msg = e instanceof Error ? e.message : String(e);
                    errors.push(`${route.name}: ${msg}`);
                    recordRouteFailure(route.name, msg, route.model);
                    onNotice?.(`route "${route.name}" failed → falling back (${msg.slice(0, 140)})`);
                }
            }
            throw new Error(`All model routes failed:\n${errors.join('\n')}`);
        },
    };
}
/**
 * A route that holds N keys for one gateway. Each key gets its own inner
 * client; on failure the key is classified (keyHealth) and the next usable key
 * is tried before the error is propagated to the router.
 *
 * Order of preference each call:
 *   1. keys that are not parked/cooling down, starting from the last one that
 *      succeeded (spreads load and keeps a recovered key in play);
 *   2. if every key is cooling down, the one whose cooldown expires soonest —
 *      better than failing the turn outright.
 */
function rotatingKeyClient(opts) {
    const clients = opts.keys.map((apiKey, index) => ({
        index,
        apiKey,
        id: keyId(opts.envVar, index, maskSecret(apiKey)),
        client: opts.make(apiKey),
    }));
    // index of the last key that answered; -1 means "start at the top"
    let cursor = -1;
    if (clients.length === 0) {
        throw new Error(`${opts.name} has no usable API key (${opts.envVar})`);
    }
    return {
        name: clients.length > 1 ? `${opts.name}[${clients.length} keys]` : opts.name,
        model: opts.model,
        async call(system, messages, tools, callOpts) {
            // Start at the key that last answered. Advancing the cursor PAST the
            // winner (an earlier "rotate every call" approach) made a parked key the
            // first candidate on every subsequent call — a wasted round trip on a key
            // known to be dead. Staying on the winner is also what a healthy key
            // deserves: nothing to gain by hopping when the current one is fine.
            const order = [];
            const start = cursor >= 0 ? cursor : 0;
            for (let step = 0; step < clients.length; step++) {
                order.push((start + step) % clients.length);
            }
            // Drop keys that are parked/cooling down; only if EVERY key is
            // unusable do we fall back to trying them anyway rather than failing.
            const usable = order.filter((i) => keyUsable(clients[i].id));
            const candidates = usable.length > 0 ? usable : order;
            const errors = [];
            for (const i of candidates) {
                const entry = clients[i];
                try {
                    const res = await entry.client.call(system, messages, tools, callOpts);
                    recordKeySuccess(entry.id);
                    cursor = i;
                    return res;
                }
                catch (e) {
                    const msg = e instanceof Error ? e.message : String(e);
                    const state = recordKeyFailure(entry.id, msg);
                    errors.push(`key#${entry.index} (${maskSecret(entry.apiKey)}): ${msg}`);
                    opts.onNotice?.(state === 'parked'
                        ? `key ${maskSecret(entry.apiKey)} rejected → parked, not retried`
                        : `key ${maskSecret(entry.apiKey)} ${state} → next key`);
                }
            }
            throw new Error(`All ${clients.length} key(s) for ${opts.name} failed:\n${errors.join('\n')}`);
        },
    };
}
return { routerClient,rotatingKeyClient };
}

__mod['llm/router.js'] = M13();

function M14() {
const { anthropicClient } = __mod['llm/client.js'];
const { geminiClient } = __mod['llm/gemini.js'];
const { oneMinClient } = __mod['llm/onemin.js'];
const { openaiClient } = __mod['llm/openai.js'];
const { rotatingKeyClient, routerClient } = __mod['llm/router.js'];
const { readProviderKeys } = __mod['core/keys.js'];
const { readProviders, providerKeyEnvVar, readRouteChain } = __mod['core/providers.js'];
/**
 * Builds the LLM client from configuration. API-only since 2026-09-29 (B25):
 * there is no local engine.
 *   BLACKROSE_PROVIDER=anthropic  → cloud (needs ANTHROPIC_API_KEY)
 *   BLACKROSE_PROVIDER=openai     → OpenAI Chat-Completions gateway (default:
 *                                    OpenRouter free models; needs BLACKROSE_OPENAI_API_KEY)
 *   BLACKROSE_PROVIDER=router     → fallback chain, e.g.
 *                                    BLACKROSE_ROUTES="openai,openai1,gemini"
 *
 * The "openai" provider speaks to ANY OpenAI-protocol gateway (OpenRouter,
 * Groq, OpenAI, DeepSeek, Mistral, xAI, KiraAI, Gemini-compat, vLLM…).
 * Numbered variants "openai1"…"openai9" let several gateways coexist in one
 * router chain:
 *   BLACKROSE_OPENAI_API_KEY / _MODEL / _BASE_URL        (route "openai")
 *   BLACKROSE_OPENAI1_API_KEY / _MODEL / _BASE_URL       (route "openai1") …
 */
const OPENAI_NAME_RE = /^openai\d*$/;
const DEFAULT_OPENAI_BASE = 'https://openrouter.ai/api/v1';
const DEFAULT_OPENAI_MODEL = 'nvidia/nemotron-3-super-120b-a12b:free';
/**
 * Routes that need NO API key. These exist so the chain can end in something
 * that cannot be billed, cannot hit a credit limit, and cannot be rate-limited
 * by an exhausted account — the failure mode B26's key rotation cannot fix.
 * Verified live 2026-09-29: Kilo Code answers HTTP 200 with native tool_calls
 * and no credential of any kind.
 */
const KEYLESS_ROUTES = {
    kilo: {
        baseUrl: 'https://api.kilo.ai/api/gateway',
        model: 'kilo-auto/free',
        note: 'free pool auto-router, 200 req/hr, no key or signup',
    },
    ovh: {
        baseUrl: 'https://oai.endpoints.kepler.ai.cloud.ovh.net/v1',
        model: 'gpt-oss-20b',
        note: 'anonymous, 2 RPM per IP — emergency fallback only',
    },
};
/** Route names that need no API key (see KEYLESS_ROUTES). */
const KEYLESS_ROUTE_NAMES = Object.keys(KEYLESS_ROUTES);
function routeProbeTarget(name, dataDir) {
    // rotatingKeyClient renames a multi-key route to "openai1[3 keys]" for the
    // tray, but the environment is still keyed by the bare route name.
    const bare = name.replace(/\s*\[\d+ keys\]$/, '');
    const up = bare.toUpperCase();
    if (OPENAI_NAME_RE.test(bare)) {
        const env = openAiEnv(bare);
        const keyEnvVar = openAiEnvVar(bare);
        const keys = readProviderKeys(dataDir, keyEnvVar);
        return {
            name,
            baseUrl: env.baseUrl.replace(/\/+$/, ''),
            model: env.model,
            apiKey: keys[0] ?? env.apiKey ?? '',
            needsKey: true,
            keyEnvVar,
        };
    }
    if (bare in KEYLESS_ROUTES) {
        const spec = KEYLESS_ROUTES[bare];
        return {
            name,
            baseUrl: (process.env[`BLACKROSE_${up}_BASE_URL`] ?? spec.baseUrl).replace(/\/+$/, ''),
            model: process.env[`BLACKROSE_${up}_MODEL`] ?? spec.model,
            apiKey: '',
            needsKey: false,
            keyEnvVar: '',
        };
    }
    const custom = readProviders(dataDir).find((p) => p.name === bare);
    if (custom) {
        const keyEnvVar = providerKeyEnvVar(custom.name);
        return {
            name,
            baseUrl: custom.baseUrl.replace(/\/+$/, ''),
            model: custom.model,
            apiKey: custom.needsKey ? readProviderKeys(dataDir, keyEnvVar)[0] ?? '' : '',
            needsKey: custom.needsKey,
            keyEnvVar,
        };
    }
    // anthropic / gemini / onemin have no OpenAI-compatible /models surface, so
    // there is nothing this probe could honestly ask them.
    return null;
}
function openAiEnv(name) {
    const up = name.toUpperCase();
    return {
        apiKey: name === 'openai'
            ? (process.env.BLACKROSE_OPENAI_API_KEY ?? process.env.OPENAI_API_KEY)
            : process.env[`BLACKROSE_${up}_API_KEY`],
        model: process.env[`BLACKROSE_${up}_MODEL`] ?? DEFAULT_OPENAI_MODEL,
        baseUrl: process.env[`BLACKROSE_${up}_BASE_URL`] ?? DEFAULT_OPENAI_BASE,
    };
}
function openAiEnvVar(name) {
    return `BLACKROSE_${name.toUpperCase()}_API_KEY`;
}
function buildOpenAiClient(name, env) {
    // Attribution headers are an OpenRouter concept (app rankings); send them
    // only there — other gateways get a plain X-Title only.
    const isOpenRouter = /openrouter\.ai/.test(env.baseUrl);
    return openaiClient({
        name,
        apiKey: env.apiKey,
        model: env.model,
        baseUrl: env.baseUrl,
        attribution: {
            siteUrl: process.env.BLACKROSE_OPENAI_SITE_URL ?? (isOpenRouter ? 'http://localhost:8788' : undefined),
            siteName: process.env.BLACKROSE_OPENAI_SITE_NAME ?? 'BlackRose',
        },
    });
}
function openAiRoute(name, dataDir) {
    const env = openAiEnv(name);
    const envVar = openAiEnvVar(name);
    // Every key this provider holds: the env primary plus any additional keys
    // sealed in the vault. With one key this is exactly the old behaviour.
    const keys = readProviderKeys(dataDir, envVar);
    if (keys.length === 0) {
        throw new Error(`${name} route requires ${envVar}` + (name === 'openai' ? ' (or OPENAI_API_KEY)' : ''));
    }
    if (keys.length === 1)
        return buildOpenAiClient(name, { ...env, apiKey: keys[0] });
    return rotatingKeyClient({
        name,
        model: env.model,
        envVar,
        keys,
        make: (apiKey) => buildOpenAiClient(name, { ...env, apiKey }),
    });
}
/** Keyless OpenAI-compatible route — no credential, and no auth header either. */
function keylessRoute(name) {
    const spec = KEYLESS_ROUTES[name];
    const base = (process.env[`BLACKROSE_${name.toUpperCase()}_BASE_URL`] ?? spec.baseUrl).replace(/\/+$/, '');
    const model = process.env[`BLACKROSE_${name.toUpperCase()}_MODEL`] ?? spec.model;
    // '' (not a placeholder) — these gateways 401 on a bogus bearer token.
    return openaiClient({ name, apiKey: '', model, baseUrl: base });
}
function singleProvider(name, config) {
    if (name === 'anthropic') {
        if (!config.apiKey)
            throw new Error('anthropic route requires ANTHROPIC_API_KEY (or BLACKROSE_API_KEY)');
        return anthropicClient({ apiKey: config.apiKey, model: config.model, baseUrl: config.baseUrl });
    }
    if (name === 'gemini') {
        // Gemini joins multi-key rotation (B26). It was the ONLY built-in provider
        // still reading a single key straight from the environment, while the vault,
        // the `<envVar>__KEYS` extras store, the key roster and the UI already
        // supported several — routespecs.ts has always listed
        // BLACKROSE_GEMINI_API_KEY. So the storage layer could hold twelve keys and
        // this branch would have used one of them.
        //
        // That matters most for embeddings: the free tier is 1000 embed requests
        // per DAY (memory/embedder.ts), so a single key silently degrades semantic
        // search to lexical for the rest of the day. Rotation turns that ceiling
        // from 1 key into N keys.
        const envVar = 'BLACKROSE_GEMINI_API_KEY';
        const stored = readProviderKeys(config.dataDir, envVar);
        // GOOGLE_AI_API_KEY stays supported as a fallback, but only as a SINGLE
        // fallback key: readProviderKeys is vault-shaped, and treating an unrelated
        // ambient variable as a rotating set would be inventing a second store.
        const keys = stored.length > 0 ? stored : [process.env.GOOGLE_AI_API_KEY ?? ''].filter(Boolean);
        if (keys.length === 0) {
            throw new Error(`gemini route requires ${envVar} (or GOOGLE_AI_API_KEY); add extra keys in Settings to rotate`);
        }
        const model = process.env.BLACKROSE_GEMINI_MODEL ?? 'gemini-2.5-flash';
        const baseUrl = process.env.BLACKROSE_GEMINI_BASE_URL;
        const maxOutputTokens = Number(process.env.BLACKROSE_GEMINI_MAX_TOKENS) || undefined;
        return rotatingKeyClient({
            name: 'gemini',
            model,
            envVar,
            keys,
            make: (apiKey) => geminiClient({ apiKey, model, baseUrl, maxOutputTokens }),
        });
    }
    if (name === 'onemin' || name === '1min') {
        // 1min.ai: proprietary chat API (no OpenAI-compatible surface) — see
        // llm/onemin.ts. Text tool protocol, single flattened prompt.
        const apiKey = process.env.BLACKROSE_ONEMIN_API_KEY;
        if (!apiKey)
            throw new Error('onemin route requires BLACKROSE_ONEMIN_API_KEY');
        return oneMinClient({
            apiKey,
            model: process.env.BLACKROSE_ONEMIN_MODEL ?? 'gpt-4o-mini',
            baseUrl: process.env.BLACKROSE_ONEMIN_BASE_URL,
            webSearch: process.env.BLACKROSE_ONEMIN_WEB_SEARCH === 'true',
        });
    }
    // Order note (checked 2026-10-01): a custom provider CAN be named "openai7",
    // which matches OPENAI_NAME_RE, and this check runs before the registry lookup
    // below. That looked like it would silently shadow the custom provider, but it
    // does not — addProvider()/applyProviders() mirror every registry entry into
    // BLACKROSE_<NAME>_BASE_URL / _MODEL, and openAiEnv() reads exactly those, so
    // the built-in branch resolves to the custom entry's URL and model anyway.
    //
    // This is load-bearing but non-obvious, so it is pinned by a regression test
    // rather than left to a future reader to rediscover. If the registry ever
    // stops mirroring into the environment, this branch must move below the
    // registry lookup.
    if (OPENAI_NAME_RE.test(name))
        return openAiRoute(name, config.dataDir);
    if (name in KEYLESS_ROUTES)
        return keylessRoute(name);
    // A provider added from the UI (B27). Treated as OpenAI-compatible unless it
    // was registered as keyless, in which case no Authorization header is sent —
    // some gateways 401 on a placeholder bearer token, so "no key" must mean
    // genuinely no header.
    const custom = readProviders(config.dataDir).find((p) => p.name === name);
    if (custom) {
        const env = { apiKey: '', model: custom.model, baseUrl: custom.baseUrl };
        if (!custom.needsKey)
            return buildOpenAiClient(custom.name, env);
        const keys = readProviderKeys(config.dataDir, providerKeyEnvVar(custom.name));
        if (keys.length === 0) {
            throw new Error(`${custom.name} needs a key — add one in Settings → API keys`);
        }
        if (keys.length === 1)
            return buildOpenAiClient(custom.name, { ...env, apiKey: keys[0] });
        return rotatingKeyClient({
            name: custom.name,
            model: custom.model,
            envVar: providerKeyEnvVar(custom.name),
            keys,
            make: (apiKey) => buildOpenAiClient(custom.name, { ...env, apiKey }),
        });
    }
    throw new Error(`Unknown provider "${name}". Supported: anthropic, openai (plus numbered openai1…openai9 gateways), gemini, onemin, the keyless routes ${Object.keys(KEYLESS_ROUTES).join(', ')}, and any provider added in Settings; or "router" with BLACKROSE_ROUTES.`);
}
function makeClient(config) {
    if (config.provider === 'mock') {
        throw new Error('mock provider is only for tests (npm test)');
    }
    if (config.provider === 'router') {
        // The chain now comes from readRouteChain(), not straight from the env var.
        // That prefers BLACKROSE_ROUTES when it is set (unchanged behaviour for a
        // scripted launch) but otherwise uses the chain sealed in the vault, which
        // is what the Connected-routes panel writes. Reading the env var directly
        // here is what made the panel's chain editor a no-op.
        const chain = readRouteChain(config.dataDir);
        const names = chain.routes;
        // writeRouteChain already published the stored chain into the environment
        // and marked it as ours. No extra assignment here: a second, unmarked write
        // is exactly what readRouteChain() would mistake for a user env var and use
        // to lock the UI read-only.
        // Fail SOFT per route. One bad entry (a name that no longer exists, a
        // missing key) used to throw out of makeClient and stop the whole app from
        // starting - e.g. a leftover "ollama" in BLACKROSE_ROUTES after the API-only
        // cutover. A stale route name should cost you that route, not the app.
        const routes = [];
        const skipped = [];
        for (const n of names) {
            try {
                routes.push(singleProvider(n, config));
            }
            catch (e) {
                const why = e instanceof Error ? e.message : String(e);
                skipped.push(n);
                console.warn(`  ↪ route "${n}" unavailable, skipped: ${why.split('\n')[0].slice(0, 140)}`);
            }
        }
        if (routes.length === 0) {
            throw new Error(`No usable route in BLACKROSE_ROUTES (${names.join(', ')}). ` +
                `Every one was skipped: ${skipped.length ? 'see warnings above' : 'none listed'}. ` +
                `Set a route that has a key, e.g. BLACKROSE_ROUTES=openai2,gemini.`);
        }
        if (skipped.length > 0) {
            console.log(`  ↪ ${routes.length} of ${names.length} route(s) active (skipped: ${skipped.join(', ')})`);
        }
        return routerClient(routes, (m) => console.log(`  ↪ ${m}`));
    }
    return singleProvider(config.provider, config);
}
return { KEYLESS_ROUTES,KEYLESS_ROUTE_NAMES,routeProbeTarget,makeClient };
}

__mod['llm/factory.js'] = M14();

function M15() {
const STATUSES = ['active', 'blocked', 'paused', 'done', 'dropped'];
function goalsDir(dataDir) {
    return path.join(dataDir, 'goals');
}
function newId(prefix) {
    return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}
function readAll(dataDir, prefix) {
    const dir = goalsDir(dataDir);
    if (!fs.existsSync(dir))
        return [];
    const out = [];
    for (const f of fs.readdirSync(dir)) {
        if (!f.startsWith(prefix) || !f.endsWith('.json'))
            continue;
        try {
            out.push(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
        }
        catch {
            // A corrupt record must not take the whole brain offline — knowledge.ts
            // learned this the same way with malformed chunk files. Skip it.
        }
    }
    return out;
}
function writeOne(dataDir, prefix, rec) {
    const dir = goalsDir(dataDir);
    fs.mkdirSync(dir, { recursive: true });
    // An id reaches a filesystem path, so it must be an id and nothing else.
    // `path.join` resolves `..`, so an id of '../../evil' would write OUTSIDE the
    // goals directory. Ids are generated internally as `<prefix>_<base36>_<rand>`,
    // so anything containing a separator or a dot-segment is not one of ours —
    // refuse rather than normalise, so a bad id can never reach disk at all.
    if (!/^[A-Za-z0-9_-]+$/.test(rec.id)) {
        throw new Error(`refusing to write a goal with a non-conforming id: ${String(rec.id).slice(0, 40)}`);
    }
    const target = path.join(dir, `${prefix}_${rec.id}.json`);
    // Belt and braces: even with a clean id, confirm the result stayed inside.
    if (path.dirname(path.resolve(target)) !== path.resolve(dir)) {
        throw new Error('refusing to write a goal outside the goals directory');
    }
    fs.writeFileSync(target, JSON.stringify(rec, null, 2), 'utf8');
}
function loadGoals(dataDir) {
    const goals = readAll(dataDir, 'goal_');
    // Stable order: priority first, then soonest deadline, then newest. This is
    // the order the user actually cares about, and both the tool output and the
    // system-prompt briefing use it, so "what's next" looks the same everywhere.
    return goals.sort((a, b) => a.priority - b.priority || deadlineSort(a, b));
}
function deadlineSort(a, b) {
    if (a.deadline && b.deadline)
        return a.deadline.localeCompare(b.deadline);
    if (a.deadline)
        return -1;
    if (b.deadline)
        return 1;
    return b.created.localeCompare(a.created);
}
function loadDecisions(dataDir) {
    return readAll(dataDir, 'decision_').sort((a, b) => b.madeAt.localeCompare(a.madeAt));
}
function getGoal(dataDir, id) {
    return loadGoals(dataDir).find((g) => g.id === id || g.id.endsWith(`_${id}`));
}
function saveGoal(dataDir, g) {
    writeOne(dataDir, 'goal', g);
}
function removeGoal(dataDir, id) {
    return removeOne(dataDir, 'goal', id);
}
function saveDecision(dataDir, d) {
    writeOne(dataDir, 'decision', d);
}
function removeDecision(dataDir, id) {
    return removeOne(dataDir, 'decision', id);
}
function removeOne(dataDir, prefix, id) {
    const dir = goalsDir(dataDir);
    if (!fs.existsSync(dir))
        return false;
    // Tolerate a short id the user typed, matching getGoal's suffix lookup.
    const hit = fs.readdirSync(dir).find((f) => f === `${prefix}_${id}.json` || f.startsWith(`${prefix}_${id}_`));
    if (!hit)
        return false;
    fs.unlinkSync(path.join(dir, hit));
    return true;
}
/** A goal due within `days`, overdue, or blocked — the things that need a person. */
function needsAttention(dataDir, now = new Date()) {
    return loadGoals(dataDir).filter((g) => {
        if (g.status === 'blocked')
            return true;
        if (g.status !== 'active')
            return false;
        if (!g.deadline)
            return false;
        const due = Date.parse(g.deadline);
        return Number.isFinite(due) && due - now.getTime() <= 7 * 86_400_000;
    });
}
/** Active goals untouched for `staleDays` — unfinished work the user forgot about. */
function staleGoals(dataDir, now = new Date(), staleDays = 14) {
    const cutoff = now.getTime() - staleDays * 86_400_000;
    return loadGoals(dataDir).filter((g) => g.status === 'active' && Date.parse(g.updated) < cutoff);
}
function makeId(prefix) {
    return newId(prefix);
}
function isStatus(v) {
    return STATUSES.includes(v);
}
/**
 * The briefing — the actual "awareness" half of the Executive Brain.
 *
 * CRUD over goals would only be a to-do list. What makes this an operating
 * layer is that the agent knows its own commitments WITHOUT being asked: this
 * text is folded into the system prompt on every turn (see llm/prompt.ts), so
 * "what should I work on?" is answerable from state rather than from whatever
 * the user happens to re-explain.
 *
 * Deliberately budgeted. The briefing goes into EVERY model call, so it is
 * capped hard: a user with 40 goals must not pay 40 goals' worth of tokens on
 * every turn. It shows what is urgent, says how much was hidden, and refuses
 * to grow further.
 */
function briefing(dataDir, now = new Date(), maxGoals = 8) {
    const goals = loadGoals(dataDir);
    if (goals.length === 0)
        return '(no goals recorded yet)';
    const attention = needsAttention(dataDir, now);
    const stale = staleGoals(dataDir, now);
    const active = goals.filter((g) => g.status === 'active' || g.status === 'blocked');
    const lines = [];
    if (attention.length > 0) {
        lines.push(`Needs attention (${attention.length}):`);
        for (const g of attention.slice(0, 5)) {
            const why = g.status === 'blocked' ? `blocked — ${g.blockedReason ?? 'no reason recorded'}` : dueLabel(g, now);
            lines.push(`- [p${g.priority}] ${g.title}${g.deadline ? ` (due ${g.deadline})` : ''} — ${why}`);
        }
    }
    if (stale.length > 0) {
        lines.push(`Stalled, untouched >14d (${stale.length}): ${stale.slice(0, 3).map((g) => g.title).join('; ')}`);
    }
    if (active.length > 0) {
        const shown = active.slice(0, maxGoals);
        lines.push('Active goals (highest priority first):');
        for (const g of shown) {
            const bits = [`[p${g.priority}]`, g.title];
            if (g.nextAction)
                bits.push(`next: ${g.nextAction}`);
            if (g.project)
                bits.push(`project: ${g.project}`);
            lines.push(`- ${bits.join(' · ')}`);
        }
        if (active.length > shown.length) {
            lines.push(`…and ${active.length - shown.length} more active goal(s) — call goal_list for the full set.`);
        }
    }
    const decisions = loadDecisions(dataDir).slice(0, 3);
    if (decisions.length > 0) {
        lines.push('Recent decisions:');
        for (const d of decisions)
            lines.push(`- ${d.question} → ${d.choice}`);
    }
    return lines.join('\n');
}
function dueLabel(g, now) {
    const due = Date.parse(g.deadline ?? '');
    if (!Number.isFinite(due))
        return 'no deadline';
    const days = Math.ceil((due - now.getTime()) / 86_400_000);
    if (days < 0)
        return `OVERDUE by ${-days}d`;
    if (days === 0)
        return 'due TODAY';
    return `due in ${days}d`;
}
return { goalsDir,loadGoals,loadDecisions,getGoal,saveGoal,removeGoal,saveDecision,removeDecision,needsAttention,staleGoals,makeId,isStatus,briefing };
}

__mod['core/executive.js'] = M15();

function M16() {
const { briefing } = __mod['core/executive.js'];
/**
 * The briefing is recomputed inside buildSystemPrompt rather than passed in.
 * Every caller (CLI, web UI, desktop shell) already passes dataDir, so doing it
 * here means all of them gain goal awareness from one change instead of three
 * coordinated ones. It reads a handful of small JSON files — cheaper than the
 * system prompt it is being spliced into, and it keeps the text honest against
 * whatever is on disk right now.
 */
function buildSystemPrompt(cwd, dataDir, memoryFiles, projectNotes = '', skills = []) {
    const platform = `${os.type()} ${os.release()} (${os.platform()})`;
    const today = new Date().toISOString().slice(0, 10);
    const memory = memoryFiles.length > 0
        ? memoryFiles.map((f) => `- ${f}`).join('\n')
        : '(empty — nothing remembered yet)';
    return `You are BlackRose, a personal AI assistant and autonomous technical agent.

IDENTITY
- Persistent identity: BlackRose. Direct, honest, competent, calm. No flattery.
- You serve one user. Respond in whatever language the user writes in.

ENVIRONMENT
- Platform: ${platform}
- Workspace (default cwd): ${cwd}
- Persistent state dir: ${dataDir}
- Today: ${today}

HOW YOU WORK
- Understand the goal first; ask questions only when truly necessary.
- Prefer reversible actions. Verify before claiming success.
- State what you are doing briefly as you go; end with a concise summary
  of what changed and what was verified.

TOOLS
- Filesystem: read_file / write_file / edit_file / list_dir.
- Execution: run_command executes PowerShell (Windows) / bash (other) with a
  timeout; it requires user approval for every call. Set background=true for
  long-running commands, then manage them with job_list / job_output /
  job_kill. Prefer dedicated file tools over shell one-liners for edits.
- Installation: install (winget/npm/pnpm/pip) always needs explicit approval.
- Web: web_fetch reads a URL; web_search queries the web. Cite sources.
- Learning: learn_file, learn_folder (pass documents:true to also ingest
  .docx/.xlsx/.pptx/.epub), learn_pdf, learn_docx, learn_xlsx, learn_pptx,
  learn_epub, learn_transcript (SRT/VTT
  subtitles) and learn_url add documents to the knowledge base;
  knowledge_search retrieves learned passages (hybrid keyword + semantic
  match — use it before answering questions the user taught you from
  documents). knowledge_list shows what has been learned.
- Scheduled tasks: schedule_task / schedule_list / schedule_remove create and
  manage prompt-jobs that run unattended on a timer. Unattended runs cannot
  approve risky actions, so scheduled prompts must stay self-contained.
- Screen (Windows): screenshot captures the screen into the conversation;
  read_image loads an image file; gui_action clicks/types/sends keys —
  all of these are privacy-sensitive and require approval.
- OCR: ocr_read extracts text from an image or scanned/image-only PDF with
  the offline Windows OCR engine; learn_pdf uses the same OCR automatically
  when a PDF has no text layer.
- Voice: say speaks a short text aloud offline (only when asked to).

MEMORY & CONTINUITY
- memory_save / memory_search / memory_list — durable facts, preferences,
  decisions, lessons. Save when the user states something durable; search
  at the start of a task; record lessons from failed approaches too.
- Retrieval quality: memory_search / knowledge_search embed text with
  Google's gemini-embedding-001 and fall back to a built-in hash embedder
  automatically if the API is unreachable. If semantic results seem weak,
  check the embeddings line in --doctor.
- project_note / project_read — this workspace's running log. Record task
  state and "where we left off" so future sessions can resume seamlessly.
${projectNotes ? `
PROJECT CONTEXT (this workspace, from project memory — resume from here):
${projectNotes}
` : `
PROJECT CONTEXT: (none recorded for this workspace yet)
`}

EXECUTIVE BRAIN
- goal_add / goal_update / goal_list / goal_focus / goal_remove — the goals,
  deadlines and priorities the user is actually working towards. Use these when
  the user states a real commitment or deadline, NOT for one-off requests.
  decision_record / decision_list preserve a choice and the reasoning behind
  it, including what would prove it wrong.
- The briefing below is regenerated every turn from disk. Use it to stay aware
  of what is due, blocked or stalled without being asked.
${briefing(dataDir)}

SKILLS & DELEGATION
- skill_save / skill_list / skill_run — reusable task recipes. Run saved
  recipes with skill_run (executed by an isolated sub-agent).
- spawn_agent delegates a focused subtask to a specialist sub-agent with a
  fresh context. Give it self-contained instructions; use it for
  parallelizable or context-heavy work.
${skills.length > 0 ? `SAVED SKILLS (run with skill_run):\n${skills.map((s) => `- ${s.name}: ${s.description}`).join('\n')}` : 'SAVED SKILLS: (none yet — offer to save one when the user repeats a complex task)'}

SAFETY
- Never run destructive commands without the user's explicit approval.
- Never exfiltrate private data (memory, files, keys) to external services.
- If a request is ambiguous or risky, ask.
`;
}
return { buildSystemPrompt };
}

__mod['llm/prompt.js'] = M16();

function M17() {
const TOOL_DEFAULTS = {
    requiresApproval: (_input, _ctx) => null,
};
/**
 * Build a complete tool from a partial definition, filling in safe defaults.
 * Mirrors the reference codebase's buildTool() pattern: defaults live in one
 * place and are fail-closed.
 */
function buildTool(def) {
    return { ...TOOL_DEFAULTS, ...def };
}
function toApiSchemas(tools) {
    return tools.map((t) => ({
        name: t.name,
        description: t.description,
        input_schema: t.input_schema,
    }));
}
/** Input helpers */
function str(input, key, fallback = '') {
    const v = input[key];
    return typeof v === 'string' ? v : fallback;
}
function num(input, key, fallback) {
    const v = input[key];
    return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}
return { buildTool,toApiSchemas,str,num };
}

__mod['core/tools.js'] = M17();

function M18() {
const { toApiSchemas } = __mod['core/tools.js'];
function errResult(toolUseId, message) {
    return { type: 'tool_result', tool_use_id: toolUseId, content: message, is_error: true };
}
/**
 * Approximate character cost of a message — the proxy for tokens (~4 chars each).
 * Tool RESULTS are counted properly: they carry file contents, command output
 * and search results, and are usually the bulk of a real conversation. Reading
 * only `input` (which tool results do not have) counted them as ~2 chars, which
 * would have made this budget almost never fire in practice.
 */
function messageChars(m) {
    if (typeof m.content === 'string')
        return m.content.length;
    let n = 0;
    for (const b of m.content) {
        if (b.type === 'text')
            n += b.text.length;
        else if (b.type === 'image')
            n += b.source.data.length;
        else if (b.type === 'tool_use')
            n += JSON.stringify(b.input ?? {}).length;
        else if (b.type === 'tool_result') {
            n += b.tool_use_id.length;
            if (typeof b.content === 'string')
                n += b.content.length;
            else {
                for (const x of b.content) {
                    if (x.type === 'text')
                        n += x.text.length;
                    else if (x.type === 'image')
                        n += x.source.data.length;
                }
            }
        }
    }
    return n;
}
/** Default budget: ~100k characters ≈ 25k input tokens per call. */
const DEFAULT_MAX_CHARS = 100_000;
const MIN_TAIL = 4;
/**
 * Trim the history that is SENT to the model, while the caller keeps the full
 * conversation for persistence. This is the real token sink: every turn
 * re-sends the entire history, so a long session costs more and more per turn
 * no matter how terse the answer is. The token-economy skills reduce what the
 * model *writes*; this reduces what it is *sent*.
 *
 * Safety rules, because a careless cut is worse than no cut:
 * - The FIRST user message is always kept: it is the original ask, and losing
 *   it makes every later turn answer the wrong question.
 * - The tail never starts on a tool_result block. Providers (Gemini especially)
 *   reject a history whose tool_result has no matching tool_use.
 * - A visible marker is inserted, so the model knows context was dropped and can
 *   ask rather than silently inventing it.
 */
function trimHistory(history, opts) {
    const maxChars = opts?.maxChars ?? Number(process.env.BLACKROSE_HISTORY_MAX_CHARS ?? DEFAULT_MAX_CHARS);
    const before = history.reduce((n, m) => n + messageChars(m), 0);
    if (history.length === 0 || before <= maxChars || maxChars <= 0) {
        // A COPY, not the input array: runAgent appends to what it gets back, and
        // returning the caller's array here would mutate their history in place.
        return { messages: [...history], dropped: 0, before, after: before };
    }
    const first = history[0];
    let budget = maxChars - messageChars(first);
    // Walk backwards from the newest message, keeping whole messages only.
    const tail = [];
    for (let i = history.length - 1; i >= 1; i--) {
        const m = history[i];
        const c = messageChars(m);
        if (budget - c < 0 && tail.length >= MIN_TAIL)
            break;
        budget -= c;
        tail.unshift(m);
    }
    // Never start the window on a tool_result (orphaned tool_use reference).
    while (tail.length > 0) {
        const head = tail[0];
        const startsWithToolResult = typeof head.content !== 'string' && head.content.some((b) => b.type === 'tool_result');
        if (!startsWithToolResult)
            break;
        tail.shift();
    }
    const marker = {
        role: 'user',
        content: `[${history.length - 1 - tail.length} earlier message(s) were trimmed from this conversation ` +
            `to save tokens. Their content is not available to you. If the answer depends on ` +
            `something said earlier, say so and ask — do not guess.]`,
    };
    const messages = [first, marker, ...tail];
    return {
        messages,
        dropped: history.length - messages.length + 1,
        before,
        after: messages.reduce((n, m) => n + messageChars(m), 0),
    };
}
function truncate(s, max) {
    return s.length <= max ? s : s.slice(0, max) + `\n... [truncated ${s.length - max} chars]`;
}
/**
 * The agent loop: call the model, execute requested tools, feed results back,
 * repeat until the model answers with text only (or the turn budget is spent).
 */
async function runAgent(o) {
    const maxTurns = o.maxTurns ?? 24;
    const byName = new Map(o.tools.map((t) => [t.name, t]));
    const schemas = toApiSchemas(o.tools);
    // `full` is the REAL conversation and is what we return, so the caller keeps
    // persisting and can resume it. `sent` is the trimmed copy the model actually
    // sees. Keeping them separate is the whole point: trimming in place would
    // silently destroy conversation history.
    const full = [...o.history];
    const trim = trimHistory(o.history);
    const messages = trim.messages;
    let lastText = '';
    // Token accounting. The adapter already reports usage; it was being discarded,
    // so there was no way to see which turn actually cost something.
    let inTok = 0;
    let outTok = 0;
    let calls = 0;
    /** One shape for every stop, so the caller gets usage either way. */
    const trimInfo = trim.dropped > 0 ? { dropped: trim.dropped, before: trim.before, after: trim.after } : undefined;
    const stoppedAt = (turns) => ({
        messages: full,
        text: lastText || '(stopped before an answer)',
        turns,
        aborted: true,
        usage: { input: inTok, output: outTok, calls },
        trimmed: trimInfo,
    });
    for (let turn = 0; turn < maxTurns; turn++) {
        if (o.signal?.aborted)
            return stoppedAt(turn);
        let res;
        try {
            res = await o.client.call(o.system, messages, schemas, { signal: o.signal });
        }
        catch (e) {
            // A cancelled request is a normal outcome, not a crash: report it with the
            // partial history so the turn can still be saved and shown.
            if (o.signal?.aborted)
                return stoppedAt(turn);
            throw e;
        }
        if (res.usage) {
            inTok += res.usage.input_tokens ?? 0;
            outTok += res.usage.output_tokens ?? 0;
        }
        calls += 1;
        const toolUses = res.content.filter((b) => b.type === 'tool_use');
        const textBlocks = res.content.filter((b) => b.type === 'text');
        if (textBlocks.length > 0) {
            lastText = textBlocks.map((b) => b.text).join('\n').trim();
            o.onText?.(lastText);
        }
        // Preserve every assistant response, including the final text-only answer.
        // The assistant turn goes into BOTH: the model sees it now, and it must be
        // persisted so the conversation stays resumable.
        const assistantMsg = { role: 'assistant', content: res.content };
        messages.push(assistantMsg);
        full.push(assistantMsg);
        if (toolUses.length === 0) {
            return { messages: full, text: lastText, turns: turn + 1, usage: { input: inTok, output: outTok, calls }, trimmed: trimInfo };
        }
        const results = [];
        for (const tu of toolUses) {
            // Stop between tools too: a 10-tool plan should not run the remaining
            // nine after the user hits Stop.
            if (o.signal?.aborted)
                return stoppedAt(turn + 1);
            o.onToolCall?.(tu.name, tu.input);
            const tool = byName.get(tu.name);
            if (!tool) {
                results.push(errResult(tu.id, `Unknown tool: ${tu.name}`));
                continue;
            }
            try {
                const reason = tool.requiresApproval?.(tu.input, o.ctx) ?? null;
                if (reason) {
                    const ok = await o.ctx.askApproval(tool.name, reason);
                    if (!ok) {
                        results.push(errResult(tu.id, 'Action denied by user.'));
                        continue;
                    }
                }
                const result = await tool.run(tu.input, o.ctx);
                o.onToolResult?.(tool.name, result);
                const resultText = truncate(result.content, 20_000);
                const images = result.images ?? [];
                results.push({
                    type: 'tool_result',
                    tool_use_id: tu.id,
                    content: images.length === 0
                        ? resultText
                        : [
                            { type: 'text', text: resultText },
                            ...images.map((img) => ({
                                type: 'image',
                                source: { type: 'base64', media_type: img.media_type, data: img.data },
                            })),
                        ],
                    is_error: result.isError,
                });
            }
            catch (e) {
                const msg = e instanceof Error ? e.message : String(e);
                o.onToolResult?.(tool.name, { content: msg, isError: true });
                results.push(errResult(tu.id, `Tool '${tu.name}' failed: ${msg}`));
            }
        }
        const toolResultMsg = { role: 'user', content: results };
        messages.push(toolResultMsg);
        full.push(toolResultMsg);
    }
    return {
        messages: full,
        text: lastText || '(turn budget exhausted before a final answer)',
        turns: maxTurns,
        usage: { input: inTok, output: outTok, calls },
        trimmed: trimInfo,
    };
}
return { messageChars,trimHistory,runAgent };
}

__mod['core/agent.js'] = M18();

function M19() {
const { runAgent } = __mod['core/agent.js'];
function extractSteps(text) {
    // accept fenced JSON, bare JSON, or a numbered list fallback
    const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    const candidates = [fenced?.[1], text.match(/\{[\s\S]*\}/)?.[0]];
    for (const c of candidates) {
        if (!c)
            continue;
        try {
            const parsed = JSON.parse(c);
            if (Array.isArray(parsed.steps)) {
                const steps = parsed.steps.filter((s) => typeof s === 'string' && s.trim().length > 0);
                if (steps.length > 0)
                    return steps.map((s) => s.trim());
            }
        }
        catch {
            /* try next candidate */
        }
    }
    const list = text
        .split('\n')
        .map((l) => l.replace(/^\s*\d+[.)]\s*/, '').trim())
        .filter((l) => l.length > 0 && l.length < 300);
    return list;
}
async function runGoal(o) {
    const maxTurns = o.maxTurnsPerStep ?? 8;
    const onToolCall = (name, input) => o.onEvent?.(`  ⚙ ${name}: ${JSON.stringify(input).slice(0, 160)}`);
    // 1) plan (single model call, no tools)
    const planRes = await o.client.call(o.system, [
        {
            role: 'user',
            content: `GOAL: ${o.goal}\n\n` +
                'You are the planning module. Reply ONLY with a JSON object of the form\n' +
                '{"steps": ["instruction", ...]} with 1-6 short, actionable steps for an\n' +
                'agent that has file/shell/web tools. The last step must verify the result.',
        },
    ], []);
    const planText = planRes.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');
    const steps = extractSteps(planText);
    if (steps.length === 0)
        throw new Error(`planner produced no usable steps: ${planText.slice(0, 300)}`);
    o.onEvent?.(`plan: ${steps.length} step(s)`);
    // 2) execute each step in its own agent loop
    const stepReports = [];
    let turns = 0;
    for (let i = 0; i < steps.length; i++) {
        const history = [
            {
                role: 'user',
                content: `Overall goal: ${o.goal}\n\n` +
                    `Plan:\n${steps.map((s, j) => `${j + 1}. ${s}`).join('\n')}\n\n` +
                    `Execute step ${i + 1} now: "${steps[i]}". Do ONLY this step.`,
            },
        ];
        o.onEvent?.(`step ${i + 1}/${steps.length}: ${steps[i].slice(0, 100)}`);
        const out = await runAgent({
            client: o.client,
            tools: o.tools,
            system: o.system,
            history,
            ctx: o.ctx,
            maxTurns,
            onToolCall,
        });
        turns += out.turns;
        stepReports.push(`Step ${i + 1} (${steps[i]}): ${out.text.slice(0, 1000)}`);
    }
    // 3) verify (agent with tools; must answer VERIFIED or NOT_VERIFIED)
    const verifyHistory = [
        {
            role: 'user',
            content: `GOAL: ${o.goal}\n\nSteps executed:\n${stepReports.join('\n')}\n\n` +
                'Verify whether the goal is actually satisfied (inspect files, run checks).\n' +
                'End your reply with exactly VERIFIED or NOT_VERIFIED.',
        },
    ];
    o.onEvent?.('verifying…');
    const vOut = await runAgent({
        client: o.client,
        tools: o.tools,
        system: o.system,
        history: verifyHistory,
        ctx: o.ctx,
        maxTurns,
        onToolCall,
    });
    turns += vOut.turns;
    // "VERIFIED" is a SUBSTRING of "NOT_VERIFIED", and the verifier writes both
    // forms: the prompt uses NOT_VERIFIED, but the model naturally answers
    // "NOT VERIFIED" with a space. The old check only matched the underscore
    // spelling, so "NOT VERIFIED" matched /VERIFIED/ on its own and the guard
    // reported success on a failed verification — the exact opposite of what a
    // fail-closed check is for. Normalise separators first, then test the
    // negative form BEFORE the positive one.
    const verdict = vOut.text.toUpperCase().replace(/[\s_-]+/g, '_');
    const verified = verdict.includes('VERIFIED') && !verdict.includes('NOT_VERIFIED');
    return {
        plan: steps,
        report: [...stepReports, `Verification: ${vOut.text.slice(0, 1000)}`].join('\n\n'),
        verified,
        turns,
    };
}
return { runGoal };
}

__mod['core/taskEngine.js'] = M19();

function M20() {
/**
 * Workspace path policy (Constitution §13/§21):
 * - Reads are free.
 * - Writes/edits inside the workspace are free.
 * - Writes/edits outside the workspace require approval.
 */
function resolveInWorkspace(cwd, target) {
    return path.isAbsolute(target) ? path.normalize(target) : path.resolve(cwd, target);
}
function isInsideWorkspace(cwd, absolutePath) {
    const rel = path.relative(path.resolve(cwd), path.resolve(absolutePath));
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}
/** Description of a write target for approval prompts. */
function writeApprovalReason(kind, absolutePath, cwd) {
    const inside = isInsideWorkspace(cwd, absolutePath);
    return `${kind}: ${absolutePath}${inside ? '' : '  (outside workspace!)'}`;
}
return { resolveInWorkspace,isInsideWorkspace,writeApprovalReason };
}

__mod['core/permissions.js'] = M20();

function M21() {
/**
 * Minimal ANSI terminal UI (Phase 4): colors, diffs, spinner — zero deps.
 */
const enabled = process.stdout.isTTY ?? false;
function wrap(code, s) {
    return enabled ? `\x1b[${code}m${s}\x1b[0m` : s;
}
const color = {
    dim: (s) => wrap('2', s),
    green: (s) => wrap('32', s),
    red: (s) => wrap('31', s),
    yellow: (s) => wrap('33', s),
    cyan: (s) => wrap('36', s),
    bold: (s) => wrap('1', s),
};
/** Line-based diff rendering for edit_file results (changed regions only). */
function renderDiff(oldText, newText, maxLines = 40) {
    const a = oldText.split(/\r?\n/);
    const b = newText.split(/\r?\n/);
    // common prefix/suffix; the middle is the changed region
    let pre = 0;
    while (pre < a.length && pre < b.length && a[pre] === b[pre])
        pre++;
    let suf = 0;
    while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf])
        suf++;
    const removed = a.slice(pre, a.length - suf);
    const added = b.slice(pre, b.length - suf);
    const lines = [];
    if (pre > 0)
        lines.push(color.dim(`   … (${pre} unchanged line${pre === 1 ? '' : 's'})`));
    for (const l of removed.slice(0, maxLines))
        lines.push(color.red(`  - ${l}`));
    for (const l of added.slice(0, maxLines))
        lines.push(color.green(`  + ${l}`));
    const rest = Math.max(removed.length, added.length) - maxLines;
    if (rest > 0)
        lines.push(color.dim(`   … (+${rest} more changed lines)`));
    if (pre + suf < Math.min(a.length, b.length) || removed.length + added.length > 0) {
        // trailing context marker only when we know the file continues
        if (a.length - suf < a.length)
            lines.push(color.dim(`   … (rest unchanged)`));
    }
    return lines.length > 0 ? lines.join('\n') : '(no changes)';
}
/** Single-line spinner on stderr; stopped with the final status. */
class Spinner {
    timer = null;
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    i = 0;
    start(label) {
        if (!enabled) {
            process.stderr.write(`  … ${label}\n`);
            return;
        }
        this.stop();
        this.timer = setInterval(() => {
            const f = this.frames[this.i++ % this.frames.length];
            process.stderr.write(`\r  ${f} ${label}   `);
        }, 100);
    }
    update(label) {
        if (!this.timer)
            return;
        this.label = label;
        process.stderr.write(`\r  ${this.frames[this.i % this.frames.length]} ${label}   `);
    }
    label = '';
    stop(final) {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
            process.stderr.write('\r' + ' '.repeat(90) + '\r');
        }
        if (final)
            process.stderr.write(`  ${final}\n`);
    }
}
return { color,renderDiff,Spinner };
}

__mod['ui/render.js'] = M21();

function M22() {
/**
 * Undo / Time Machine (B2, docs/07-BUILD-CHECKLIST) — the rollback layer that a
 * system whose whole job is TAKING ACTIONS must have.
 *
 * Before a mutating tool touches disk it records a PRE-IMAGE of what it is about
 * to change:
 *   • `snapshotFiles` — exact files a tool is about to write/edit (cheap, always on).
 *   • `snapshotTree`  — a bounded copy of the workspace before an approval-gated
 *     `run_command` / `install`, which can change anything.
 * Pre-images are content-addressed (sha256 blobs), so repeated snapshots of an
 * unchanged file cost nothing extra.
 *
 * Layout (inside dataDir, never inside `.aistate` — snapshots are local
 * insurance, not identity to be synced between machines):
 *   undo/entries/<id>.json   manifest: what changed, when, why, which blobs
 *   undo/blobs/<sha256>      file pre-image
 *
 * `restore()` writes the pre-images back and first snapshots the CURRENT state
 * of the same paths, so undoing is itself undoable. Entries that were restored
 * are flagged and skipped by `undoLast()`.
 *
 * LIMITS (stated, not hidden): a tree snapshot is bounded by file count, file
 * size, total bytes and wall-clock — a workspace bigger than the caps is marked
 * `partial`, and restoring it will not reproduce it perfectly. Changes made
 * outside the workspace (registry, global npm, %APPDATA%) are never captured.
 */
/** Retention + caps, read live so tests and users can tune them per process. */
function keepEntries() {
    return Math.max(3, Number(process.env.BLACKROSE_UNDO_KEEP ?? 30));
}
function maxFileBytes() {
    return Number(process.env.BLACKROSE_UNDO_MAX_FILE_BYTES ?? 5 * 1024 * 1024);
}
function maxTreeFiles() {
    return Number(process.env.BLACKROSE_UNDO_MAX_FILES ?? 3000);
}
function maxTreeBytes() {
    return Number(process.env.BLACKROSE_UNDO_MAX_TOTAL_BYTES ?? 200 * 1024 * 1024);
}
function treeBudgetMs() {
    return Number(process.env.BLACKROSE_UNDO_BUDGET_MS ?? 4000);
}
function treeIntervalMs() {
    return Number(process.env.BLACKROSE_UNDO_TREE_INTERVAL_MS ?? 60_000);
}
/**
 * Ceiling for the WHOLE journal, as opposed to a single snapshot.
 *
 * maxFileBytes / maxTreeFiles / maxTreeBytes each bound ONE snapshot. Nothing
 * bounded their sum: pruning was purely by entry count, so keep=30 large
 * snapshots could occupy gigabytes before the disk complained. Measured on this
 * machine before the fix — a single entry held 22.5 MB, which is 0.4% of what
 * 30 of them could reach. 512 MB stays generous for a personal rollback journal
 * (a few dozen ordinary edits is single-digit megabytes) while still being a
 * number a user can reason about.
 */
function maxJournalBytes() {
    return Number(process.env.BLACKROSE_UNDO_MAX_JOURNAL_BYTES ?? 512 * 1024 * 1024);
}
/**
 * The byte budget will never prune the journal to nothing: undoLast needs at
 * least the newest change, and a rollback point that deleted itself for being
 * large would turn a safety net into a liability. If that one entry alone
 * exceeds the budget it is kept, and undoStats reports the overflow — visible
 * beats silently losing the only rollback point.
 */
const MIN_UNDO_ENTRIES = 1;
const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', 'dist-build', 'target', 'build', 'out', 'dist-electron',
    '.next', '.nuxt', '.venv', 'venv', '__pycache__', 'vendor', '.pnpm-store', '.turbo',
    '.cache', 'coverage', 'undo', '.blackrose',
]);
function undoRoot(dataDir) {
    return path.join(dataDir, 'undo');
}
function entriesDir(dataDir) {
    return path.join(undoRoot(dataDir), 'entries');
}
function blobsDir(dataDir) {
    return path.join(undoRoot(dataDir), 'blobs');
}
function entryFile(dataDir, id) {
    return path.join(entriesDir(dataDir), `${id}.json`);
}
function blobFile(dataDir, sha) {
    return path.join(blobsDir(dataDir), sha);
}
/**
 * Lexicographically sortable, unique id. The stamp keeps MILLISECONDS and a
 * process-local counter: with one-second stamps, every entry written during a
 * single burst of tool calls sorted in an arbitrary order, so `listEntries` and
 * `undoLast` could hand back the wrong "latest" change.
 */
let entrySeq = 0;
function newEntryId() {
    const stamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 17);
    entrySeq += 1;
    // The random tail keeps ids unique across PROCESSES too (desktop app + CLI
    // running at once), while the timestamp prefix keeps them sortable.
    return `undo_${stamp}_${String(entrySeq % 1000).padStart(3, '0')}_${crypto.randomBytes(2).toString('hex')}`;
}
function storeBlob(dataDir, bytes) {
    const sha = crypto.createHash('sha256').update(bytes).digest('hex');
    const target = blobFile(dataDir, sha);
    if (!fs.existsSync(target)) {
        fs.mkdirSync(blobsDir(dataDir), { recursive: true });
        fs.writeFileSync(target, bytes);
    }
    return sha;
}
/** Temp-name counter: unique per process, no crypto import needed for one call. */
let entryTmpCounter = 0;
function writeEntry(dataDir, entry) {
    fs.mkdirSync(entriesDir(dataDir), { recursive: true });
    // ATOMIC. This manifest is the rollback point: it is written BEFORE the tool
    // touches disk, and a plain writeFileSync truncates first, so a crash (or a
    // kill, or a full disk) partway through leaves a half-written JSON file that
    // readEntry() cannot parse — the entry silently vanishes from the journal even
    // though the change it describes is about to happen on disk. That is the worst
    // possible outcome for undo: the change happened and nothing can roll it back.
    // Temp + fsync + rename (atomic within a filesystem), same pattern as
    // vault.ts:165. Unique per write via pid + counter so concurrent snapshots
    // never share a temp file.
    const file = entryFile(dataDir, entry.id);
    const tmp = `${file}.tmp-${process.pid}-${entryTmpCounter++}`;
    try {
        const fd = fs.openSync(tmp, 'w');
        try {
            fs.writeFileSync(fd, JSON.stringify(entry, null, 2), 'utf8');
            fs.fsyncSync(fd);
        }
        finally {
            fs.closeSync(fd);
        }
        fs.renameSync(tmp, file);
    }
    catch (e) {
        try {
            fs.rmSync(tmp, { force: true });
        }
        catch {
            /* nothing further to do */
        }
        // snapshotFiles() catches this, but restoreEntry() does not: an entry that
        // cannot be re-written as `restored` must not read as a failed rollback.
        throw e;
    }
}
/* ─────────────────────────── snapshotting ─────────────────────────── */
function undoEnabled() {
    return (process.env.BLACKROSE_UNDO ?? '1') !== '0';
}
/**
 * Record the pre-images of files a tool is about to write. Returns the entry id
 * (usable with `undo_changes`) or null when nothing was recorded. NEVER throws —
 * losing the safety net must not take the user's real operation down with it.
 */
function snapshotFiles(input) {
    if (!undoEnabled())
        return null;
    try {
        const files = [];
        for (const p of input.paths) {
            try {
                const stat = fs.statSync(p);
                if (!stat.isFile())
                    continue;
                if (stat.size > maxFileBytes()) {
                    files.push({ path: p, existed: true, size: stat.size }); // too big to journal
                    continue;
                }
                const bytes = fs.readFileSync(p);
                files.push({ path: p, sha: storeBlob(input.dataDir, bytes), existed: true, size: stat.size });
            }
            catch {
                files.push({ path: p, existed: false, size: 0 }); // did not exist → undo deletes it
            }
        }
        if (files.length === 0)
            return null;
        const entry = {
            id: newEntryId(),
            ts: new Date().toISOString(),
            tool: input.tool,
            reason: input.reason.slice(0, 300),
            cwd: input.cwd,
            kind: 'files',
            status: 'open',
            role: input.role ?? 'action',
            files,
        };
        writeEntry(input.dataDir, entry);
        pruneEntries(input.dataDir);
        return entry.id;
    }
    catch {
        return null;
    }
}
/** Convenience for the single-file write/edit tools. */
function snapshotBeforeWrite(dataDir, cwd, tool, target) {
    return snapshotFiles({ dataDir, cwd, tool, reason: `${tool} → ${target}`, paths: [target] });
}
/** cwd → timestamp of the last tree snapshot, so bursts of commands share one. */
const lastTreeSnapshot = new Map();
function walkWorkspace(dataDir, root, deadline) {
    const files = [];
    let partial = false;
    let total = 0;
    const stack = [root];
    while (stack.length > 0) {
        const dir = stack.pop();
        let dirents;
        try {
            dirents = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            continue; // unreadable directory: skip, do not fail the snapshot
        }
        for (const e of dirents) {
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (SKIP_DIRS.has(e.name))
                    continue;
                stack.push(full);
                continue;
            }
            if (!e.isFile())
                continue;
            if (files.length >= maxTreeFiles() || total >= maxTreeBytes() || Date.now() > deadline) {
                partial = true;
                continue;
            }
            let stat;
            try {
                stat = fs.statSync(full);
            }
            catch {
                continue;
            }
            if (stat.size > maxFileBytes()) {
                partial = true;
                continue; // too big to journal whole; caps are stated in the header
            }
            try {
                const bytes = fs.readFileSync(full);
                total += bytes.length;
                files.push({ path: full, sha: storeBlob(dataDir, bytes), existed: true, size: stat.size });
            }
            catch {
                /* unreadable file — nothing to journal */
            }
        }
    }
    return { files, partial };
}
/**
 * Bounded pre-image of the whole workspace before an approval-gated command or
 * install. Shares one snapshot per workspace inside TREE_MIN_INTERVAL_MS so a
 * burst of commands does not pay the walk cost every time.
 */
function snapshotTree(input) {
    if (!undoEnabled())
        return null;
    try {
        const root = path.resolve(input.cwd);
        const last = lastTreeSnapshot.get(root) ?? 0;
        if (Date.now() - last < treeIntervalMs())
            return null;
        lastTreeSnapshot.set(root, Date.now());
        const walked = walkWorkspace(input.dataDir, root, Date.now() + treeBudgetMs());
        if (walked.files.length === 0)
            return null;
        const entry = {
            id: newEntryId(),
            ts: new Date().toISOString(),
            tool: input.tool,
            reason: input.reason.slice(0, 300),
            cwd: root,
            kind: 'tree',
            status: 'open',
            role: 'action',
            partial: walked.partial,
            files: walked.files,
        };
        writeEntry(input.dataDir, entry);
        pruneEntries(input.dataDir);
        return entry.id;
    }
    catch {
        return null;
    }
}
/* ─────────────────────────── reading back ─────────────────────────── */
const HEX64 = /^[0-9a-f]{64}$/;
function parseEntry(raw) {
    try {
        const e = JSON.parse(raw);
        if (!e || typeof e.id !== 'string' || !Array.isArray(e.files))
            return null;
        return { ...e, files: e.files.filter((f) => typeof f?.path === 'string') };
    }
    catch {
        return null;
    }
}
function readEntry(dataDir, id) {
    if (!/^[a-z0-9_]+$/i.test(id))
        return null;
    const file = entryFile(dataDir, id);
    if (!fs.existsSync(file))
        return null;
    return parseEntry(fs.readFileSync(file, 'utf8'));
}
/** Newest first. Malformed entry files are ignored, not fatal. */
function listEntries(dataDir, limit = 25) {
    const dir = entriesDir(dataDir);
    if (!fs.existsSync(dir))
        return [];
    const out = [];
    for (const name of fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort().reverse()) {
        const e = parseEntry(fs.readFileSync(path.join(dir, name), 'utf8'));
        if (e)
            out.push(e);
        if (out.length >= limit)
            break;
    }
    return out;
}
function undoStats(dataDir) {
    const bd = blobsDir(dataDir);
    let blobBytes = 0;
    if (fs.existsSync(bd)) {
        for (const b of fs.readdirSync(bd)) {
            try {
                blobBytes += fs.statSync(path.join(bd, b)).size;
            }
            catch {
                /* ignore */
            }
        }
    }
    const dir = entriesDir(dataDir);
    return {
        entries: fs.existsSync(dir) ? fs.readdirSync(dir).filter((n) => n.endsWith('.json')).length : 0,
        blobBytes,
        root: undoRoot(dataDir),
        keep: keepEntries(),
    };
}
/** Keep the newest N entries; garbage-collect blobs nothing references. */
function pruneEntries(dataDir) {
    const dir = entriesDir(dataDir);
    if (!fs.existsSync(dir))
        return;
    const bd = blobsDir(dataDir);
    // Entry ids are timestamp-prefixed, so reverse sort is newest-first and
    // `.pop()` below removes the OLDEST survivor.
    const names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort().reverse();
    const kept = names.slice(0, keepEntries());
    for (const stale of names.slice(keepEntries()))
        fs.rmSync(path.join(dir, stale), { force: true });
    /** Blobs still referenced by the surviving entries, plus their total size. */
    const measure = (live) => {
        const alive = new Set();
        for (const name of live) {
            let e = null;
            try {
                e = parseEntry(fs.readFileSync(path.join(dir, name), 'utf8'));
            }
            catch {
                continue; // vanished underneath us; treat as referencing nothing
            }
            for (const f of e?.files ?? [])
                if (f.sha && HEX64.test(f.sha))
                    alive.add(f.sha);
        }
        let bytes = 0;
        if (fs.existsSync(bd)) {
            for (const b of alive) {
                try {
                    bytes += fs.statSync(path.join(bd, b)).size;
                }
                catch {
                    /* ignore */
                }
            }
        }
        return { alive, bytes };
    };
    let { alive, bytes } = measure(kept);
    // AGGREGATE BYTE BUDGET.
    //
    // The existing caps bound ONE snapshot (5 MB per file, 3000 files, 200 MB
    // total) but nothing bounded the journal as a whole: pruning was purely by
    // entry COUNT, so keep=30 large workspace snapshots is gigabytes of undo
    // history that grows until the disk is full. Measured on this machine before
    // the fix: a single entry held 22.5 MB — 0.4% of what 30 of them could reach.
    //
    // Blobs are content-addressed, so an entry that shares content with a newer
    // one frees NOTHING when dropped. The budget therefore re-measures after every
    // drop instead of assuming each removal helped, and stops at MIN_KEEP so
    // undoLast always has at least the newest change to work with. If that one
    // entry alone exceeds the budget it is kept and the overflow is visible in
    // `undoStats` — silently deleting the only rollback point would be worse than
    // reporting a large journal.
    const budget = maxJournalBytes();
    while (bytes > budget && kept.length > MIN_UNDO_ENTRIES) {
        const dropped = kept.pop();
        if (!dropped)
            break;
        fs.rmSync(path.join(dir, dropped), { force: true });
        ({ alive, bytes } = measure(kept));
    }
    if (!fs.existsSync(bd))
        return;
    for (const blob of fs.readdirSync(bd)) {
        if (!alive.has(blob))
            fs.rmSync(path.join(bd, blob), { force: true });
    }
}
/**
 * Roll a recorded entry back. The current state of the same paths is snapshotted
 * first, so the restore is itself undoable. The journal directory is never a
 * restore target, and blob ids are shape-checked before use.
 */
function restoreEntry(dataDir, id) {
    const entry = readEntry(dataDir, id);
    if (!entry)
        return { ok: false, error: `No undo entry: ${id}` };
    const journal = path.resolve(undoRoot(dataDir));
    snapshotFiles({
        dataDir,
        cwd: entry.cwd,
        tool: 'undo',
        reason: `pre-restore snapshot before restoring ${entry.id} (${entry.tool})`,
        paths: entry.files.map((f) => f.path),
        role: 'safety',
    });
    let restored = 0;
    let deleted = 0;
    const skipped = [];
    for (const f of entry.files) {
        const target = path.resolve(f.path);
        if (target.toLowerCase().startsWith(journal.toLowerCase())) {
            skipped.push(f.path); // never let a restore rewrite its own journal
            continue;
        }
        try {
            if (!f.existed) {
                if (fs.existsSync(target))
                    fs.rmSync(target, { force: true });
                deleted += 1;
                continue;
            }
            if (!f.sha || !HEX64.test(f.sha) || !fs.existsSync(blobFile(dataDir, f.sha))) {
                skipped.push(f.path);
                continue;
            }
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.copyFileSync(blobFile(dataDir, f.sha), target);
            restored += 1;
        }
        catch {
            skipped.push(f.path);
        }
    }
    writeEntry(dataDir, { ...entry, status: 'restored' });
    pruneEntries(dataDir);
    return {
        ok: true,
        result: {
            id: entry.id,
            tool: entry.tool,
            reason: entry.reason,
            files: entry.files.length,
            restored,
            deleted,
            skipped,
            partial: entry.partial === true,
        },
    };
}
/** Restore the most recent agent action that has not already been rolled back. */
function undoLast(dataDir) {
    const open = listEntries(dataDir, 50).find((e) => e.status !== 'restored' && e.role !== 'safety');
    if (!open)
        return { ok: false, error: 'Nothing to undo — no recorded changes.' };
    return restoreEntry(dataDir, open.id);
}
/* @@SECTION_END@@ */
return { keepEntries,undoRoot,undoEnabled,snapshotFiles,snapshotBeforeWrite,snapshotTree,readEntry,listEntries,undoStats,restoreEntry,undoLast };
}

__mod['core/undo.js'] = M22();

function M23() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { isInsideWorkspace, resolveInWorkspace, writeApprovalReason } = __mod['core/permissions.js'];
const { renderDiff } = __mod['ui/render.js'];
const { snapshotBeforeWrite } = __mod['core/undo.js'];
const MAX_READ_LINES = 2000;
const readFileTool = buildTool({
    name: 'read_file',
    description: 'Read a text file from disk. Returns content with 1-based line numbers. Optionally limit to a line range.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'File path (absolute or relative to the workspace)' },
            start_line: { type: 'number', description: 'Optional 1-based first line to read' },
            end_line: { type: 'number', description: 'Optional 1-based last line to read' },
        },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        // Return isError rather than throwing: a missing file is an ordinary tool
        // outcome the model can react to, and every sibling tool here answers that
        // way. Letting statSync throw ends the turn with a raw stack instead.
        if (!fs.existsSync(p))
            return { content: `File not found: ${p}`, isError: true };
        const stat = fs.statSync(p);
        if (stat.isDirectory())
            return { content: `${p} is a directory, not a file.`, isError: true };
        if (stat.size > 5 * 1024 * 1024)
            return { content: `File too large to read whole (${stat.size} bytes). Read ranges instead.`, isError: true };
        const raw = fs.readFileSync(p, 'utf8');
        const lines = raw.split(/\r?\n/);
        const start = Math.max(1, num(input, 'start_line', 1));
        const end = Math.min(lines.length, num(input, 'end_line', start + MAX_READ_LINES - 1));
        const numbered = lines
            .slice(start - 1, end)
            .map((l, i) => `${start + i} | ${l}`)
            .join('\n');
        const note = lines.length > end ? `\n... (${lines.length} lines total; showing ${start}-${end})` : '';
        return { content: numbered + note || '(empty file)' };
    },
});
const writeFileTool = buildTool({
    name: 'write_file',
    description: 'Create or overwrite a text file with the given content.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'File path (absolute or relative to the workspace)' },
            content: { type: 'string', description: 'Full file content to write' },
        },
        required: ['path', 'content'],
    },
    requiresApproval: (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        if (isInsideWorkspace(ctx.cwd, p) && fs.existsSync(p))
            return null; // in-workspace edit of known file
        if (isInsideWorkspace(ctx.cwd, p))
            return null; // in-workspace creation
        return writeApprovalReason('Write file', p, ctx.cwd);
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        snapshotBeforeWrite(ctx.dataDir, ctx.cwd, 'write_file', p); // B2: pre-image before overwriting
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, str(input, 'content'), 'utf8');
        return { content: `Wrote ${p} (${fs.statSync(p).size} bytes).` };
    },
});
const editFileTool = buildTool({
    name: 'edit_file',
    description: 'Replace an exact, unique snippet of text in an existing file. Fails if old_text is not found or matches more than once.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'File to edit' },
            old_text: { type: 'string', description: 'Exact text to replace (must be unique in the file)' },
            new_text: { type: 'string', description: 'Replacement text' },
        },
        required: ['path', 'old_text', 'new_text'],
    },
    requiresApproval: (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        return isInsideWorkspace(ctx.cwd, p) ? null : writeApprovalReason('Edit file', p, ctx.cwd);
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const raw = fs.readFileSync(p, 'utf8');
        const oldText = str(input, 'old_text');
        const newText = str(input, 'new_text');
        const count = raw.split(oldText).length - 1;
        if (count === 0)
            return { content: 'old_text not found in file.', isError: true };
        if (count > 1)
            return { content: `old_text matches ${count} times; make it unique.`, isError: true };
        snapshotBeforeWrite(ctx.dataDir, ctx.cwd, 'edit_file', p); // B2: only once the edit is known to apply
        fs.writeFileSync(p, raw.replace(oldText, newText), 'utf8');
        const diff = renderDiff(oldText, newText);
        return { content: `Edited ${p}.\n${diff}` };
    },
});
const listDirTool = buildTool({
    name: 'list_dir',
    description: 'List a directory (name, type, size). Read-only.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Directory path (default: workspace root)' },
        },
        required: [],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path') || '.');
        if (!fs.existsSync(p))
            return { content: `Directory not found: ${p}`, isError: true };
        const entries = fs.readdirSync(p, { withFileTypes: true });
        if (entries.length === 0)
            return { content: '(empty directory)' };
        const lines = entries
            .slice(0, 500)
            .map((e) => {
            const size = e.isFile() ? ` ${fs.statSync(path.join(p, e.name)).size}b` : '';
            return `${e.isDirectory() ? '[dir] ' : '      '}${e.name}${size}`;
        });
        return { content: lines.join('\n') };
    },
});
return { readFileTool,writeFileTool,editFileTool,listDirTool };
}

__mod['tools/files.js'] = M23();

function M24() {
/**
 * Background process registry + shared shell execution (Phase 3).
 * Jobs are session-scoped: the registry lives in memory, output is capped.
 */

const MAX_JOB_OUTPUT = 200_000;
/**
 * How many finished jobs to keep. Each one retains up to MAX_JOB_OUTPUT bytes
 * of captured output, so an unbounded registry is 200 KB per background command
 * held for the whole session — a long-running assistant eventually dies on its
 * own bookkeeping. Only the most recent MAX_JOBS are kept; RUNNING jobs are
 * never evicted, since killJob/getJob must still resolve their ids.
 */
const MAX_JOBS = 50;
const jobs = new Map();
let jobSeq = 0;
/** Drop the oldest settled jobs once the registry exceeds MAX_JOBS. */
function trimJobs() {
    if (jobs.size <= MAX_JOBS)
        return;
    for (const [id, job] of jobs) {
        if (jobs.size <= MAX_JOBS)
            break;
        if (job.status === 'running')
            continue;
        jobs.delete(id);
    }
}
function shellArgs(command) {
    const isWin = process.platform === 'win32';
    return isWin
        ? { file: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', command] }
        : { file: '/bin/bash', args: ['-c', command] };
}
/** Kill a process tree (Windows needs taskkill; a plain signal leaves children). */
function killTree(pid) {
    try {
        if (process.platform === 'win32')
            spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true });
        else
            process.kill(pid, 'SIGTERM');
    }
    catch {
        /* already dead */
    }
}
function attachCapture(child, onLine) {
    let output = '';
    const append = (chunk) => {
        const s = typeof chunk === 'string' ? chunk : chunk.toString();
        if (onLine)
            for (const line of s.split(/\r?\n/))
                if (line.trim())
                    onLine(line);
        output = (output + s).slice(-MAX_JOB_OUTPUT);
    };
    child.stdout?.on('data', append);
    child.stderr?.on('data', append);
    return () => output;
}
/** Start a command as a tracked background job; returns the job id immediately. */
function startJob(command, cwd, onLine) {
    const id = `job_${++jobSeq}`;
    const job = {
        id,
        pid: undefined,
        command,
        status: 'running',
        exitCode: null,
        startedAt: Date.now(),
        endedAt: null,
        output: '',
    };
    jobs.set(id, job);
    trimJobs();
    const { file, args } = shellArgs(command);
    const child = spawn(file, args, { cwd, windowsHide: true });
    job.pid = child.pid;
    const getOutput = attachCapture(child, onLine);
    job.output = '';
    const syncOutput = () => {
        job.output = getOutput();
    };
    const syncTimer = setInterval(syncOutput, 200);
    syncTimer.unref?.();
    child.on('error', (e) => {
        clearInterval(syncTimer);
        syncOutput();
        job.status = 'failed';
        job.endedAt = Date.now();
        job.output += `\n[spawn error] ${e.message}`;
        trimJobs();
    });
    child.on('close', (code, signal) => {
        clearInterval(syncTimer);
        syncOutput();
        job.endedAt = Date.now();
        job.exitCode = code;
        job.status = signal ? 'killed' : code === 0 ? 'done' : 'failed';
        // A settled job is now evictable: trim on completion too, since a long
        // session can finish many jobs without ever starting a new one.
        trimJobs();
    });
    return id;
}
function killJob(id) {
    const job = jobs.get(id);
    if (!job || job.status !== 'running' || job.pid === undefined)
        return false;
    killTree(job.pid);
    return true;
}
function getJob(id) {
    return jobs.get(id);
}
function listJobs() {
    return [...jobs.values()].sort((a, b) => b.startedAt - a.startedAt);
}
/**
 * Run a shell command to completion with live line streaming and a hard
 * timeout (kills the whole process tree).
 */
function execShell(command, cwd, timeoutMs, onLine) {
    return new Promise((resolve) => {
        const { file, args } = shellArgs(command);
        const child = spawn(file, args, { cwd, windowsHide: true });
        const getOutput = attachCapture(child, onLine);
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            if (child.pid !== undefined)
                killTree(child.pid);
        }, timeoutMs);
        child.on('error', (e) => {
            clearTimeout(timer);
            resolve({ output: `${getOutput()}\n[spawn error] ${e.message}`.trim(), exitCode: 1, timedOut: false });
        });
        child.on('close', (code) => {
            clearTimeout(timer);
            resolve({
                output: getOutput().trim(),
                exitCode: timedOut ? 124 : (code ?? 1),
                timedOut,
            });
        });
    });
}
return { MAX_JOB_OUTPUT,shellArgs,killTree,startJob,killJob,getJob,listJobs,execShell };
}

__mod['core/processes.js'] = M24();

function M25() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { execShell, getJob, killJob, listJobs, startJob } = __mod['core/processes.js'];
const { snapshotTree } = __mod['core/undo.js'];
const runCommandTool = buildTool({
    name: 'run_command',
    description: 'Execute a shell command (PowerShell on Windows, bash elsewhere) in the workspace. Captures stdout/stderr, streams output live. Set background=true to run as a tracked background job. Use dedicated file tools for file edits.',
    input_schema: {
        type: 'object',
        properties: {
            command: { type: 'string', description: 'The command to execute' },
            timeout_ms: { type: 'number', description: 'Timeout in ms (default 60000, max 300000)' },
            background: { type: 'boolean', description: 'Run as a background job; returns a job id instead of waiting' },
        },
        required: ['command'],
    },
    requiresApproval: (input) => `Run command: ${str(input, 'command')}`,
    run: async (input, ctx) => {
        const command = str(input, 'command');
        // B2: a command can change anything in the workspace, so take a bounded
        // tree pre-image first (never fatal, shared per workspace per minute).
        snapshotTree({ dataDir: ctx.dataDir, cwd: ctx.cwd, tool: 'run_command', reason: `run_command: ${command}` });
        if (input.background === true) {
            const id = startJob(command, ctx.cwd, ctx.log ? (line) => ctx.log?.(`[bg] ${line.slice(0, 200)}`) : undefined);
            return { content: `Started background job ${id}. Use job_output / job_list / job_kill to manage it.` };
        }
        const timeoutMs = Math.min(300_000, Math.max(1_000, num(input, 'timeout_ms', 60_000)));
        const out = await execShell(command, ctx.cwd, timeoutMs, ctx.log ? (l) => ctx.log?.(l.slice(0, 240)) : undefined);
        const header = `exit=${out.exitCode}${out.timedOut ? ' (timed out)' : ''}`;
        const body = out.output || '(no output)';
        return { content: `${header}\n${body}`, isError: out.exitCode !== 0 };
    },
});
const jobListTool = buildTool({
    name: 'job_list',
    description: 'List background jobs started this session (status, command, exit code).',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async () => {
        const jobs = listJobs();
        if (jobs.length === 0)
            return { content: 'No background jobs this session.' };
        return {
            content: jobs
                .map((j) => {
                const ms = ((j.endedAt ?? Date.now()) - j.startedAt) / 1000;
                return `${j.id}  ${j.status.padEnd(7)} exit=${j.exitCode ?? '-'}  ${ms.toFixed(1)}s  ${j.command.slice(0, 90)}`;
            })
                .join('\n'),
        };
    },
});
const jobOutputTool = buildTool({
    name: 'job_output',
    description: 'Show captured output of a background job (tail).',
    input_schema: {
        type: 'object',
        properties: {
            id: { type: 'string', description: 'Job id, e.g. job_1' },
            last: { type: 'number', description: 'How many trailing characters to show (default 3000)' },
        },
        required: ['id'],
    },
    run: async (input) => {
        const job = getJob(str(input, 'id'));
        if (!job)
            return { content: `Unknown job: ${str(input, 'id')}`, isError: true };
        const tail = job.output.slice(-Math.max(200, num(input, 'last', 3000)));
        return { content: `${job.id} [${job.status}] exit=${job.exitCode ?? '-'}\n${tail || '(no output)'}` };
    },
});
const jobKillTool = buildTool({
    name: 'job_kill',
    description: 'Kill a running background job (and its process tree).',
    input_schema: {
        type: 'object',
        properties: { id: { type: 'string', description: 'Job id, e.g. job_1' } },
        required: ['id'],
    },
    requiresApproval: (input) => `Kill background job ${str(input, 'id')}`,
    run: async (input) => {
        const id = str(input, 'id');
        return killJob(id)
            ? { content: `Kill signal sent to ${id}.` }
            : { content: `Cannot kill ${id} (unknown or already stopped).`, isError: true };
    },
});
return { runCommandTool,jobListTool,jobOutputTool,jobKillTool };
}

__mod['tools/shell.js'] = M25();

function M26() {
const { buildTool, str } = __mod['core/tools.js'];
const { execShell } = __mod['core/processes.js'];
const { snapshotTree } = __mod['core/undo.js'];
const RECIPES = {
    winget: { command: (p) => `winget install --id ${p} -e --accept-source-agreements --accept-package-agreements`, timeout: 600_000 },
    npm: { command: (p) => `npm install -g ${p}`, timeout: 300_000 },
    pnpm: { command: (p) => `pnpm add -g ${p}`, timeout: 300_000 },
    pip: { command: (p) => `pip install ${p}`, timeout: 300_000 },
};
const installTool = buildTool({
    name: 'install',
    description: 'Install software via a package manager (winget | npm | pnpm | pip). Always requires explicit user approval. Prefer winget for desktop apps, npm/pip for language packages.',
    input_schema: {
        type: 'object',
        properties: {
            manager: { type: 'string', description: 'One of: winget, npm, pnpm, pip' },
            package: { type: 'string', description: 'Package id/name' },
        },
        required: ['manager', 'package'],
    },
    requiresApproval: (input) => `Install software on this machine: ${str(input, 'manager')} → ${str(input, 'package')}`,
    run: async (input, ctx) => {
        const manager = str(input, 'manager').toLowerCase();
        const pkg = str(input, 'package').trim();
        const recipe = RECIPES[manager];
        if (!recipe)
            return { content: `Unsupported manager "${manager}". Use: ${Object.keys(RECIPES).join(', ')}.`, isError: true };
        // Package identifiers are a small, well-known alphabet. ALLOWLIST rather than
        // denylist: the previous filter blocked \r \n ; & | but NOT PowerShell's
        // `$(...)` subexpression, a backtick escape, or `<`/`>` redirection — and the
        // name is interpolated straight into a shell string, so `install` with
        // package `$(whoami)` executed a command. A denylist over shell metacharacters
        // is unbounded; this alphabet is not.
        //
        // Covers: npm scopes (@scope/pkg), versions (pkg@1.2.3), pnpm (~, ^),
        // python extras (pkg[extra]), dotted and underscored names, and registry
        // paths. Anything else is a shell metacharacter or a path.
        if (!pkg || !/^(@?[a-z0-9][a-z0-9._~^@/+-]*)$/i.test(pkg)) {
            return { content: 'Invalid package name.', isError: true };
        }
        // B2: installs mostly act outside the workspace (global npm, registry,
        // %APPDATA%) and undo cannot reach those; the workspace tree pre-image is
        // still worth taking, and the undo tool states the limit out loud.
        snapshotTree({ dataDir: ctx.dataDir, cwd: ctx.cwd, tool: 'install', reason: `install ${manager} → ${pkg}` });
        const out = await execShell(recipe.command(pkg), ctx.cwd, recipe.timeout);
        return {
            content: `exit=${out.exitCode}\n${out.output || '(no output)'}`,
            isError: out.exitCode !== 0,
        };
    },
});
return { installTool };
}

__mod['tools/install.js'] = M26();

function M27() {
const { buildTool, str } = __mod['core/tools.js'];
const UA = 'Mozilla/5.0 (BlackRose personal assistant)';
function stripHtml(html) {
    return html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, ' ')
        .trim();
}
async function fetchWithTimeout(url, init, ms = 20_000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
        return await fetch(url, { ...init, signal: ctrl.signal, headers: { 'user-agent': UA, ...(init?.headers ?? {}) } });
    }
    finally {
        clearTimeout(timer);
    }
}
const webFetchTool = buildTool({
    name: 'web_fetch',
    description: 'Fetch a URL and return readable text (HTML tags stripped, max ~50KB).',
    input_schema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'Full http(s) URL' } },
        required: ['url'],
    },
    run: async (input) => {
        const url = str(input, 'url');
        if (!/^https?:\/\//i.test(url))
            return { content: 'Only http(s) URLs are supported.', isError: true };
        const res = await fetchWithTimeout(url);
        const ct = res.headers.get('content-type') ?? '';
        const text = await res.text();
        const body = ct.includes('html') ? stripHtml(text) : text;
        return { content: `HTTP ${res.status} ${ct}\n\n${body.slice(0, 50_000)}`, isError: !res.ok };
    },
});
const webSearchTool = buildTool({
    name: 'web_search',
    description: 'Search the web. Returns a list of result titles and URLs (best-effort, no API key needed).',
    input_schema: {
        type: 'object',
        properties: { query: { type: 'string', description: 'Search query' } },
        required: ['query'],
    },
    run: async (input) => {
        const query = str(input, 'query');
        const res = await fetchWithTimeout(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {}, 20_000);
        const html = await res.text();
        const results = [];
        const re = /<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
        let m;
        while ((m = re.exec(html)) && results.length < 8) {
            let href = m[1];
            if (href.startsWith('//'))
                href = 'https:' + href;
            // DuckDuckGo wraps results in a redirect: extract the real target
            const uddg = /[?&]uddg=([^&]+)/.exec(href);
            const url = uddg ? decodeURIComponent(uddg[1]) : href;
            const title = stripHtml(m[2]);
            if (title)
                results.push({ title, url });
        }
        if (results.length === 0)
            return { content: 'No results parsed (search layout may have changed).', isError: true };
        return { content: results.map((r, i) => `${i + 1}. ${r.title}\n   ${r.url}`).join('\n') };
    },
});
return { stripHtml,fetchWithTimeout,webFetchTool,webSearchTool };
}

__mod['tools/web.js'] = M27();

function M28() {
/**
 * Dependency-free TF-IDF retrieval used by memory and knowledge search.
 * Score = Σ (tf · idf) normalized by document length, plus a small recency
 * boost so freshly saved notes outrank stale ones on ties.
 */
function tokenize(text) {
    return (text.toLowerCase().match(/[a-z0-9_][a-z0-9_-]*/g) ?? []).filter((t) => t.length >= 2);
}
function snippetAround(text, term, radius = 90) {
    const lower = text.toLowerCase();
    const idx = lower.indexOf(term);
    if (idx === -1)
        return text.slice(0, radius * 2).replace(/\s+/g, ' ');
    const start = Math.max(0, idx - radius);
    const end = Math.min(text.length, idx + term.length + radius);
    return (start > 0 ? '…' : '') + text.slice(start, end).replace(/\s+/g, ' ') + (end < text.length ? '…' : '');
}
function rankDocs(query, docs, topK = 5) {
    const queryTerms = Array.from(new Set(tokenize(query)));
    if (queryTerms.length === 0 || docs.length === 0)
        return [];
    const docTokens = docs.map((d) => tokenize(d.text));
    const df = new Map();
    for (const tokens of docTokens) {
        for (const t of new Set(tokens))
            df.set(t, (df.get(t) ?? 0) + 1);
    }
    const N = docs.length;
    const now = Date.now();
    const scored = docs.map((d, i) => {
        const tokens = docTokens[i];
        const tf = new Map();
        for (const t of tokens)
            tf.set(t, (tf.get(t) ?? 0) + 1);
        let score = 0;
        for (const q of queryTerms) {
            const f = tf.get(q);
            if (!f)
                continue;
            const idf = Math.log(1 + N / (df.get(q) ?? 1));
            score += f * idf;
        }
        if (tokens.length > 0)
            score = score / Math.sqrt(tokens.length);
        if (d.mtime) {
            const ageDays = Math.max(0, (now - d.mtime) / 86_400_000);
            score *= 1 + Math.max(0, 1 - ageDays / 30) * 0.2;
        }
        const firstTerm = queryTerms.find((q) => tokens.includes(q)) ?? '';
        return { id: d.id, score, snippet: snippetAround(d.text, firstTerm) };
    });
    return scored
        .filter((s) => s.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, topK);
}
return { tokenize,rankDocs };
}

__mod['memory/tfidf.js'] = M28();

function M29() {
const { tokenize } = __mod['memory/tfidf.js'];
/**
 * Pure-JS hashed subword embeddings (fastText-style, zero dependencies).
 *
 * A text is embedded by hashing features into a fixed-size vector (feature
 * hashing / "hashing trick"): stemmed word unigrams, word bigrams and
 * character trigrams. Hashing keeps the representation deterministic and
 * dependency-free; subword features give morphological robustness ("checklist"
 * matches "checklists", "deploy" is near "deployment") without any trained
 * model. Cosine similarity over these vectors is lexical generalization, NOT
 * model-based semantics — a real embedding model can replace this module later
 * behind the same interface (loadStore / vectorFor / cosine).
 */
const EMBED_MODEL = 'br-hash-v1';
const EMBED_DIM = 256;
/** Minimal, deterministic suffix stemmer (en-oriented, conservative). */
function stem(token) {
    let t = token;
    if (t.length > 4 && t.endsWith('ies'))
        return t.slice(0, -3) + 'y';
    if (t.length > 5 && t.endsWith('sses'))
        return t.slice(0, -2);
    for (const suf of ['ing', 'ed', 'es', 'ly', 's']) {
        if (t.length > suf.length + 2 && t.endsWith(suf)) {
            t = t.slice(0, -suf.length);
            break;
        }
    }
    return t;
}
/** FNV-1a 32-bit string hash — fast, deterministic, good bucket spread. */
function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
}
/** Feature set for one text: weighted unigrams, bigrams and char trigrams. */
function embedFeatures(text) {
    const feats = new Map();
    const bump = (k, w) => feats.set(k, (feats.get(k) ?? 0) + w);
    const tokens = tokenize(text);
    for (const tok of tokens) {
        bump('w:' + stem(tok), 1);
        const padded = ` ${tok} `;
        for (let i = 0; i + 3 <= padded.length; i++)
            bump('c:' + padded.slice(i, i + 3), 0.4);
    }
    for (let i = 0; i + 1 < tokens.length; i++) {
        bump('b:' + stem(tokens[i]) + '_' + stem(tokens[i + 1]), 0.7);
    }
    return feats;
}
/** Embed text into a normalized dim-dimensional vector. */
function embedText(text, dim = EMBED_DIM) {
    const v = new Float64Array(dim);
    for (const [k, w] of embedFeatures(text)) {
        const h = fnv1a(k);
        const bucket = h % dim;
        const sign = (Math.imul(h, 0x9e3779b1) >>> 31) === 1 ? -1 : 1;
        v[bucket] += sign * w;
    }
    let norm = 0;
    for (const x of v)
        norm += x * x;
    norm = Math.sqrt(norm) || 1;
    for (let i = 0; i < dim; i++)
        v[i] /= norm;
    return v;
}
/** Cosine similarity (inputs are expected to be L2-normalized). */
function cosine(a, b) {
    let d = 0;
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++)
        d += a[i] * b[i];
    return d;
}
/** Cheap, deterministic text fingerprint for change detection. */
function textHash(text) {
    return fnv1a(text);
}
return { EMBED_MODEL,EMBED_DIM,stem,fnv1a,embedFeatures,embedText,cosine,textHash };
}

__mod['memory/embed.js'] = M29();

function M30() {
const { EMBED_DIM, EMBED_MODEL, embedText } = __mod['memory/embed.js'];
const { keyId, keyUsable, recordKeyFailure, recordKeySuccess } = __mod['llm/keyHealth.js'];
const { maskSecret, readProviderKeys } = __mod['core/keys.js'];
/**
 * Pluggable embedding backend for vectors.ts / hybrid.ts.
 *
 * API-only since 2026-09-29 (docs/07-BUILD-CHECKLIST B25/B5): the primary
 * backend is Google's `gemini-embedding-001` (3072-dim), called through
 * `batchEmbedContents` so an entire query+document set is ONE HTTP request.
 * Semantics, not just morphology: "how do I deploy" ranks near "release
 * checklist steps".
 *
 * Fallback backend: the pure-JS hashed subword embedder (br-hash-v1, 256-dim)
 * from embed.ts, used when no key is configured, the call fails, or
 * BLACKROSE_EMBED=off. Retrieval then degrades to lexical â€” it does not break.
 * Every vector in the store records which model made it (see vectors.ts);
 * different models never share a vector space, so switching between the API
 * encoder and the hash fallback invalidates the old index rather than mixing
 * spaces.
 *
 * Configuration:
 *   BLACKROSE_EMBED          â€” "off" forces the hash embedder everywhere
 *   BLACKROSE_EMBED_MODEL    â€” model id (default: gemini-embedding-001)
 *   BLACKROSE_EMBED_API_KEY  â€” key; defaults to the Gemini key already stored
 *                              in the vault (BLACKROSE_GEMINI_API_KEY)
 *
 * Only Gemini was verified to serve embeddings to the configured routes on
 * 2026-09-29 (Groq exposes none, NVIDIA nv-embed-v1 is EOL, OpenRouter 401,
 * HF/Cloudflare no such model), so this is a single provider by design.
 */



const HASH_DIM = EMBED_DIM;
const HASH_MODEL = EMBED_MODEL;
const DEFAULT_EMBED_MODEL = 'gemini-embedding-001';
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const EMBED_TIMEOUT_MS = 20_000;
/**
 * Gemini batchEmbedContents caps a request; chunk to stay well inside it.
 *
 * Measured live 2026-09-30 against the configured key: n=1/10/25 return 200
 * (3072-d), n=50 and n=100 return HTTP 429. The published limit is not
 * published for this key's tier, so the batch is sized to the largest size
 * verified to succeed with headroom, not to a guessed 100. The binding limit
 * on this key turned out to be requests-per-minute rather than per-request
 * size (see BATCH_PAUSE_MS); 25 is the per-request half of the story.
 *
 * This matters beyond throughput: embedBatch treats ANY failed batch as a
 * whole-call fallback to the hash embedder, so an over-large batch silently
 * downgrades the entire corpus to lexical-only retrieval instead of erroring.
 * Oversized here means "no semantic search", not "slower search".
 */
const MAX_BATCH = 8;
/**
 * Delay between batches. The binding constraint is the free tier's per-minute
 * REQUEST budget, not the per-request size cap: a probe of 25 single-text
 * requests returned 200 four times and 429 twenty times. So the pause is what
 * keeps a full-corpus run inside the window; the batch size is only there to
 * stay under the per-request cap.
 */
const BATCH_PAUSE_MS = 2_000;
/**
 * 429/5xx retry budget. The free tier's embedding quota is a DAILY budget, not
 * a per-minute one â€” see DAILY_QUOTA_NOTE. A single-text probe kept returning
 * 429 for 9+ minutes straight, so waiting inside a run cannot rescue it.
 *
 * The ladder therefore only covers short, transient throttles: 4 attempts,
 * 2s base, 15s ceiling, so a genuinely stuck call fails over to the hash
 * embedder within ~30s instead of hanging a user query for minutes. It is
 * deliberately not sized to outlast an exhausted daily quota, because that
 * would mean hanging a warm-up for hours to no purpose â€” that case is
 * detected outright (see DAILY_QUOTA_ID). When the daily quota is spent the
 * honest outcome is a fallback plus a clear message, not a long stall.
 */
const MAX_RETRIES = 4;
const BASE_BACKOFF_MS = 2_000;
const MAX_BACKOFF_MS = 15_000;
/**
 * Why a full-corpus warm-up cannot be completed in one sitting on a free key.
 *
 * The API says it plainly: quota metric
 * `embed_content_free_tier_requests`, quota id
 * `EmbedContentRequestsPerDayPerProjectPerModel-FreeTier`, value 1000, and
 * "Please retry in 40s" â€” but a 40s wait does not help, because the metric is
 * per DAY. The 40s is the generic per-minute throttle message; the binding
 * limit is the 1000/day cap.
 *
 * Consequence for this project: 643 knowledge chunks at MAX_BATCH=25 is ~26
 * requests, which fits comfortably inside 1000/day. That is why partial runs
 * got through several hundred chunks before the window closed â€” the cap was
 * already partly spent by earlier experiments that same day. Running the
 * warm-up once a day, or switching BLACKROSE_EMBED_MODEL to a paid tier,
 * completes the corpus.
 *
 * Because retrieval re-embeds lazily anyway (see vectors.ts), a partial warm-up
 * is not a broken state: unembedded chunks embed on first touch.
 *
 * Exposed for the doctor/warm-up messaging via freeTierDailyRequestQuota().
 */
const DAILY_QUOTA_FREE_TIER_REQUESTS = 1000;
/** Free-tier daily embedding request cap for this model, for user-facing hints. */
function freeTierDailyRequestQuota() {
    return DAILY_QUOTA_FREE_TIER_REQUESTS;
}
/**
 * When the DAILY quota was last observed exhausted (epoch ms), or 0.
 *
 * WHY THIS EXISTS: until 2026-10-02 the only signal that retrieval had silently
 * degraded from semantic to lexical was a console.warn below. The desktop app
 * has no console, so a user got keyword-only search with nothing on screen to
 * explain it â€” the exact "invisible to the user" failure the B5 review called
 * out. Health and --doctor can now ask instead of guessing.
 *
 * It is cleared by the next SUCCESSFUL API batch rather than by a clock, so it
 * self-heals the moment Google rolls the per-day budget over â€” no guessing
 * about the reset timezone, and a cleared flag is direct evidence that the API
 * is answering again.
 */
let quotaExhaustedAt = 0;
/** Epoch-ms of the last observed daily-quota exhaustion, or 0 if none/healthy. */
function embedQuotaExhaustedAt() {
    return quotaExhaustedAt;
}
/**
 * Snapshot of the embedding subsystem for /api/health and --doctor.
 * Purely local: reads configuration + in-process state, makes NO HTTP call, so
 * it can run on every health poll.
 *
 * `degraded` here means "the backend would answer with lexical vectors right
 * now" â€” true for an explicitly disabled/no-key setup too, because for the
 * user the consequence is identical (keyword search, not semantic search).
 */
function embedStatus() {
    const backend = embedBackendLabel();
    return {
        backend,
        configured: backend === 'gemini',
        activeModel: backend === 'gemini' ? embedModelName() : HASH_MODEL,
        dailyRequestQuota: DAILY_QUOTA_FREE_TIER_REQUESTS,
        quotaExhaustedAt,
        degraded: backend === 'hash' || quotaExhaustedAt > 0,
    };
}
/**
 * Embedding key pool (B5 follow-up).
 *
 * Measured 2026-10-02 against the live API with this machine's stored keys: 10 of
 * 13 Gemini keys still serve `batchEmbedContents` (dim 3072) and 3 answer HTTP 403
 * "Your project has been denied access". The free tier is 1000 embed requests per
 * day PER KEY, so a pool is worth real multiples â€” but the old `embedKey()` read a
 * single environment variable and never consulted the vault, which meant the whole
 * pool was invisible and one spent key silently degraded the corpus to the hash
 * embedder for the rest of the day.
 *
 * Two deliberate choices:
 *
 * - Key health is tracked under its OWN namespace ('BLACKROSE_EMBED_API_KEY#N'),
 *   not the chat route's. Embedding budget being spent says nothing about a key's
 *   ability to answer a chat turn; sharing a health record would let a spent
 *   embedding quota park a perfectly good conversational key.
 * - `configureEmbedKeys` is an explicit seam rather than a global read of some
 *   ambient data dir. If a host never calls it, behaviour is exactly what it was
 *   before â€” env-only, no rotation â€” so nothing depends on this being wired.
 */
let EMBED_KEY_POOL = [];
/** Load the embedding key pool from the vault. Safe to call more than once. */
function configureEmbedKeys(dataDir) {
    const stored = readProviderKeys(dataDir, 'BLACKROSE_GEMINI_API_KEY');
    // A dedicated embed key still wins: it is an explicit operator override for
    // exactly this subsystem and must not be rotated away from.
    const dedicated = process.env.BLACKROSE_EMBED_API_KEY?.trim();
    EMBED_KEY_POOL = dedicated ? [dedicated] : stored;
    return EMBED_KEY_POOL.length;
}
/** How many keys the embedder may use (diagnostics; never exposes a value). */
function embedKeyCount() {
    return pool().length;
}
/** The pool, or the legacy single-key env chain when it was never configured. */
function pool() {
    if (EMBED_KEY_POOL.length > 0)
        return EMBED_KEY_POOL;
    const legacy = process.env.BLACKROSE_EMBED_API_KEY ?? process.env.BLACKROSE_GEMINI_API_KEY ?? process.env.GOOGLE_AI_API_KEY ?? '';
    return legacy ? [legacy] : [];
}
function embedKeyId(index) {
    return keyId('BLACKROSE_EMBED_API_KEY', index, maskSecret(pool()[index] ?? ''));
}
/** Next key worth trying: skip ones already parked/cooling down. */
function nextKey(cursor) {
    const keys = pool();
    if (keys.length === 0)
        return null;
    for (let step = 0; step < keys.length; step++) {
        const i = (cursor + step) % keys.length;
        const id = embedKeyId(i);
        if (step === keys.length - 1 || keyUsable(id))
            return { key: keys[i], id, index: i };
    }
    return null;
}
function embedKey() {
    return pool()[0] ?? '';
}
function embedModelName() {
    return process.env.BLACKROSE_EMBED_MODEL ?? DEFAULT_EMBED_MODEL;
}
/** Base URL for diagnostics (no HTTP call). */
function embedBaseUrl() {
    return GEMINI_BASE;
}
function normalize(values) {
    let norm = 0;
    for (const x of values)
        norm += x * x;
    norm = Math.sqrt(norm) || 1;
    return Float64Array.from(values, (x) => x / norm);
}
/**
 * Retry a batch that came back 429. The Gemini free tier enforces a
 * per-minute request/token budget, so a full-corpus warm-up reliably trips it
 * partway through â€” that is a transient condition, not a broken backend.
 *
 * Without this, a 429 becomes indistinguishable from "no key" and embedBatch
 * falls back to the hash embedder, silently downgrading the whole corpus to
 * lexical-only retrieval (see MAX_BATCH). Backing off and retrying keeps the
 * corpus in one real vector space.
 *
 * Only 429/5xx are retried: a 400 (bad key, bad request) will never succeed,
 * so retrying it just delays the honest fallback.
 *
 * The daily-quota 429 is NOT retried at all. That is the single most important
 * branch here: the free tier's exhausted quota comes back as a 429 carrying the
 * quota id `EmbedContentRequestsPerDayPerProjectPerModel-FreeTier`, alongside a
 * misleading "retry in 40s" hint. Retrying it made every embedding call in the
 * app stall for the whole backoff ladder (up to ~8 minutes per call), which
 * froze the smoke suite and would freeze a user query. When the daily budget is
 * spent the honest outcome is an immediate fallback plus one clear log line.
 */
const DAILY_QUOTA_ID = 'EmbedContentRequestsPerDayPerProjectPerModel-FreeTier';
/** True when a 429 body is the exhausted-per-DAY quota, which no wait can fix. */
async function isDailyQuotaExhausted(res) {
    try {
        const body = await res.text();
        return body.includes(DAILY_QUOTA_ID);
    }
    catch {
        return false;
    }
}
async function attemptWithKey(model, chunk, apiKey) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), EMBED_TIMEOUT_MS);
    try {
        // x-goog-api-key header, NOT ?key=... in the query string: a URL lands in
        // proxy logs, browser history and error echoes. llm/gemini.ts already made
        // this call; the embedder was the last place still leaking the secret.
        const res = await fetch(`${GEMINI_BASE}/models/${model}:batchEmbedContents`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
            body: JSON.stringify({
                requests: chunk.map((text) => ({ model: `models/${model}`, content: { parts: [{ text }] } })),
            }),
            signal: ac.signal,
        });
        if (res.status === 429) {
            return (await isDailyQuotaExhausted(res)) ? { kind: 'spent' } : { kind: 'transient' };
        }
        if (res.status === 401 || res.status === 403) {
            const body = await res.text().catch(() => '');
            return { kind: 'rejected', detail: `HTTP ${res.status} ${body.replace(/\s+/g, ' ').slice(0, 120)}` };
        }
        if (res.status >= 500)
            return { kind: 'transient' };
        if (!res.ok)
            return { kind: 'fatal' };
        const data = (await res.json());
        if (data.error || !Array.isArray(data.embeddings) || data.embeddings.length !== chunk.length)
            return { kind: 'fatal' };
        const out = [];
        for (const e of data.embeddings) {
            if (!e || !Array.isArray(e.values) || e.values.length === 0)
                return { kind: 'fatal' };
            if (!e.values.every((v) => typeof v === 'number' && Number.isFinite(v)))
                return { kind: 'fatal' };
            out.push(normalize(e.values));
        }
        return { kind: 'ok', vectors: out };
    }
    catch {
        // Network/abort: transient, same as a 5xx.
        return { kind: 'transient' };
    }
    finally {
        clearTimeout(t);
    }
}
async function postBatchWithRetry(model, chunk) {
    let cursor = 0;
    let spentAll = false;
    const total = Math.max(pool().length, 1);
    // One pass over the pool. A spent or rejected key is stepped over rather than
    // retried, which is what makes a 13-key pool behave like a single healthy one.
    for (let step = 0; step < total; step++) {
        const entry = nextKey(cursor);
        if (!entry)
            break;
        cursor = entry.index;
        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                // Exponential backoff, capped: long enough to clear a per-minute
                // window, short enough that a warm-up of hundreds of chunks still ends.
                const wait = Math.min(BASE_BACKOFF_MS * 2 ** (attempt - 1), MAX_BACKOFF_MS);
                await new Promise((r) => setTimeout(r, wait));
            }
            const r = await attemptWithKey(model, chunk, entry.key);
            if (r.kind === 'ok') {
                recordKeySuccess(entry.id);
                // Reaching here means the API answered â€” so any earlier daily-quota
                // exhaustion is over. Cleared here rather than by a timer so the flag
                // can never claim "degraded" while the backend is demonstrably healthy.
                quotaExhaustedAt = 0;
                return r.vectors;
            }
            if (r.kind === 'fatal')
                return null;
            if (r.kind === 'rejected') {
                recordKeyFailure(entry.id, r.detail);
                break; // try the next key; never burn retries on a dead credential
            }
            if (r.kind === 'spent') {
                // This key's per-DAY budget is gone. No wait helps THIS key, but another
                // key may have budget left â€” that is the entire reason for a pool.
                recordKeyFailure(entry.id, `daily embedding quota exhausted (${DAILY_QUOTA_ID})`);
                spentAll = true;
                break;
            }
            // transient: rotate to the NEXT key rather than replaying the backoff
            // ladder on this one. A 429/5xx is usually a rate window that another
            // key in the pool is outside of, so waiting here just burns the turn while
            // a working credential sits idle. The ladder still runs when there is
            // nowhere left to rotate to (last key of the pool).
            recordKeyFailure(entry.id, 'transient embedding failure (429/5xx/network)');
            // Only rotate when a DIFFERENT key is actually available; otherwise fall
            // through to the backoff ladder below rather than giving up.
            const others = pool().filter((_, i) => i !== entry.index && keyUsable(embedKeyId(i)));
            if (others.length > 0) {
                cursor = (entry.index + 1) % pool().length;
                break;
            }
        }
    }
    if (spentAll) {
        // Every key tried had its daily budget spent. That is the only condition
        // that genuinely means "retrieval is lexical now", so it is the only one
        // that sets the user-visible degraded flag.
        quotaExhaustedAt = Date.now();
        console.warn(`[embed] Gemini daily embedding quota is exhausted on all ${pool().length} key(s) ` +
            `(${DAILY_QUOTA_ID}, ${DAILY_QUOTA_FREE_TIER_REQUESTS}/day each). Falling back to the ` +
            'hash embedder â€” retrieval stays lexical until a quota resets. No retry: the cap is per day.');
    }
    return null;
}
async function postBatch(model, chunk) {
    return postBatchWithRetry(model, chunk);
}
/** Test seam: drop the configured pool back to the legacy env-only behaviour. */
function resetEmbedKeys() {
    EMBED_KEY_POOL = [];
}
/**
 * Embed one or more texts, always within a single vector space. The whole set
 * goes to the API in one (or few) batched call; if any batch fails the entire
 * batch falls back to the hash embedder â€” never a mix of two spaces.
 */
async function embedBatch(texts) {
    const model = embedModelName();
    if (process.env.BLACKROSE_EMBED !== 'off' && embedKey()) {
        const out = [];
        for (let i = 0; i < texts.length; i += MAX_BATCH) {
            // Pace between batches so a large set (e.g. a knowledge warm-up) does not
            // walk into the rate window and fall back wholesale.
            if (i > 0)
                await new Promise((r) => setTimeout(r, BATCH_PAUSE_MS));
            const part = await postBatch(model, texts.slice(i, i + MAX_BATCH));
            if (!part) {
                out.length = 0;
                break;
            }
            out.push(...part);
        }
        if (out.length === texts.length && out.length > 0) {
            return { vectors: out, backend: 'gemini', model, dim: out[0].length };
        }
    }
    return {
        vectors: texts.map((t) => embedText(t)),
        backend: 'hash',
        model: HASH_MODEL,
        dim: HASH_DIM,
    };
}
/** Single-text convenience wrapper. */
async function embedOne(text) {
    return embedBatch([text]);
}
/** Current backend label for diagnostics (no HTTP call). */
function embedBackendLabel() {
    return process.env.BLACKROSE_EMBED === 'off' || !embedKey() ? 'hash' : 'gemini';
}
/** True when the API backend is configured and enabled. */
function embedApiConfigured() {
    return embedBackendLabel() === 'gemini';
}
/**
 * Test seam kept for existing callers. There is no cached probe any more â€” the
 * API backend is chosen from configuration on every call â€” so this is a no-op
 * retained so test/inspection code does not have to change.
 */
function resetEmbedProbe() {
    /* no cached probe to clear */
}
return { freeTierDailyRequestQuota,embedQuotaExhaustedAt,embedStatus,configureEmbedKeys,embedKeyCount,embedModelName,embedBaseUrl,resetEmbedKeys,embedBatch,embedOne,embedBackendLabel,embedApiConfigured,resetEmbedProbe };
}

__mod['memory/embedder.js'] = M30();

function M31() {
const { textHash } = __mod['memory/embed.js'];
const { embedBatch } = __mod['memory/embedder.js'];
/** Monotonic suffix so two saves in one process never collide on a temp file. */
let tmpCounter = 0;
const MAX_ENTRIES = 8000;
function loadStore(dataDir, model, dim) {
    const p = path.join(dataDir, 'vectors', 'index.json');
    let file = { model, dim, entries: {} };
    let rebuilt = false;
    // "Adopted" means the on-disk index was actually usable AND carried vectors.
    // An empty or absent file is not something worth protecting: there is nothing
    // there to lose, so a fallback write is harmless (and self-healing).
    let adopted = false;
    try {
        const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
        // dim <= 0 means "not known yet": adopt the stored dimension when the
        // model matches, instead of forcing a rebuild on every load.
        const dimOk = dim <= 0 ? raw.dim > 0 : raw.dim === dim;
        if (raw.model === model && dimOk && raw.entries && typeof raw.entries === 'object') {
            file = { model: raw.model, dim: raw.dim, entries: raw.entries };
            adopted = Object.keys(raw.entries).length > 0;
        }
        else {
            rebuilt = true; // model/dim changed → old vectors are invalid, start fresh
        }
    }
    catch {
        /* first load, corrupt, or model changed → rebuild */
    }
    return { path: p, file, dirty: rebuilt, rebuilt, unsafeFallback: false, hadRealIndex: adopted };
}
/** Decode a stored vector (base64 Float32) for similarity computation. */
function decode(v) {
    const buf = Buffer.from(v, 'base64');
    return new Float32Array(buf.buffer, buf.byteOffset, Math.floor(buf.byteLength / 4));
}
/**
 * Return vectors for the given ids, embedding + upserting the ones that are
 * missing or whose text fingerprint changed. The whole batch is embedded in
 * one backend call (one vector space, one round trip). Marks the store dirty
 * (persist with saveStore).
 */
async function vectorsFor(store, items) {
    const missing = [];
    for (const { id, text } of items) {
        const h = textHash(text);
        const existing = store.file.entries[id];
        if (!existing || existing.h !== h)
            missing.push({ id, text });
    }
    const out = new Map();
    const fresh = new Map();
    if (missing.length > 0) {
        const res = await embedBatch(missing.map((m) => m.text));
        if (res.model !== store.file.model || res.dim !== store.file.dim) {
            // Backend changed mid-flight: old vectors are invalid in the new space.
            store.file = { model: res.model, dim: res.dim, entries: {} };
            store.rebuilt = true;
            // ...and writing THAT to disk is how a real store gets destroyed by a
            // transient outage. The hash embedder "works", so every search silently
            // succeeds while quietly replacing a 3072-d Gemini index with 256-d
            // lexical vectors. Observed live on 2026-09-30: with the daily quota
            // spent, ordinary searches in the running app rewrote the whole index as
            // br-hash-v1 and the warm-up then found 643 "already embedded" chunks in
            // the wrong space. So a fallback result is served from memory and never
            // persisted — see saveStore.
            store.unsafeFallback = true;
            // The swap above dropped every previously-cached id, including the ones
            // in THIS call that needed no embedding. Leaving them to be read back
            // from the (now empty) store dereferenced undefined and crashed the tool
            // with "Cannot read properties of undefined (reading 'v')" — a hard
            // failure in the exact situation the fallback exists to survive. Re-embed
            // them so the whole call is answered from one vector space.
            const stranded = items.filter((it) => !missing.some((m) => m.id === it.id));
            if (stranded.length > 0) {
                const again = await embedBatch(stranded.map((s) => s.text));
                stranded.forEach((s, i) => {
                    const v = again.vectors[i];
                    fresh.set(s.id, v);
                    store.file.entries[s.id] = {
                        v: Buffer.from(new Float32Array(v).buffer).toString('base64'),
                        h: textHash(s.text),
                    };
                });
            }
        }
        missing.forEach((m, i) => {
            const v = res.vectors[i];
            fresh.set(m.id, v);
            store.file.entries[m.id] = {
                v: Buffer.from(new Float32Array(v).buffer).toString('base64'),
                h: textHash(m.text),
            };
        });
        store.dirty = true;
    }
    for (const { id } of items)
        out.set(id, fresh.get(id) ?? decode(store.file.entries[id].v));
    return out;
}
/** Drop entries whose ids are no longer present (namespace-scoped pruning). */
function pruneStore(store, keepIds, prefix) {
    let changed = false;
    for (const id of Object.keys(store.file.entries)) {
        if (id.startsWith(prefix) && !keepIds.has(id)) {
            delete store.file.entries[id];
            changed = true;
        }
    }
    if (changed)
        store.dirty = true;
}
/** Persist the store (no-op unless dirty). Caps the entry count.
 *
 *  REFUSES to write when the in-memory index came from a fallback backend
 *  (store.unsafeFallback). Retrieval still works — the fallback vectors are in
 *  memory and every search this session behaves normally — but persisting them
 *  would overwrite a genuine vector space with lexical-grade vectors, and the
 *  loss is invisible until much later. A failed embed is a reason to keep the
 *  last good index, never a reason to replace it.
 */
function saveStore(store) {
    if (!store.dirty)
        return;
    // Refuse ONLY when a real index would be destroyed. The two cases differ:
    //
    //  - hadRealIndex === false: nothing usable was on disk (no index yet, or the
    //    model/dim changed), so there is nothing to protect. Writing the fallback
    //    is correct and self-healing: the header names the fallback, so the next
    //    healthy run rebuilds back to the API space on its own.
    //  - hadRealIndex === true: a good index was loaded and a fallback result
    //    would silently replace it. This is the destructive case, seen live on
    //    2026-09-30 when an app session with a spent quota rewrote a 3072-d
    //    gemini-embedding-001 index as 256-d br-hash-v1. Never write.
    if (store.unsafeFallback && store.hadRealIndex) {
        store.dirty = false;
        console.warn(`[vectors] not saving: ${store.file.model} fallback vectors would overwrite the ` +
            'real index. Retrieval is degraded to lexical for this session only.');
        return;
    }
    const ids = Object.keys(store.file.entries);
    if (ids.length > MAX_ENTRIES) {
        for (const id of ids.slice(0, ids.length - MAX_ENTRIES))
            delete store.file.entries[id];
    }
    fs.mkdirSync(path.dirname(store.path), { recursive: true });
    // ATOMIC. This is the whole retrieval index: a plain writeFileSync truncates
    // first, so an interrupt (crash, kill, power loss) mid-write leaves a
    // half-serialised JSON file and the ENTIRE index is lost with no error — the
    // silent data-loss failure mode. Write a sibling temp file, flush it, then
    // rename, which is atomic within a filesystem. Same pattern as vault.ts:165.
    // Unique per write via pid + a monotonic counter, so two concurrent saves can
    // never share a temp file. Avoids importing crypto for one call.
    const tmp = `${store.path}.tmp-${process.pid}-${tmpCounter++}`;
    try {
        const fd = fs.openSync(tmp, 'w');
        try {
            fs.writeFileSync(fd, JSON.stringify(store.file));
            fs.fsyncSync(fd);
        }
        finally {
            fs.closeSync(fd);
        }
        fs.renameSync(tmp, store.path);
    }
    catch (e) {
        // Leave the previous good index intact rather than swapping in a bad one.
        try {
            fs.rmSync(tmp, { force: true });
        }
        catch { /* nothing further to do */ }
        throw e;
    }
    store.dirty = false;
}
/**
 * Read the on-disk index header without loading every vector, for /api/health
 * and --doctor. Returns null when there is no usable index yet.
 *
 * A gemini-embedding-001 index is ~8 KB per entry, so parsing index.json on
 * every health poll would be a multi-megabyte read every few seconds. The stat
 * mtime is the cache key: the file is re-parsed only when it actually changes,
 * which costs one syscall in the common case.
 *
 * This is deliberately a separate path from loadStore(): health only needs to
 * REPORT what is on disk, and must never adopt, rebuild or mutate it.
 */
let indexStatsCache = null;
function vectorIndexStats(dataDir) {
    const p = path.join(dataDir, 'vectors', 'index.json');
    try {
        const st = fs.statSync(p);
        if (indexStatsCache && indexStatsCache.key === p && indexStatsCache.mtimeMs === st.mtimeMs) {
            return indexStatsCache.stats;
        }
        const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (!raw || typeof raw !== 'object' || !raw.entries)
            return null;
        const stats = {
            model: raw.model,
            dim: raw.dim,
            entries: Object.keys(raw.entries).length,
        };
        indexStatsCache = { key: p, mtimeMs: st.mtimeMs, stats };
        return stats;
    }
    catch {
        // Absent, unreadable or mid-write: report "no index" rather than failing a
        // health check. Saving is atomic enough in practice, but health must never
        // be the thing that surfaces a transient parse error.
        indexStatsCache = null;
        return null;
    }
}
return { loadStore,vectorsFor,pruneStore,saveStore,vectorIndexStats };
}

__mod['memory/vectors.js'] = M31();

function M32() {
const { cosine } = __mod['memory/embed.js'];
const { rankDocs } = __mod['memory/tfidf.js'];
const { loadStore, pruneStore, saveStore, vectorsFor } = __mod['memory/vectors.js'];
const { embedModelName } = __mod['memory/embedder.js'];
/** Calibrated on 768-d nomic-embed-text; 256-d hashed vectors spread wider. */
function cosFloor(dim) {
    return dim >= 384 ? 0.25 : 0.08;
}
const MIN_SCORE = 0.02;
async function hybridRank(query, docs, store, prefix, topK = 5, 
/**
 * How many lexical candidates to embed and re-rank semantically.
 *
 * WHY THIS EXISTS (2026-10-01). hybridRank used to embed the query AND every
 * document in the corpus before it could score anything. Embedding is paced at
 * MAX_BATCH = 8 with a 2s pause between batches, so a 643-chunk knowledge base
 * is 81 network round trips and 160+ seconds of dead time — and knowledge_search
 * returned nothing at all until it finished. The user sees a frozen tool with
 * no output; from the outside it is indistinguishable from a broken search.
 *
 * Ranking the lexical candidates first and embedding only those cuts the
 * network work to a handful of requests regardless of corpus size, and costs
 * nothing in quality: TF-IDF is already half the score, so the documents that
 * will win are almost always already in its top slice. The semantic pass then
 * re-orders that shortlist, which is the part it is actually good at.
 *
 * Over-fetching by 5x guards the case where semantics would have promoted a
 * document TF-IDF ranked low.
 */
candidates = Math.max(topK * 5, 20)) {
    if (docs.length === 0)
        return [];
    pruneStore(store, new Set(docs.map((d) => d.id)), prefix);
    // Lexical first — it needs no network and it decides who gets embedded.
    const tfidf = rankDocs(query, docs, docs.length);
    if (tfidf.length === 0)
        return [];
    const shortlist = tfidf.slice(0, Math.min(candidates, docs.length));
    // One batched backend call for the query + the shortlist only: a single vector
    // space, a single model load, a small number of round trips.
    const vecs = await vectorsFor(store, [
        { id: '\u0000query', text: query },
        ...shortlist.map((r) => {
            const d = docs.find((x) => x.id === r.id);
            return { id: r.id, text: d.text };
        }),
    ]);
    saveStore(store);
    const q = vecs.get('\u0000query');
    const floor = cosFloor(q.length);
    // Loop, not Math.max(...scores): spreading a very large corpus into an
    // argument list throws RangeError once the doc count exceeds the engine's
    // argument limit, and this is the hot retrieval path — one oversized library
    // would break search outright rather than degrade.
    let maxT = 1e-9;
    for (const r of tfidf)
        if (r.score > maxT)
            maxT = r.score;
    const byId = new Map(tfidf.map((r) => [r.id, r]));
    const scored = [];
    for (const r of shortlist) {
        const d = docs.find((x) => x.id === r.id);
        const cosN = Math.max(0, (cosine(q, vecs.get(d.id)) - floor) / (1 - floor));
        const t = byId.get(d.id);
        const tN = t ? t.score / maxT : 0;
        const combined = 0.5 * tN + 0.5 * cosN;
        if (combined <= MIN_SCORE)
            continue;
        scored.push({ id: d.id, score: combined, snippet: t?.snippet ?? d.text.slice(0, 180).replace(/\s+/g, ' ') });
    }
    return scored.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, topK);
}
/**
 * Test/inspection helper: open a store bound to the currently configured
 * embedding backend (model + dim are validated/recorded by the store).
 */
function openStore(dataDir) {
    return loadStore(dataDir, embedModelName(), 0);
}
return { hybridRank,openStore };
}

__mod['memory/hybrid.js'] = M32();

function M33() {
/**
 * Secret redaction for anything BlackRose persists (idea taken from Hindsight's
 * "Memory Defense": scan every retain for secrets and either redact or refuse
 * before it reaches storage).
 *
 * WHY THIS EXISTS
 * BlackRose writes memories, knowledge chunks and transcripts to disk as
 * PLAINTEXT markdown/JSON, and embeds them into a searchable vector index. That
 * is the point — the files are meant to be inspectable — but it means anything
 * the agent reads becomes durable and retrievable. A key that appears in a
 * document the user learns, in a transcript, or in a "remember this" note is
 * then stored in three places at once (the source file, the chunk JSON, and
 * the embedding), and will happily be echoed back into a later chat.
 *
 * The vault already protects the keys BlackRose itself manages. This protects
 * the far more likely path: a secret that arrives as CONTENT.
 *
 * Design choices:
 *  - Redact, do not refuse. Blocking a learn because one line looks like a
 *    token would be maddening; the caller can always read the original file.
 *  - Redact before chunking, so the vector index never sees the secret. A
 *    redaction applied after embedding would still leak via similarity search.
 *  - Shape, not value. Nothing here tries to judge whether a string is a REAL
 *    key; it only recognizes the well-known shapes, so false positives are
 *    possible and are reported to the caller rather than hidden.
 */
/**
 * name → pattern. Order matters: more specific shapes first.
 *
 * Exported so scripts/scan-secrets.ts can reuse these EXACT patterns to check
 * what is about to be committed. A second, divergent list in a pre-commit guard
 * is how a scanner starts disagreeing with the thing it is supposed to mirror.
 */
const SECRET_PATTERNS = [
    // Anthropic FIRST. `sk-ant-…` also satisfies the generic OpenAI shape
    // (`sk-` + url-safe chars), and OpenAI sat first, so every Anthropic key was
    // reported as `openai_key` — a redaction report that names the wrong provider
    // is worse than none, because it sends the user looking in the wrong vault.
    // Most specific shape first is the whole contract of this list.
    { name: 'anthropic_key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
    // OpenAI-style, including project keys (explicitly not `sk-ant-`, which the
    // line above owns).
    { name: 'openai_key', re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
    // Google / Gemini / YouTube-style AIza
    { name: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    // Newer Google key shape, observed live 2026-10-02: "AQ." + ~50 url-safe chars
    // (53 total), handed out alongside the classic AIza keys. It authenticates
    // against the same generativelanguage endpoints via x-goog-api-key, so it is a
    // first-class credential and must be redacted exactly like the old shape.
    // Named by SHAPE, not by Google's internal taxonomy — we observed the string,
    // we did not read their docs, and guessing a product name here would be a lie
    // baked into the code. The generic assigned_secret pattern does NOT cover a
    // bare pasted key, which is precisely how these arrive (a .txt attachment).
    { name: 'google_key_aq', re: /\bAQ\.[A-Za-z0-9_-]{20,}\b/g },
    // GitHub tokens
    { name: 'github_token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
    { name: 'github_fine_grained', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
    // GitLab
    { name: 'gitlab_token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
    // AWS access key id
    { name: 'aws_access_key', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
    // Slack
    { name: 'slack_token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
    // Google Cloud service account private key
    { name: 'gcp_private_key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    // Generic "key = value" assignments, but ONLY for names that are secret-ish,
    //    so that ordinary prose ("the api key is stored in the vault") is not mangled.
    //
    //  Two things this had wrong until 2026-10-02, both found by running the
    //  scanner at the real motion_token.json and getting a FALSE "clean":
    //
    //  1. JSON never matched. The pattern ended the key NAME and then demanded
    //     [:=], but in `"token": "value"` a closing quote sits between the two.
    //     So every quoted JSON key was invisible — and JSON is the dominant format
    //     for credential files, including this project's own knowledge chunks.
    //  2. Compound names never matched. `\btoken` cannot match inside
    //     `refresh_token`, because `_` is a word character so there is no boundary
    //     before `t`. `refresh_token` and `access_token` both sailed through.
    //
    //  Fixed with an optional quoted-key suffix and an optional compound prefix.
    //  Plain prose still does not match: there is no `:` or `=` after the name.
    {
        name: 'assigned_secret',
        re: /\b((?:[a-z0-9]+[_-])?(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|client[_-]?secret|auth[_-]?token)["']?\s*[:=]\s*)(["']?)([A-Za-z0-9_\-./+=]{16,})\2/gi,
    },
];
/**
 * Replace anything that looks like a credential. Returns the cleaned text plus
 * what was found, so the caller can TELL the user rather than silently
 * swallowing a key — a silent redaction would be indistinguishable from data
 * loss when they go looking for it later.
 */
function redactSecrets(input) {
    let text = input;
    const kinds = new Set();
    let count = 0;
    for (const { name, re } of SECRET_PATTERNS) {
        // Assigned secrets keep their key name and separator so the structure of
        // the document survives; only the value is replaced.
        text = text.replace(re, (...args) => {
            const whole = args[0];
            count++;
            kinds.add(name);
            if (name === 'assigned_secret') {
                const prefix = args[1];
                const quote = args[2];
                return `${prefix}${quote}[REDACTED:${name}]${quote}`;
            }
            if (name === 'gcp_private_key')
                return `[REDACTED:${name}]`;
            // Whole-token shapes: keep a short prefix so the reader can tell WHICH
            // credential it was without the value being usable.
            const head = name === 'openai_key' || name === 'anthropic_key' ? whole.slice(0, 7) : '';
            return `${head}[REDACTED:${name}]`;
        });
    }
    return { text, count, kinds: [...kinds] };
}
/** One-line human summary for a tool result, e.g. "3 secrets (openai_key, github_token)". */
function describeRedactions(r) {
    if (r.count === 0)
        return '';
    return `${r.count} secret-like value(s) redacted [${r.kinds.join(', ')}] — originals were not stored`;
}
return { SECRET_PATTERNS,redactSecrets,describeRedactions };
}

__mod['memory/redact.js'] = M33();

function M34() {
const { buildTool, str } = __mod['core/tools.js'];
const { hybridRank, openStore } = __mod['memory/hybrid.js'];
const { saveStore, vectorsFor } = __mod['memory/vectors.js'];
const { resetEmbedProbe } = __mod['memory/embedder.js'];
const { redactSecrets } = __mod['memory/redact.js'];
/** Persistent memory: markdown files under ~/.blackrose/memory — inspectable, portable. */
// Memory filenames. Truncation at 80 chars keeps paths sane, but on its own it
// made two long keys with a shared prefix collide into ONE file — the second
// save silently overwrote the first, which is data loss the user never sees.
// Appending a short hash of the FULL key keeps the name readable while making
// distinct keys distinct files.
const slug = (key) => {
    const base = key.toLowerCase().replace(/[^a-z0-9-_]+/g, '-').replace(/^-+|-+$/g, '');
    if (!base)
        return 'note';
    if (base.length <= 80)
        return base;
    // FNV-1a over the full key: 8 hex chars is plenty to break the collision and
    // keeps the filename short. No dependency needed.
    let h = 0x811c9dc5;
    for (let i = 0; i < key.length; i++) {
        h ^= key.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return `${base.slice(0, 71)}-${h.toString(16).padStart(8, '0')}`;
};
function memoryPath(dataDir) {
    return path.join(dataDir, 'memory');
}
function listMemoryFiles(dataDir) {
    const dir = memoryPath(dataDir);
    if (!fs.existsSync(dir))
        return [];
    return fs.readdirSync(dir).filter((f) => f.endsWith('.md')).sort();
}
const memorySaveTool = buildTool({
    name: 'memory_save',
    description: 'Persist a durable fact, preference, decision, or lesson to long-term memory (survives sessions and machine moves).',
    input_schema: {
        type: 'object',
        properties: {
            key: { type: 'string', description: 'Short hierarchical key, e.g. "prefs/editor" or "project/blackrose/decisions"' },
            content: { type: 'string', description: 'What to remember (markdown)' },
        },
        required: ['key', 'content'],
    },
    run: async (input, ctx) => {
        const key = str(input, 'key').trim();
        if (!key)
            return { content: 'key is required', isError: true };
        // Redact BEFORE writing and before embedding: a memory is the most likely
        // place a credential ends up ("remember this key for later"), and it would
        // otherwise be persisted twice — once as markdown, once in the vector index.
        const scrub = redactSecrets(str(input, 'content').trim());
        const p = path.join(memoryPath(ctx.dataDir), `${slug(key)}.md`);
        const entry = `# ${key}\n\n- saved: ${new Date().toISOString()}\n\n${scrub.text}\n`;
        fs.mkdirSync(memoryPath(ctx.dataDir), { recursive: true });
        fs.writeFileSync(p, entry, 'utf8');
        // keep the semantic index in sync (hybrid memory_search)
        const store = openStore(ctx.dataDir);
        await vectorsFor(store, [{ id: `mem:${slug(key)}`, text: entry }]);
        saveStore(store);
        resetEmbedProbe(); // a just-pulled model should be picked up immediately
        // Tell the user rather than silently dropping their data: a secret that
        // vanished with no explanation is indistinguishable from a bug.
        const note = scrub.count > 0
            ? ` ⚠ ${scrub.count} secret-like value(s) redacted [${scrub.kinds.join(', ')}] and NOT stored.`
            : '';
        return { content: `Remembered "${key}" (${p}).${note}` };
    },
});
const memorySearchTool = buildTool({
    name: 'memory_search',
    description: 'Search long-term memory (hybrid: keyword TF-IDF + semantic vector match over all memory files).',
    input_schema: {
        type: 'object',
        properties: { query: { type: 'string', description: 'Keywords or a phrase to search for' } },
        required: ['query'],
    },
    run: async (input, ctx) => {
        const files = listMemoryFiles(ctx.dataDir);
        if (files.length === 0)
            return { content: 'Memory is empty.' };
        const dir = memoryPath(ctx.dataDir);
        const docs = files.map((f) => ({
            id: `mem:${f.replace(/\.md$/, '')}`,
            text: fs.readFileSync(path.join(dir, f), 'utf8'),
            mtime: fs.statSync(path.join(dir, f)).mtimeMs,
        }));
        const store = openStore(ctx.dataDir);
        const ranked = await hybridRank(str(input, 'query'), docs, store, 'mem:', 5);
        if (ranked.length === 0)
            return { content: `No memory matches "${str(input, 'query')}".` };
        return {
            content: ranked
                .map((r) => `== ${r.id.replace(/^mem:/, '')} (score ${r.score.toFixed(2)}) ==\n${r.snippet}`)
                .join('\n\n'),
        };
    },
});
const memoryListTool = buildTool({
    name: 'memory_list',
    description: 'List all memory keys (file names) in long-term memory.',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async (_input, ctx) => {
        const files = listMemoryFiles(ctx.dataDir);
        return { content: files.length ? files.map((f) => `- ${f.replace(/\.md$/, '')}`).join('\n') : 'Memory is empty.' };
    },
});
return { memorySaveTool,memorySearchTool,memoryListTool };
}

__mod['tools/memory.js'] = M34();

function M35() {
/**
 * Zero-dependency PDF text extraction (best-effort).
 *
 * Scans the raw bytes for `stream ... endstream` payloads, inflates them
 * (zlib / raw-deflate / stored), then interprets each decoded stream as a
 * PDF content stream: text shown with `(...) Tj`, `[...] TJ` or `<hex> Tj`
 * is concatenated; `Td / TD / T* / ET` produce line breaks.
 *
 * Known limitations (documented in the roadmap): no CMap/ToUnicode decoding
 * (some fonts extract garbled), no encrypted-PDF decryption, and scanned /
 * image-only PDFs contain no text layer at all — those need OCR.
 */
/**
 * Cap on decompressed output, in bytes. A document is untrusted input: a few
 * KB of deflate can expand to gigabytes (a decompression bomb), and without a
 * bound `inflateSync` allocates until the process dies — taking the agent down
 * from what looks like learning a file. 256 MB is far above any real text or
 * office document and far below anything that will exhaust a machine.
 */
const MAX_INFLATE_BYTES = 256 * 1024 * 1024;
function tryInflate(b) {
    try {
        return zlib.inflateSync(b, { maxOutputLength: MAX_INFLATE_BYTES });
    }
    catch {
        /* not zlib-framed, or hit the output cap */
    }
    try {
        return zlib.inflateRawSync(b, { maxOutputLength: MAX_INFLATE_BYTES });
    }
    catch {
        /* not raw deflate either, or over the cap */
    }
    return null;
}
/** Extract text from one decoded content stream; null when not text-like. */
function textFromContentStream(decoded) {
    const content = decoded.toString('latin1');
    if (!content.includes('Tj') && !content.includes('TJ'))
        return null;
    let out = '';
    let pending = '';
    let i = 0;
    let inInlineImage = false;
    while (i < content.length) {
        const c = content[i];
        if (inInlineImage) {
            if (c === 'E' && content[i + 1] === 'I') {
                inInlineImage = false;
                i += 2;
            }
            else
                i++;
            continue;
        }
        if (c === '(') {
            // literal string, escape-aware, depth-tracked
            i++;
            let depth = 1;
            let s = '';
            while (i < content.length && depth > 0) {
                const ch = content[i];
                if (ch === '\\') {
                    const n = content[i + 1];
                    if (n === 'n')
                        (s += '\n'), (i += 2);
                    else if (n === 'r')
                        (s += '\r'), (i += 2);
                    else if (n === 't')
                        (s += '\t'), (i += 2);
                    else if (n === 'b')
                        (s += '\b'), (i += 2);
                    else if (n === 'f')
                        (s += '\f'), (i += 2);
                    else if (n === '(')
                        (s += '('), (i += 2);
                    else if (n === ')')
                        (s += ')'), (i += 2);
                    else if (n === '\\')
                        (s += '\\'), (i += 2);
                    else if (n === '\n')
                        i += 2; // escaped line break → join lines
                    else if (n !== undefined && n >= '0' && n <= '7') {
                        let oct = '';
                        let j = i + 1;
                        while (j < content.length && oct.length < 3 && content[j] >= '0' && content[j] <= '7') {
                            oct += content[j];
                            j++;
                        }
                        s += String.fromCharCode(parseInt(oct, 8) & 0xff);
                        i = j;
                    }
                    else {
                        s += n ?? '';
                        i += 2;
                    }
                }
                else if (ch === '(') {
                    depth++;
                    s += ch;
                    i++;
                }
                else if (ch === ')') {
                    depth--;
                    if (depth > 0)
                        s += ch;
                    i++;
                }
                else {
                    s += ch;
                    i++;
                }
            }
            pending += s;
            continue;
        }
        if (c === '<') {
            if (content[i + 1] === '<') {
                i += 2; // dictionary operator, not a hex string
                continue;
            }
            const close = content.indexOf('>', i);
            if (close === -1)
                break;
            const hex = content.slice(i + 1, close).replace(/[^0-9a-fA-F]/g, '');
            for (let j = 0; j + 1 < hex.length; j += 2) {
                pending += String.fromCharCode(parseInt(hex.slice(j, j + 2), 16));
            }
            i = close + 1;
            continue;
        }
        if (/[A-Za-z'"*]/.test(c)) {
            let j = i;
            while (j < content.length && /[A-Za-z0-9'"*]/.test(content[j]))
                j++;
            const op = content.slice(i, j);
            i = j;
            if (op === 'BI') {
                inInlineImage = true; // skip inline image binary until EI
                pending = '';
                continue;
            }
            if (op === 'Tj' || op === "'" || op === '"') {
                out += pending + ' ';
                pending = '';
            }
            else if (op === 'TJ') {
                out += pending; // array shows: kerning already splits words
                pending = '';
            }
            else if (op === 'Td' || op === 'TD' || op === 'T*' || op === 'ET') {
                if (pending) {
                    out += pending;
                    pending = '';
                }
                out += '\n';
            }
            continue;
        }
        i++;
    }
    if (pending)
        out += pending;
    const letters = (out.match(/[A-Za-z]/g) ?? []).length;
    const controls = (out.match(/[\x00-\x08\x0e-\x1f]/g) ?? []).length;
    if (letters < 4 || controls > letters * 0.2)
        return null;
    return out.replace(/\r/g, '');
}
function extractPdfText(buf) {
    const src = buf.toString('latin1');
    const texts = [];
    let idx = 0;
    for (;;) {
        const s = src.indexOf('stream', idx);
        if (s === -1)
            break;
        if (s > 0 && /[A-Za-z]/.test(src[s - 1])) {
            // part of a longer word (e.g. "endstream") — skip to avoid false hits
            idx = s + 6;
            continue;
        }
        let ds = s + 6;
        if (src[ds] === '\r')
            ds++;
        if (src[ds] === '\n')
            ds++;
        const e = src.indexOf('endstream', ds);
        if (e === -1)
            break;
        idx = e + 9;
        const raw = Buffer.from(src.slice(ds, e), 'latin1');
        const decoded = tryInflate(raw) ?? raw;
        const t = textFromContentStream(decoded);
        if (t)
            texts.push(t);
    }
    return texts
        .join('\n')
        .replace(/[ \t]+/g, ' ')
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0)
        .join('\n');
}
return { extractPdfText };
}

__mod['memory/pdf.js'] = M35();

function M36() {
/**
 * Zero-dependency ZIP reading.
 *
 * DOCX, XLSX, PPTX and EPUB are all the same container: a ZIP archive holding
 * XML/XHTML parts. This module walks the central directory (no libraries) and
 * inflates each entry with node:zlib, handing it to a visitor. One pass over
 * the directory, each entry inflated at most once.
 *
 * Only the two storage methods that matter in practice are supported: 0
 * (stored) and 8 (deflate). Anything else, or a corrupt entry, is skipped
 * rather than throwing — a partially-readable document should still yield the
 * parts that did parse.
 */

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
/**
 * Cap on decompressed output per member, in bytes. Office files are untrusted
 * input: a few KB of deflate can expand to gigabytes (decompression bomb), and
 * unbounded inflate allocates until the process dies. 256 MB is far above any
 * real .docx/.xlsx/.pptx member and far below anything that exhausts a machine.
 */
const MAX_INFLATE_BYTES = 256 * 1024 * 1024;
function findEocd(b) {
    // EOCD is at most 22 bytes + a 64KB comment
    const min = Math.max(0, b.length - 22 - 65535);
    for (let i = b.length - 22; i >= min; i--) {
        if (b.readUInt32LE(i) === EOCD_SIG)
            return i;
    }
    return -1;
}
/** Cheap sniff: a ZIP starts with a local-file-header signature. */
function isZip(b) {
    return b.length >= 4 && b.readUInt32LE(0) === LFH_SIG;
}
/**
 * Visit every file entry in the archive. Directory entries (name ending '/')
 * are skipped. Entries that fail to inflate are skipped silently.
 */
function readZip(b, visit) {
    const eocd = findEocd(b);
    if (eocd === -1)
        return;
    const count = b.readUInt16LE(eocd + 10);
    let ptr = b.readUInt32LE(eocd + 16);
    for (let i = 0; i < count; i++) {
        if (ptr + 46 > b.length || b.readUInt32LE(ptr) !== CD_SIG)
            break;
        const method = b.readUInt16LE(ptr + 10);
        const compSize = b.readUInt32LE(ptr + 20);
        const nameLen = b.readUInt16LE(ptr + 28);
        const extraLen = b.readUInt16LE(ptr + 30);
        const commentLen = b.readUInt16LE(ptr + 32);
        const localOffset = b.readUInt32LE(ptr + 42);
        const name = b.subarray(ptr + 46, ptr + 46 + nameLen).toString('utf8');
        if (!name.endsWith('/') && localOffset + 30 <= b.length) {
            // data starts after the local header: sig + fixed fields + name + extra
            const lNameLen = b.readUInt16LE(localOffset + 26);
            const lExtraLen = b.readUInt16LE(localOffset + 28);
            const dataStart = localOffset + 30 + lNameLen + lExtraLen;
            const raw = b.subarray(dataStart, dataStart + compSize);
            let out = null;
            if (method === 0)
                out = raw;
            else if (method === 8) {
                try {
                    // Bounded: an office document is untrusted input, and a few KB of
                    // deflate can expand to gigabytes (decompression bomb). Cap the output
                    // so learning a crafted .docx/.xlsx/.pptx cannot exhaust memory.
                    out = zlib.inflateRawSync(raw, { maxOutputLength: MAX_INFLATE_BYTES });
                }
                catch {
                    out = null;
                }
            }
            if (out)
                visit(name, out);
        }
        ptr += 46 + nameLen + extraLen + commentLen;
    }
}
/** Decode the standard XML/HTML entities. Shared by every OOXML extractor. */
function decodeXmlEntities(s) {
    return s
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
        .replace(/&amp;/g, '&');
}
return { isZip,readZip,decodeXmlEntities };
}

__mod['memory/zip.js'] = M36();

function M37() {
const { decodeXmlEntities, readZip } = __mod['memory/zip.js'];
/**
 * Zero-dependency DOCX text extraction.
 *
 * A .docx is a ZIP archive whose main content lives in word/document.xml.
 * The container is read by ./zip.ts (shared with XLSX/PPTX/EPUB); this module
 * only pulls the visible text out of the OOXML runs: <w:t> elements are
 * concatenated, </w:p> paragraph ends become newlines, and XML entities are
 * decoded. Headers/footers, text boxes and embedded objects are not part of
 * document.xml and are skipped.
 */

/** Extract plain text from a .docx buffer; '' when no text layer is found. */
function extractDocxText(buf) {
    let text = '';
    readZip(buf, (name, data) => {
        if (name !== 'word/document.xml' || text)
            return;
        const xml = data.toString('utf8');
        const lines = [];
        for (const para of xml.split(/<\/w:p>/)) {
            let line = '';
            const re = /<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g;
            let m;
            while ((m = re.exec(para)) !== null)
                line += m[1];
            line = decodeXmlEntities(line).replace(/\s+/g, ' ').trim();
            if (line)
                lines.push(line);
        }
        text = lines.join('\n');
    });
    return text;
}
return { extractDocxText };
}

__mod['memory/docx.js'] = M37();

function M38() {
const { decodeXmlEntities, readZip } = __mod['memory/zip.js'];
/**
 * Zero-dependency XLSX text extraction.
 *
 * A .xlsx is a ZIP archive (OOXML): cell strings live in the shared-strings
 * table (xl/sharedStrings.xml, entries <t>…</t>) and sheet data lives in
 * xl/worksheets/sheetN.xml as <v>value</v> (shared-string index when type "s")
 * or inline <t> text. Rows are emitted as tab-joined plain cells with an
 * [SheetName] heading, so retrieval reads a table, not raw XML.
 */

function sheetNameFor(fileName) {
    const base = fileName.split('/').pop() ?? fileName;
    const m = /^sheet(\d+)\.xml$/i.exec(base);
    return m ? `Sheet${m[1]}` : base.replace(/\.xml$/i, '');
}
function cellString(cellInner, typeAttr, shared) {
    const tMatch = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/i.exec(cellInner);
    if (tMatch)
        return decodeXmlEntities(tMatch[1]).replace(/\s+/g, ' ').trim();
    const vMatch = /<v>([\s\S]*?)<\/v>/i.exec(cellInner);
    const raw = vMatch ? vMatch[1].trim() : '';
    if (!raw)
        return '';
    if (typeAttr.toLowerCase() === 's') {
        const idx = Number(raw);
        if (Number.isInteger(idx) && idx >= 0 && idx < shared.length)
            return shared[idx];
        return raw;
    }
    return decodeXmlEntities(raw);
}
/** Extract readable table text from an .xlsx buffer; '' when nothing is found. */
function extractXlsxText(buf) {
    const shared = [];
    const sheets = new Map();
    readZip(buf, (name, data) => {
        if (name === 'xl/sharedStrings.xml') {
            const xml = data.toString('utf8');
            const re = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
            let m;
            while ((m = re.exec(xml)) !== null) {
                shared.push(decodeXmlEntities(m[1]).replace(/\s+/g, ' ').trim());
            }
        }
        else if (/^xl\/worksheets\/sheet\d+\.xml$/i.test(name)) {
            sheets.set(name, data.toString('utf8'));
        }
    });
    const parts = [];
    for (const [name, xml] of [...sheets.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
        const rows = [];
        const rowRe = /<row[^>]*>([\s\S]*?)<\/row>/gi;
        let rowM;
        while ((rowM = rowRe.exec(xml)) !== null) {
            const cells = [];
            const cellRe = /<c(?:\s[^>]*)?t="([^"]*)"[^>]*>([\s\S]*?)<\/c>|<c(?:\s[^>]*)?>([\s\S]*?)<\/c>/gi;
            let cellM;
            while ((cellM = cellRe.exec(rowM[1])) !== null) {
                const typeAttr = cellM[1] ?? '';
                const inner = cellM[2] ?? cellM[3] ?? '';
                cells.push(cellString(inner, typeAttr, shared));
            }
            while (cells.length > 0 && cells[cells.length - 1] === '')
                cells.pop();
            if (cells.some((c) => c !== ''))
                rows.push(cells.join('\t'));
        }
        if (rows.length > 0)
            parts.push(`[${sheetNameFor(name)}]\n${rows.join('\n')}`);
    }
    return parts.join('\n\n');
}
return { extractXlsxText };
}

__mod['memory/xlsx.js'] = M38();

function M39() {
const { decodeXmlEntities, readZip } = __mod['memory/zip.js'];
/**
 * Zero-dependency PPTX text extraction.
 *
 * A .pptx is a ZIP archive (OOXML): each slide lives at
 * ppt/slides/slideN.xml and visible runs are <a:t>…</a:t> text elements.
 * Slides are emitted in numeric order with a [Slide N] heading.
 */

/** Extract readable slide text from a .pptx buffer; '' when nothing is found. */
function extractPptxText(buf) {
    const slides = new Map();
    readZip(buf, (name, data) => {
        const m = /^ppt\/slides\/slide(\d+)\.xml$/i.exec(name);
        if (!m)
            return;
        const n = Number(m[1]);
        if (!Number.isInteger(n) || n <= 0)
            return;
        const xml = data.toString('utf8');
        const lines = [];
        for (const para of xml.split(/<\/a:p>/)) {
            let line = '';
            const re = /<a:t(?:\s[^>]*)?>([\s\S]*?)<\/a:t>/g;
            let t;
            while ((t = re.exec(para)) !== null)
                line += t[1];
            line = decodeXmlEntities(line).replace(/\s+/g, ' ').trim();
            if (line)
                lines.push(line);
        }
        if (lines.length > 0)
            slides.set(n, lines.join('\n'));
    });
    return [...slides.entries()]
        .sort(([a], [b]) => a - b)
        .map(([n, text]) => `[Slide ${n}]\n${text}`)
        .join('\n\n');
}
return { extractPptxText };
}

__mod['memory/pptx.js'] = M39();

function M40() {
const { decodeXmlEntities, readZip } = __mod['memory/zip.js'];
/**
 * Zero-dependency EPUB text extraction.
 *
 * An .epub is a ZIP archive holding XHTML/HTML spine documents plus metadata.
 * Content documents (any *.xhtml/*.html/*.htm/xml part that is NOT inside
 * META-INF/) are stripped to text and emitted with a [chapter filename]
 * heading, in archive order. OPF/toc metadata parts are informational only —
 * the reading text lives in the content documents.
 */

function stripTags(html) {
    let s = html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ');
    const blocks = [];
    for (const chunk of s.split(/<\/(?:p|div|h[1-6]|li|tr|section|article|header|footer|blockquote)[^>]*>/gi)) {
        const line = decodeXmlEntities(chunk.replace(/<[^>]+>/g, ' '))
            .replace(/\s+/g, ' ')
            .trim();
        if (line)
            blocks.push(line);
    }
    if (blocks.length > 0)
        return blocks.join('\n');
    const flat = decodeXmlEntities(s.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
    return flat;
}
/** Extract readable text from an .epub buffer; '' when nothing is found. */
function extractEpubText(buf) {
    const docs = [];
    readZip(buf, (name, data) => {
        if (name.startsWith('META-INF/'))
            return;
        if (!/\.(x?html?|xml)$/i.test(name))
            return;
        const text = stripTags(data.toString('utf8'));
        if (text.replace(/\s+/g, '').length >= 20) {
            docs.push({ name: name.split('/').pop() ?? name, text });
        }
    });
    return docs.map((d) => `[${d.name}]\n${d.text}`).join('\n\n');
}
return { extractEpubText };
}

__mod['memory/epub.js'] = M40();

function M41() {
/**
 * Zero-dependency subtitle / transcript parsing (SRT + WebVTT).
 *
 * Both formats are cue-based: blocks separated by blank lines, each with an
 * optional numeric/identifier line, a `-->` timestamp line, and one or more
 * text lines. This module extracts just the spoken text, collapsing repeated
 * consecutive lines (common in auto-generated captions) and decoding basic
 * HTML tags/entities sometimes embedded in subtitles.
 */
function stripMarkup(line) {
    return line
        .replace(/<[^>]+>/g, '') // <i>, <c>, <v Speaker>, …
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;|&apos;/g, "'")
        .replace(/&amp;/g, '&')
        .replace(/\s+/g, ' ')
        .trim();
}
/** Extract plain transcript text from SRT or WebVTT content; '' when empty. */
function parseTranscript(raw) {
    const lines = [];
    for (const block of raw.replace(/\r\n/g, '\n').split(/\n{2,}/)) {
        const cue = [];
        for (const line of block.split('\n')) {
            const t = line.trim();
            if (!t)
                continue;
            if (/^\d+$/.test(t))
                continue; // SRT sequence number
            if (t === 'WEBVTT' || t.startsWith('WEBVTT ') || /^(NOTE|STYLE|REGION)\b/.test(t))
                continue;
            if (t.includes('-->'))
                continue; // timestamp line
            cue.push(stripMarkup(t));
        }
        const text = cue.filter(Boolean).join(' ').trim();
        if (text)
            lines.push(text);
    }
    // collapse consecutive duplicates (rolling auto-captions repeat phrases)
    const out = [];
    for (const l of lines) {
        if (out.length > 0 && out[out.length - 1] === l)
            continue;
        out.push(l);
    }
    return out.join('\n');
}
return { parseTranscript };
}

__mod['memory/transcript.js'] = M41();

function M42() {
const { execShell } = __mod['core/processes.js'];
/**
 * Windows-native OCR (Phase 6): `Windows.Media.Ocr` for images and
 * `Windows.Data.Pdf` for rendering scanned PDF pages, driven through
 * PowerShell 5.1 WinRT projection — zero npm dependencies, fully offline,
 * same pattern as the SAPI `say` tool. Returns null when the platform
 * cannot do OCR (non-Windows, or no recognizer language installed) so
 * callers can degrade gracefully.
 */


const PS_BOOT = [
    "[void][Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]",
    "[void][Windows.Globalization.Language,Windows.Foundation,ContentType=WindowsRuntime]",
    "[void][Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime]",
    "[void][Windows.Storage.StorageFile,Windows.Foundation,ContentType=WindowsRuntime]",
    "[void][Windows.Data.Pdf.PdfDocument,Windows.Foundation,ContentType=WindowsRuntime]",
    "[void][Windows.Storage.Streams.InMemoryRandomAccessStream,Windows.Foundation,ContentType=WindowsRuntime]",
    'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
].join('; ');
// Generic AsTask for IAsyncOperation`1 (PowerShell 5.1 WinRT await helper)
const PS_AWAIT = "$at=([System.WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'})[0];" +
    'function Await($t,$rt){$m=$at.MakeGenericMethod($rt);$tk=$m.Invoke($null,@($t));$tk.Wait(-1)|Out-Null;return $tk.Result}';
// Non-generic AsTask for IAsyncAction (RenderToStreamAsync) — reflection, since
// PowerShell cannot resolve the overload statically.
const PS_AWAIT_ACTION = "$aa=([System.WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'})[0];";
const PS_ENGINE = "$en=[Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages();" +
    "if(-not $en){$en=[Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US'))};" +
    'if(-not $en){throw "no-ocr-engine"}';
function psPath(p) {
    return p.replace(/'/g, "''");
}
function parseOcrOutput(output, exitCode) {
    if (exitCode !== 0)
        return null;
    const m = output.match(/BLACKROSE_OCR_BEGIN\s*([\s\S]*)$/);
    if (!m)
        return null;
    const text = m[1].trim();
    return text.length > 0 ? text : null;
}
/** OCR one image file (png/jpg/bmp/tif). Returns recognized text or null. */
async function ocrImageFile(imagePath, cwd, timeoutMs = 60_000) {
    if (process.platform !== 'win32' || !fs.existsSync(imagePath))
        return null;
    const ps = [
        PS_BOOT,
        PS_AWAIT,
        PS_ENGINE,
        `$f=[Windows.Storage.StorageFile]::GetFileFromPathAsync('${psPath(imagePath)}');$f=Await $f ([Windows.Storage.StorageFile]);`,
        '$s=$f.OpenAsync([Windows.Storage.FileAccessMode]::Read);$s=Await $s ([Windows.Storage.Streams.IRandomAccessStream]);',
        '$d=[Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($s);$d=Await $d ([Windows.Graphics.Imaging.BitmapDecoder]);',
        '$b=$d.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,[Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied);$b=Await $b ([Windows.Graphics.Imaging.SoftwareBitmap]);',
        '$r=$en.RecognizeAsync($b);$r=Await $r ([Windows.Media.Ocr.OcrResult]);',
        '$s.Dispose();$b.Dispose();',
        "Write-Output ('BLACKROSE_OCR_LINES=' + $r.Lines.Count)",
        'Write-Output BLACKROSE_OCR_BEGIN',
        'Write-Output $r.Text',
    ].join('; ');
    const r = await execShell(ps, cwd, timeoutMs);
    return parseOcrOutput(r.output, r.exitCode);
}
/**
 * OCR a scanned PDF: render each page with Windows.Data.Pdf to a PNG
 * stream (2x scale, capped), OCR the renders, join in page order.
 * Returns null when the PDF API is unavailable or nothing could be read.
 */
async function ocrPdfFile(pdfPath, cwd, maxPages = 30, timeoutMs = 180_000) {
    if (process.platform !== 'win32' || !fs.existsSync(pdfPath))
        return null;
    const ps = [
        "$ErrorActionPreference='Stop'",
        PS_BOOT,
        PS_AWAIT,
        PS_AWAIT_ACTION,
        PS_ENGINE,
        `$f=[Windows.Storage.StorageFile]::GetFileFromPathAsync('${psPath(pdfPath)}');$f=Await $f ([Windows.Storage.StorageFile]);`,
        '$pdf=[Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($f);$pdf=Await $pdf ([Windows.Data.Pdf.PdfDocument]);',
        "Write-Output ('BLACKROSE_PDF_PAGES=' + $pdf.PageCount)",
        `$n=[Math]::Min($pdf.PageCount,${Math.max(1, Math.min(60, maxPages))})`,
        'for($i=0;$i -lt $n;$i++){',
        '$pg=$pdf.GetPage($i)',
        '$st=[Windows.Storage.Streams.InMemoryRandomAccessStream]::new()',
        // RenderToStreamAsync returns IAsyncAction — reflect the non-generic AsTask and block on it
        '$tk=$aa.Invoke($null,@($pg.RenderToStreamAsync($st)));$tk.Wait()',
        '$pg.Dispose()',
        '$dec=[Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($st);$dec=Await $dec ([Windows.Graphics.Imaging.BitmapDecoder]);',
        '$sb=$dec.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,[Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied);$sb=Await $sb ([Windows.Graphics.Imaging.SoftwareBitmap]);',
        '$res=$en.RecognizeAsync($sb);$res=Await $res ([Windows.Media.Ocr.OcrResult]);',
        '$st.Dispose();$sb.Dispose()',
        "if($res -and $res.Text){Write-Output ('BLACKROSE_PAGE ' + $i + ' BEGIN');Write-Output $res.Text}",
        '}',
    ].join('; ');
    const r = await execShell(ps, cwd, timeoutMs);
    if (r.exitCode !== 0)
        return null;
    // Strict: only text between explicit page markers counts; anything else
    // (PowerShell error chatter merged into stdout) must never leak through.
    const parts = r.output.split(/BLACKROSE_PAGE \d+ BEGIN[^\n]*/).slice(1);
    if (parts.length === 0)
        return null;
    const text = parts
        .map((s) => s.replace(/(At line:1 char[\s\S]*)$/, '').trim())
        .filter((s) => s.length > 0 && !/^\s*(Exception calling|You cannot call|The property )/.test(s))
        .join('\n\n')
        .trim();
    return text.length > 0 ? text : null;
}
return { ocrImageFile,ocrPdfFile };
}

__mod['memory/ocr.js'] = M42();

function M43() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { resolveInWorkspace } = __mod['core/permissions.js'];
const { hybridRank } = __mod['memory/hybrid.js'];
const { extractPdfText } = __mod['memory/pdf.js'];
const { extractDocxText } = __mod['memory/docx.js'];
const { extractXlsxText } = __mod['memory/xlsx.js'];
const { extractPptxText } = __mod['memory/pptx.js'];
const { extractEpubText } = __mod['memory/epub.js'];
const { parseTranscript } = __mod['memory/transcript.js'];
const { ocrPdfFile } = __mod['memory/ocr.js'];
const { saveStore, vectorsFor } = __mod['memory/vectors.js'];
const { openStore } = __mod['memory/hybrid.js'];
const { resetEmbedProbe } = __mod['memory/embedder.js'];
const { redactSecrets } = __mod['memory/redact.js'];
const { fetchWithTimeout, stripHtml } = __mod['tools/web.js'];
const { tokenize } = __mod['memory/tfidf.js'];
const MAX_LEARN_BYTES = 2 * 1024 * 1024;
const CHUNK_TARGET = 900;
function knowledgeDir(dataDir) {
    return path.join(dataDir, 'knowledge');
}
/** FNV-1a 32-bit hash as base36 — a stable short discriminator for a source. */
function hash8(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(36);
}
const SLUG_MAX = 80;
/**
 * Filename-safe id for a knowledge source.
 * Long sources are truncated for readability, but a hash of the FULL source is
 * appended — otherwise two paths sharing their first SLUG_MAX characters would
 * silently overwrite each other's learned document (one clobbers the other).
 */
const slug = (s) => {
    const cleaned = s.toLowerCase().replace(/[^a-z0-9-_]+/g, '-').replace(/^-+|-+$/g, '');
    if (cleaned.length === 0)
        return `source-${hash8(s)}`;
    if (cleaned.length <= SLUG_MAX)
        return cleaned;
    return `${cleaned.slice(0, SLUG_MAX - 9)}-${hash8(s)}`;
};
function chunkText(text, target = CHUNK_TARGET) {
    const paragraphs = text.split(/\n\s*\n/);
    const chunks = [];
    let cur = '';
    const push = () => {
        if (cur.trim())
            chunks.push(cur.trim());
        cur = '';
    };
    for (const p of paragraphs) {
        if (p.length > target * 2) {
            for (const sentence of p.replace(/\n/g, ' ').split(/(?<=[.!?])\s+/)) {
                if ((cur + sentence).length > target && cur)
                    push();
                cur += (cur ? ' ' : '') + sentence;
            }
        }
        else {
            if ((cur + p).length > target && cur)
                push();
            cur += (cur ? '\n\n' : '') + p;
        }
    }
    push();
    return chunks;
}
/**
 * Chunk + persist a learned document as JSON. Returns the chunk count and the
 * vector entries; the caller indexes them (see indexKnowledge) so a bulk import
 * can pay for one store load/save instead of one per document.
 */
function writeKnowledgeFile(dataDir, source, kind, text) {
    // Scrub BEFORE chunking, so a secret is never written to the chunk JSON and
    // never reaches the embedding (see src/memory/redact.ts for why order matters).
    const scrub = redactSecrets(text);
    const chunks = chunkText(scrub.text);
    const id = slug(source);
    const file = { source, kind, saved: new Date().toISOString(), chunks };
    fs.mkdirSync(knowledgeDir(dataDir), { recursive: true });
    fs.writeFileSync(path.join(knowledgeDir(dataDir), `${id}.json`), JSON.stringify(file, null, 2), 'utf8');
    return {
        chunks: chunks.length,
        entries: chunks.map((c, i) => ({ id: `kb:${id}#chunk${i + 1}`, text: c })),
        redacted: scrub.count,
        redactionKinds: scrub.kinds,
    };
}
/** Index chunks into the semantic store in ONE load + ONE save. */
async function indexKnowledge(dataDir, entries) {
    if (entries.length === 0)
        return;
    // semantic index for hybrid knowledge_search (self-healing if skipped)
    const store = openStore(dataDir);
    await vectorsFor(store, entries);
    saveStore(store);
}
/** Chunk + persist a learned document and keep its vector index up to date. */
async function saveKnowledge(dataDir, source, kind, text) {
    const { chunks, entries } = writeKnowledgeFile(dataDir, source, kind, text);
    await indexKnowledge(dataDir, entries);
    return chunks;
}
/** Same, but reports what was redacted so the caller can tell the user. */
async function saveKnowledgeReport(dataDir, source, kind, text) {
    const r = writeKnowledgeFile(dataDir, source, kind, text);
    await indexKnowledge(dataDir, r.entries);
    return { chunks: r.chunks, redacted: r.redacted, kinds: r.redactionKinds };
}
/**
 * Extensions a bulk walk will ingest. Deliberately text/code only by default:
 * PDFs stay one-at-a-time via learn_pdf, because auto-OCR on a scanned PDF
 * shells out to the Windows OCR engine and a folder full of them would make
 * this call unpredictably slow.
 */
const TEXT_EXTENSIONS = new Set([
    '.md', '.markdown', '.mdx', '.txt', '.text', '.rst', '.adoc',
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.jsonc', '.json5',
    '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.c', '.h', '.cc', '.cpp', '.hpp',
    '.cs', '.swift', '.scala', '.php', '.lua', '.pl', '.r',
    '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd',
    '.sql', '.graphql', '.gql', '.proto', '.tf', '.hcl',
    '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.env', '.properties',
    '.html', '.htm', '.css', '.scss', '.less', '.vue', '.svelte',
    '.xml', '.csv', '.tsv', '.tex',
]);
/**
 * Document extensions only ingested when `documents: true` is passed to
 * learn_folder. These are all fast no-OCR container parses (ZIP/OOXML or epub
 * XHTML) — unlike scanned-PDF OCR, which still stays one-at-a-time via
 * learn_pdf. DOCX is included so folders with Word files can be learned too.
 */
const DOC_EXTENSIONS = new Set(['.docx', '.xlsx', '.pptx', '.epub']);
function extractDocumentText(ext, buf) {
    if (ext === '.docx')
        return extractDocxText(buf);
    if (ext === '.xlsx')
        return extractXlsxText(buf);
    if (ext === '.pptx')
        return extractPptxText(buf);
    if (ext === '.epub')
        return extractEpubText(buf);
    return '';
}
/** Directories a bulk walk skips by default: deps, build output, caches. */
const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor', 'coverage',
    'next', '.next', '.nuxt', '.cache', '.venv', 'venv', '__pycache__',
    '.mypy_cache', '.pytest_cache', '.ruff_cache', '.tox', '.gradle',
    'bower_components', 'jspm_packages', 'site-packages', '.terraform',
    '.idea', '.vscode', '.blackrose', '.pnpm-store',
]);
/** A NUL byte in the first 8 KB means binary — an extension can lie, a NUL can't. */
function looksBinary(buf) {
    const n = Math.min(buf.length, 8000);
    for (let i = 0; i < n; i++)
        if (buf[i] === 0)
            return true;
    return false;
}
const learnFileTool = buildTool({
    name: 'learn_file',
    description: 'Learn a text document (md/txt/code, max 2MB): chunk it into the persistent knowledge base so it can be searched later with knowledge_search.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: 'Document path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES)
            return { content: `File too large to learn (${stat.size} bytes).`, isError: true };
        const text = fs.readFileSync(p, 'utf8');
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned ${p} → ${n} chunk(s) stored in knowledge base.` };
    },
});
const learnFolderTool = buildTool({
    name: 'learn_folder',
    description: 'Learn EVERY text/code document under a directory in one call: walks the tree, chunks each file and stores it in the knowledge base so knowledge_search can find it. Skips binaries plus build output and dependency folders (node_modules/.git/dist/…) by default. Use this instead of many learn_file calls. PDFs stay one-at-a-time via learn_pdf; DOCX/XLSX/PPTX/EPUB can be included by passing documents:true.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Directory to walk (absolute or workspace-relative)' },
            maxFiles: { type: 'number', description: 'Max files to ingest (default 300)' },
            maxBytes: { type: 'number', description: 'Max total bytes to ingest (default 20971520 = 20 MB)' },
            documents: { type: 'boolean', description: 'Also ingest .docx/.xlsx/.pptx/.epub documents (default false — text/code only)' },
        },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const dir = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        let stat;
        try {
            stat = fs.statSync(dir);
        }
        catch {
            return { content: `No such directory: ${dir}`, isError: true };
        }
        if (!stat.isDirectory()) {
            return { content: `Not a directory: ${dir} — use learn_file for a single file.`, isError: true };
        }
        const maxFiles = Math.max(1, Math.min(5000, Math.floor(num(input, 'maxFiles', 300))));
        const maxBytes = Math.max(1024, Math.min(512 * 1024 * 1024, Math.floor(num(input, 'maxBytes', 20 * 1024 * 1024))));
        const wantDocs = input['documents'] === true;
        let ingested = 0;
        let totalBytes = 0;
        let chunkTotal = 0;
        let skipExt = 0;
        let skipDoc = 0;
        let skipBinary = 0;
        let skipLarge = 0;
        let skipUnreadable = 0;
        let skipEmpty = 0;
        let skipLink = 0;
        let dirsSkipped = 0;
        let stop = null;
        const entries = [];
        // Iterative walk (explicit stack): a deep tree must not blow the call stack.
        const stack = [dir];
        outer: while (stack.length > 0) {
            const current = stack.pop();
            let dirents;
            try {
                dirents = fs.readdirSync(current, { withFileTypes: true });
            }
            catch {
                continue;
            }
            for (const d of dirents) {
                const full = path.join(current, d.name);
                // Never follow symlinks/junctions: they can escape the tree the user
                // named, and they can form cycles.
                if (d.isSymbolicLink()) {
                    skipLink++;
                    continue;
                }
                if (d.isDirectory()) {
                    if (d.name.startsWith('.') || SKIP_DIRS.has(d.name.toLowerCase()))
                        dirsSkipped++;
                    else
                        stack.push(full);
                    continue;
                }
                if (!d.isFile())
                    continue;
                const ext = path.extname(d.name).toLowerCase();
                const isDoc = DOC_EXTENSIONS.has(ext);
                if (!TEXT_EXTENSIONS.has(ext) && !(wantDocs && isDoc)) {
                    skipExt++;
                    continue;
                }
                if (isDoc && !wantDocs) {
                    skipDoc++;
                    continue;
                }
                if (ingested >= maxFiles) {
                    stop = `file cap (${maxFiles} files) reached`;
                    break outer;
                }
                let st;
                try {
                    st = fs.statSync(full);
                }
                catch {
                    skipUnreadable++;
                    continue;
                }
                if (st.size > MAX_LEARN_BYTES) {
                    skipLarge++;
                    continue;
                }
                if (totalBytes + st.size > maxBytes) {
                    stop = `byte cap (${maxBytes} bytes) reached`;
                    break outer;
                }
                let buf;
                try {
                    buf = fs.readFileSync(full);
                }
                catch {
                    skipUnreadable++;
                    continue;
                }
                // Office/epub documents are containers (ZIP), not UTF-8 text: extract
                // their readable text with the matching OOXML/XHTML extractor.
                let text;
                if (isDoc) {
                    let extracted = '';
                    try {
                        extracted = extractDocumentText(ext, buf);
                    }
                    catch {
                        extracted = '';
                    }
                    if (extracted.replace(/\s+/g, '').length < 20) {
                        skipEmpty++;
                        continue;
                    }
                    text = extracted;
                }
                else {
                    if (looksBinary(buf)) {
                        skipBinary++;
                        continue;
                    }
                    text = buf.toString('utf8');
                    if (text.trim().length === 0) {
                        skipEmpty++;
                        continue;
                    }
                }
                const res = writeKnowledgeFile(ctx.dataDir, full, 'file', text);
                entries.push(...res.entries);
                chunkTotal += res.chunks;
                ingested++;
                totalBytes += st.size;
                if (ingested % 25 === 0)
                    ctx.log?.(`learn_folder: ${ingested} file(s) so far…`);
            }
        }
        // ONE index pass for the whole run, instead of one per file.
        await indexKnowledge(ctx.dataDir, entries);
        const skipped = `Skipped: ${skipExt} unsupported extension, ${skipDoc} document(s) (pass documents:true to include .docx/.xlsx/.pptx/.epub), ${skipBinary} binary, ${skipLarge} over ${MAX_LEARN_BYTES} bytes, ${skipEmpty} empty, ${skipUnreadable} unreadable, ${skipLink} symlink(s); ${dirsSkipped} directory/ies skipped.`;
        if (ingested === 0)
            return { content: `No text/code files found under ${dir}. ${skipped}` };
        const lines = [
            `Learned ${ingested} file(s) from ${dir} → ${chunkTotal} chunk(s), ${(totalBytes / 1024 / 1024).toFixed(2)} MB ingested.`,
            skipped,
        ];
        if (stop)
            lines.push(`STOPPED EARLY: ${stop} — some files were NOT ingested.`);
        lines.push('Search it with knowledge_search.');
        return { content: lines.join('\n') };
    },
});
const learnPdfTool = buildTool({
    name: 'learn_pdf',
    description: 'Learn a PDF document: extract the embedded text layer (zero-dependency extractor for standard text PDFs); scanned/image-only PDFs automatically fall back to the offline Windows OCR engine (Windows.Media.Ocr + Windows.Data.Pdf).',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: 'PDF file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `PDF too large to learn (${stat.size} bytes).`, isError: true };
        }
        const buf = fs.readFileSync(p);
        if (buf.subarray(0, 5).toString('latin1') !== '%PDF-') {
            return { content: 'Not a PDF file (missing %PDF- header).', isError: true };
        }
        let text;
        try {
            text = extractPdfText(buf);
        }
        catch (e) {
            return { content: `PDF extraction failed: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
        if (text.replace(/\s+/g, '').length < 20) {
            // No text layer → likely a scanned/image-only PDF. Try the offline
            // Windows OCR engine (page renders via Windows.Data.Pdf) before giving up.
            const ocr = await ocrPdfFile(p, ctx.cwd);
            if (!ocr || ocr.replace(/\s+/g, '').length < 20) {
                return {
                    content: 'No extractable text found (scanned/image-only PDF, encrypted, or unusual font encoding?), and OCR found nothing readable. Try ocr_read on it directly.',
                    isError: true,
                };
            }
            text = ocr;
            const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
            return { content: `Learned PDF ${p} via OCR → ${n} chunk(s), ${text.length} chars recognized.` };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned PDF ${p} → ${n} chunk(s), ${text.length} chars extracted.` };
    },
});
const learnDocxTool = buildTool({
    name: 'learn_docx',
    description: 'Learn a Word document (.docx): extract the body text from word/document.xml (zero-dependency ZIP+OOXML parser) and store it in the knowledge base. Headers/footers and embedded media are not included.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: '.docx file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `DOCX too large to learn (${stat.size} bytes).`, isError: true };
        }
        const buf = fs.readFileSync(p);
        if (buf.subarray(0, 4).toString('latin1') !== 'PK\x03\x04') {
            return { content: 'Not a .docx file (missing ZIP signature).', isError: true };
        }
        const text = extractDocxText(buf);
        if (text.replace(/\s+/g, '').length < 20) {
            return { content: 'No body text found in word/document.xml (empty document or unsupported layout).', isError: true };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned DOCX ${p} → ${n} chunk(s), ${text.length} chars extracted.` };
    },
});
const learnXlsxTool = buildTool({
    name: 'learn_xlsx',
    description: 'Learn a spreadsheet (.xlsx): extract every sheet as tab-joined cell rows (zero-dependency ZIP+OOXML parser; shared-string table resolved) and store it in the knowledge base.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: '.xlsx file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `XLSX too large to learn (${stat.size} bytes).`, isError: true };
        }
        const buf = fs.readFileSync(p);
        if (buf.subarray(0, 4).toString('latin1') !== 'PK\x03\x04') {
            return { content: 'Not an .xlsx file (missing ZIP signature).', isError: true };
        }
        const text = extractXlsxText(buf);
        if (text.replace(/\s+/g, '').length < 20) {
            return { content: 'No readable cells found in the workbook (empty sheets or unsupported layout).', isError: true };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned XLSX ${p} → ${n} chunk(s), ${text.length} chars extracted.` };
    },
});
const learnPptxTool = buildTool({
    name: 'learn_pptx',
    description: 'Learn a presentation (.pptx): extract each slide as text in order (zero-dependency ZIP+OOXML parser over <a:t> runs) and store it in the knowledge base.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: '.pptx file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `PPTX too large to learn (${stat.size} bytes).`, isError: true };
        }
        const buf = fs.readFileSync(p);
        if (buf.subarray(0, 4).toString('latin1') !== 'PK\x03\x04') {
            return { content: 'Not a .pptx file (missing ZIP signature).', isError: true };
        }
        const text = extractPptxText(buf);
        if (text.replace(/\s+/g, '').length < 20) {
            return { content: 'No slide text found (empty deck or unsupported layout).', isError: true };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned PPTX ${p} → ${n} chunk(s), ${text.length} chars extracted.` };
    },
});
const learnEpubTool = buildTool({
    name: 'learn_epub',
    description: 'Learn an e-book (.epub): extract the readable text of each content document (zero-dependency ZIP+XHTML parser, metadata skipped) and store it in the knowledge base.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: '.epub file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `EPUB too large to learn (${stat.size} bytes).`, isError: true };
        }
        const buf = fs.readFileSync(p);
        if (buf.subarray(0, 4).toString('latin1') !== 'PK\x03\x04') {
            return { content: 'Not an .epub file (missing ZIP signature).', isError: true };
        }
        const text = extractEpubText(buf);
        if (text.replace(/\s+/g, '').length < 20) {
            return { content: 'No readable text found in the e-book content documents.', isError: true };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned EPUB ${p} → ${n} chunk(s), ${text.length} chars extracted.` };
    },
});
const learnTranscriptTool = buildTool({
    name: 'learn_transcript',
    description: 'Learn a subtitle/transcript file (.srt or .vtt): strip timestamps and markup, collapse repeated caption lines, and store the spoken text in the knowledge base.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: '.srt or .vtt file path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const stat = fs.statSync(p);
        if (stat.size > MAX_LEARN_BYTES) {
            return { content: `Transcript too large to learn (${stat.size} bytes).`, isError: true };
        }
        const text = parseTranscript(fs.readFileSync(p, 'utf8'));
        if (text.replace(/\s+/g, '').length < 20) {
            return { content: 'No cue text found in the transcript (empty or unsupported format).', isError: true };
        }
        const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
        return { content: `Learned transcript ${p} → ${n} chunk(s), ${text.length} chars of spoken text.` };
    },
});
const learnUrlTool = buildTool({
    name: 'learn_url',
    description: 'Fetch a web page, extract readable text, and store it in the knowledge base for later search.',
    input_schema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'http(s) URL to learn' } },
        required: ['url'],
    },
    run: async (input, ctx) => {
        const url = str(input, 'url');
        if (!/^https?:\/\//i.test(url))
            return { content: 'Only http(s) URLs are supported.', isError: true };
        const res = await fetchWithTimeout(url);
        const ct = res.headers.get('content-type') ?? '';
        const raw = await res.text();
        const text = ct.includes('html') ? stripHtml(raw) : raw;
        const n = await saveKnowledge(ctx.dataDir, url, 'url', text);
        resetEmbedProbe(); // a just-pulled model should be picked up immediately
        return { content: `Learned ${url} (HTTP ${res.status}) → ${n} chunk(s).`, isError: !res.ok };
    },
});
const knowledgeSearchTool = buildTool({
    name: 'knowledge_search',
    description: 'Search the learned knowledge base (hybrid: TF-IDF + semantic vector ranking over chunks). Returns the best matching passages with their sources.',
    input_schema: {
        type: 'object',
        properties: {
            query: { type: 'string', description: 'What to look for' },
            k: { type: 'number', description: 'Max passages to return (default 4)' },
        },
        required: ['query'],
    },
    run: async (input, ctx) => {
        const dir = knowledgeDir(ctx.dataDir);
        if (!fs.existsSync(dir))
            return { content: 'Knowledge base is empty. Use learn_file / learn_pdf / learn_url first.' };
        const entries = [];
        for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
            // The knowledge dir may contain stray JSON files that are not chunk
            // files (agent runs have written artifacts here). Skip anything that
            // does not parse or does not carry a chunks array instead of crashing
            // the whole search.
            let kf = null;
            try {
                const parsed = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
                if (parsed && Array.isArray(parsed.chunks))
                    kf = parsed;
            }
            catch {
                /* not a knowledge file — skip */
            }
            if (!kf)
                continue;
            const base = f.replace(/\.json$/, '');
            kf.chunks.forEach((c, i) => entries.push({ id: `kb:${base}#chunk${i + 1}`, text: c, mtime: Date.parse(kf.saved) }));
        }
        const store = openStore(ctx.dataDir);
        const ranked = await hybridRank(str(input, 'query'), entries, store, 'kb:', Math.max(1, num(input, 'k', 4)));
        if (ranked.length === 0)
            return { content: 'No knowledge matches that query.' };
        return {
            content: ranked
                .map((r) => `[${r.id.replace(/^kb:/, '')}] (score ${r.score.toFixed(2)})\n${r.snippet}`)
                .join('\n\n---\n\n'),
        };
    },
});
// ---------------------------------------------------------------------------
// FORGETTING (B6)
// ---------------------------------------------------------------------------
// Until this existed, knowledge could be added but never removed: learn the
// wrong file, paste the wrong URL, ingest a doc with a secret in it, and the
// only way out was to delete files by hand in the data dir. Worse, deleting the
// JSON alone is NOT enough — the vectors survive, so knowledge_search keeps
// returning passages from a document that no longer exists on disk.
//
// This is the prerequisite for B7 (dedup): you cannot remove near-duplicates
// from a corpus you cannot delete from.
/**
 * Duplicate detection for the knowledge base (B7).
 *
 * WHY THIS EXISTS. The corpus was near-duplicated: two copies of the Instagram
 * playbook (178 and 200 chunks) measured 98% shared vocabulary, and 194 of the
 * 208 near-duplicate chunk pairs found spanned two different sources. That
 * inflates every count, drowns retrieval in repeats of the same passage, and
 * makes "learned the same thing twice" indistinguishable from learning something
 * new.
 *
 * WHY SHINGLES, NOT RAW TOKEN SETS. Comparing Jaccard over bag-of-words token
 * sets is wrong in a way that matters: two documents listing the same 20 hook
 * techniques in a different ORDER score as near-identical, because a set forgets
 * sequence. Shingles (consecutive word n-grams) keep order, so a reordered
 * document is correctly seen as different. Token-level comparison is still used
 * for the source-level CONTAINMENT check, where "does this subset add anything?"
 * is exactly the right question and sequence is not.
 *
 * Nothing here deletes anything. This module only reports; removal goes through
 * the existing forgetKnowledge path so deletion stays a single, auditable route
 * that also purges vectors.
 */

/** Consecutive word n-grams. Order-sensitive, unlike a token set. */
function shingles(text, n = 5) {
    const words = tokenize(text);
    if (words.length === 0)
        return new Set();
    if (words.length < n) {
        // Too short to shingle: fall back to the whole text, so short but identical
        // chunks (a repeated URL, a one-line caption) are still comparable.
        return new Set([words.join(' ')]);
    }
    const out = new Set();
    for (let i = 0; i + n <= words.length; i++)
        out.add(words.slice(i, i + n).join(' '));
    return out;
}
/** |A∩B| / |A∪B| over two shingle sets. */
function shingleJaccard(a, b) {
    if (a.size === 0 || b.size === 0)
        return 0;
    let inter = 0;
    const [small, large] = a.size <= b.size ? [a, b] : [b, a];
    for (const s of small)
        if (large.has(s))
            inter++;
    return inter / (a.size + b.size - inter);
}
/** |A∩B| / min(|A|,|B|) — "how much of the smaller thing is already covered". */
function shingleContainment(a, b) {
    if (a.size === 0 || b.size === 0)
        return 0;
    let inter = 0;
    const [small, large] = a.size <= b.size ? [a, b] : [b, a];
    for (const s of small)
        if (large.has(s))
            inter++;
    return inter / small.size;
}
/** Chunks with fewer words than this are not compared — too little signal. */
const MIN_WORDS = 12;
/**
 * Group near-duplicate chunks.
 *
 * Comparison is roughly O(n·k) rather than O(n²): each chunk is bucketed by a
 * few of its own shingles, and only chunks sharing a bucket are scored. On a
 * 643-chunk corpus that is the difference between ~200k comparisons and ~2k,
 * and it is what keeps a sweep usable as the corpus grows.
 *
 * `threshold` is Jaccard over shingles. 0.85 was chosen against this corpus: it
 * catches the repeated playbook sections while leaving genuinely different
 * chapters apart. It is a parameter rather than a constant because the right
 * value depends on the material — code and prose do not duplicate the same way.
 */
function findDuplicateGroups(docs, threshold = 0.85) {
    const usable = docs.filter((d) => tokenize(d.text).length >= MIN_WORDS);
    if (usable.length < 2)
        return [];
    const sets = usable.map((d) => shingles(d.text));
    // Bucket -> candidate indices. Only a few shingles per chunk are used as keys
    // so that common phrases do not funnel everything into one bucket.
    const buckets = new Map();
    usable.forEach((_d, i) => {
        for (const key of [...sets[i]].slice(0, 8)) {
            const b = buckets.get(key);
            if (b)
                b.push(i);
            else
                buckets.set(key, [i]);
        }
    });
    const seen = new Set();
    const groups = [];
    for (let i = 0; i < usable.length; i++) {
        const keepKey = usable[i].id + '#' + usable[i].chunk;
        if (seen.has(keepKey))
            continue;
        const cands = new Set();
        for (const key of [...sets[i]].slice(0, 8)) {
            for (const j of buckets.get(key) ?? [])
                if (j > i)
                    cands.add(j);
        }
        const drop = [];
        for (const j of cands) {
            const dropKey = usable[j].id + '#' + usable[j].chunk;
            if (seen.has(dropKey))
                continue;
            const score = shingleJaccard(sets[i], sets[j]);
            if (score >= threshold) {
                drop.push({ ...usable[j], score: Number(score.toFixed(3)) });
                seen.add(dropKey);
            }
        }
        if (drop.length) {
            seen.add(keepKey);
            groups.push({ keep: usable[i], drop });
        }
    }
    return groups;
}
/**
 * Find sources that are largely a subset of another.
 *
 * This is the coarse view, and it is where the real savings are: the two
 * Instagram playbook copies are 178 and 200 chunks at 98% containment, so
 * removing the redundant one reclaims ~180 chunks at a stroke, versus shaving
 * near-duplicates one chunk at a time.
 *
 * Containment rather than Jaccard on purpose. A 180-chunk playbook and a
 * 25-chunk video summary can share most of the summary's vocabulary while the
 * summary adds almost nothing — Jaccard would call that a weak match, and
 * containment calls it 90% redundant, which is the question actually being asked.
 */
function findRedundantSources(sources, threshold = 0.9) {
    const vocab = sources.map((s) => {
        const set = new Set();
        for (const c of s.chunks)
            for (const t of tokenize(c))
                set.add(t);
        return set;
    });
    // Largest first, so a big document becomes the keeper and small subsets get
    // absorbed by it rather than the other way round.
    const order = sources.map((_s, i) => i).sort((a, b) => sources[b].chunks.length - sources[a].chunks.length);
    const out = [];
    const absorbed = new Set();
    for (const i of order) {
        if (absorbed.has(i))
            continue;
        const covered = [];
        for (const j of order) {
            if (j === i || absorbed.has(j))
                continue;
            // Only absorb a SMALLER source into a bigger one. Absorbing a large source
            // into a small one would delete the more complete copy — the single worst
            // failure mode here, so it is excluded structurally rather than by a check
            // someone could forget.
            if (sources[j].chunks.length >= sources[i].chunks.length)
                continue;
            const c = shingleContainment(vocab[j], vocab[i]);
            if (c >= threshold) {
                covered.push({
                    id: sources[j].id,
                    chunks: sources[j].chunks.length,
                    source: sources[j].source,
                    containment: Number(c.toFixed(3)),
                });
                absorbed.add(j);
            }
        }
        if (covered.length) {
            out.push({
                keep: { id: sources[i].id, chunks: sources[i].chunks.length, source: sources[i].source },
                covered,
            });
        }
    }
    return out;
}
/** Every stored knowledge source, with the file that holds it. */
function listKnowledgeSources(dataDir) {
    const dir = knowledgeDir(dataDir);
    if (!fs.existsSync(dir))
        return [];
    const out = [];
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
        try {
            const kf = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
            // Skip stray JSON an agent run dropped here: no chunks array means it is
            // not a knowledge file, and it must never be listed or deleted.
            if (!kf || !Array.isArray(kf.chunks))
                continue;
            out.push({ file: f, source: kf.source, kind: kf.kind, saved: kf.saved, chunks: kf.chunks.length });
        }
        catch {
            /* unparseable — not a knowledge file */
        }
    }
    return out;
}
/**
 * Resolve a user-supplied reference to stored sources.
 *
 * Accepts the source text itself ("https://…/post", a path) or the bare
 * knowledge id ("my-notes-a1b2c3"). Users paste what they can see, and
 * knowledge_list only ever shows them the source — the id is an implementation
 * detail, so requiring it would ask for something the UI never displayed.
 *
 * Matching is EXACT first, then unique-substring. The looser pass only ever
 * resolves when it matches exactly one source: deleting three documents because
 * someone typed three letters of their name is not a recoverable mistake.
 */
function resolveForgetTargets(dataDir, ref) {
    const all = listKnowledgeSources(dataDir);
    const needle = ref.trim().toLowerCase();
    if (!needle)
        return { exact: [], fuzzy: [] };
    const id = (s) => s.file.replace(/\.json$/, '').toLowerCase();
    const exact = all.filter((s) => s.source.toLowerCase() === needle || id(s) === needle);
    if (exact.length)
        return { exact, fuzzy: [] };
    const fuzzy = all.filter((s) => s.source.toLowerCase().includes(needle) || id(s).includes(needle));
    return { exact: [], fuzzy };
}
/**
 * Delete knowledge sources and purge their vectors.
 *
 * The vector purge is the part that is easy to forget and the reason this is
 * more than an fs.rm: knowledge_search ranks against the semantic index, so a
 * deleted document whose embeddings are still in the store keeps surfacing in
 * results until the store is rebuilt by hand.
 */
function forgetKnowledge(dataDir, ref) {
    const { exact, fuzzy } = resolveForgetTargets(dataDir, ref);
    let targets = [];
    let ambiguous = [];
    if (exact.length)
        targets = exact;
    else if (fuzzy.length === 1)
        targets = fuzzy;
    else if (fuzzy.length > 1)
        ambiguous = fuzzy;
    if (ambiguous.length)
        return { removed: [], vectorsPurged: 0, notFound: true, ambiguous };
    if (!targets.length)
        return { removed: [], vectorsPurged: 0, notFound: true, ambiguous: [] };
    const dir = knowledgeDir(dataDir);
    let vectorsPurged = 0;
    for (const t of targets) {
        try {
            fs.rmSync(path.join(dir, t.file), { force: true });
        }
        catch {
            continue; // reported below by checking what actually survived
        }
        vectorsPurged += purgeKnowledgeVectors(dataDir, t.file.replace(/\.json$/, ''));
    }
    // Report only what genuinely went, rather than claiming a deletion that failed.
    const removed = targets.filter((t) => !fs.existsSync(path.join(dir, t.file)));
    return { removed, vectorsPurged, notFound: removed.length === 0, ambiguous: [] };
}
/** Drop every vector belonging to one knowledge source. Returns how many went. */
function purgeKnowledgeVectors(dataDir, id) {
    const prefix = `kb:${id}#`;
    let n = 0;
    try {
        const store = openStore(dataDir);
        for (const key of Object.keys(store.file.entries)) {
            if (key.startsWith(prefix)) {
                delete store.file.entries[key];
                n++;
            }
        }
        if (n > 0) {
            store.dirty = true;
            // saveStore refuses to persist a fallback index over a real one. That
            // guard is right when EMBEDDING, but here we are only DELETING, and the
            // refusal would silently leave the purged vectors in place — the exact bug
            // this function exists to prevent. Removing entries never replaces a good
            // vector space with a bad one, so clearing the flag is safe.
            store.unsafeFallback = false;
            saveStore(store);
        }
    }
    catch {
        // A missing or unreadable store is not a reason to fail the deletion: the
        // JSON is gone, which is what the user asked for. There is simply nothing
        // to purge.
    }
    return n;
}
const knowledgeForgetTool = buildTool({
    name: 'knowledge_forget',
    description: 'Delete learned knowledge so it can never come back in search results: pass the source ' +
        '(a URL or file path) or its knowledge id from knowledge_list. Removes the stored ' +
        'document AND its vectors. Use this when the wrong thing was learned, a document is ' +
        'out of date, or it contained something it should not have.',
    input_schema: {
        type: 'object',
        properties: {
            source: { type: 'string', description: 'The source to forget: a URL, a file path, or a knowledge id.' },
        },
        required: ['source'],
    },
    run: async (input, ctx) => {
        const ref = str(input, 'source');
        if (!ref.trim())
            return { content: 'Nothing specified. Pass the source to forget.', isError: true };
        const r = forgetKnowledge(ctx.dataDir, ref);
        if (r.ambiguous.length) {
            return {
                content: `"${ref}" matches ${r.ambiguous.length} sources — nothing was deleted. ` +
                    'Re-run with the full source or the knowledge id:\n' +
                    r.ambiguous.map((s) => `- ${s.file.replace(/\.json$/, '')} → ${s.source}`).join('\n'),
                isError: true,
            };
        }
        if (r.notFound) {
            return {
                content: `No learned source matches "${ref}". Nothing was deleted. Use knowledge_list to see what is stored.`,
                isError: true,
            };
        }
        const names = r.removed.map((s) => s.source).join(', ');
        const chunks = r.removed.reduce((n, s) => n + s.chunks, 0);
        return {
            content: `Forgot ${r.removed.length} source(s) — ${names}. Removed ${chunks} chunk(s) and ` +
                `purged ${r.vectorsPurged} vector(s). It will no longer appear in knowledge_search.`,
        };
    },
});
/**
 * Scan the corpus for duplication. Reports only — deletes nothing.
 *
 * The default for a destructive-looking tool is to do nothing and say what it
 * found. Removing 178 chunks on a hunch is not a decision to make blind, and the
 * whole value of the sweep is that the numbers are visible BEFORE the decision.
 */
function sweepDuplicates(dataDir, threshold = 0.85) {
    const dir = knowledgeDir(dataDir);
    const sources = [];
    const docs = [];
    if (fs.existsSync(dir)) {
        for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
            let kf = null;
            try {
                const parsed = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
                if (parsed && Array.isArray(parsed.chunks))
                    kf = parsed;
            }
            catch {
                /* stray file — skip */
            }
            if (!kf)
                continue;
            const id = f.replace(/\.json$/, '');
            sources.push({ id, source: kf.source, chunks: kf.chunks });
            kf.chunks.forEach((c, i) => docs.push({ id, chunk: i + 1, text: c }));
        }
    }
    const overlaps = findRedundantSources(sources);
    const groups = findDuplicateGroups(docs, threshold);
    const redundantSources = [];
    for (const o of overlaps) {
        for (const c of o.covered) {
            redundantSources.push({ keep: o.keep.id, drop: c.id, chunks: c.chunks, containment: c.containment });
        }
    }
    const duplicateChunks = groups.flatMap((g) => g.drop.map((d) => `${d.id}#${d.chunk}`));
    // Chunks inside an already-redundant source are not counted twice.
    const redundantIds = new Set(redundantSources.map((r) => r.drop));
    const chunkSavings = duplicateChunks.filter((ref) => !redundantIds.has(ref.split('#')[0])).length;
    return {
        sources: sources.length,
        chunks: docs.length,
        redundantSources,
        duplicateChunks,
        reclaimable: redundantSources.reduce((n, r) => n + r.chunks, 0) + chunkSavings,
    };
}
const knowledgeDedupTool = buildTool({
    name: 'knowledge_dedup',
    description: 'Scan the learned knowledge for duplicates and report what a cleanup would reclaim. ' +
        'Reports only — deletes nothing. Use this to see whether the corpus has redundancy ' +
        'before removing anything with knowledge_forget.',
    input_schema: {
        type: 'object',
        properties: {
            threshold: { type: 'number', description: 'Similarity 0-1; higher is stricter (default 0.85).' },
        },
        required: [],
    },
    run: async (input, ctx) => {
        const t = num(input, 'threshold', 0.85);
        const s = sweepDuplicates(ctx.dataDir, Math.min(0.99, Math.max(0.5, t)));
        if (!s.redundantSources.length && !s.duplicateChunks.length) {
            return { content: `No duplication found across ${s.sources} source(s) / ${s.chunks} chunk(s).` };
        }
        const lines = [
            `Scanned ${s.sources} source(s) / ${s.chunks} chunk(s). Nothing was changed.`,
            '',
        ];
        if (s.redundantSources.length) {
            lines.push('Sources almost entirely covered by another:');
            for (const r of s.redundantSources) {
                lines.push(`  ${(r.containment * 100).toFixed(0)}% of "${r.drop}" (${r.chunks} chunks) is already in "${r.keep}"`);
            }
            lines.push('');
        }
        if (s.duplicateChunks.length) {
            lines.push(`${s.duplicateChunks.length} near-duplicate chunk(s), e.g.:`);
            for (const c of s.duplicateChunks.slice(0, 8))
                lines.push(`  ${c}`);
            if (s.duplicateChunks.length > 8)
                lines.push(`  ... and ${s.duplicateChunks.length - 8} more`);
            lines.push('');
        }
        lines.push(`A full cleanup would reclaim about ${s.reclaimable} chunk(s).`, 'Nothing has been deleted. Remove sources with knowledge_forget if you agree.');
        return { content: lines.join('\n') };
    },
});
const knowledgeListTool = buildTool({
    name: 'knowledge_list',
    description: 'List learned sources with chunk counts, newest first. Optional limit/offset paginate a large corpus for row-style UIs; without them every source is returned.',
    input_schema: {
        type: 'object',
        properties: {
            limit: { type: 'integer', description: 'Return at most this many sources.' },
            offset: { type: 'integer', description: 'Skip this many sources first (pagination).' },
        },
        required: [],
    },
    run: async (input, ctx) => {
        const dir = knowledgeDir(ctx.dataDir);
        if (!fs.existsSync(dir))
            return { content: 'Knowledge base is empty.' };
        const items = [];
        for (const f of fs.readdirSync(dir)) {
            if (!f.endsWith('.json'))
                continue;
            const p = path.join(dir, f);
            try {
                const kf = JSON.parse(fs.readFileSync(p, 'utf8'));
                if (!kf || !Array.isArray(kf.chunks))
                    continue;
                items.push({
                    line: `- [${kf.kind}] ${kf.source} (${kf.chunks.length} chunks, saved ${kf.saved.slice(0, 10)})`,
                    mtime: fs.statSync(p).mtimeMs,
                });
            }
            catch {
                // stray non-knowledge file — skip it and keep listing the rest
            }
        }
        if (!items.length)
            return { content: 'Knowledge base is empty.' };
        // Newest first, so a paginated page is the most recently learned material.
        // mtime rather than kf.saved: ordering must still work for files written
        // before that field existed.
        items.sort((a, b) => b.mtime - a.mtime);
        const lim = Number(input.limit);
        const off = Number(input.offset);
        const limit = Number.isFinite(lim) ? Math.min(1000, Math.max(1, Math.trunc(lim))) : items.length;
        const offset = Number.isFinite(off) ? Math.max(0, Math.trunc(off)) : 0;
        const page = items.slice(offset, offset + limit);
        const lines = page.map((i) => i.line);
        // Always say when the page is partial: a truncated list that reads as the
        // whole corpus is exactly the class of confusion the unreadable knowledge
        // panel produced ("0 knowledge chunks" when hundreds existed).
        if (offset > 0 || page.length < items.length) {
            lines.push('');
            lines.push(`showing ${offset + 1}-${offset + page.length} of ${items.length} sources`);
        }
        return { content: lines.join('\n') };
    },
});
return { chunkText,writeKnowledgeFile,indexKnowledge,saveKnowledge,saveKnowledgeReport,learnFileTool,learnFolderTool,learnPdfTool,learnDocxTool,learnXlsxTool,learnPptxTool,learnEpubTool,learnTranscriptTool,learnUrlTool,knowledgeSearchTool,shingles,shingleJaccard,shingleContainment,findDuplicateGroups,findRedundantSources,listKnowledgeSources,resolveForgetTargets,forgetKnowledge,knowledgeForgetTool,sweepDuplicates,knowledgeDedupTool,knowledgeListTool };
}

__mod['tools/knowledge.js'] = M43();

function M44() {
const { buildTool, num, str } = __mod['core/tools.js'];
/**
 * Project memory: per-workspace running log (~/.blackrose/projects/<slug>.md).
 * The most recent notes are injected into the system prompt so BlackRose can
 * "continue where we left off" in this workspace.
 */
function projectFileFor(dataDir, cwd) {
    const slug = path.basename(path.resolve(cwd)).toLowerCase().replace(/[^a-z0-9-_]+/g, '-') || 'workspace';
    return path.join(dataDir, 'projects', `${slug}.md`);
}
function readProjectNotes(dataDir, cwd, maxChars = 1500) {
    const p = projectFileFor(dataDir, cwd);
    if (!fs.existsSync(p))
        return '';
    const raw = fs.readFileSync(p, 'utf8').trim();
    if (!raw)
        return '';
    return raw.length <= maxChars ? raw : '…' + raw.slice(-maxChars);
}
const projectNoteTool = buildTool({
    name: 'project_note',
    description: 'Append a durable note to this workspace\'s project memory (decisions, state, "where we left off"). These notes are auto-loaded at the start of every future session in this workspace.',
    input_schema: {
        type: 'object',
        properties: { note: { type: 'string', description: 'The note to remember for this workspace' } },
        required: ['note'],
    },
    run: async (input, ctx) => {
        const note = str(input, 'note').trim();
        if (!note)
            return { content: 'note is required', isError: true };
        const p = projectFileFor(ctx.dataDir, ctx.cwd);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.appendFileSync(p, `- ${new Date().toISOString()} — ${note}\n`, 'utf8');
        return { content: `Project note recorded (${p}).` };
    },
});
const projectReadTool = buildTool({
    name: 'project_read',
    description: 'Read this workspace\'s project memory (recent notes, newest last).',
    input_schema: {
        type: 'object',
        properties: { last: { type: 'number', description: 'Show only the last N notes (default 20)' } },
        required: [],
    },
    run: async (input, ctx) => {
        const p = projectFileFor(ctx.dataDir, ctx.cwd);
        if (!fs.existsSync(p))
            return { content: 'No project memory for this workspace yet.' };
        const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
        const n = Math.max(1, num(input, 'last', 20));
        return { content: lines.slice(-n).join('\n') };
    },
});
return { projectFileFor,readProjectNotes,projectNoteTool,projectReadTool };
}

__mod['tools/project.js'] = M44();

function M45() {
const { buildTool, num, str } = __mod['core/tools.js'];
function file(dataDir) {
    return path.join(dataDir, 'schedules.json');
}
function loadSchedules(dataDir) {
    const f = file(dataDir);
    if (!fs.existsSync(f))
        return [];
    try {
        return JSON.parse(fs.readFileSync(f, 'utf8'));
    }
    catch {
        return [];
    }
}
function saveSchedules(dataDir, list) {
    fs.writeFileSync(file(dataDir), JSON.stringify(list, null, 2), 'utf8');
}
function addSchedule(dataDir, s) {
    const list = loadSchedules(dataDir);
    const full = {
        ...s,
        id: `sch_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
        enabled: true,
        created: new Date().toISOString(),
        runCount: 0,
    };
    list.push(full);
    saveSchedules(dataDir, list);
    return full;
}
function removeSchedule(dataDir, id) {
    const list = loadSchedules(dataDir);
    const next = list.filter((s) => s.id !== id);
    if (next.length === list.length)
        return false;
    saveSchedules(dataDir, next);
    return true;
}
/** Cron-lite: "every N minutes" or daily at HH:MM. */
function isDue(s, now = new Date()) {
    if (!s.enabled)
        return false;
    if (s.everyMinutes && s.everyMinutes > 0) {
        if (!s.lastRun)
            return true;
        return now.getTime() - Date.parse(s.lastRun) >= s.everyMinutes * 60_000;
    }
    if (s.dailyAt && /^\d{2}:\d{2}$/.test(s.dailyAt)) {
        // LOCAL throughout. The day-rollover check used to compare UTC dates
        // (now.toISOString().slice(0,10)) against LOCAL clock fields
        // (now.getHours()), so the two halves of the condition disagreed. In any
        // timezone that is not UTC the boundary disagrees: a task set for 23:00
        // local near midnight UTC would either be skipped for a day or fire twice,
        // because "which day is it" and "what time is it" were answered by
        // different clocks. Both now read the local clock.
        const sameLocalDay = (iso, ref) => {
            const d = new Date(iso);
            return (d.getFullYear() === ref.getFullYear() &&
                d.getMonth() === ref.getMonth() &&
                d.getDate() === ref.getDate());
        };
        if (s.lastRun && sameLocalDay(s.lastRun, now))
            return false;
        const [h, m] = s.dailyAt.split(':').map(Number);
        return now.getHours() > h || (now.getHours() === h && now.getMinutes() >= m);
    }
    return false;
}
const scheduleTaskTool = buildTool({
    name: 'schedule_task',
    description: 'Create a persistent scheduled task: a prompt BlackRose runs by itself on a timer (every_minutes OR daily_at "HH:MM"). Unattended runs cannot approve dangerous actions. Requires approval.',
    input_schema: {
        type: 'object',
        properties: {
            name: { type: 'string', description: 'Short name for the task' },
            prompt: { type: 'string', description: 'The full prompt to run when the task fires' },
            every_minutes: { type: 'number', description: 'Run every N minutes (mutually exclusive with daily_at)' },
            daily_at: { type: 'string', description: 'Run daily at HH:MM local time' },
        },
        required: ['name', 'prompt'],
    },
    requiresApproval: (input) => `Create scheduled task "${str(input, 'name')}" that runs unattended`,
    run: async (input, ctx) => {
        const everyMinutes = input.every_minutes === undefined ? undefined : num(input, 'every_minutes', 0);
        const dailyAt = str(input, 'daily_at') || undefined;
        if (!everyMinutes && !dailyAt)
            return { content: 'Provide every_minutes or daily_at.', isError: true };
        if (everyMinutes && dailyAt)
            return { content: 'Provide only one of every_minutes / daily_at.', isError: true };
        if (dailyAt && !/^\d{2}:\d{2}$/.test(dailyAt))
            return { content: 'daily_at must be HH:MM.', isError: true };
        // Reject a non-positive interval instead of coercing it. A negative value is
        // truthy, so it passed the "did they give one?" check, then line 107 mapped
        // it to `undefined` — leaving a schedule with NO trigger that reports
        // success and silently never fires. A task the user believes is running is
        // worse than a task that was refused.
        if (everyMinutes !== undefined && !(everyMinutes > 0)) {
            return { content: 'every_minutes must be greater than 0.', isError: true };
        }
        const s = addSchedule(ctx.dataDir, {
            name: str(input, 'name').slice(0, 80),
            prompt: str(input, 'prompt'),
            everyMinutes: everyMinutes && everyMinutes > 0 ? Math.max(1, Math.round(everyMinutes)) : undefined,
            dailyAt,
        });
        return {
            content: `Scheduled "${s.name}" (${s.id}): ${s.everyMinutes ? `every ${s.everyMinutes} min` : `daily at ${s.dailyAt}`}. Fires while BlackRose is running.`,
        };
    },
});
const scheduleListTool = buildTool({
    name: 'schedule_list',
    description: 'List scheduled tasks and their last-run status.',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async (_input, ctx) => {
        const list = loadSchedules(ctx.dataDir);
        if (list.length === 0)
            return { content: 'No scheduled tasks.' };
        return {
            content: list
                .map((s) => `${s.id}  ${s.enabled ? 'on ' : 'off'}  ${s.everyMinutes ? `every ${s.everyMinutes}m` : `daily ${s.dailyAt}`}  runs:${s.runCount}  last:${s.lastRun?.slice(0, 16) ?? 'never'}  ${s.name}: ${s.prompt.slice(0, 60)}`)
                .join('\n'),
        };
    },
});
const scheduleRemoveTool = buildTool({
    name: 'schedule_remove',
    description: 'Delete a scheduled task by id.',
    input_schema: {
        type: 'object',
        properties: { id: { type: 'string', description: 'Schedule id, e.g. sch_x1y2z3_abcd' } },
        required: ['id'],
    },
    run: async (input, ctx) => {
        return removeSchedule(ctx.dataDir, str(input, 'id'))
            ? { content: 'Scheduled task removed.' }
            : { content: `Unknown schedule id: ${str(input, 'id')}`, isError: true };
    },
});
return { loadSchedules,saveSchedules,addSchedule,removeSchedule,isDue,scheduleTaskTool,scheduleListTool,scheduleRemoveTool };
}

__mod['tools/schedule.js'] = M45();

function M46() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { resolveInWorkspace } = __mod['core/permissions.js'];
const { execShell } = __mod['core/processes.js'];
/**
 * Screen awareness & GUI control (Phase 3, Windows-first via PowerShell /
 * user32). Privacy rule: every screen interaction requires explicit approval,
 * and screenshots are stored under ~/.blackrose/screenshots.
 */
const MEDIA_TYPES = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
};
const screenshotTool = buildTool({
    name: 'screenshot',
    description: 'Capture the screen to a PNG file (stored in ~/.blackrose/screenshots) and attach it to the conversation so you can see it. Requires user approval (privacy).',
    input_schema: {
        type: 'object',
        properties: {},
        required: [],
    },
    requiresApproval: () => 'Screen capture is privacy-sensitive',
    run: async (_input, ctx) => {
        if (process.platform !== 'win32')
            return { content: 'screenshot is currently Windows-only.', isError: true };
        const dir = path.join(ctx.dataDir, 'screenshots');
        fs.mkdirSync(dir, { recursive: true });
        const out = path.join(dir, `shot-${Date.now()}.png`);
        const ps = [
            'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
            '$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
            '$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height',
            '$g=[System.Drawing.Graphics]::FromImage($bmp)',
            '$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size)',
            `$bmp.Save('${out.replace(/\\/g, '\\\\')}',[System.Drawing.Imaging.ImageFormat]::Png)`,
            '$g.Dispose(); $bmp.Dispose()',
        ].join('; ');
        const r = await execShell(ps, ctx.cwd, 30_000);
        if (r.exitCode !== 0 || !fs.existsSync(out)) {
            return { content: `Screenshot failed: ${r.output.slice(0, 500)}`, isError: true };
        }
        const data = fs.readFileSync(out).toString('base64');
        return {
            content: `Screenshot saved: ${out} (${fs.statSync(out).size} bytes). The image is attached.`,
            images: [{ media_type: 'image/png', data }],
        };
    },
});
const readImageTool = buildTool({
    name: 'read_image',
    description: 'Load an image file (png/jpg/gif/webp) from disk and attach it to the conversation so a vision-capable model can see it.',
    input_schema: {
        type: 'object',
        properties: { path: { type: 'string', description: 'Image path (absolute or workspace-relative)' } },
        required: ['path'],
    },
    run: async (input, ctx) => {
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        const ext = path.extname(p).toLowerCase();
        const mediaType = MEDIA_TYPES[ext];
        if (!mediaType)
            return { content: `Unsupported image type: ${ext}`, isError: true };
        // isError, not a throw, for a missing file — same contract as the other
        // file tools; the model should get a sentence it can act on.
        if (!fs.existsSync(p))
            return { content: `Image not found: ${p}`, isError: true };
        const stat = fs.statSync(p);
        if (stat.size > 5 * 1024 * 1024)
            return { content: `Image too large (${stat.size} bytes).`, isError: true };
        return {
            content: `Image loaded: ${p} (${stat.size} bytes).`,
            images: [{ media_type: mediaType, data: fs.readFileSync(p).toString('base64') }],
        };
    },
});
const SENDKEYS_SPECIALS = /[+^%~(){}[\]]/g;
function escapeSendKeys(text) {
    return text.replace(SENDKEYS_SPECIALS, (c) => `{${c}}`);
}
const guiActionTool = buildTool({
    name: 'gui_action',
    description: 'Basic GUI control on Windows: click (mouse move + click at x,y), type (send text to the focused window), or key (send a key like {ENTER}, {TAB}, ^c for Ctrl+C). Always requires approval.',
    input_schema: {
        type: 'object',
        properties: {
            action: { type: 'string', description: 'One of: click, double_click, type, key' },
            x: { type: 'number', description: 'Screen X coordinate (click actions)' },
            y: { type: 'number', description: 'Screen Y coordinate (click actions)' },
            text: { type: 'string', description: 'Text to type, or key sequence for the key action' },
        },
        required: ['action'],
    },
    requiresApproval: (input) => `GUI control: ${str(input, 'action')} ${input.x !== undefined ? `at (${num(input, 'x', 0)},${num(input, 'y', 0)}) ` : ''}${str(input, 'text').slice(0, 80)}`,
    run: async (input, ctx) => {
        if (process.platform !== 'win32')
            return { content: 'gui_action is currently Windows-only.', isError: true };
        const action = str(input, 'action');
        const ps = [
            'Add-Type -AssemblyName System.Windows.Forms',
            "Add-Type -TypeDefinition '[DllImport(\"user32.dll\")] public static extern bool SetCursorPos(int x, int y); [DllImport(\"user32.dll\")] public static extern void mouse_event(uint f, uint dx, uint dy, uint b, UIntPtr e);' -Name U32 -Namespace Win",
        ];
        if (action === 'click' || action === 'double_click') {
            const x = Math.round(num(input, 'x', 0));
            const y = Math.round(num(input, 'y', 0));
            ps.push(`[Win.U32]::SetCursorPos(${x},${y})`);
            const seq = action === 'double_click'
                ? '0x02;[Win.U32]::mouse_event(0x04,0,0,0,[UIntPtr]::Zero);Start-Sleep -m 50;[Win.U32]::mouse_event(0x02,0,0,0,[UIntPtr]::Zero);[Win.U32]::mouse_event(0x04,0,0,0,[UIntPtr]::Zero)'
                : '0x02;[Win.U32]::mouse_event(0x04,0,0,0,[UIntPtr]::Zero)';
            ps.push(`[Win.U32]::mouse_event(${seq})`);
        }
        else if (action === 'type') {
            const raw = str(input, 'text');
            if (!raw)
                return { content: 'text is required for the type action', isError: true };
            ps.push(`[System.Windows.Forms.SendKeys]::SendWait('${escapeSendKeys(raw).replace(/'/g, "''")}')`);
        }
        else if (action === 'key') {
            const raw = str(input, 'text');
            if (!raw)
                return { content: 'text is required for the key action (e.g. {ENTER}, ^c)', isError: true };
            ps.push(`[System.Windows.Forms.SendKeys]::SendWait('${raw.replace(/'/g, "''")}')`);
        }
        else {
            return { content: `Unknown action "${action}". Use: click, double_click, type, key`, isError: true };
        }
        const r = await execShell(ps.join('; '), ctx.cwd, 20_000);
        return {
            content: r.exitCode === 0 ? `GUI action done: ${action}` : `GUI action failed: ${r.output.slice(0, 400)}`,
            isError: r.exitCode !== 0,
        };
    },
});
return { screenshotTool,readImageTool,guiActionTool };
}

__mod['tools/desktop.js'] = M46();

function M47() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { execShell } = __mod['core/processes.js'];
const { resolveInWorkspace } = __mod['core/permissions.js'];
/**
 * Local push-to-talk (backlog 3-STT): speech-to-text through the LOCAL
 * Windows dictation engine (System.Speech Recognition, shared desktop
 * recognizer) — zero dependencies, fully offline, audio never leaves the
 * machine. Complements the cloud `transcribe_audio` tool:
 *   listen  → live mic → local Windows recognizer (private, offline)
 *   transcribe_audio → audio file → cloud whisper (files, higher accuracy)
 *
 * Config (all optional): BLACKROSE_LISTEN_MS (max recording window,
 * default 8000), BLACKROSE_LISTEN_LOCALE (recognizer locale, default en-US).
 */
/** True when a local System.Speech dictation recognizer is installed. */
async function localSttAvailable() {
    if (process.platform !== 'win32')
        return false;
    const r = await execShell("Add-Type -AssemblyName System.Speech; Write-Output ('BR_SR_COUNT=' + [System.Speech.Recognition.SpeechRecognitionEngine]::InstalledRecognizers().Count)", process.cwd(), 30_000);
    const m = r.output.match(/BR_SR_COUNT=(\d+)/);
    return r.exitCode === 0 && !!m && Number(m[1]) > 0;
}
/** Listening window in ms: input seconds (1–15) else BLACKROSE_LISTEN_MS else 8s. */
function listenWindowMs(input, env = process.env) {
    const envMs = Math.max(1000, Math.min(15_000, Number(env.BLACKROSE_LISTEN_MS) || 8000));
    // `seconds` is declared as a NUMBER in the schema — read it with `num()`
    // (the project helper; `str()` is string-only and would silently drop it).
    const seconds = num(input, 'seconds', Math.round(envMs / 1000));
    return Math.round(Math.max(1, Math.min(15, seconds)) * 1000);
}
/**
 * Strict, success-gated parse of the recognizer's output (the project rule for
 * PowerShell/WinRT wrappers: never trust raw stdout). Only text between the
 * explicit markers counts, and only when the run reported READY and exited 0.
 */
function parseListenOutput(output, exitCode) {
    if (exitCode !== 0)
        return { ready: false, text: '' };
    const ready = output.includes('BLACKROSE_LISTEN_READY') && output.includes('BLACKROSE_LISTEN_TEXT=');
    const m = output.match(/BLACKROSE_LISTEN_TEXT=([^\r\n]*)/);
    return { ready, text: ready && m ? m[1].trim() : '' };
}
/**
 * One push-to-talk listen through the local Windows dictation engine (mic
 * only). Shared by the `listen` tool and the UI's POST /api/listen endpoint
 * (the composer mic button) so both paths behave identically. Never throws
 * for expected failures — returns a structured result instead.
 */
async function runListenMic(ctx, seconds) {
    if (process.platform !== 'win32') {
        return { ok: false, text: '', detail: 'listen is currently Windows-only (System.Speech).' };
    }
    if (!(await localSttAvailable())) {
        return {
            ok: false,
            text: '',
            detail: 'No local speech recognizer is installed (System.Speech found none). Enable Windows Speech Recognition (Settings → Time & language → Speech) or use transcribe_audio (cloud).',
        };
    }
    const ms = listenWindowMs(seconds === undefined ? {} : { seconds });
    const locale = (process.env.BLACKROSE_LISTEN_LOCALE || 'en-US').replace(/'/g, "''");
    const script = [
        "$ErrorActionPreference='Stop'",
        'Add-Type -AssemblyName System.Speech',
        '$r=[System.Speech.Recognition.SpeechRecognitionEngine]::new()',
        `$ci=[System.Globalization.CultureInfo]::new('${locale}')`,
        'if ($r.RecognizerInfo.Culture.Name -ne $ci.Name) {',
        '  $alt=[System.Speech.Recognition.SpeechRecognitionEngine]::InstalledRecognizers() | Where-Object { $_.Culture.Name -eq $ci.Name } | Select-Object -First 1',
        '  if ($alt) { $r=[System.Speech.Recognition.SpeechRecognitionEngine]::new($alt) }',
        '}',
        '$r.LoadGrammar((New-Object System.Speech.Recognition.DictationGrammar))',
        '$r.SetInputToDefaultAudioDevice()',
        '$r.InitialSilenceTimeout=[TimeSpan]::FromMilliseconds(' + ms + ')',
        '$r.BabbleTimeout=[TimeSpan]::FromMilliseconds(' + Math.min(ms, 3000) + ')',
        '$r.EndSilenceTimeout=[TimeSpan]::FromMilliseconds(700)',
        "Write-Output 'BLACKROSE_LISTEN_READY'",
        '$parts=@()',
        '$res=$r.Recognize([TimeSpan]::FromMilliseconds(' + ms + '))',
        'if ($res) { $parts += $res.Text }',
        "Write-Output ('BLACKROSE_LISTEN_TEXT=' + ($parts -join ' ').Trim())",
    ].join('; ');
    const run = await execShell(script, ctx.cwd, ms + 45_000);
    const parsed = parseListenOutput(run.output, run.exitCode);
    if (!parsed.ready) {
        return {
            ok: false,
            text: '',
            detail: `listen failed (exit ${run.exitCode}): ${run.output.replace(/\s+/g, ' ').slice(0, 300)}`,
        };
    }
    return { ok: true, text: parsed.text, detail: `Heard nothing within ${Math.round(ms / 1000)}s.` };
}
const listenTool = buildTool({
    name: 'listen',
    description: 'Speech-to-text with the LOCAL Windows dictation engine (offline; audio never leaves the machine). Without arguments it listens to the MICROPHONE for a few seconds (push-to-talk); with path=<.wav> it transcribes that WAV file locally instead. Use for voice input or quick spoken notes; use transcribe_audio for cloud-accuracy transcription of other formats.',
    input_schema: {
        type: 'object',
        properties: {
            seconds: {
                type: 'number',
                description: 'How long to listen, 1-15 seconds (default 8, or BLACKROSE_LISTEN_MS)',
            },
            path: {
                type: 'string',
                description: 'Optional .wav file to transcribe locally and offline (short clip) instead of the microphone',
            },
        },
    },
    // Local-only, but a mic is opening — tell the user what's happening.
    requiresApproval: (input, _ctx) => 
    // Trimmed here exactly as run() trims it: a whitespace-only `path` used to
    // make the prompt say "transcribes the WAV file" while run() went on to open
    // the MICROPHONE. An approval prompt that lies about the action is the one
    // thing this prompt exists to prevent.
    typeof input?.path === 'string' && input.path.trim()
        ? 'Transcribes the WAV file with the local Windows dictation engine (offline; nothing leaves the machine).'
        : 'Opens the MICROPHONE and listens locally (Windows dictation engine; audio never leaves the machine).',
    run: async (input, ctx) => {
        const wavArg = str(input, 'path').trim();
        if (!wavArg) {
            const r = await runListenMic(ctx, num(input, 'seconds', 8));
            if (!r.ok)
                return { content: r.detail, isError: true };
            if (!r.text) {
                return {
                    content: `Heard nothing within ${num(input, 'seconds', 8)}s (speak after approving, and check the mic is Windows' default input).`,
                };
            }
            return {
                content: `Heard (local Windows dictation, offline):\n\n${r.text}`,
            };
        }
        const p = resolveInWorkspace(ctx.cwd, wavArg);
        if (!fs.existsSync(p))
            return { content: `File not found: ${p}`, isError: true };
        if (path.extname(p).toLowerCase() !== '.wav') {
            return { content: 'The local engine reads .wav only — use transcribe_audio for other formats.', isError: true };
        }
        const ms = listenWindowMs(input);
        const locale = (process.env.BLACKROSE_LISTEN_LOCALE || 'en-US').replace(/'/g, "''");
        const safe = (s) => s.replace(/'/g, "''");
        const script = [
            "$ErrorActionPreference='Stop'",
            'Add-Type -AssemblyName System.Speech',
            '$r=[System.Speech.Recognition.SpeechRecognitionEngine]::new()',
            `$ci=[System.Globalization.CultureInfo]::new('${safe(locale)}')`,
            'if ($r.RecognizerInfo.Culture.Name -ne $ci.Name) {',
            '  $alt=[System.Speech.Recognition.SpeechRecognitionEngine]::InstalledRecognizers() | Where-Object { $_.Culture.Name -eq $ci.Name } | Select-Object -First 1',
            '  if ($alt) { $r=[System.Speech.Recognition.SpeechRecognitionEngine]::new($alt) }',
            '}',
            '$r.LoadGrammar((New-Object System.Speech.Recognition.DictationGrammar))',
            `$r.SetInputToWaveFile('${safe(p)}')`,
            '$r.InitialSilenceTimeout=[TimeSpan]::FromMilliseconds(' + ms + ')',
            '$r.BabbleTimeout=[TimeSpan]::FromMilliseconds(' + Math.min(ms, 3000) + ')',
            '$r.EndSilenceTimeout=[TimeSpan]::FromMilliseconds(700)',
            "Write-Output 'BLACKROSE_LISTEN_READY'",
            '$parts=@()',
            '$res=$r.Recognize([TimeSpan]::FromMilliseconds(' + Math.max(ms, 10_000) + '))',
            'if ($res) { $parts += $res.Text }',
            "Write-Output ('BLACKROSE_LISTEN_TEXT=' + ($parts -join ' ').Trim())",
        ].join('; ');
        const run = await execShell(script, ctx.cwd, Math.max(ms, 10_000) + 45_000);
        const parsed = parseListenOutput(run.output, run.exitCode);
        if (!parsed.ready) {
            return {
                content: `listen failed (exit ${run.exitCode}): ${run.output.replace(/\s+/g, ' ').slice(0, 300)}`,
                isError: true,
            };
        }
        if (!parsed.text) {
            return {
                content: `Heard nothing in ${path.basename(p)} (the dictation engine may not match this clip's speech/language).`,
            };
        }
        return {
            content: `Transcript of ${path.basename(p)} (local Windows dictation, offline):\n\n${parsed.text}`,
        };
    },
});
const sayTool = buildTool({
    name: 'say',
    description: 'Speak a short text aloud through the computer speakers (offline OS text-to-speech). Use when the user asks to hear a response. Keep it under ~300 words.',
    input_schema: {
        type: 'object',
        properties: { text: { type: 'string', description: 'Text to speak' } },
        required: ['text'],
    },
    run: async (input, ctx) => {
        const text = str(input, 'text').trim();
        if (!text)
            return { content: 'text is required', isError: true };
        if (process.platform !== 'win32') {
            return { content: 'say is currently Windows-only (SAPI).', isError: true };
        }
        const safe = text.replace(/'/g, "''").replace(/[\r\n]+/g, ' ').slice(0, 4000);
        const ps = [
            "Add-Type -AssemblyName System.Speech",
            "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer",
            `$s.Speak('${safe}')`,
        ].join('; ');
        const r = await execShell(ps, ctx.cwd, 120_000);
        return {
            content: r.exitCode === 0 ? `Spoke ${safe.length} chars aloud.` : `TTS failed: ${r.output.slice(0, 300)}`,
            isError: r.exitCode !== 0,
        };
    },
});
return { localSttAvailable,listenWindowMs,parseListenOutput,runListenMic,listenTool,sayTool };
}

__mod['tools/voice.js'] = M47();

function M48() {
const { buildTool, str } = __mod['core/tools.js'];
const { resolveInWorkspace } = __mod['core/permissions.js'];
const { ocrImageFile, ocrPdfFile } = __mod['memory/ocr.js'];
/**
 * OCR tool (Phase 6, Windows-native): read text out of images and
 * image-only (scanned) PDFs using the OS OCR engine — offline, no
 * dependencies. Read-only, so no approval is required (mirrors read_image).
 */
const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.bmp', '.tif', '.tiff', '.gif']);
const ocrReadTool = buildTool({
    name: 'ocr_read',
    description: 'Read text from an image (png/jpg/bmp/tif/gif) or a scanned/image-only PDF using the offline Windows OCR engine. Use when read_file shows gibberish/binary or learn_pdf extracts no text.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Image or PDF path (absolute or workspace-relative)' },
            max_pages: { type: 'number', description: 'For PDFs: max pages to OCR (default 30)' },
        },
        required: ['path'],
    },
    run: async (input, ctx) => {
        if (process.platform !== 'win32') {
            return { content: 'ocr_read is currently Windows-only (Windows.Media.Ocr).', isError: true };
        }
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        if (!fs.existsSync(p))
            return { content: `File not found: ${p}`, isError: true };
        const ext = path.extname(p).toLowerCase();
        const label = path.basename(p);
        if (ext === '.pdf') {
            const stat = fs.statSync(p);
            if (stat.size > 50 * 1024 * 1024)
                return { content: `PDF too large to OCR (${stat.size} bytes).`, isError: true };
            const text = await ocrPdfFile(p, ctx.cwd, Math.max(1, Math.min(60, Number(input.max_pages) || 30)));
            if (!text)
                return { content: `OCR found no readable text in ${label}.`, isError: true };
            return { content: `OCR of ${label} (${stat.size} bytes):\n\n${text.slice(0, 40_000)}` };
        }
        if (!IMAGE_EXTS.has(ext)) {
            return { content: `Unsupported type ${ext} — ocr_read reads images and PDFs.`, isError: true };
        }
        const stat = fs.statSync(p);
        if (stat.size > 20 * 1024 * 1024)
            return { content: `Image too large to OCR (${stat.size} bytes).`, isError: true };
        const text = await ocrImageFile(p, ctx.cwd);
        if (!text)
            return { content: `OCR found no readable text in ${label}.`, isError: true };
        return { content: `OCR of ${label} (${stat.size} bytes):\n\n${text.slice(0, 20_000)}` };
    },
});
return { ocrReadTool };
}

__mod['tools/ocr.js'] = M48();

function M49() {
const { buildTool, str } = __mod['core/tools.js'];
const { resolveInWorkspace } = __mod['core/permissions.js'];
const { fetchWithTimeout } = __mod['tools/web.js'];
const { saveKnowledge } = __mod['tools/knowledge.js'];
/**
 * Speech-to-text (backlog item 2): send an audio/video file to an
 * OpenAI-compatible /audio/transcriptions endpoint and return the transcript.
 * Default backend: Groq's free whisper-large-v3-turbo (the Groq gateway is
 * already configured as the `openai1` router route). Optionally save a
 * sidecar .transcript.txt and/or ingest into the knowledge base so
 * knowledge_search can find what was said.
 *
 * Config (all optional — falls back to the Groq router route):
 *   BLACKROSE_STT_API_KEY   → else BLACKROSE_OPENAI1_API_KEY
 *   BLACKROSE_STT_BASE_URL  → default https://api.groq.com/openai/v1
 *   BLACKROSE_STT_MODEL     → default whisper-large-v3-turbo
 * The key is never logged or returned.
 */
const AUDIO_EXTS = new Set([
    '.flac', '.mp3', '.mp4', '.mpeg', '.mpga', '.m4a', '.ogg', '.oga', '.opus', '.wav', '.webm',
]);
const MAX_AUDIO_BYTES = 25 * 1024 * 1024; // API file limit (Groq free tier)
function sttConfig() {
    return {
        apiKey: process.env.BLACKROSE_STT_API_KEY ?? process.env.BLACKROSE_OPENAI1_API_KEY,
        baseUrl: (process.env.BLACKROSE_STT_BASE_URL ?? 'https://api.groq.com/openai/v1').replace(/\/+$/, ''),
        model: process.env.BLACKROSE_STT_MODEL ?? 'whisper-large-v3-turbo',
    };
}
const transcribeAudioTool = buildTool({
    name: 'transcribe_audio',
    description: 'Speech-to-text: transcribe an audio/video file (mp3/wav/m4a/flac/ogg/opus/webm/mp4, max 25MB) via the configured STT cloud API (default: Groq whisper-large-v3-turbo). Use save:true to write a .transcript.txt sidecar and/or ingest:true to learn it into the knowledge base for knowledge_search.',
    input_schema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Audio/video file path (absolute or workspace-relative)' },
            language: { type: 'string', description: 'Optional ISO-639-1 language hint, e.g. "en"' },
            save: { type: 'boolean', description: 'Write <file>.transcript.txt next to the audio (default false)' },
            ingest: { type: 'boolean', description: 'Also learn the transcript into the knowledge base (default false)' },
        },
        required: ['path'],
    },
    // Privacy-sensitive by definition: user audio leaves the machine for a
    // third-party cloud API → every call is approval-gated (fail-closed).
    requiresApproval: (_input, _ctx) => {
        const c = sttConfig();
        return `Sends the audio file to the STT cloud API (${c.baseUrl}, model ${c.model}) for transcription.`;
    },
    run: async (input, ctx) => {
        const cfg = sttConfig();
        if (!cfg.apiKey) {
            return {
                content: 'STT is not configured: set BLACKROSE_STT_API_KEY (or BLACKROSE_OPENAI1_API_KEY — the Groq gateway key works as-is).',
                isError: true,
            };
        }
        const p = resolveInWorkspace(ctx.cwd, str(input, 'path'));
        if (!fs.existsSync(p))
            return { content: `File not found: ${p}`, isError: true };
        const ext = path.extname(p).toLowerCase();
        if (!AUDIO_EXTS.has(ext)) {
            return {
                content: `Unsupported audio type ${ext} — transcribe_audio reads ${[...AUDIO_EXTS].join(', ')}.`,
                isError: true,
            };
        }
        const stat = fs.statSync(p);
        if (stat.size > MAX_AUDIO_BYTES) {
            return {
                content: `Audio too large for the STT API (${(stat.size / 1024 / 1024).toFixed(1)} MB > 25 MB limit).`,
                isError: true,
            };
        }
        const language = str(input, 'language').trim();
        const form = new FormData();
        form.append('file', new Blob([fs.readFileSync(p)]), path.basename(p));
        form.append('model', cfg.model);
        form.append('response_format', 'text');
        if (language)
            form.append('language', language);
        let text = '';
        try {
            const res = await fetchWithTimeout(`${cfg.baseUrl}/audio/transcriptions`, { method: 'POST', headers: { authorization: `Bearer ${cfg.apiKey}` }, body: form }, 300_000);
            if (!res.ok) {
                const body = await res.text().catch(() => '');
                const hint = res.status === 429 ? ' (rate limited — free tier; try again later)' : '';
                return {
                    content: `STT API error (HTTP ${res.status})${hint}: ${body.replace(/\s+/g, ' ').slice(0, 300)}`,
                    isError: true,
                };
            }
            text = (await res.text()).trim();
        }
        catch (e) {
            return { content: `STT request failed: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
        if (!text)
            return { content: `Transcription came back empty for ${path.basename(p)}.`, isError: true };
        const notes = [];
        if (input.save === true) {
            const sidecar = p.replace(/\.[^./\\]+$/, '') + '.transcript.txt';
            fs.writeFileSync(sidecar, text + '\n', 'utf8');
            notes.push(`saved → ${sidecar}`);
        }
        if (input.ingest === true) {
            const n = await saveKnowledge(ctx.dataDir, p, 'file', text);
            notes.push(`learned → ${n} knowledge chunk(s)`);
        }
        return {
            content: `Transcript of ${path.basename(p)} (${(stat.size / 1024).toFixed(0)} KB, model ${cfg.model}):\n\n${text}` +
                (notes.length ? `\n\n${notes.join(' · ')}` : ''),
        };
    },
});
return { sttConfig,transcribeAudioTool };
}

__mod['tools/stt.js'] = M49();

function M50() {
const { buildTool, str } = __mod['core/tools.js'];
const { execShell } = __mod['core/processes.js'];
const { transcribeAudioTool } = __mod['tools/stt.js'];
const { saveKnowledge } = __mod['tools/knowledge.js'];
/**
 * Watch a video from a link (Instagram reels, YouTube, direct mp4, …):
 * download it with yt-dlp, transcribe the audio through the SAME verified
 * cloud STT path as transcribe_audio (the API accepts .mp4/.webm directly,
 * so no ffmpeg is needed), and return title/uploader/duration + transcript.
 * Optionally save a .transcript.txt sidecar and/or ingest the transcript
 * into the knowledge base.
 *
 * yt-dlp location (first hit wins):
 *   BLACKROSE_YTDLP → <dataDir-independent> ~/.blackrose/bin/yt-dlp.exe → PATH.
 * If none is found on Windows the official standalone exe is auto-downloaded
 * from https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe
 * into ~/.blackrose/bin (outside the repo, survives reinstalls).
 *
 * Limits: download is capped at 24 MB (the STT API takes ≤ 25 MB) — reels and
 * short clips are the target, not films. Private/login-walled posts need
 * cookies: put extra yt-dlp args in BLACKROSE_YTDLP_ARGS (e.g.
 * "--cookies-from-browser chrome").
 */
const YTDLP_URL = 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe';
const MAX_VIDEO_BYTES = 24 * 1024 * 1024;
function ytDlpPath(env = process.env) {
    const override = (env.BLACKROSE_YTDLP ?? '').trim();
    if (override)
        return override;
    const home = env.USERPROFILE ?? env.HOME ?? '';
    if (home) {
        const local = path.join(home, '.blackrose', 'bin', process.platform === 'win32' ? 'yt-dlp.exe' : 'yt-dlp');
        if (fs.existsSync(local))
            return local;
    }
    return 'yt-dlp';
}
async function ensureYtDlp(env = process.env) {
    const found = ytDlpPath(env);
    if (found !== 'yt-dlp' || process.platform !== 'win32')
        return found;
    // Windows and no local copy: auto-download the official standalone exe.
    const home = env.USERPROFILE ?? env.HOME ?? '';
    const binDir = path.join(home, '.blackrose', 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const dest = path.join(binDir, 'yt-dlp.exe');
    const res = await fetch(YTDLP_URL, { redirect: 'follow', signal: AbortSignal.timeout(600_000) });
    if (!res.ok || !res.body)
        throw new Error(`yt-dlp download failed: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    // Verify the bytes before they become an executable we will spawn. A plain
    // redirect-followed download writes whatever the network handed us straight
    // to disk and runs it on the next watch_video call — a proxy error page, a
    // captive-portal HTML body or a truncated transfer would all execute. 'MZ' is
    // the DOS/PE header of every Windows exe; yt-dlp's standalone build has it.
    if (buf.length < 2 || buf[0] !== 0x4d || buf[1] !== 0x5a) {
        throw new Error(`yt-dlp download was not a Windows executable (${buf.length} bytes, expected an MZ/PE header) — ` +
            'refusing to write it. Check the network path or set BLACKROSE_YTDLP to a trusted binary.');
    }
    // Write via a temp name in the same directory, then rename: a half-written
    // yt-dlp.exe at the final path would be found by ytDlpPath() on every later
    // call and fail confusingly.
    const tmp = `${dest}.${process.pid}.download`;
    try {
        fs.writeFileSync(tmp, buf);
        fs.renameSync(tmp, dest);
    }
    catch (e) {
        try {
            fs.rmSync(tmp, { force: true });
        }
        catch {
            /* best effort */
        }
        throw e;
    }
    return dest;
}
/** One metadata probe: validates the URL and returns title/uploader/duration. */
function parseDumpJson(output, exitCode) {
    if (exitCode !== 0)
        return null;
    const line = output.split(/\r?\n/).find((l) => l.trim().startsWith('{'));
    if (!line)
        return null;
    try {
        const j = JSON.parse(line);
        if (typeof j.title !== 'string')
            return null;
        return {
            title: j.title,
            uploader: typeof j.uploader === 'string' ? j.uploader : '',
            duration: typeof j.duration === 'number' ? j.duration : 0,
        };
    }
    catch {
        return null;
    }
}
const q = (s) => s.replace(/'/g, "''");
const watchVideoTool = buildTool({
    name: 'watch_video',
    description: 'Watch a video/reel from a link (Instagram reel, YouTube, direct mp4/webm URL): downloads it with yt-dlp (cap 24 MB — short clips, not films), transcribes the audio via the cloud STT API, and returns title/uploader/duration plus the full transcript. save:true writes a .transcript.txt sidecar in blackrose-uploads/; ingest:true also learns it into the knowledge base. Private/login-walled posts need cookies via BLACKROSE_YTDLP_ARGS.',
    input_schema: {
        type: 'object',
        properties: {
            url: { type: 'string', description: 'Video/reel page or direct file URL' },
            save: { type: 'boolean', description: 'Write <title>.transcript.txt into blackrose-uploads/ (default false)' },
            ingest: { type: 'boolean', description: 'Also learn the transcript into the knowledge base (default false)' },
        },
        required: ['url'],
    },
    // Two privacy-relevant hops: a download from the open web, then the audio
    // leaves the machine for the cloud STT API — approval-gated, fail-closed.
    requiresApproval: (input, _ctx) => `Downloads the video at "${str(input, 'url').slice(0, 80)}" with yt-dlp and sends its audio to the cloud STT API for transcription.`,
    run: async (input, ctx) => {
        const url = str(input, 'url').trim();
        if (!/^https?:\/\//i.test(url)) {
            return { content: 'url must be an http(s) link.', isError: true };
        }
        const ytdlp = await ensureYtDlp();
        const extra = (process.env.BLACKROSE_YTDLP_ARGS ?? '').trim();
        // Harden both yt-dlp calls against stalled CDN reads: without this a
        // hung connection sits until the whole process timeout (up to 10 min).
        const harden = '--socket-timeout 30 --retries 3';
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'blackrose-watch-'));
        let ingestedChunks = 0;
        try {
            // 1) Metadata probe — also validates that the URL is a supported video.
            const meta = await execShell(`& '${q(ytdlp)}' --dump-json --no-playlist --no-warnings ${harden} ${extra} '${q(url)}'`.trim(), ctx.cwd, 120_000);
            const info = parseDumpJson(meta.output, meta.exitCode);
            if (!info) {
                return {
                    content: `Could not read a video from that link (yt-dlp exit ${meta.exitCode}). For private/login-walled posts set BLACKROSE_YTDLP_ARGS (e.g. --cookies-from-browser chrome). ${meta.output.replace(/\s+/g, ' ').slice(0, 200)}`,
                    isError: true,
                };
            }
            // 2) Download (best single mp4/webm file — no ffmpeg merge).
            const dl = await execShell(`& '${q(ytdlp)}' --no-playlist --no-warnings --no-progress --no-part --socket-timeout 30 --retries 3 --max-filesize ${MAX_VIDEO_BYTES} -f 'b[ext=mp4]/b[ext=webm]/b' -o '${q(path.join(tmp, 'video.%(ext)s'))}' ${extra} '${q(url)}'`.trim(), ctx.cwd, 600_000);
            const files = fs.readdirSync(tmp).filter((f) => f.startsWith('video.'));
            if (dl.exitCode !== 0 || files.length === 0) {
                const big = /larger than/.test(dl.output);
                return {
                    content: big
                        ? 'That video is larger than the 24 MB watch cap (the STT API takes ≤ 25 MB). Reels and short clips work; films do not.'
                        : `Download failed (yt-dlp exit ${dl.exitCode}): ${dl.output.replace(/\s+/g, ' ').slice(0, 200)}`,
                    isError: true,
                };
            }
            const video = path.join(tmp, files[0]);
            if (fs.statSync(video).size > 25 * 1024 * 1024) {
                return { content: 'Downloaded file exceeds the 25 MB STT API limit.', isError: true };
            }
            // 3) Transcribe through the same verified STT path (save/ingest handled here).
            const tr = await transcribeAudioTool.run({ path: video }, ctx);
            const transcript = tr.isError ? '' : String(tr.content).split('\n\n').slice(1).join('\n\n').trim();
            // 4) Sidecar + knowledge ingest, keyed by title (not the tmp path).
            const slug = info.title.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'watched-video';
            if (input['save'] === true && transcript) {
                const dir = path.join(ctx.cwd, 'blackrose-uploads');
                fs.mkdirSync(dir, { recursive: true });
                fs.writeFileSync(path.join(dir, `${slug}.transcript.txt`), transcript + '\n', 'utf8');
            }
            if (input['ingest'] === true && transcript) {
                ingestedChunks = await saveKnowledge(ctx.dataDir, `${info.title} (${url})`, 'url', transcript);
            }
            const metaLine = [
                info.title,
                info.uploader ? `by ${info.uploader}` : '',
                info.duration ? `${Math.round(info.duration)}s` : '',
            ].filter(Boolean).join(' — ');
            const head = `Watched: ${metaLine}`;
            if (!tr.isError) {
                const notes = input['ingest'] === true ? ` (ingested ${ingestedChunks} chunk(s))` : '';
                return {
                    content: `${head}${notes}\n\n${transcript || String(tr.content)}`,
                };
            }
            // Transcript unavailable (no STT key, unsupported audio, …) — metadata still useful.
            return { content: `${head}\n\nTranscription unavailable: ${String(tr.content).slice(0, 300)}` };
        }
        finally {
            try {
                fs.rmSync(tmp, { recursive: true, force: true });
            }
            catch { /* best effort */ }
        }
    },
});
return { ytDlpPath,parseDumpJson,watchVideoTool };
}

__mod['tools/video.js'] = M50();

function M51() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { fetchWithTimeout } = __mod['tools/web.js'];
/**
 * Instagram scraping via Apify (https://apify.com), then learn the captions
 * into the knowledge base. Two steps, because they cost money and take time:
 *
 *   1. `instagram_scrape` — run the Apify Instagram Scraper actor against
 *      profile/hashtag URLs, wait for the run, return a ranked markdown
 *      playbook. Costs Apify credits.
 *   2. `instagram_learn` — learn that markdown. Free.
 *
 * Split so a scrape can be reviewed before it pollutes the knowledge base.
 *
 * Auth: APIFY_TOKEN env var (Apify console -> Settings -> Integrations).
 * The token is NEVER echoed back in tool output.
 *
 * Notes:
 * - The actor is a paid third-party scraper, a SEPARATE service from
 *   Instagram, and it can break when Instagram changes. watch_video
 *   (yt-dlp + your own browser cookies) is the no-extra-account path for a
 *   few known reels; this is the path for "the last N posts of a profile".
 * - Runs are polled, not streamed: a 200-post run can take several minutes.
 */
const APIFY = 'https://api.apify.com/v2';
// Apify identifies an actor as "<owner>~<name>" with a TILDE. The slash form
// (apify/instagram-scraper) 404s with "there is no API endpoint at this URL".
// Both /acts/{id}/runs and /actors/{id}/runs work for starting a run.
const ACTOR = 'apify~instagram-scraper';
/** Apify run status values that mean "stop waiting". */
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'ABORTED', 'TIMED-OUT']);
function token() {
    return (process.env.APIFY_TOKEN ?? '').trim() || null;
}
function noToken() {
    return {
        content: 'APIFY_TOKEN is not set. Get a token at https://console.apify.com -> Settings -> Integrations, ' +
            'then add it in the BlackRose API key manager (or the APIFY_TOKEN environment variable).',
        isError: true,
    };
}
/** Join a path (which may already carry a query) with the auth token safely. */
function apifyUrl(p, tok) {
    const sep = p.includes('?') ? '&' : '?';
    return `${APIFY}${p}${sep}token=${encodeURIComponent(tok)}`;
}
async function apifyGet(p, tok) {
    const res = await fetchWithTimeout(apifyUrl(p, tok));
    const body = (await res.json().catch(() => ({})));
    if (!res.ok)
        throw new Error(body?.error?.message ?? `Apify API HTTP ${res.status}`);
    // Most endpoints wrap the payload as { data: ... }, but the dataset ITEMS
    // endpoint returns a bare JSON array. Unwrapping .data blindly turned a
    // 180-item result into undefined.
    if (body && typeof body === 'object' && !Array.isArray(body) && 'data' in body) {
        return body.data;
    }
    return body;
}
/**
 * Start an actor run WITH its input. Apify's run endpoint is POST-only: the
 * request body is passed straight through to the actor as INPUT. A GET here
 * starts a run with empty input, which for the Instagram Scraper means it has
 * no URLs and returns an empty dataset.
 */
async function apifyStartRun(p, tok, input, ms = 60_000) {
    const res = await fetchWithTimeout(apifyUrl(p, tok), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input),
    }, ms);
    const body = (await res.json().catch(() => ({})));
    if (!res.ok)
        throw new Error(body?.error?.message ?? `Apify API HTTP ${res.status}`);
    return body.data;
}
/** Poll a run until it reaches a terminal state (or we give up). */
async function waitForRun(runId, tok, ctx) {
    const deadline = Date.now() + 15 * 60_000;
    let last = '';
    while (Date.now() < deadline) {
        const run = await apifyGet(`/actor-runs/${runId}`, tok);
        if (run.status !== last) {
            last = run.status;
            ctx.log?.(`apify run ${runId}: ${run.status}`);
        }
        if (TERMINAL.has(run.status))
            return run;
        await new Promise((r) => setTimeout(r, 10_000));
    }
    throw new Error(`Apify run ${runId} did not finish within 15 minutes (last status: ${last || 'unknown'})`);
}
/** Render scraped posts as a markdown playbook, best-performing first. */
function toPlaybook(posts, label) {
    const ranked = posts
        .filter((p) => p && typeof p.caption === 'string' && p.caption.trim())
        .sort((a, b) => (b.likesCount ?? 0) - (a.likesCount ?? 0));
    const lines = [
        `INSTAGRAM PLAYBOOK — ${label}. Scraped via Apify ${new Date().toISOString().slice(0, 10)}.`,
        `${ranked.length} post(s) with captions, ranked by likes. Learn what caption styles,`,
        'hashtag sets and topics perform, then apply them.',
        '',
    ];
    ranked.forEach((p, i) => {
        const plays = p.videoPlayCount ?? p.videoViewCount;
        const dur = typeof p.videoDuration === 'number' ? Math.round(p.videoDuration) : null;
        const bits = [`${(p.likesCount ?? 0).toLocaleString()} likes`];
        if (plays)
            bits.push(`${Number(plays).toLocaleString()} plays`);
        if (dur)
            bits.push(`${dur}s`);
        lines.push(`## #${i + 1} — ${bits.join(', ')} (${String(p.timestamp ?? '').slice(0, 10) || 'undated'}, @${p.ownerUsername ?? '?'})`);
        const tags = Array.isArray(p.hashtags) ? p.hashtags.filter((h) => typeof h === 'string') : [];
        lines.push(`Hashtags: ${tags.join(' ') || '(none)'}`);
        lines.push(`Caption: ${p.caption.replace(/\s+\n/g, '\n').trim()}`);
        if (p.firstComment?.text)
            lines.push(`Pinned comment: ${String(p.firstComment.text).slice(0, 300)}`);
        lines.push('');
    });
    return lines.join('\n');
}
function countPosts(md) {
    return md.split('## #').length - 1;
}
const instagramScrapeTool = buildTool({
    name: 'instagram_scrape',
    description: 'Scrape a public Instagram profile or hashtag with Apify and return a ranked markdown playbook of its captions (most likes first). Costs Apify credits and can take minutes. Review the result, then call instagram_learn to store it. Needs APIFY_TOKEN.',
    input_schema: {
        type: 'object',
        properties: {
            targets: {
                type: 'string',
                description: 'One or more Instagram URLs separated by commas or newlines (profiles or hashtags), e.g. "https://www.instagram.com/petergriffin.ai/"',
            },
            results: { type: 'number', description: 'Max posts per target (default 30)' },
        },
        required: ['targets'],
    },
    run: async (input, ctx) => {
        const tok = token();
        if (!tok)
            return noToken();
        const targets = str(input, 'targets')
            .split(/[\n,]+/)
            .map((t) => t.trim())
            .filter(Boolean);
        if (!targets.length)
            return { content: 'No targets given.', isError: true };
        const results = num(input, 'results', 30) || 30;
        // A scrape costs money and takes minutes — ask before spending.
        const ok = await ctx.askApproval('instagram_scrape', `Run the Apify Instagram Scraper on ${targets.length} target(s), ${results} posts each? This spends Apify credits and can take several minutes.`);
        if (!ok)
            return { content: 'Instagram scrape declined by the user.' };
        ctx.log?.(`starting Apify scrape of ${targets.length} target(s)…`);
        let run;
        try {
            // The actor needs its URLs: directUrls is the field the Instagram
            // Scraper reads for "scrape exactly these profiles/hashtags".
            const started = await apifyStartRun(`/acts/${ACTOR}/runs`, tok, { directUrls: targets, results });
            run = await waitForRun(started.id, tok, ctx);
        }
        catch (e) {
            return { content: `Apify scrape failed: ${e.message}`, isError: true };
        }
        if (run.status !== 'SUCCEEDED') {
            return { content: `Apify run ${run.id} ended as ${run.status} — nothing to learn.`, isError: true };
        }
        if (!run.defaultDatasetId) {
            return { content: `Apify run ${run.id} succeeded but produced no dataset.`, isError: true };
        }
        // A dataset read failure must not crash the tool — the run already
        // happened (and was charged), so report the ids and let the user retry
        // the fetch rather than throwing an unhandled rejection.
        let posts;
        try {
            posts = await apifyGet(`/datasets/${run.defaultDatasetId}/items?clean=true&format=json`, tok);
        }
        catch (e) {
            return {
                content: `Apify run ${run.id} succeeded but its dataset could not be read: ${e.message}\n` +
                    `Dataset id: ${run.defaultDatasetId} — retry the scrape, or fetch it from the Apify console.`,
                isError: true,
            };
        }
        const label = targets
            .map((t) => t.replace(/^https?:\/\/(www\.)?instagram\.com\//, '').replace(/\/$/, ''))
            .join(', ');
        const md = toPlaybook(Array.isArray(posts) ? posts : [], label);
        const n = countPosts(md);
        if (n === 0) {
            return {
                content: `Apify returned ${Array.isArray(posts) ? posts.length : 0} post(s) but none had a caption. Nothing to learn.`,
                isError: true,
            };
        }
        // Persist so instagram_learn can ingest it by path without re-pasting.
        const out = path.join(ctx.dataDir, 'instagram-playbook.md');
        fs.mkdirSync(ctx.dataDir, { recursive: true });
        fs.writeFileSync(out, md, 'utf8');
        ctx.log?.(`scrape done: ${n} captioned post(s) -> ${out}`);
        return {
            content: `${md}\n\n---\nSaved to: ${out}\nNext: call instagram_learn with path: "${out}" to add it to the knowledge base.`,
        };
    },
});
const instagramLearnTool = buildTool({
    name: 'instagram_learn',
    description: 'Learn an Instagram playbook into the knowledge base. Pass path: to a saved playbook .md (from instagram_scrape) or markdown: with the text itself. Free — spends no Apify credits.',
    input_schema: {
        type: 'object',
        properties: {
            markdown: { type: 'string', description: 'The playbook text itself' },
            path: { type: 'string', description: 'Path to a saved playbook .md file' },
            confirm: { type: 'boolean', description: 'Required with markdown: confirms ingesting the text' },
        },
    },
    run: async (input, ctx) => {
        const md = str(input, 'markdown').trim();
        const file = str(input, 'path').trim();
        if (!md && !file) {
            return {
                content: 'Pass path: to a saved playbook .md, or markdown: with the text (plus confirm:true).',
                isError: true,
            };
        }
        const { learnFileTool } = await import("./knowledge.js");
        if (file)
            return learnFileTool.run({ path: file }, ctx);
        if (input.confirm !== true) {
            return {
                content: 'About to add this playbook to the knowledge base. Re-call with confirm:true to ingest it, ' +
                    'or pass path: instead to learn a saved file.',
            };
        }
        const out = path.join(ctx.dataDir, 'instagram-playbook.md');
        fs.mkdirSync(ctx.dataDir, { recursive: true });
        fs.writeFileSync(out, md, 'utf8');
        ctx.log?.(`saved playbook to ${out}`);
        return learnFileTool.run({ path: out }, ctx);
    },
});
return { toPlaybook,countPosts,instagramScrapeTool,instagramLearnTool };
}

__mod['tools/instagram.js'] = M51();

function M52() {
function skillsDir(dataDir) {
    return path.join(dataDir, 'skills');
}
/**
 * The `file` value every built-in skill carries.
 *
 * It is how a caller tells a shipped skill from one the user saved, and that
 * distinction matters because the two are counted on different surfaces
 * (--doctor reports both separately; /api/health reports the merged total).
 * Exported so the marker is a single named value rather than a magic string
 * repeated in every consumer.
 */
const BUILTIN_FILE = '(built-in)';
/**
 * Built-in skills. These ship with BlackRose rather than living in the user's
 * skills folder, so the token-economy guidance works on a fresh install and
 * cannot be lost by clearing data. A user skill with the same name wins — that
 * is the escape hatch for overriding anything here.
 *
 * Each one is a *behavioural* recipe, not a tutorial: the model already knows
 * how to be verbose, it has to be told not to.
 */
const BUILTIN_SKILLS = [
    {
        name: 'token-economy',
        description: 'Answer in the fewest turns and tokens that still answers the question',
        instructions: `Spend as little as possible per turn, without answering badly.

- Answer the question that was asked. Do not also answer the two you anticipated.
- Do not restate the user's request back before answering it.
- No closing offers ("let me know if you want..."). No summary of what you just did
  unless it was non-obvious or the user asked.
- If a tool result already contains the answer, do not call another tool to
  confirm it.
- Never re-read a file you have already read this session, unless it was changed
  by something in between.
- Prefer one tool call that does the job over several that each do part of it.
- Short answers by default. Length should follow the question, never a quota.`,
        file: '(built-in)',
    },
    {
        name: 'think-before-spending',
        description: 'Plan once, then execute — stop deliberating when the plan is clear',
        instructions: `Reasoning should be short and decisive.

- Decide the approach in your head, then act. Do not narrate every candidate
  option you considered.
- Once you have a workable plan, take it. Do not keep refining a plan that is
  already good enough.
- Batch independent tool calls into a single turn instead of one per turn.
- If a tool fails, read the error and change the one thing that was wrong. Do not
  restart the whole approach.
- If you notice you are re-deriving something already in this conversation or in
  memory, stop and use the existing answer.
- Stop as soon as the task is done. Do not add verification passes, polish, or
  extra reads "to be safe" unless the change is destructive or the user asked.`,
        file: '(built-in)',
    },
    {
        name: 'small-task-delegation',
        description: 'Hand small self-contained jobs to a sub-agent so they run on a cheap model',
        instructions: `Not every task deserves the main model.

- If a subtask is self-contained, mechanical, and has a short verifiable answer
  (summarise this file, find every X, draft a title, check this format), hand it
  to \`spawn_agent\` with a complete, self-contained instruction.
- Give the sub-agent everything it needs: the exact path, the exact question,
  and the format you want back. It cannot see this conversation.
- Sub-agents run on a different route (BLACKROSE_SUBAGENT_ROUTE, e.g. the free
  kilo route) and cannot spawn further agents, so keep them small.
- Do not delegate work that needs the full conversation's context — a sub-agent
  starts fresh and will get it wrong.
- Do not delegate a decision that only you can make with the user's intent in
  front of you.`,
        file: '(built-in)',
    },
];
const slug = (name) => name.toLowerCase().replace(/[^a-z0-9-_]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'skill';
function loadSkills(dataDir) {
    const out = [];
    const dir = skillsDir(dataDir);
    if (fs.existsSync(dir)) {
        for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.md')).sort()) {
            try {
                const raw = fs.readFileSync(path.join(dir, f), 'utf8');
                const m = raw.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
                if (!m)
                    continue;
                const meta = m[1];
                const get = (k) => {
                    const km = meta.match(new RegExp(`^${k}:\\s*(.+)$`, 'm'));
                    return km ? km[1].trim() : '';
                };
                const name = get('name') || f.replace(/\.md$/, '');
                out.push({
                    name,
                    description: get('description'),
                    instructions: m[2].trim(),
                    file: f,
                });
            }
            catch {
                /* skip unreadable skill */
            }
        }
    }
    // Built-ins last, and only where the user has not overridden the name.
    const taken = new Set(out.map((s) => s.name.toLowerCase()));
    for (const b of BUILTIN_SKILLS) {
        if (!taken.has(b.name.toLowerCase()))
            out.push(b);
    }
    return out;
}
function saveSkill(dataDir, name, description, instructions) {
    const dir = skillsDir(dataDir);
    fs.mkdirSync(dir, { recursive: true });
    const skill = { name, description, instructions, file: `${slug(name)}.md` };
    const frontmatter = `---\nname: ${name}\ndescription: ${description}\n---\n`;
    fs.writeFileSync(path.join(dir, skill.file), `${frontmatter}\n${instructions.trim()}\n`, 'utf8');
    return skill;
}
function findSkill(dataDir, name) {
    const needle = name.toLowerCase();
    return loadSkills(dataDir).find((s) => s.name.toLowerCase() === needle || s.file === `${slug(name)}.md`);
}
return { BUILTIN_FILE,BUILTIN_SKILLS,loadSkills,saveSkill,findSkill };
}

__mod['skills/skills.js'] = M52();

function M53() {
const { buildTool, str } = __mod['core/tools.js'];
const { loadSkills, saveSkill, findSkill } = __mod['skills/skills.js'];
/** Skills (Phase 5): save / list / run reusable task recipes. */
const skillSaveTool = buildTool({
    name: 'skill_save',
    description: 'Save a reusable skill (task recipe) to long-term storage. Skills are plain markdown the agent can run later with skill_run.',
    input_schema: {
        type: 'object',
        properties: {
            name: { type: 'string', description: 'Short skill name, e.g. "release"' },
            description: { type: 'string', description: 'One-line description shown in the system prompt' },
            instructions: { type: 'string', description: 'The full step-by-step recipe (markdown)' },
        },
        required: ['name', 'description', 'instructions'],
    },
    requiresApproval: (input) => `Save skill "${str(input, 'name')}"`,
    run: async (input, ctx) => {
        const name = str(input, 'name').trim();
        const instructions = str(input, 'instructions').trim();
        if (!name || !instructions)
            return { content: 'name and instructions are required.', isError: true };
        const s = saveSkill(ctx.dataDir, name, str(input, 'description'), instructions);
        return { content: `Skill "${s.name}" saved to ${s.file}.` };
    },
});
const skillListTool = buildTool({
    name: 'skill_list',
    description: 'List saved skills (name, description).',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async (_input, ctx) => {
        const skills = loadSkills(ctx.dataDir);
        if (skills.length === 0)
            return { content: 'No skills saved yet. Create one with skill_save.' };
        return { content: skills.map((s) => `- ${s.name}: ${s.description}`).join('\n') };
    },
});
const skillRunTool = buildTool({
    name: 'skill_run',
    description: 'Execute a saved skill: its instructions are run by an isolated sub-agent (fresh context) with your optional arguments.',
    input_schema: {
        type: 'object',
        properties: {
            name: { type: 'string', description: 'Skill name' },
            args: { type: 'string', description: 'Optional arguments/context for this run' },
        },
        required: ['name'],
    },
    run: async (input, ctx) => {
        const skill = findSkill(ctx.dataDir, str(input, 'name'));
        if (!skill)
            return { content: `Unknown skill: ${str(input, 'name')}`, isError: true };
        if (!ctx.runSubTask)
            return { content: 'Sub-agent execution is not available in this context.', isError: true };
        const args = str(input, 'args').trim();
        const task = `SKILL: ${skill.name}\n\n${skill.instructions}\n\n` +
            (args ? `ARGUMENTS / CONTEXT:\n${args}\n` : 'Follow the instructions exactly.');
        return ctx.runSubTask(task, `skill:${skill.name}`);
    },
});
return { skillSaveTool,skillListTool,skillRunTool };
}

__mod['tools/skills.js'] = M53();

function M54() {
const { buildTool, str } = __mod['core/tools.js'];
/**
 * Multi-agent (Phase 5): spawn a specialist sub-agent. The sub-agent runs in
 * an isolated context with the same tools but cannot spawn further agents
 * (the host wires its ctx without runSubTask), so recursion is depth-1.
 */
const spawnAgentTool = buildTool({
    name: 'spawn_agent',
    description: 'Spawn a specialist sub-agent to work on a focused task in isolation (e.g. deep research, a review pass, an exploratory refactor). It has the same tools but its own fresh context; its final answer is returned to you. Use for parallelizable or context-heavy subtasks.',
    input_schema: {
        type: 'object',
        properties: {
            task: { type: 'string', description: 'Self-contained instructions for the sub-agent' },
            role: { type: 'string', description: 'Optional persona, e.g. "security reviewer" or "researcher"' },
        },
        required: ['task'],
    },
    run: async (input, ctx) => {
        if (!ctx.runSubTask) {
            return { content: 'Sub-agents are not available here (already inside a sub-agent run).', isError: true };
        }
        const role = str(input, 'role').trim();
        const task = role ? `ROLE: ${role}\n\nTASK: ${str(input, 'task')}` : str(input, 'task');
        return ctx.runSubTask(task, role || 'sub-agent');
    },
});
return { spawnAgentTool };
}

__mod['tools/agentTool.js'] = M54();

function M55() {
const { buildTool, num, str } = __mod['core/tools.js'];
const { briefing, getGoal, isStatus, loadDecisions, loadGoals, makeId, saveDecision, saveGoal, } = __mod['core/executive.js'];
/**
 * Executive Brain tools (B12).
 *
 * No approval gate, deliberately — and this follows the calibration the rest of
 * the codebase already uses rather than the blanket "tools that change state
 * must be approved" reading of core/tools.ts. In this project approval means
 * "this leaves the machine or acts on its own": run_command, gui_action,
 * listen, install, schedule_task. Internal knowledge writes (memory_save and
 * every learn_*) do not require approval. A goal is a private note to itself.
 * If it could start an unattended job it WOULD need approval.
 */
/**
 * Validators return an error STRING rather than throwing.
 *
 * agent.ts converts a thrown tool error into an isError tool result, so either
 * style reaches the model — but a caller that invokes a tool directly gets an
 * unhandled exception, and the sibling record tool (schedule_task) returns
 * { isError } instead. Match the codebase: the tool itself decides what a bad
 * input means, because only it knows the wording the model should see.
 */
function priorityErr(input, fallback = 3) {
    if (input.priority === undefined)
        return undefined;
    const n = num(input, 'priority', -1);
    return Number.isInteger(n) && n >= 1 && n <= 5 ? undefined : 'priority must be an integer 1-5 (1 = highest).';
}
function parsePriority(input, fallback = 3) {
    return num(input, 'priority', fallback);
}
function dateErr(input, key) {
    const v = str(input, key).trim();
    return !v || /^\d{4}-\d{2}-\d{2}$/.test(v) ? undefined : `${key} must be YYYY-MM-DD.`;
}
function parseDate(input, key) {
    return str(input, key).trim() || undefined;
}
const goalAddTool = buildTool({
    name: 'goal_add',
    description: 'Record a goal the user is actually working towards. Use this when the user states a real objective, commitment or deadline — not for one-off requests. `why` is required: a goal with no reason cannot be re-prioritised later.',
    input_schema: {
        type: 'object',
        properties: {
            title: { type: 'string', description: 'Short imperative statement of the goal' },
            why: { type: 'string', description: 'Why this matters to the user — the reason behind the goal' },
            priority: { type: 'number', description: '1 = highest, 5 = lowest (default 3)' },
            deadline: { type: 'string', description: 'Due date as YYYY-MM-DD' },
            project: { type: 'string', description: 'Project or workspace this belongs to' },
            next_action: { type: 'string', description: 'The single next concrete step' },
        },
        required: ['title', 'why'],
    },
    run: async (input, ctx) => {
        const badP = priorityErr(input);
        if (badP)
            return { content: badP, isError: true };
        const badD = dateErr(input, 'deadline');
        if (badD)
            return { content: badD, isError: true };
        const now = new Date().toISOString();
        const g = {
            id: makeId('goal'),
            title: str(input, 'title').slice(0, 160),
            why: str(input, 'why').slice(0, 600),
            status: 'active',
            priority: parsePriority(input),
            deadline: parseDate(input, 'deadline'),
            project: str(input, 'project').trim() || undefined,
            nextAction: str(input, 'next_action').trim() || undefined,
            created: now,
            updated: now,
        };
        saveGoal(ctx.dataDir, g);
        return {
            content: `Recorded goal ${g.id}: [p${g.priority}] ${g.title}${g.deadline ? ` (due ${g.deadline})` : ''}. It will now appear in the briefing on every turn.`,
        };
    },
});
const goalUpdateTool = buildTool({
    name: 'goal_update',
    description: 'Update a recorded goal: change its status, priority, deadline or next action. Set status=blocked together with blocked_reason so the blockage is recorded, not just implied.',
    input_schema: {
        type: 'object',
        properties: {
            id: { type: 'string', description: 'Goal id from goal_list' },
            status: { type: 'string', description: 'active | blocked | paused | done | dropped' },
            priority: { type: 'number', description: '1-5 (1 = highest)' },
            deadline: { type: 'string', description: 'YYYY-MM-DD' },
            next_action: { type: 'string', description: 'The single next concrete step' },
            blocked_reason: { type: 'string', description: 'Why it is blocked (required when status=blocked)' },
        },
        required: ['id'],
    },
    run: async (input, ctx) => {
        const id = str(input, 'id');
        const g = getGoal(ctx.dataDir, id);
        if (!g)
            return { content: `No goal ${id}. Call goal_list to see current goals.`, isError: true };
        const badP = priorityErr(input);
        if (badP)
            return { content: badP, isError: true };
        const badD = dateErr(input, 'deadline');
        if (badD)
            return { content: badD, isError: true };
        const raw = str(input, 'status');
        let status;
        if (raw) {
            if (!isStatus(raw)) {
                return { content: `Unknown status "${raw}". Use active | blocked | paused | done | dropped.`, isError: true };
            }
            status = raw;
        }
        if (status === 'blocked' && !str(input, 'blocked_reason')) {
            return { content: 'Record why it is blocked (blocked_reason) — a blocked goal without a reason cannot be unblocked.', isError: true };
        }
        const next = { ...g, updated: new Date().toISOString() };
        if (status)
            next.status = status;
        if (input.priority !== undefined)
            next.priority = parsePriority(input, g.priority);
        const d = parseDate(input, 'deadline');
        if (d)
            next.deadline = d;
        if (str(input, 'next_action').trim())
            next.nextAction = str(input, 'next_action').trim();
        if (str(input, 'blocked_reason').trim())
            next.blockedReason = str(input, 'blocked_reason').trim();
        if (next.status === 'done' || next.status === 'dropped')
            next.blockedReason = undefined;
        saveGoal(ctx.dataDir, next);
        return { content: `${next.id} → ${next.status} [p${next.priority}] ${next.title}${next.blockedReason ? ` (blocked: ${next.blockedReason})` : ''}` };
    },
});
const goalListTool = buildTool({
    name: 'goal_list',
    description: 'List recorded goals, highest priority first. Filter with status (active/blocked/paused/done/dropped) to see finished or blocked work.',
    input_schema: {
        type: 'object',
        properties: { status: { type: 'string', description: 'Filter by status; omit for all' } },
        required: [],
    },
    run: async (input, ctx) => {
        const want = str(input, 'status').trim();
        if (want && !isStatus(want)) {
            return { content: `Unknown status "${want}". Use active | blocked | paused | done | dropped.`, isError: true };
        }
        const list = want ? loadGoals(ctx.dataDir).filter((g) => g.status === want) : loadGoals(ctx.dataDir);
        if (list.length === 0)
            return { content: want ? `No ${want} goals.` : 'No goals recorded yet.' };
        return {
            content: list
                .map((g) => {
                const bits = [`${g.id}  [p${g.priority}]  ${g.status}`];
                if (g.deadline)
                    bits.push(`due ${g.deadline}`);
                if (g.project)
                    bits.push(`project ${g.project}`);
                bits.push(g.title);
                if (g.nextAction)
                    bits.push(`| next: ${g.nextAction}`);
                if (g.blockedReason)
                    bits.push(`| blocked: ${g.blockedReason}`);
                return bits.join('  ');
            })
                .join('\n'),
        };
    },
});
const goalFocusTool = buildTool({
    name: 'goal_focus',
    description: 'The Executive Brain briefing: what needs attention, what is stalled, active goals in priority order, and recent decisions. This is already folded into every turn — call it to see the same view verbatim.',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async (_input, ctx) => ({ content: briefing(ctx.dataDir) }),
});
const decisionRecordTool = buildTool({
    name: 'decision_record',
    description: 'Record a decision made with the user, with the reasoning and what would count as evidence it was wrong. Link it to a goal so the trade-off survives the conversation.',
    input_schema: {
        type: 'object',
        properties: {
            question: { type: 'string', description: 'The question that was decided' },
            choice: { type: 'string', description: 'What was decided' },
            rationale: { type: 'string', description: 'Why — the reasoning at the time' },
            goal_id: { type: 'string', description: 'Goal this decision serves, if any' },
            alternatives: { type: 'string', description: 'What else was considered and why it lost' },
            revisit_when: { type: 'string', description: 'What would tell us this choice was wrong' },
        },
        required: ['question', 'choice', 'rationale'],
    },
    run: async (input, ctx) => {
        const d = {
            id: makeId('decision'),
            question: str(input, 'question').slice(0, 300),
            choice: str(input, 'choice').slice(0, 300),
            rationale: str(input, 'rationale').slice(0, 800),
            alternatives: str(input, 'alternatives').trim() || undefined,
            goalId: str(input, 'goal_id').trim() || undefined,
            revisitWhen: str(input, 'revisit_when').trim() || undefined,
            madeAt: new Date().toISOString(),
        };
        if (d.goalId && !getGoal(ctx.dataDir, d.goalId))
            d.goalId = undefined;
        saveDecision(ctx.dataDir, d);
        return { content: `Recorded decision ${d.id}: ${d.question} → ${d.choice}${d.goalId ? ` (goal ${d.goalId})` : ''}` };
    },
});
const decisionListTool = buildTool({
    name: 'decision_list',
    description: 'List recorded decisions, newest first, with their reasoning.',
    input_schema: { type: 'object', properties: {}, required: [] },
    run: async (_input, ctx) => {
        const list = loadDecisions(ctx.dataDir);
        if (list.length === 0)
            return { content: 'No decisions recorded yet.' };
        return {
            content: list
                .map((d) => {
                const bits = [`${d.id}  ${d.madeAt.slice(0, 10)}`];
                if (d.goalId)
                    bits.push(`goal ${d.goalId}`);
                bits.push(`${d.question} → ${d.choice}`);
                if (d.rationale)
                    bits.push(`| ${d.rationale.slice(0, 160)}`);
                if (d.revisitWhen)
                    bits.push(`| revisit if: ${d.revisitWhen.slice(0, 120)}`);
                return bits.join('  ');
            })
                .join('\n'),
        };
    },
});
const goalRemoveTool = buildTool({
    name: 'goal_remove',
    description: 'Retire a recorded goal by id. This marks it dropped rather than deleting it — the history stays visible.',
    input_schema: {
        type: 'object',
        properties: { id: { type: 'string', description: 'Goal id from goal_list' } },
        required: ['id'],
    },
    run: async (input, ctx) => {
        const id = str(input, 'id');
        const g = getGoal(ctx.dataDir, id);
        if (!g)
            return { content: `No goal ${id}.`, isError: true };
        saveGoal(ctx.dataDir, { ...g, status: 'dropped', blockedReason: undefined, updated: new Date().toISOString() });
        return { content: `Goal ${g.id} marked dropped (${g.title}). It stays visible in goal_list with status=dropped.` };
    },
});
return { goalAddTool,goalUpdateTool,goalListTool,goalFocusTool,decisionRecordTool,decisionListTool,goalRemoveTool };
}

__mod['tools/goals.js'] = M55();

function M56() {
const { buildTool, str } = __mod['core/tools.js'];
const { listEntries, readEntry, restoreEntry, undoLast, undoStats } = __mod['core/undo.js'];
/**
 * The `undo` tool (B2, docs/07-BUILD-CHECKLIST) — the user-facing door on the
 * rollback journal in core/undo.ts. Mutating tools record a pre-image before
 * they act; this tool hands that rollback back.
 *
 * Stated honestly in its own description: it can only roll back actions taken
 * while undo was enabled, only inside what was captured (exact files for
 * write/edit, a bounded workspace tree for run_command/install), and never
 * changes made outside the workspace (registry, global npm, %APPDATA%).
 */
function oneLine(e) {
    const flags = [
        e.status === 'restored' ? 'already restored' : '',
        e.partial ? 'PARTIAL snapshot' : '',
        e.role === 'safety' ? 'auto pre-restore snapshot' : '',
    ]
        .filter(Boolean)
        .join(', ');
    const head = `${e.id}  ${e.ts}  ${e.tool}  ${e.files.length} file(s)${flags ? `  [${flags}]` : ''}`;
    return `${head}\n    ${e.reason}`;
}
/** The entry `undo` would roll back right now, or null when there is nothing. */
function pendingEntry(dataDir, id) {
    if (id)
        return readEntry(dataDir, id);
    return listEntries(dataDir, 50).find((e) => e.status !== 'restored' && e.role !== 'safety') ?? null;
}
const undoTool = buildTool({
    name: 'undo',
    description: 'Roll back the most recent file-changing action (or a specific one by id). write_file, edit_file, run_command and install record a pre-image of what they are about to change before doing so, and this tool puts it back. action=list shows the journal, action=stats shows journal size. Limits: only actions taken while undo was enabled are recorded; workspace-wide snapshots taken for run_command/install are capped by size and may be PARTIAL; and changes made outside the workspace (registry, global npm, %APPDATA%) were never captured. Every restore is itself snapshotted, so it can be redone by passing that entry id (it appears in action=list as "auto pre-restore snapshot"); a bare undo always targets the last real agent action, never the safety snapshot.',
    input_schema: {
        type: 'object',
        properties: {
            action: {
                type: 'string',
                description: 'undo (default) | list | stats',
            },
            id: {
                type: 'string',
                description: 'Optional entry id from action=list. Omit to roll back the latest action.',
            },
        },
        required: [],
    },
    // Restoring overwrites files, so it is approval-gated like any other write —
    // and the prompt names exactly what is coming back.
    requiresApproval: (input, ctx) => {
        const action = (str(input, 'action') || 'undo').toLowerCase();
        if (action === 'list' || action === 'stats')
            return null;
        const target = pendingEntry(ctx.dataDir, str(input, 'id'));
        if (!target)
            return null; // run() reports "nothing to undo" without touching disk
        return (`Undo: restore ${target.files.length} file(s) to how they were before ` +
            `${target.tool} at ${target.ts}${target.partial ? ' (PARTIAL snapshot — restore may be incomplete)' : ''}`);
    },
    run: async (input, ctx) => {
        const action = (str(input, 'action') || 'undo').toLowerCase();
        if (action === 'stats') {
            const s = undoStats(ctx.dataDir);
            return {
                content: `entries: ${s.entries} (keeping the newest ${s.keep})\n` +
                    `pre-image data: ${(s.blobBytes / 1024 / 1024).toFixed(2)} MB\n` +
                    `journal: ${s.root}`,
            };
        }
        if (action === 'list') {
            const entries = listEntries(ctx.dataDir, 20);
            if (entries.length === 0)
                return { content: 'Nothing in the undo journal yet — no file-changing actions recorded.' };
            return { content: entries.map(oneLine).join('\n') };
        }
        if (action !== 'undo')
            return { content: `Unknown action "${action}". Use undo, list, or stats.`, isError: true };
        const id = str(input, 'id');
        if (id && !readEntry(ctx.dataDir, id))
            return { content: `No undo entry with id "${id}". Run action=list to see the journal.`, isError: true };
        const outcome = id ? restoreEntry(ctx.dataDir, id) : undoLast(ctx.dataDir);
        if (!outcome.ok || !outcome.result)
            return { content: outcome.error ?? 'Undo failed.', isError: true };
        const r = outcome.result;
        const lines = [
            `Rolled back ${r.id} (${r.tool} — ${r.reason})`,
            `  restored: ${r.restored} file(s)`,
            `  deleted: ${r.deleted} file(s) that did not exist before`,
        ];
        if (r.skipped.length > 0)
            lines.push(`  skipped (${r.skipped.length}, pre-image unavailable): ${r.skipped.slice(0, 10).join(', ')}`);
        if (r.partial)
            lines.push('  NOTE: this was a PARTIAL snapshot — the workspace may not be exactly as it was.');
        lines.push('  This restore was itself snapshotted, so it can be undone.');
        return { content: lines.join('\n'), isError: r.restored === 0 && r.deleted === 0 };
    },
});
return { undoTool };
}

__mod['tools/undo.js'] = M56();

function M57() {
const { readFileTool, writeFileTool, editFileTool, listDirTool } = __mod['tools/files.js'];
const { runCommandTool, jobListTool, jobOutputTool, jobKillTool } = __mod['tools/shell.js'];
const { installTool } = __mod['tools/install.js'];
const { webFetchTool, webSearchTool } = __mod['tools/web.js'];
const { memorySaveTool, memorySearchTool, memoryListTool } = __mod['tools/memory.js'];
const { learnDocxTool, learnEpubTool, learnFileTool, learnFolderTool, learnPdfTool, learnPptxTool, learnTranscriptTool, learnUrlTool, learnXlsxTool, knowledgeSearchTool, knowledgeListTool, knowledgeForgetTool, knowledgeDedupTool, } = __mod['tools/knowledge.js'];
const { projectNoteTool, projectReadTool } = __mod['tools/project.js'];
const { scheduleTaskTool, scheduleListTool, scheduleRemoveTool, } = __mod['tools/schedule.js'];
const { screenshotTool, readImageTool, guiActionTool } = __mod['tools/desktop.js'];
const { sayTool, listenTool } = __mod['tools/voice.js'];
const { ocrReadTool } = __mod['tools/ocr.js'];
const { transcribeAudioTool } = __mod['tools/stt.js'];
const { watchVideoTool } = __mod['tools/video.js'];
const { instagramScrapeTool, instagramLearnTool } = __mod['tools/instagram.js'];
const { skillSaveTool, skillListTool, skillRunTool } = __mod['tools/skills.js'];
const { spawnAgentTool } = __mod['tools/agentTool.js'];
const { decisionListTool, decisionRecordTool, goalAddTool, goalFocusTool, goalListTool, goalRemoveTool, goalUpdateTool, } = __mod['tools/goals.js'];
const { undoTool } = __mod['tools/undo.js'];
/** The Phase 1–5 tool registry. New tools: implement buildTool(...) and add here. */
function buildTools() {
    return [
        // filesystem
        readFileTool,
        writeFileTool,
        editFileTool,
        listDirTool,
        // rollback: puts back what the file tools and commands above are about to change
        undoTool,
        // execution & background jobs
        runCommandTool,
        jobListTool,
        jobOutputTool,
        jobKillTool,
        installTool,
        // web
        webFetchTool,
        webSearchTool,
        // memory
        memorySaveTool,
        memorySearchTool,
        memoryListTool,
        // knowledge (learning from documents / web)
        learnFileTool,
        learnFolderTool,
        learnPdfTool,
        learnDocxTool,
        learnXlsxTool,
        learnPptxTool,
        learnEpubTool,
        learnTranscriptTool,
        learnUrlTool,
        knowledgeSearchTool,
        knowledgeListTool,
        knowledgeForgetTool,
        knowledgeDedupTool,
        // project memory (per-workspace continuity)
        projectNoteTool,
        projectReadTool,
        // scheduled tasks
        scheduleTaskTool,
        scheduleListTool,
        scheduleRemoveTool,
        // screen awareness & GUI control
        screenshotTool,
        readImageTool,
        guiActionTool,
        // voice output
        sayTool,
        // push-to-talk (LOCAL mic STT, offline; approval-gated — a mic is opening)
        listenTool,
        // speech-to-text (cloud STT; every call approval-gated)
        transcribeAudioTool,
        // watch a video/reel from a link (yt-dlp download → cloud STT transcript)
        watchVideoTool,
        // Instagram research via Apify (scrape captions → learn into the KB)
        instagramScrapeTool,
        instagramLearnTool,
        // OCR (offline Windows engine)
        ocrReadTool,
        // skills (reusable task recipes) & multi-agent
        skillSaveTool,
        skillListTool,
        skillRunTool,
        spawnAgentTool,
        // Executive Brain (B12): goals, priorities, deadlines, decisions.
        // Registered AFTER everything above so they sit last in the tool list —
        // the agent reaches for them when the user states a commitment, not on
        // every turn, and putting them early would crowd out the working tools.
        goalAddTool,
        goalUpdateTool,
        goalListTool,
        goalFocusTool,
        goalRemoveTool,
        decisionRecordTool,
        decisionListTool,
    ];
}
return { buildTools };
}

__mod['tools/index.js'] = M57();

function M58() {
/** Temp-name counter: unique per process without importing crypto for one call. */
let tmpCounter = 0;
function sessionsDir(dataDir) {
    return path.join(dataDir, 'sessions');
}
/**
 * Read the existing session header, or null when there is none.
 *
 * WHY THE GUARD: this used to be a bare JSON.parse. A single truncated file —
 * an old non-atomic write, a disk full, a kill mid-write — made EVERY later
 * save of that session throw, and the throw propagated out of saveSession into
 * the chat loop. The session was then unopenable AND un-saveable: permanently
 * bricked by a bug the user could not see or undo. A corrupt file must never be
 * able to stop a conversation from being recorded, so parsing failures degrade
 * to "no previous session" (a fresh `created` stamp) and the bad bytes are moved
 * to sessions/corrupt/ instead of deleted, in case they are worth recovering.
 */
function readExistingSession(p) {
    if (!fs.existsSync(p))
        return null;
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    }
    catch {
        quarantineCorrupt(p);
        return null;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        quarantineCorrupt(p);
        return null;
    }
    return parsed;
}
/** Move an unparseable session file aside (best effort — never throws). */
function quarantineCorrupt(p) {
    try {
        const dir = path.join(path.dirname(p), 'corrupt');
        fs.mkdirSync(dir, { recursive: true });
        fs.renameSync(p, path.join(dir, path.basename(p)));
    }
    catch {
        /* already gone, or unwritable — the caller still gets a usable null */
    }
}
function saveSession(dataDir, id, messages) {
    const dir = sessionsDir(dataDir);
    fs.mkdirSync(dir, { recursive: true });
    const p = path.join(dir, `${id}.json`);
    const existing = readExistingSession(p);
    const file = {
        id,
        created: existing?.created ?? new Date().toISOString(),
        updated: new Date().toISOString(),
        messages,
    };
    // ATOMIC. A plain writeFileSync truncates first, so an interrupt mid-write
    // leaves half a JSON file — the exact corrupt state that used to brick the
    // session. Write a sibling temp, flush it, then rename (atomic within a
    // filesystem). Same pattern as vault.ts:165 / memory/vectors.ts:208; unique
    // per write via pid + counter so two concurrent saves never share a temp file.
    const tmp = `${p}.tmp-${process.pid}-${tmpCounter++}`;
    try {
        const fd = fs.openSync(tmp, 'w');
        try {
            fs.writeFileSync(fd, JSON.stringify(file, null, 2), 'utf8');
            fs.fsyncSync(fd);
        }
        finally {
            fs.closeSync(fd);
        }
        fs.renameSync(tmp, p);
    }
    catch (e) {
        try {
            fs.rmSync(tmp, { force: true });
        }
        catch {
            /* nothing further to do */
        }
        throw e; // the caller asked us to save; failing silently is worse
    }
    return p;
}
function sessionFileId(offsetHours) {
    const d = new Date(Date.now() - (offsetHours ?? 0) * 3600_000);
    // millisecond-precision + random suffix: two conversations created in the
    // same second (e.g. New chat → quick first message) must never collide on
    // one file and overwrite each other.
    const rand = Math.random().toString(36).slice(2, 6);
    return `session-${d.toISOString().replace(/[:.]/g, '-').slice(0, 19)}-${rand}`;
}
/**
 * Move a session file aside (sessions/cleared/) so fresh sessions don't
 * resume a conversation that was just cleared in the UI. Best-effort: any
 * failure leaves the file where it is.
 */
function archiveSession(dataDir, id) {
    const src = path.join(sessionsDir(dataDir), `${id}.json`);
    if (!fs.existsSync(src))
        return;
    const dstDir = path.join(sessionsDir(dataDir), 'cleared');
    try {
        fs.mkdirSync(dstDir, { recursive: true });
        fs.renameSync(src, path.join(dstDir, `${id}.json`));
    }
    catch {
        /* best effort — worst case the cleared session stays resumable */
    }
}
/** Load the most recently updated session file (for `--resume`). */
function loadLatestSession(dataDir) {
    const dir = sessionsDir(dataDir);
    if (!fs.existsSync(dir))
        return null;
    const files = fs
        .readdirSync(dir)
        .filter((f) => f.endsWith('.json'))
        .sort(); // timestamped ids → lexicographic sort = chronological
    for (let i = files.length - 1; i >= 0; i--) {
        try {
            const f = JSON.parse(fs.readFileSync(path.join(dir, files[i]), 'utf8'));
            if (Array.isArray(f.messages) && f.messages.length > 0) {
                return { id: files[i].replace(/\.json$/, ''), messages: f.messages };
            }
        }
        catch {
            /* skip unreadable/corrupt sessions */
        }
    }
    return null;
}
/** First user text in a message list (session title source). */
function firstUserText(messages) {
    for (const m of messages) {
        if (m.role !== 'user')
            continue;
        const text = typeof m.content === 'string'
            ? m.content
            : Array.isArray(m.content)
                ? m.content
                    .filter((b) => b.type === 'text')
                    .map((b) => b.text)
                    .join(' ')
                : '';
        const clean = text.replace(/\s+/g, ' ').trim();
        if (clean)
            return clean;
    }
    return '';
}
/** Every persisted session (newest first) for the UI sidebar. */
function listSessions(dataDir, limit = 100) {
    const dir = sessionsDir(dataDir);
    if (!fs.existsSync(dir))
        return [];
    const out = [];
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
        try {
            const s = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
            if (!Array.isArray(s.messages) || s.messages.length === 0)
                continue;
            out.push({
                id: f.replace(/\.json$/, ''),
                title: firstUserText(s.messages).slice(0, 80) || '(untitled)',
                created: s.created ?? '',
                updated: s.updated ?? '',
                turns: s.messages.length,
            });
        }
        catch {
            /* skip unreadable/corrupt sessions */
        }
    }
    out.sort((a, b) => (a.updated < b.updated ? 1 : -1));
    return out.slice(0, limit);
}
/** Load one session by id (ids are timestamped file stems — strictly validated). */
function loadSession(dataDir, id) {
    if (!/^[A-Za-z0-9._-]+$/.test(id) || id.includes('..'))
        return null;
    const p = path.join(sessionsDir(dataDir), `${id}.json`);
    try {
        const s = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (!Array.isArray(s.messages))
            return null;
        return { id, messages: s.messages };
    }
    catch {
        return null;
    }
}
/** Move a session to sessions/deleted/ (recoverable on disk, gone from the list). */
function deleteSession(dataDir, id) {
    if (!/^[A-Za-z0-9._-]+$/.test(id) || id.includes('..'))
        return false;
    const src = path.join(sessionsDir(dataDir), `${id}.json`);
    if (!fs.existsSync(src))
        return false;
    const dstDir = path.join(sessionsDir(dataDir), 'deleted');
    try {
        fs.mkdirSync(dstDir, { recursive: true });
        fs.renameSync(src, path.join(dstDir, `${id}.json`));
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Compact a conversation: fold everything except the last `keepLast` messages
 * into a short plain-text summary message. Keeps the API's user/assistant
 * alternation intact (the summary is a user message; the kept tail is
 * re-anchored so it starts with a user turn).
 */
function compactHistory(messages, keepLast = 8) {
    if (messages.length <= keepLast)
        return { messages, removed: 0 };
    const old = messages.slice(0, messages.length - keepLast);
    let recent = messages.slice(-keepLast);
    const digest = old
        .map((m) => {
        const text = typeof m.content === 'string'
            ? m.content
            : Array.isArray(m.content)
                ? m.content
                    .filter((b) => b.type === 'text')
                    .map((b) => b.text)
                    .join(' ')
                : '';
        const clean = text.replace(/\s+/g, ' ').trim();
        return clean ? `- ${m.role}: ${clean.slice(0, 200)}` : null;
    })
        .filter((x) => x !== null)
        .join('\n');
    const summary = {
        role: 'user',
        content: `[Conversation continued. Summary of the earlier part of this session:\n${digest || '(no text content)'}\nUse it as context; do not comment on it.]`,
    };
    // the kept tail must start with a user turn for strict alternation
    if (recent[0]?.role !== 'user') {
        const firstUser = recent.findIndex((m) => m.role === 'user');
        recent = firstUser === -1 ? recent : recent.slice(firstUser);
    }
    return { messages: [summary, ...recent], removed: old.length };
}
return { saveSession,sessionFileId,archiveSession,loadLatestSession,listSessions,loadSession,deleteSession,compactHistory };
}

__mod['session/history.js'] = M58();

function M59() {
/**
 * .aistate v1 — portable, encrypted AI state (memory, knowledge, projects,
 * experiences, sessions).
 *
 * Format:  "BRSTATE1" | salt(16) | iv(12) | gcm-tag(16) | gzip(JSON)
 * Crypto:  AES-256-GCM, key = scrypt(password, salt, 32). GCM provides both
 *          confidentiality and integrity (tamper → decrypt throws).
 *
 * v2 adds incremental deltas: a sha256 manifest (~/.blackrose/state-manifest.json)
 * tracks the last exported state; exportStateIncremental only packs files that
 * changed since then. Imports merge and refresh the manifest.
 */
const MAGIC = Buffer.from('BRSTATE1');
/**
 * Directories that travel with an export.
 *
 * `skills` was added 2026-10-02: the project's central promise is that changing
 * machine must not erase identity, knowledge or skills — but `skills/` was never
 * listed here, so an export silently omitted every user-written recipe and a
 * migrated machine came up without any of them (`loadSkills` reads
 * `<dataDir>/skills`, see skills/skills.ts). That is a direct violation of the
 * stated principle, so it is now included.
 *
 * Deliberately NOT listed, and why:
 *  - `keys.enc` / `vault.key` — secrets. The vault is device-bound by design
 *    (DPAPI + per-store sealing), so a copied vault cannot be opened elsewhere;
 *    shipping it would export the keys in a form the destination cannot use.
 *  - `state-manifest.json` — export bookkeeping, not AI state.
 *  - `undo/`, `bin/`, `*.log` — local artefacts of this machine.
 *  - root-level files (`mcp.json`, `schedules.json`) — the import validator
 *    rejects every single-component path by design (regression test "state
 *    import rejects unsafe path mcp.json"). Making them portable is a design
 *    change to that security boundary, not a one-line addition; left for an
 *    explicit decision.
 */
const STATE_DIRS = ['memory', 'knowledge', 'projects', 'experiences', 'sessions', 'vectors', 'skills', 'goals'];
const MANIFEST = 'state-manifest.json';
const CONFLICT_COPY = /\.incoming-[a-f0-9]{12}$/i;
function deriveKey(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}
function walk(dir) {
    const out = [];
    if (!fs.existsSync(dir))
        return out;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory())
            out.push(...walk(p));
        else
            out.push(p);
    }
    return out;
}
function collectData(dataDir, only) {
    const data = {};
    for (const dir of STATE_DIRS) {
        for (const f of walk(path.join(dataDir, dir))) {
            const rel = path.relative(dataDir, f).replace(/\\/g, '/');
            // Conflict copies are deliberately local review artifacts. Syncing them
            // automatically would spread unresolved duplicates between devices.
            if (CONFLICT_COPY.test(rel))
                continue;
            if (only && !only(rel))
                continue;
            data[rel] = fs.readFileSync(f, 'utf8');
        }
    }
    return data;
}
function seal(password, data) {
    const payload = zlib.gzipSync(Buffer.from(JSON.stringify({ version: 1, exportedAt: new Date().toISOString(), data }, null, 0), 'utf8'));
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(password, salt), iv);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([MAGIC, salt, iv, tag, encrypted]);
}
function exportState(dataDir, password, outPath) {
    if (!password)
        throw new Error('A password is required (state contains private data).');
    const data = collectData(dataDir);
    const blob = seal(password, data);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const target = outPath ?? path.join(dataDir, `ai-full-${stamp}.aistate`);
    fs.writeFileSync(target, blob);
    return { path: target, files: Object.keys(data).length, bytes: blob.length };
}
/**
 * v2: incremental export — only files whose sha256 differs from the manifest
 * of the previous export are packed. The manifest is refreshed afterwards.
 */
function exportStateIncremental(dataDir, password, outPath) {
    if (!password)
        throw new Error('A password is required (state contains private data).');
    const manifestPath = path.join(dataDir, MANIFEST);
    let manifest = {};
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).files ?? {};
    }
    catch {
        /* first export or no manifest yet */
    }
    const data = collectData(dataDir, (rel) => {
        const sha = sha256File(path.join(dataDir, rel));
        return manifest[rel] !== sha;
    });
    const skipped = countStateFiles(dataDir) - Object.keys(data).length;
    const blob = seal(password, data);
    // Millisecond precision plus a short random suffix. This stamp names the
    // export file, so two exports inside the same second used to produce the SAME
    // path — the second write silently overwrote the first, and a user who
    // exported, changed something, and exported again lost the earlier backup
    // without any error. Second resolution was plenty for a human filename and
    // useless as a unique key.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 23) +
        '-' +
        crypto.randomBytes(3).toString('hex');
    const target = outPath ?? path.join(dataDir, `ai-delta-${stamp}.aistate`);
    fs.writeFileSync(target, blob);
    // refresh manifest to cover the full current state
    const files = { ...manifest };
    for (const dir of STATE_DIRS) {
        for (const f of walk(path.join(dataDir, dir))) {
            const rel = path.relative(dataDir, f).replace(/\\/g, '/');
            files[rel] = sha256File(f);
        }
    }
    fs.writeFileSync(manifestPath, JSON.stringify({ version: 2, updatedAt: new Date().toISOString(), files }, null, 2), 'utf8');
    return { path: target, files: Object.keys(data).length, skipped: Math.max(0, skipped), bytes: blob.length };
}
/** Archives use portable, slash-separated paths under the exported state directories. */
function importTarget(root, rel) {
    const parts = rel.split('/');
    const invalid = parts.length < 2 || !STATE_DIRS.includes(parts[0]) || parts.some((part) => !part || part === '.' || part === '..' || /[\\\x00-\x1f:<>"|?*]/.test(part) ||
        /[. ]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
    if (invalid)
        throw new Error(`Invalid state path: ${JSON.stringify(rel)}`);
    const target = path.resolve(root, ...parts);
    const relative = path.relative(root, target);
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new Error(`Invalid state path: ${JSON.stringify(rel)}`);
    }
    checkImportLinks(root, parts);
    return target;
}
/** Do not follow existing symlinks/junctions, including dangling links and the leaf itself. */
function checkImportLinks(root, parts) {
    let current = root;
    for (const part of parts) {
        current = path.join(current, part);
        const stat = fs.lstatSync(current, { throwIfNoEntry: false });
        if (!stat)
            break;
        if (stat.isSymbolicLink())
            throw new Error(`Invalid state path: symbolic link at ${current}`);
    }
}
function importState(dataDir, filePath, password) {
    const blob = fs.readFileSync(filePath);
    if (blob.length < MAGIC.length + 44 || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error('Not a valid .aistate file (bad magic header).');
    }
    const salt = blob.subarray(MAGIC.length, MAGIC.length + 16);
    const iv = blob.subarray(MAGIC.length + 16, MAGIC.length + 28);
    const tag = blob.subarray(MAGIC.length + 28, MAGIC.length + 44);
    const encrypted = blob.subarray(MAGIC.length + 44);
    let payload;
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(password, salt), iv);
        decipher.setAuthTag(tag); // wrong password OR tampered file → throws here
        payload = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }
    catch {
        throw new Error('Decryption failed: wrong password or corrupted .aistate file.');
    }
    const parsed = JSON.parse(zlib.gunzipSync(payload).toString('utf8'));
    if (!parsed || parsed.version !== 1)
        throw new Error(`Unsupported .aistate version: ${parsed?.version}`);
    if (!parsed.data || typeof parsed.data !== 'object' || Array.isArray(parsed.data)) {
        throw new Error('Invalid state content: expected a file map');
    }
    const root = path.resolve(dataDir);
    // Validate the entire archive before writing anything, so a bad entry cannot
    // cause earlier entries to overwrite existing state before the import fails.
    const entries = Object.entries(parsed.data).map(([rel, content]) => {
        if (typeof content !== 'string')
            throw new Error(`Invalid state content: ${JSON.stringify(rel)}`);
        return { rel, content, target: importTarget(root, rel) };
    });
    checkImportLinks(root, [MANIFEST]);
    let restored = 0;
    let conflicts = 0;
    const manifestPath = path.join(root, MANIFEST);
    let manifest = {};
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).files ?? {};
    }
    catch {
        /* no manifest yet */
    }
    fs.mkdirSync(root, { recursive: true });
    for (const { rel, content, target } of entries) {
        checkImportLinks(root, rel.split('/'));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        const incomingHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
        const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
        const currentHash = current === null ? '' : crypto.createHash('sha256').update(current, 'utf8').digest('hex');
        // A matching manifest says this device has not changed the file since its
        // last accepted sync, so a newer incoming version may safely replace it.
        if (current !== null && current !== content && manifest[rel] !== currentHash) {
            // State is personal data: preserve both versions rather than silently
            // replacing a file that was independently changed on this device.
            const conflictRel = `${rel}.incoming-${incomingHash.slice(0, 12)}`;
            const conflictTarget = importTarget(root, conflictRel);
            checkImportLinks(root, conflictRel.split('/'));
            fs.writeFileSync(conflictTarget, content, 'utf8');
            conflicts += 1;
            continue;
        }
        fs.writeFileSync(target, content, 'utf8');
        manifest[rel] = incomingHash;
        restored += 1;
    }
    fs.writeFileSync(manifestPath, JSON.stringify({ version: 2, updatedAt: new Date().toISOString(), files: manifest }, null, 2), 'utf8');
    return { restored, conflicts };
}
function sha256File(f) {
    return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
}
function countStateFiles(dataDir) {
    let n = 0;
    for (const dir of STATE_DIRS)
        n += walk(path.join(dataDir, dir)).length;
    return n;
}
return { exportState,exportStateIncremental,importState };
}

__mod['state/aistate.js'] = M59();

function M60() {
const { buildTool } = __mod['core/tools.js'];
function loadMcpConfig(dataDir) {
    const f = path.join(dataDir, 'mcp.json');
    if (!fs.existsSync(f))
        return [];
    try {
        const parsed = JSON.parse(fs.readFileSync(f, 'utf8'));
        return (parsed.servers ?? []).filter((s) => s.name && s.command);
    }
    catch {
        return [];
    }
}
/**
 * Ceiling on the un-newline'd portion of a server's stdout.
 *
 * WHY: JSON-RPC over stdio is newline-delimited, so the buffer only drains when
 * a '\n' arrives. A server that never emits one — hostile, buggy, or just
 * logging in a loop — makes this string grow with every chunk until the process
 * runs out of memory. Nothing else bounds it: the child is spawned once at
 * startup and can live for the whole session. Past the cap we reset rather than
 * trim, because the buffer is a mid-line fragment at that point — there is no
 * frame boundary to resynchronise to, and trying to keep the tail would just
 * re-parse garbage. Dropping it costs at most the in-flight line; the next
 * newline re-syncs the stream. 8 MB is far above any legitimate single JSON-RPC
 * response (which carries tool output, not media) and far below a memory cliff.
 */
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;
class McpConnection {
    child;
    buffer = '';
    seq = 0;
    pending = new Map();
    constructor(server, cwd) {
        this.child = spawn(server.command, server.args ?? [], { cwd, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
        this.child.stdout?.on('data', (d) => {
            this.buffer += d.toString();
            if (this.buffer.length > MAX_BUFFER_BYTES)
                this.buffer = '';
            let idx;
            while ((idx = this.buffer.indexOf('\n')) >= 0) {
                const line = this.buffer.slice(0, idx).trim();
                this.buffer = this.buffer.slice(idx + 1);
                if (!line)
                    continue;
                try {
                    const msg = JSON.parse(line);
                    if (typeof msg.id === 'number' && this.pending.has(msg.id)) {
                        const resolve = this.pending.get(msg.id);
                        this.pending.delete(msg.id);
                        resolve(msg);
                    }
                }
                catch {
                    /* ignore malformed lines (some servers log to stdout) */
                }
            }
        });
    }
    request(method, params, timeoutMs) {
        const id = ++this.seq;
        const req = { jsonrpc: '2.0', id, method, params };
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`MCP request "${method}" timed out`));
            }, timeoutMs);
            this.pending.set(id, (r) => {
                clearTimeout(timer);
                resolve(r);
            });
            this.child.stdin?.write(JSON.stringify(req) + '\n');
        });
    }
    async handshake() {
        const res = await this.request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'blackrose', version: '0.1.0' } }, 10_000);
        if (res.error)
            throw new Error(`MCP initialize failed: ${res.error.message}`);
        this.child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    }
    async listTools() {
        const res = await this.request('tools/list', {}, 10_000);
        if (res.error)
            throw new Error(`MCP tools/list failed: ${res.error.message}`);
        const r = res.result;
        return r.tools ?? [];
    }
    async callTool(name, args) {
        const res = await this.request('tools/call', { name, arguments: args }, 60_000);
        if (res.error)
            throw new Error(`MCP tools/call failed: ${res.error.message}`);
        const r = res.result;
        const text = (r.content ?? [])
            .filter((c) => c.type === 'text')
            .map((c) => c.text ?? '')
            .join('\n');
        return text || '(empty MCP result)';
    }
    kill() {
        if (this.child.pid !== undefined) {
            try {
                if (process.platform === 'win32') {
                    spawn('taskkill', ['/PID', String(this.child.pid), '/T', '/F'], { windowsHide: true });
                }
                else {
                    this.child.kill('SIGTERM');
                }
            }
            catch {
                /* already dead */
            }
        }
    }
}
/** Build ToolDefs for one server; keeps the connection open until killed. */
async function mcpToolsForServer(server, cwd) {
    const conn = new McpConnection(server, cwd);
    await conn.handshake();
    const remote = await conn.listTools();
    const prefix = `mcp__${server.name}__`;
    const tools = remote
        .filter((t) => /^[a-zA-Z0-9_-]+$/.test(t.name))
        .map((t) => buildTool({
        name: prefix + t.name,
        description: `[MCP:${server.name}] ${t.description ?? t.name}`,
        input_schema: t.inputSchema ?? { type: 'object', properties: {}, required: [] },
        requiresApproval: server.trusted
            ? undefined
            : (input) => `MCP tool ${prefix}${t.name} ${JSON.stringify(input).slice(0, 100)}`,
        run: async (input) => {
            try {
                return { content: await conn.callTool(t.name, input) };
            }
            catch (e) {
                return { content: e instanceof Error ? e.message : String(e), isError: true };
            }
        },
    }));
    return { tools, kill: () => conn.kill() };
}
/** Register tools from every configured server; broken/down servers are skipped. */
async function registerMcpTools(dataDir, cwd) {
    const out = [];
    for (const server of loadMcpConfig(dataDir)) {
        try {
            const { tools } = await mcpToolsForServer(server, cwd);
            out.push(...tools);
        }
        catch {
            /* server down or broken → skip it, BlackRose keeps booting */
        }
    }
    return out;
}
return { loadMcpConfig,mcpToolsForServer,registerMcpTools };
}

__mod['mcp/client.js'] = M60();

function M61() {
const { loadSchedules, saveSchedules, isDue } = __mod['tools/schedule.js'];
const { runAgent } = __mod['core/agent.js'];
function appendLog(dataDir, line) {
    fs.appendFileSync(path.join(dataDir, 'schedules.log'), `${line}\n`, 'utf8');
}
function startScheduler(o) {
    const tickMs = o.tickMs ?? 30_000;
    let busy = false;
    let stopped = false;
    const timer = setInterval(() => {
        // `void tick()` DISCARDS the promise, so any rejection inside tick becomes an
        // unhandled rejection — which terminates the process by default since Node 15.
        // One malformed schedule file or a write failure would therefore take the
        // whole agent down, silently, from a background timer. Catch it, report it,
        // and keep the schedule alive: a failing task must not kill the scheduler.
        void tick().catch((e) => {
            o.onEvent?.(`⚠ scheduler tick failed: ${e instanceof Error ? e.message : String(e)}`);
        });
    }, tickMs);
    timer.unref?.();
    const runOne = async (s) => {
        const started = new Date().toISOString();
        // persist lastRun BEFORE running so a crash can't cause a tight loop
        const list = loadSchedules(o.dataDir);
        const entry = list.find((x) => x.id === s.id);
        if (entry) {
            entry.lastRun = started;
            entry.runCount += 1;
            saveSchedules(o.dataDir, list);
        }
        o.onEvent?.(`⏰ scheduled task "${s.name}" firing`);
        const unattended = {
            cwd: o.cwd,
            dataDir: o.dataDir,
            askApproval: async (_tool, reason) => {
                const allow = (process.env.BLACKROSE_SCHEDULE_APPROVE ?? '').toLowerCase() === 'all';
                if (!allow) {
                    o.onEvent?.(`  ⚠ unattended run auto-denied: ${reason.slice(0, 120)}`);
                    return false;
                }
                return true;
            },
            log: (line) => o.onEvent?.(`  ${line}`),
        };
        try {
            const outcome = await runAgent({
                client: o.client,
                tools: o.tools,
                system: o.system(),
                history: [{ role: 'user', content: `SCHEDULED TASK "${s.name}"\n\n${s.prompt}` }],
                ctx: unattended,
                maxTurns: o.maxTurns ?? 12,
            });
            const list2 = loadSchedules(o.dataDir);
            const entry2 = list2.find((x) => x.id === s.id);
            if (entry2) {
                entry2.lastResult = outcome.text.slice(0, 500);
                saveSchedules(o.dataDir, list2);
            }
            appendLog(o.dataDir, `${started} | ${s.name} | ${outcome.text.slice(0, 300).replace(/\n/g, ' ')}`);
            o.onEvent?.(`  ✓ scheduled task "${s.name}" finished`);
        }
        catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            appendLog(o.dataDir, `${started} | ${s.name} | ERROR ${msg.slice(0, 300)}`);
            o.onEvent?.(`  ✗ scheduled task "${s.name}" failed: ${msg.slice(0, 200)}`);
        }
    };
    const tick = async () => {
        if (stopped || busy)
            return;
        const due = loadSchedules(o.dataDir).filter((s) => isDue(s));
        if (due.length === 0)
            return;
        busy = true;
        try {
            for (const s of due)
                await runOne(s);
        }
        finally {
            busy = false;
        }
    };
    return {
        stop: () => {
            stopped = true;
            clearInterval(timer);
        },
    };
}
return { startScheduler };
}

__mod['schedule/runner.js'] = M61();

function M62() {
const { runAgent } = __mod['core/agent.js'];
const { runGoal } = __mod['core/taskEngine.js'];
const { memorySaveTool, memorySearchTool } = __mod['tools/memory.js'];
const { knowledgeSearchTool } = __mod['tools/knowledge.js'];
const { exportStateIncremental, importState } = __mod['state/aistate.js'];
function tokensMatch(a, b) {
    const ha = crypto.createHash('sha256').update(a).digest();
    const hb = crypto.createHash('sha256').update(b).digest();
    return crypto.timingSafeEqual(ha, hb);
}
function readBody(req, limit) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (c) => {
            size += c.length;
            if (size > limit) {
                reject(new Error('request body too large'));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}
async function startBridge(o) {
    if (!o.token || o.token.length < 8) {
        throw new Error('bridge token must be at least 8 characters');
    }
    const maxBody = o.maxBodyBytes ?? 8 * 1024 * 1024; // 8MB (sync pushes can be large)
    const startedAt = Date.now();
    const auditPath = path.join(o.dataDir, 'bridge.log');
    const audit = (entry) => {
        try {
            fs.mkdirSync(o.dataDir, { recursive: true });
            fs.appendFileSync(auditPath, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', 'utf8');
        }
        catch {
            /* auditing must never break serving */
        }
    };
    const server = http.createServer(async (req, res) => {
        const t0 = Date.now();
        const method = req.method ?? 'GET';
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        const route = url.pathname;
        const respond = (status, body, ct = 'application/json; charset=utf-8') => {
            res.writeHead(status, { 'content-type': ct });
            res.end(body);
            audit({ method, path: route, status, ms: Date.now() - t0 });
        };
        const json = (status, obj) => respond(status, JSON.stringify(obj, null, 2));
        const bad = (status, msg) => json(status, { error: msg });
        try {
            // auth: every route except /health requires a valid bearer token
            const isHealth = method === 'GET' && route === '/health';
            if (!isHealth) {
                const header = req.headers.authorization ?? '';
                const provided = header.startsWith('Bearer ') ? header.slice(7) : '';
                if (!provided || !tokensMatch(provided, o.token)) {
                    return bad(401, 'unauthorized (missing or invalid bearer token)');
                }
            }
            if (isHealth) {
                return json(200, {
                    name: 'blackrose-bridge',
                    version: o.version ?? '0.6.0',
                    provider: o.client.name,
                    model: o.client.model,
                    uptimeS: Math.round((Date.now() - startedAt) / 1000),
                });
            }
            if (route === '/ask' && method === 'POST') {
                const body = JSON.parse((await readBody(req, maxBody)).toString('utf8') || '{}');
                const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
                if (!prompt)
                    return bad(400, 'field "prompt" is required');
                const maxTurns = typeof body.maxTurns === 'number' ? Math.min(Math.max(1, body.maxTurns), 24) : 12;
                const outcome = await runAgent({
                    client: o.client,
                    tools: o.tools,
                    system: o.system,
                    history: [{ role: 'user', content: prompt }],
                    ctx: o.ctx,
                    maxTurns,
                });
                return json(200, { reply: outcome.text, turns: outcome.turns });
            }
            if (route === '/goal' && method === 'POST') {
                const body = JSON.parse((await readBody(req, maxBody)).toString('utf8') || '{}');
                const goal = typeof body.goal === 'string' ? body.goal.trim() : '';
                if (!goal)
                    return bad(400, 'field "goal" is required');
                const r = await runGoal({
                    client: o.client,
                    tools: o.tools,
                    system: o.system,
                    ctx: o.ctx,
                    goal,
                    maxTurnsPerStep: 8,
                });
                return json(200, {
                    report: r.report,
                    verified: r.verified,
                    plan: r.plan,
                    turns: r.turns,
                });
            }
            if (route === '/memory' && method === 'POST') {
                const body = JSON.parse((await readBody(req, 1024 * 1024)).toString('utf8') || '{}');
                if (typeof body.content !== 'string' || !body.content.trim()) {
                    return bad(400, 'field "content" is required');
                }
                const key = typeof body.key === 'string' && body.key.trim() ? body.key : 'bridge';
                const r = await memorySaveTool.run({ key, content: body.content }, o.ctx);
                return json(r.isError ? 400 : 200, { content: r.content });
            }
            if (route === '/memory' && method === 'GET') {
                const q = url.searchParams.get('q') ?? '';
                if (!q.trim())
                    return bad(400, 'query parameter "q" is required');
                const r = await memorySearchTool.run({ query: q }, o.ctx);
                return json(200, { content: r.content });
            }
            if (route === '/knowledge' && method === 'GET') {
                const q = url.searchParams.get('q') ?? '';
                if (!q.trim())
                    return bad(400, 'query parameter "q" is required');
                const r = await knowledgeSearchTool.run({ query: q, k: 4 }, o.ctx);
                return json(200, { content: r.content });
            }
            if (route === '/state/export' && method === 'POST') {
                const body = JSON.parse((await readBody(req, 4096)).toString('utf8') || '{}');
                if (typeof body.password !== 'string' || !body.password) {
                    return bad(400, 'field "password" is required (state is always encrypted at rest)');
                }
                const delta = exportStateIncremental(o.dataDir, body.password);
                const blob = fs.readFileSync(delta.path);
                fs.rmSync(delta.path, { force: true });
                res.writeHead(200, {
                    'content-type': 'application/octet-stream',
                    'x-aistate-files': String(delta.files),
                    'x-aistate-skipped': String(delta.skipped),
                });
                res.end(blob);
                audit({ method, path: route, status: 200, ms: Date.now() - t0, files: delta.files });
                return;
            }
            if (route === '/state/import' && method === 'POST') {
                const rawPw = req.headers['x-password'];
                const password = typeof rawPw === 'string' ? decodeURIComponent(rawPw) : '';
                if (!password)
                    return bad(400, 'header "x-password" is required');
                const blob = await readBody(req, maxBody);
                if (!blob.subarray(0, 8).toString('latin1').startsWith('BRSTATE1')) {
                    return bad(400, 'body is not a .aistate file');
                }
                const tmp = path.join(o.dataDir, `tmp-import-${Date.now()}.aistate`);
                fs.writeFileSync(tmp, blob);
                try {
                    const r = importState(o.dataDir, tmp, password);
                    return json(200, { restored: r.restored });
                }
                finally {
                    fs.rmSync(tmp, { force: true });
                }
            }
            return bad(404, `no route: ${method} ${route}`);
        }
        catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            audit({ method, path: route, status: 500, ms: Date.now() - t0, error: msg });
            try {
                bad(500, msg);
            }
            catch {
                /* response already sent */
            }
        }
    });
    const connections = new Set();
    server.on('connection', (c) => {
        connections.add(c);
        c.on('close', () => connections.delete(c));
    });
    const host = o.host ?? '127.0.0.1';
    const port = await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(o.port ?? 8787, host, () => {
            const addr = server.address();
            resolve(typeof addr === 'object' && addr ? addr.port : (o.port ?? 8787));
        });
    });
    return {
        port,
        host,
        url: `http://${host === '0.0.0.0' || host === '::' ? 'localhost' : host}:${port}`,
        close: () => new Promise((resolve) => {
            for (const c of connections)
                c.destroy();
            server.close(() => resolve());
        }),
    };
}
return { startBridge };
}

__mod['bridge/server.js'] = M62();

function M63() {
/**
 * Resilience wrapper (Phase 6.3): retries transient LLM failures with
 * exponential backoff + jitter, and passes non-transient errors through
 * immediately (auth/quota problems must fail fast and loudly).
 *
 * Transient: HTTP 429 / 5xx, "overloaded", rate limits, network hiccups
 * (ECONNRESET, ETIMEDOUT, "fetch failed", ...). Everything else — notably
 * HTTP 401/400 (bad key, no credits, bad request) — is surfaced on first try.
 */
const TRANSIENT_RE = /HTTP 429|HTTP 5\d\d|overloaded|rate.?limit|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|fetch failed|socket hang up|network/i;
function isTransientError(e) {
    const msg = e instanceof Error ? e.message : String(e);
    return TRANSIENT_RE.test(msg);
}
function resilientClient(inner, opts = {}) {
    const maxRetries = opts.maxRetries ?? 4;
    const base = opts.baseDelayMs ?? 800;
    return {
        name: inner.name,
        model: inner.model,
        async call(system, messages, tools, callOpts) {
            for (let attempt = 0;; attempt++) {
                try {
                    return await inner.call(system, messages, tools, callOpts);
                }
                catch (e) {
                    // A cancelled request must not be retried with backoff — that is
                    // exactly the spend the user asked to stop.
                    if (callOpts?.signal?.aborted)
                        throw e;
                    if (attempt >= maxRetries || !isTransientError(e))
                        throw e;
                    const delay = Math.round(base * 2 ** attempt + Math.random() * 100);
                    opts.onRetry?.(attempt + 1, delay, e);
                    await new Promise((r) => setTimeout(r, delay));
                }
            }
        },
    };
}
return { isTransientError,resilientClient };
}

__mod['llm/resilient.js'] = M63();

function M64() {
const { exportStateIncremental, importState } = __mod['state/aistate.js'];
async function jsonCall(base, token, route, body, method = 'POST') {
    const res = await fetch(base.replace(/\/$/, '') + route, {
        method,
        headers: {
            'content-type': 'application/json',
            ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok)
        throw new Error(`bridge ${res.status}: ${text.slice(0, 300)}`);
    return JSON.parse(text);
}
function bridgeHealth(base) {
    return jsonCall(base, '', '/health', undefined, 'GET');
}
function bridgeAsk(base, token, prompt, maxTurns) {
    return jsonCall(base, token, '/ask', { prompt, maxTurns });
}
function bridgeGoal(base, token, goal) {
    return jsonCall(base, token, '/goal', { goal });
}
function bridgeMemorySave(base, token, key, content) {
    return jsonCall(base, token, '/memory', { key, content });
}
function bridgeMemorySearch(base, token, query) {
    return jsonCall(base, token, `/memory?q=${encodeURIComponent(query)}`, undefined, 'GET');
}
function bridgeKnowledgeSearch(base, token, query) {
    return jsonCall(base, token, `/knowledge?q=${encodeURIComponent(query)}`, undefined, 'GET');
}
/**
 * Sync push: export an incremental (encrypted) delta from the local state and
 * import it on the remote machine. Refreshes the local delta manifest.
 */
async function bridgeSyncPush(base, token, dataDir, password) {
    if (!password)
        throw new Error('state password required (--state-password or BLACKROSE_STATE_PASSWORD)');
    const delta = exportStateIncremental(dataDir, password);
    const blob = fs.readFileSync(delta.path);
    fs.rmSync(delta.path, { force: true });
    const res = await fetch(base.replace(/\/$/, '') + '/state/import', {
        method: 'POST',
        headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/octet-stream',
            'x-password': encodeURIComponent(password),
        },
        body: blob,
    });
    const text = await res.text();
    if (!res.ok)
        throw new Error(`bridge sync push ${res.status}: ${text.slice(0, 300)}`);
    return { ...JSON.parse(text), files: delta.files };
}
/**
 * Sync pull: fetch the remote machine's encrypted delta and merge it into the
 * local state dir (imports merge; existing files are overwritten by newer
 * remote content).
 */
async function bridgeSyncPull(base, token, dataDir, password) {
    if (!password)
        throw new Error('state password required (--state-password or BLACKROSE_STATE_PASSWORD)');
    const res = await fetch(base.replace(/\/$/, '') + '/state/export', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ password }),
    });
    if (!res.ok)
        throw new Error(`bridge sync pull ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const tmp = path.join(dataDir, `.sync-pull-${Date.now()}.aistate`);
    fs.writeFileSync(tmp, buf);
    try {
        return importState(dataDir, tmp, password);
    }
    finally {
        fs.rmSync(tmp, { force: true });
    }
}
return { bridgeHealth,bridgeAsk,bridgeGoal,bridgeMemorySave,bridgeMemorySearch,bridgeKnowledgeSearch,bridgeSyncPush,bridgeSyncPull };
}

__mod['bridge/client.js'] = M64();

function M65() {
const { makeClient } = __mod['llm/factory.js'];
const { buildSystemPrompt } = __mod['llm/prompt.js'];
const { buildTools } = __mod['tools/index.js'];
const { runAgent } = __mod['core/agent.js'];
const { registerMcpTools } = __mod['mcp/client.js'];
const { loadSkills } = __mod['skills/skills.js'];
const { readProjectNotes } = __mod['tools/project.js'];
const { startBridge } = __mod['bridge/server.js'];
const { resilientClient } = __mod['llm/resilient.js'];
const { bridgeAsk, bridgeGoal, bridgeHealth, bridgeMemorySearch, bridgeSyncPull, bridgeSyncPush, } = __mod['bridge/client.js'];
/**
 * Bridge entrypoints (Phase 6):
 *  - runBridge(config, argv): `node src/index.ts --bridge [port]` — serve the
 *    agent over HTTP (loopback by default, fail-closed approvals).
 *  - runRemote(argv, dataDir): `node src/index.ts --remote <url> --token <t>
 *    --ask/--goal/--memory-search/--sync-push/--sync-pull ...`
 */
function systemPromptFor(config) {
    const memDir = path.join(config.dataDir, 'memory');
    const memoryKeys = fs.existsSync(memDir) ? fs.readdirSync(memDir).filter((f) => f.endsWith('.md')) : [];
    return buildSystemPrompt(config.cwd, config.dataDir, memoryKeys, readProjectNotes(config.dataDir, config.cwd), loadSkills(config.dataDir).map((s) => ({ name: s.name, description: s.description })));
}
function flagValue(argv, flag) {
    const i = argv.indexOf(flag);
    return i !== -1 ? (argv[i + 1] ?? '').trim() : '';
}
/** Everything after `flag` until the next --flag (multi-word prompts). */
function flagRest(argv, flag) {
    const i = argv.indexOf(flag);
    if (i === -1)
        return '';
    const rest = [];
    for (let j = i + 1; j < argv.length; j++) {
        if (j > i + 1 && argv[j].startsWith('--'))
            break;
        rest.push(argv[j]);
    }
    return rest.join(' ').trim();
}
async function runBridge(config, argv) {
    const portIdx = argv.indexOf('--bridge');
    const portArg = Number(argv[portIdx + 1]);
    const port = Number.isFinite(portArg) && portArg > 0 ? portArg : 8787;
    const host = process.env.BLACKROSE_BRIDGE_HOST ?? '127.0.0.1';
    const generated = !process.env.BLACKROSE_BRIDGE_TOKEN;
    const token = process.env.BLACKROSE_BRIDGE_TOKEN ?? crypto.randomBytes(16).toString('hex');
    let client;
    try {
        // transient-error retry for bridge-served runs too (same policy as the REPL)
        client = resilientClient(makeClient(config), {
            onRetry: (a, d, e) => console.log(`  [bridge] ↻ transient LLM error (${e instanceof Error ? e.message.slice(0, 90) : String(e)}) — retry ${a} in ${d}ms`),
        });
    }
    catch (e) {
        console.error(`${e instanceof Error ? e.message : String(e)}\n` +
            'Set ANTHROPIC_API_KEY, or point BLACKROSE_PROVIDER at any API gateway.');
        process.exit(1);
    }
    let tools = buildTools();
    const mcp = await registerMcpTools(config.dataDir, config.cwd);
    if (mcp.length > 0)
        tools = [...tools, ...mcp];
    const autoApprove = process.env.BLACKROSE_BRIDGE_APPROVE === 'all';
    const baseCtx = {
        cwd: config.cwd,
        dataDir: config.dataDir,
        askApproval: async (name, reason) => {
            if (autoApprove)
                return true;
            console.log(`  [bridge] denied ${name}: ${reason.slice(0, 90)} (set BLACKROSE_BRIDGE_APPROVE=all to allow)`);
            return false;
        },
        log: (l) => console.log(`  ${l}`),
    };
    // depth-1 sub-agents, same policy as the REPL host
    const ctx = {
        ...baseCtx,
        runSubTask: async (task, label) => {
            console.log(`  [bridge] sub-agent started (${label ?? 'task'})`);
            const outcome = await runAgent({
                client,
                tools: tools.filter((t) => t.name !== 'spawn_agent' && t.name !== 'skill_run'),
                system: systemPromptFor(config),
                history: [{ role: 'user', content: task }],
                ctx: baseCtx,
                maxTurns: 12,
            });
            console.log(`  [bridge] sub-agent finished (${outcome.turns} turns)`);
            return { content: outcome.text || '(sub-agent returned no text)' };
        },
    };
    const h = await startBridge({
        client,
        system: systemPromptFor(config),
        tools,
        ctx,
        dataDir: config.dataDir,
        token,
        port,
        host,
    });
    console.log(`BlackRose bridge listening on ${h.url}`);
    console.log(`  provider: ${client.name} · model: ${client.model}`);
    if (generated) {
        console.log(`  token (generated for this run, or set BLACKROSE_BRIDGE_TOKEN): ${token}`);
    }
    console.log(`  approvals: ${autoApprove ? 'AUTO (BLACKROSE_BRIDGE_APPROVE=all)' : 'fail-closed — remote actions are denied'}`);
    console.log(`  audit log: ${path.join(config.dataDir, 'bridge.log')}`);
    console.log('  Ctrl+C to stop.');
    const stop = () => {
        void h.close().then(() => process.exit(0));
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    setInterval(() => { }, 60_000); // keep the event loop alive
}
async function runRemote(argv, dataDir) {
    const base = flagValue(argv, '--remote');
    const token = flagValue(argv, '--token');
    if (!base || !token) {
        console.error('usage: node src/index.ts --remote <url> --token <token> --ask|--goal|--memory-search|--health|--sync-push|--sync-pull ...');
        process.exit(1);
    }
    const password = flagValue(argv, '--state-password') || process.env.BLACKROSE_STATE_PASSWORD || '';
    try {
        if (argv.includes('--ask')) {
            const prompt = flagRest(argv, '--ask');
            if (!prompt)
                throw new Error('--ask needs a prompt, e.g. --ask "status update?"');
            const r = await bridgeAsk(base, token, prompt);
            console.log(r.reply);
            return;
        }
        if (argv.includes('--goal')) {
            const goal = flagRest(argv, '--goal');
            if (!goal)
                throw new Error('--goal needs a goal text');
            const r = await bridgeGoal(base, token, goal);
            console.log(r.report);
            console.log(`  goal status: ${r.verified ? 'VERIFIED ✓' : 'NOT VERIFIED ✗'} · plan: ${r.plan.length} step(s) · turns: ${r.turns}`);
            return;
        }
        if (argv.includes('--memory-search')) {
            const q = flagRest(argv, '--memory-search');
            if (!q)
                throw new Error('--memory-search needs a query');
            console.log((await bridgeMemorySearch(base, token, q)).content);
            return;
        }
        if (argv.includes('--health')) {
            const h = await bridgeHealth(base);
            console.log(`${h.name} v${h.version} · ${h.provider}/${h.model} · up ${h.uptimeS}s`);
            return;
        }
        if (argv.includes('--sync-push')) {
            const r = await bridgeSyncPush(base, token, dataDir, password);
            console.log(`  ✓ pushed ${r.files} changed file(s) → remote imported ${r.restored}`);
            if (r.conflicts > 0) {
                console.log(`  ! ${r.conflicts} conflict copy/copies preserved on the remote device (*.incoming-<hash>)`);
            }
            return;
        }
        if (argv.includes('--sync-pull')) {
            const r = await bridgeSyncPull(base, token, dataDir, password);
            console.log(`  ✓ pulled and merged ${r.restored} file(s) from remote`);
            if (r.conflicts > 0) {
                console.log(`  ! ${r.conflicts} conflict copy/copies preserved locally (*.incoming-<hash>)`);
            }
            return;
        }
        throw new Error('no action given: use --ask, --goal, --memory-search, --health, --sync-push or --sync-pull');
    }
    catch (e) {
        console.error(`remote error: ${e instanceof Error ? e.message : String(e)}`);
        process.exit(1);
    }
}
return { runBridge,runRemote };
}

__mod['bridge/main.js'] = M65();

function M66() {
/**
 * Risk tiers for approval decisions.
 *
 * The UI (and the CLI) can run in a "trust" mode where ordinary tool calls do
 * not stop for a human. That is only safe if the ALWAYS-ASK set is small,
 * explicit, and fails closed — so the classification lives in ONE place and is
 * driven by a deny-list of genuinely dangerous tools, not by an allow-list of
 * safe ones (a new tool added tomorrow must default to asking, never to
 * auto-running).
 *
 * Tier meanings:
 *   'auto'   — runs without asking in trust mode.
 *   'ask'    — ALWAYS asks, even in trust mode. Irreversible, destructive,
 *              spends money, touches the mic/screen, or reaches the network.
 *   'none'   — the tool does not require approval at all (read-only).
 */
/**
 * Tools that ALWAYS require a human decision, in every mode.
 *
 * Deliberately conservative. Anything not listed here is 'auto' *only* while
 * the user has explicitly turned trust mode on; with trust off (the default)
 * every approval-gated tool still asks, so this list only ever REDUCES
 * friction, it never removes the fail-closed default.
 */
const ALWAYS_ASK = new Set([
    // executes arbitrary commands on the machine
    'run_command',
    'install',
    // can permanently schedule unattended work
    'schedule_task',
    // can write anywhere on disk, including outside the workspace
    'write_file',
    'edit_file',
    // overwrites and deletes files by restoring a pre-image — the rollback path
    // is itself destructive, so trust mode must not auto-run it unattended
    'undo',
    // opens the microphone
    'listen',
    // captures the screen / drives the GUI
    'screenshot',
    'gui_action',
    // sends data off the machine
    'transcribe_audio',
    'watch_video',
    'instagram_scrape',
    // talks to a remote MCP server
    'mcp_call',
]);
/** Classify a tool by name. Unknown tools are 'auto' only under explicit trust. */
function riskTier(toolName) {
    if (ALWAYS_ASK.has(toolName))
        return 'ask';
    return 'auto';
}
/** True when this tool must ask even in trust mode. */
function alwaysAsk(toolName) {
    return ALWAYS_ASK.has(toolName);
}
/** The always-ask list, for the UI to show the user what trust mode will not cover. */
function alwaysAskList() {
    return [...ALWAYS_ASK].sort();
}
return { riskTier,alwaysAsk,alwaysAskList };
}

__mod['core/trust.js'] = M66();

function M67() {
/**
 * The "permission needed" chime, embedded as base64.
 *
 * Kept in its own module rather than inlined in assets.ts for two reasons. The
 * data URI is ~127KB of base64, which would swamp the file it lived in and make
 * every unrelated edit to the page a merge hazard. And it has to be a DATA URI
 * rather than a fetched file: this UI ships inside a Node SEA .exe with zero
 * external assets, so there is no path on disk to resolve at runtime and no
 * second file for the packager to miss.
 *
 * Played through a single Audio element created lazily. Browsers block audio
 * until the user has interacted with the page, so the element is "unlocked" on
 * the first click or keypress (see primeAudio in the page script); without
 * that, play() rejects silently and the chime appears broken for exactly the
 * users who need it most — someone looking at another window.
 */
/** base64 of an MP3, used as the src of a data: URI. */
const APPROVAL_CHIME_BASE64 = 'SUQzBAAAAAEBflRTU0UAAAAOAAADTGF2ZjYwLjE2LjEwMUdFT0IAAQFcAAADYXBwbGljYXRpb24vYzJwYQBjMnBhAGMycGEgbWFuaWZlc3Qgc3RvcmUAAABA77+9anVtYgAAAB5qdW1kYzJwYQARABDvv70AAO+/vQA477+9cQNjMnBhAAAAQO+/vWp1bWIAAABHanVtZGMybWEAEQAQ77+9AADvv70AOO+/vXEDdXJuOmMycGE6NDQ2MDIwMGQtOWVhYS00MmE2LWFkMTQtZDg4ZjJkNWI2OTEwAAAAAu+/vWp1bWIAAAApanVtZGMyYXMAEQAQ77+9AADvv70AOO+/vXEDYzJwYS5hc3NlcnRpb25zAAAAAO+/vWp1bWIAAABOanVtZGpzb24AEQAQ77+9AADvv70AOO+/vXETc3Rkcy5zY2hlbWEtb3JnLkNyZWF0aXZlV29yawAAAAAYYzJzaO+/vRls77+977+9JBfZmO+/vTRd77+977+977+9bAAAAH5qc29ueyJAY29udGV4dCI6Imh0dHBzOi8vc2NoZW1hLm9yZyIsIkB0eXBlIjoiQ3JlYXRpdmVXb3JrIiwiYXV0aG9yIjpbeyJAdHlwZSI6Ik9yZ2FuaXphdGlvbiIsIm5hbWUiOiJFbGV2ZW4gTGFicyBJbmMuIn1dfQAAAO+/vWp1bWIAAABBanVtZGNib3IAEQAQ77+9AADvv70AOO+/vXETYzJwYS5hY3Rpb25zLnYyAAAAABhjMnNo77+9LUnIte+/ve+/ve+/ve+/ve+/ve+/vWhtWs+qAAAA77+9Y2Jvcu+/vWdhY3Rpb25z77+977+9ZmFjdGlvbmxjMnBhLmNyZWF0ZWRxZGlnaXRhbFNvdXJjZVR5cGV4Rmh0dHA6Ly9jdi5pcHRjLm9yZy9uZXdzY29kZXMvZGlnaXRhbHNvdXJjZXR5cGUvdHJhaW5lZEFsZ29yaXRobWljTWVkaWEAAADvv71qdW1iAAAAQGp1bWRjYm9yABEAEO+/vQAA77+9ADjvv71xE2MycGEuaGFzaC5kYXRhAAAAABhjMnNoAe+/ve+/vXfvv71jCO+/vTLvv71gTSVc77+9AAAAe2Nib3Lvv71qZXhjbHVzaW9uc++/ve+/vWVzdGFydBhXZmxlbmd0aBlA77+9ZG5hbWVuanVtYmYgbWFuaWZlc3RjYWxnZnNoYTI1NmRoYXNoWCBRVUvvv73vv73vv71eSO+/ve+/ve+/vVg577+977+9XO+/ve+/vSN+NHjNtWwX77+977+977+977+9ME5jcGFkSAAAAAAAAAAAAAACV2p1bWIAAAAnanVtZGMyY2wAEQAQ77+9AADvv70AOO+/vXEDYzJwYS5jbGFpbS52MgAAAAIoY2Jvcu+/vWppbnN0YW5jZUlEeCx4bXA6aWlkOmY4MTI2YWQ1LWNmN2EtNDU4ZS04ZDA5LWU2ZDc1ZjUxYjFlMHRjbGFpbV9nZW5lcmF0b3JfaW5mb++/vWRuYW1lakVsZXZlbkxhYnN3b3JnLmNvbnRlbnRhdXRoLmMycGFfcnNmMC44OS4waXNpZ25hdHVyZXhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYTo0NDYwMjAwZC05ZWFhLTQyYTYtYWQxNC1kODhmMmQ1YjY5MTAvYzJwYS5zaWduYXR1cmVyY3JlYXRlZF9hc3NlcnRpb25z77+977+9Y3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFgg2LJv77+977+9EADvv71KYgVKFe+/vSZj77+9eO+/ve+/ve+/vUPvv70+77+9R++/ve+/vUvvv70bTXNnYXRoZXJlZF9hc3NlcnRpb25z77+977+9Y3VybHg3c2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvc3Rkcy5zY2hlbWEtb3JnLkNyZWF0aXZlV29ya2RoYXNoWCDvv73vv73vv71p77+9d++/ve+/ve+/ve+/vQRo77+977+977+9Nu+/vRzvv73vv73vv71qExZ677+977+977+9LSgi77+9Y3VybHgqc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5hY3Rpb25zLnYyZGhhc2hYIO+/ve+/vQXvv71T77+9Mu+/ve+/vRbvv71Ja0wA77+9C0UZ77+9aHdMcu+/vSvvv70K77+977+9UUBjYWxnZnNoYTI1NgAAO1NqdW1iAAAAKGp1bWRjMmNzABEAEO+/vQAA77+9ADjvv71xA2MycGEuc2lnbmF0dXJlAAAAOyNjYm9y0oRZDmHvv70BOCIYIe+/vVkENjDvv70EMjDvv70DGu+/vQMCAQICEAJb77+9Y3Fw77+9DH/vv715G++/ve+/ve+/ve+/vTANBgkq77+9SO+/ve+/vQ0BAQwFADBmMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSUwIwYDVQQDExxEaWdpQ2VydCBEb2N1bWVudCBTaWduaW5nIENBMB4XDTI1MTAwNzAwMDAwMFoXDTI2MTAwNjIzNTk1OVowVjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMRkwFwYDVQQKExBFbGV2ZW4gTGFicyBJbmMuMRkwFwYDVQQDExBFbGV2ZW4gTGFicyBJbmMuMHYwEAYHKu+/vUjvv709AgEGBSvvv70EACIDYgAE77+977+9PO+/vWzJse+/vVrvv70677+977+9P++/vTrvv73vv73vv70j77+977+9dBERQyo177+9V++/ve+/ve+/vTsk77+977+977+96IyXw5bvv70C77+977+977+9He+/vTbvv71A77+977+9PwkI77+977+9Fe+/vSc7FHXvv73vv73vv70pQ++/ve+/ve+/ve+/ve+/ve+/ve+/vQQkWWLvv73vv71577+977+977+9XHYV77+9ZEbvv73vv70B77+9MO+/vQHvv70wHwYDVR0jBBgwFu+/vRTvv73vv70177+977+977+977+977+977+977+977+9DO+/vVpv77+9L0vvv71kMB0GA1UdDgQWBBTvv70QJzpv77+977+9eO+/vVHvv73CgVzvv73vv71177+9au+/vTAWBgNVHSAEDzANMAsGCWDvv71IAe+/ve+/vWwDFTAOBgNVHQ8BAe+/vQQEAwIH77+9MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDDvv73vv70GA1UdHwTvv73vv70w77+977+9MD/vv70977+9O++/vTlodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnREb2N1bWVudFNpZ25pbmdDQS1nMS5jcmwwP++/vT3vv70777+9OWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydERvY3VtZW50U2lnbmluZ0NBLWcxLmNybDB7BggrBgEFBQcBAQRvMG0wJAYIKwYBBQUHMAHvv70YaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAC77+9OWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydERvY3VtZW50U2lnbmluZ0NBLmNydDANBgkq77+9SO+/ve+/vQ0BAQwFAAPvv70BAQDvv73vv70d77+977+9Zu+/ve+/ve+/vRUR77+977+9zKHvv71lbXXvv713Zu+/ve+/vWzvv70/C++/vQTvv73vv71N77+977+977+977+9Q++/vQ8D77+9H++/vQA+77+9c++/vStF77+9zKhg77+977+9X2vvv71z77+977+9JO+/ve+/ve+/ve+/ve+/vWYy77+977+977+977+9ZX8J77+9U++/ve+/vSzvv71p77+9KDRDeu+/ve+/vUF077+9VBDvv71k77+9K++/vWDvv71ScO+/ve+/vUzvv70iFz1d77+9Dh4V77+9eO+/vd+hKVUM77+977+9cjjvv73vv71b77+977+9fe+/ve+/vTrvv73Vuu+/ve+/vVnvv73vv71CKUR277+977+977+9U++/vXHvv71J77+9MO+/vQAG77+9QgDvv73vv71E77+977+9Su+/ve+/ve+/ve+/ve+/vduH77+9SDHvv73vv73vv73vv73vv73vv73vv73vv70b77+9b295C2Alcgca77+9B++/ve+/ve+/vQ/vv71S77+977+9A++/vcey77+977+977+9Ze+/vVokPe+/vUfvv71gfu+/vQjvv70677+977+9MO+/vRIEN++/ve+/ve+/ve+/vQTvv71e77+9Pu+/vVkGYDDvv70GXDDvv70FRO+/vQMCAQICEAnHt9uyeCQ377+9GV5q77+9M++/vRAwDQYJKu+/vUjvv73vv70NAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTEzMTEwNTEyMDAwMFoXDTI4MTEwNTEyMDAwMFowZjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTElMCMGA1UEAxMcRGlnaUNlcnQgRG9jdW1lbnQgU2lnbmluZyBDQTDvv70BIjANBgkq77+9SO+/ve+/vQ0BAQEFAAPvv70BDwAw77+9AQoC77+9AQEA77+9URY6d++/ve+/vRYk77+977+977+977+93pV6MQ1K77+9au+/vX0lfO+/ve+/ve+/ve+/ve+/vQg0aO+/vQkmPjFF77+9IUhM1Znvv73vv73vv70a77+9d++/ve+/vWcP77+9Wu+/ve+/vQ/vv73vv73vv73vv70YKu+/ve+/vVQMYu+/vSNi77+9Ye+/vW5PF2Ie77+977+977+9EO+/vcOd77+977+977+977+977+977+9xq5LLe+/vUjvv71j77+9He+/vWDvv70W77+977+977+977+9cTTvv71e77+9FdiKSu+/vRM2MO+/vQ02HC3vv70OT++/vTHvv71ZTu+/vQsy77+9Ymx1Ze+/vXrvv73vv73vv71bNEjvv73vv71L77+9IFbvv73vv71I77+977+977+9Y0wDJ++/vTBVZ++/vRUbKUAj77+977+977+977+9DWUA77+9Ee+/vSJPb0Tvv73vv73vv71ydeK6rDFNXe+/vQ/vv73vv70s77+977+9KN2oRgU477+9EBTvv73vv70/77+9Fu+/vU5a77+9X++/ve+/vUbvv71BFG/vv73vv73vv73vv73vv73vv701Ci3vv70s77+977+977+977+9Du+/vQIDAQAB77+977+9AwUw77+9AwEwEgYDVR0TAQHvv70ECDAGAQHvv70CAQAwDgYDVR0PAQHvv70EBAMCAe+/vTA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAHvv70YaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMO+/ve+/vQYDVR0fBHoweDA677+9OO+/vTbvv700aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA677+9OO+/vTbvv700aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQw77+9Ae+/vQYDVR0gBO+/vQHvv70w77+9Ae+/vTDvv70B77+9Bgpg77+9SAHvv73vv71sAAIEMO+/vQHvv70wKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw77+9AWQGCCsGAQUFBwICMO+/vQFWHu+/vQFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYO+/vUgB77+977+9bAMVMB0GA1UdDgQWBBTvv73vv70177+977+977+977+977+977+977+977+9DO+/vVpv77+9L0vvv71kMB8GA1UdIwQYMBbvv70UReuir++/ve+/vcuCMS1R77+977+977+9Ie+/ve+/vW3vv70PMA0GCSrvv71I77+977+9DQEBCwUAA++/vQEBAFlw77+977+9MO+/ve+/vVPvv718Ae+/ve+/vRQGCe+/ve+/vWRLZV7vv71e77+9DFTvv73vv71m77+9XO+/ve+/vd+Pemp377+977+9LO+/vQ9F77+9cu+/ve+/vXU477+9JSnvv73vv71uQWsF77+977+977+94Z62HO+/vShcIX/vv73vv73RoTHvv70G77+977+9Uu+/ve+/ve+/vUzvv70h77+977+977+977+9H++/vVXvv73vv73vv70r77+9d++/vRDvv73vv71c77+9MTnvv73vv70KeXch77+977+977+9cF3vv71mAhHvv73vv73vv73Lre+/vTYK77+977+977+9Cu+/ve+/ve+/vd2477+977+9B1ES77+977+9be+/ve+/vUTvv70I77+977+9ee+/ve+/ve+/vWIR77+977+9eWnvv73vv73vv73vv73HrwHvv71O77+977+977+9He+/vRDvv73vv71vNu+/vTVU0YtH77+9dlnvv70MCe+/vWrvv71k77+9Le+/vU/vv70777+9NiBJ77+977+9F++/vXsPIU9H047SkO+/vWltT++/vRTvv73vv71l77+9Ou+/ve+/vU/vv70UH++/vXEzSe+/vVXvv73vv73vv73vv70R77+9WQPvv70w77+9A++/vTDvv70C77+977+9AwIBAgIQDO+/ve+/ve+/vRfvv71G77+977+977+9YO+/vRvvv70wOTANBgkq77+9SO+/ve+/vQ0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0Ew77+9ASIwDQYJKu+/vUjvv73vv70NAQEBBQAD77+9AQ8AMO+/vQEKAu+/vQEBAO+/vQ4V77+977+9Q++/vVzvv73vv73vv71g77+9cRLvv73vv73vv70m77+977+977+977+977+977+9IDkoWGAM77+977+92qkV77+9MmE877+977+9KO+/ve+/ve+/vdyfCgzvv70Xeu+/ve+/ve+/ve+/ve+/vXlTXDHvv70q77+9D++/vTI2du+/ve+/ve+/vTzvv73vv73vv71q77+9Ie+/vVJh358g77+9H++/ve+/ve+/vRhk77+9Eltf77+9WBg177+9R82hNu+/vWt/1LA4Pu+/vRvDjDPvv73vv70vGO+/vSgP77+977+977+977+977+9bkTvv71hNe+/vRbvv71Z77+977+9dm3vv73vv71LDSvvv70LctqeYNCO77+9Ne+/vXhV77+9IO+/ve+/ve+/vW0K77+9SXwx77+9M2wi77+977+9Mlrvv73vv70T77+9Ee+/vTkX77+977+9OnLvv73vv73vv73vv73vv73vv70XMXXvv73vv719Iu+/vT8BRu+/ve+/vSh5yLHvv73vv71XF++/vX4cDu+/ve+/ve+/ve+/vVbvv73vv73vv73vv73vv73vv73vv73vv73FqD/vv70W77+977+977+977+977+9CF8Yd08CAwEAAe+/vWMwYTAOBgNVHQ8BAe+/vQQEAwIB77+9MA8GA1UdEwEB77+9BAUwAwEB77+9MB0GA1UdDgQWBBRF66Kv77+977+9y4IxLVHvv73vv73vv70h77+977+9be+/vQ8wHwYDVR0jBBgwFu+/vRRF66Kv77+977+9y4IxLVHvv73vv73vv70h77+977+9be+/vQ8wDQYJKu+/vUjvv73vv70NAQEFBQAD77+9AQEA77+9Du+/ve+/ve+/ve+/ve+/ve+/vXJzemTvv73vv73vv71yZu+/vTLvv71CdWLvv73vv73vv73vv73vv73vv73vv71W77+977+977+977+9FCjvv70N77+9YFwSTFjvv73vv70977+9SUVY77+9NWka77+9R++/vVbvv71577+9Eu+/vWfvv73vv73vv71/CTzvv73vv70mLCDvv70977+9KO+/ve+/vV/vv70i4peEH++/vWXvv73vv73vv73vv71nSe+/vV3vv70JKu+/vSbvv71477+9fT8r77+9JjVtX++/vQHvv71JW++/vQEF77+977+9PSXvv73Mtn/vv73vv71v77+977+977+9ZGjvv70t77+977+9Qu+/ve+/ve+/vR7vv71i77+9UGfvv71s77+977+977+9H2sMNgcWfzd877+9W21677+9EkZg77+977+9JwTvv71Lzpfvv73vv71nKmgR34Dvv70MM2bvv70TDRRu77+9fx9jEB7vv73vv70bJW1s77+977+977+9YQHvv73Soybvv70Qce+/ve+/ve+/ve+/ve+/vcOZUe+/vSsHCO+/vS7vv71Q77+977+977+9CkUv77+977+977+9Z3NpZ1RzdDLvv71pdHN0VG9rZW5z77+977+9Y3ZhbFkXbzDvv70XawYJKu+/vUjvv73vv70NAQcC77+977+9F1ww77+9F1gCAQMxDzANBglg77+9SAFlAwQCAQUAMO+/ve+/vQYLKu+/vUjvv73vv70NAQkQAQTvv710BHIwcAIBAQYJYO+/vUgB77+977+9bAcBMDEwDQYJYO+/vUgBZQMEAgEFAAQgOO+/ve+/ve+/vSrvv73vv73vv73vv73vv73vv70PfAY2Cg5F77+9PO+/ve+/vQbvv73vv70j77+9Ke+/vXYCEQDvv73vv73vv71c34bvv70177+9Tmvvv70M77+977+9OhgPMjAyNjEwMDExNTM0MTZaAgkA77+9X++/ve+/vdKb77+9Pe+/ve+/vRM6MO+/vQbvv70w77+9BNWgAwIBAgIQCE/vv70zT35FTu+/ve+/vQ/vv73vv73vv70YNTANBgkq77+9SO+/ve+/vQ0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYgMTDvv70CIjANBgkq77+9SO+/ve+/vQ0BAQEFAAPvv70CDwAw77+9AgoC77+9AgEA77+9e++/ve+/ve+/ve+/ve+/vUrvv73Um0xl77+977+9OO+/vTDvv718CQ7vv73vv73vv71CLu+/vVrvv71877+9JjF/NWJrFO+/vXLbh9yk77+977+9GO+/vcuF77+9awDvv71Tdg/vv70TMe+/ve+/vXcObmgIblnvv73vv70qEO+/vWTvv714Nnrvv71+77+977+9WQXJiQnvv710ASURMO+/vW4U77+977+977+977+9bA8D77+9BSkU77+9OO+/vSYQSO+/ve+/ve+/vT9277+977+9AO+/ve+/vUHvv73vv73vv71N77+977+9Je+/vVZ777+977+9XiMl77+977+9SAvvv73vv70q77+9VzNFKe+/vUR677+977+977+9Hxnvv73vv73vv70oGBJYbnbvv70j77+977+977+9woPvv73vv70K77+9JUzvv73vv70iDe+/ve+/vRw7Tmnvv71ldH5I77+977+9bu+/vQ7vv73vv73vv70/ZXEiB++/ve+/ve+/vT3RlO+/vXdxfVbvv705RVzvv71v77+9ISEz77+977+977+977+977+977+9Te+/ve+/ve+/vXUR77+9bu+/vWXvv70n77+9Wdu5N++/vXLvv71cFEZ9FO+/ve+/vT7vv71N77+9a++/vX7vv73vv73vv73vv73vv70NHnjvv73vv71n77+9ExYN77+977+977+977+9bFRsIu+/vW/vv71BNe+/vSvvv73vv73vv73vv71J77+977+977+9NV4VYO+/vTA7aO+/ve+/vQty77+9Bg9WY++/vUzvv73vv73vv73Ll++/ve+/ve+/vW5d77+9f++/vXLvv73vv70J77+9Ze+/vVQ4LO+/vTHvv73vv73vv70u77+9AmTvv71jbgvvv70mCg9TZHXvv70nb++/vS1U77+977+977+9de+/vUDvv70u77+977+977+977+977+977+977+977+9fHfvv73Wowvvv73vv71B77+9Y++/ve+/vQDvv73Gve+/ve+/vVhxI92Z77+9Mu+/vRBA77+9bu+/vQjvv73vv73vv71eQ03vv70PDO+/vTg477+977+9LTHvv73vv73vv71b77+9MO+/vX/vv73vv73vv70DEX1M77+9LCBQfBvvv73vv73fpklkZQvvv73vv73vv70v77+977+9DyLvv71w77+977+9M++/vdicflfvv73vv71tczhC77+9cO+/vUAhelwwJT0CAwEAAe+/ve+/vQHvv70w77+9Ae+/vTAMBgNVHRMBAe+/vQQCMAAwHQYDVR0OBBYEFBTvv71j77+9MC7vv71K77+9bu+/ve+/ve+/ve+/vUB+77+977+977+977+9MB8GA1UdIwQYMBbvv70U77+9b1NK77+977+9Bnx677+977+9Vu+/vS/vv71J77+977+9TjAOBgNVHQ8BAe+/vQQEAwIH77+9MBYGA1UdJQEB77+9BAwwCgYIKwYBBQUHAwgw77+977+9BggrBgEFBQcBAQTvv73vv70w77+977+9MCQGCCsGAQUFBzAB77+9GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAu+/vVFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBU77+9Uu+/vVDvv71OaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ++/vQwBBAIwCwYJYO+/vUgB77+977+9bAcBMA0GCSrvv71I77+977+9DQEBCwUAA++/vQIBAO+/ve+/vTphHu+/vVIK35nvv70J77+9fn0oQO+/vWvvv71i77+977+9Iu+/vQ10CBDvv70yKu+/vWsV77+9W++/vTDvv70/77+9ZF5sFznvv73OpWzvv70vOVPvv71qLO+/vSpDCy3vv71EEO+/ve+/vUMeAu+/vS3vv73vv73PjkXvv71reFhnTXTvv73vv71a77+977+9Te+/vWbvv70f77+977+9Wu+/vXfvv70w77+977+977+977+9S++/vQ/vv71nOGfvv71aPhQ2AB1mR8eEe++/ve+/vR9EVh7vv71I77+977+9cEN/77+977+9Uu+/vXzdje+/vTXvv73vv73vv71377+9Ye+/ve+/vWfvv70R77+977+935Xvv73vv70r77+9YBjvv70077+977+9ae+/vQ9Z77+9LO+/vciOaO+/ve+/vRLCie+/ve+/ve+/vTTvv71g77+9xoU477+977+977+9aWsD77+9GRzvv70FUe+/ve+/ve+/vSJN77+9PO+/vT7vv71XIXlpDO+/vT/vv73vv71UZRROee+/ve+/vRlYJu+/ve+/vU4l77+977+977+9dGHvv73vv73vv70VQe+/vXJETjbvv70e77+9NgDvv73vv73vv704bSlZ77+977+9PStsdcS7bu+/ve+/vQ8p77+977+9FjzKigwf77+9bceb77+9P++/vVnvv70T77+9ee+/ve+/vVPvv70s77+9HO+/vQfvv71aa8qrOkB577+9Xu+/vU1477+977+9AMyy77+9dE3vv73vv70w77+9Ku+/ve+/vWkU77+9LCkRYVnvv70DYO+/ve+/vVLvv717U++/vW9x77+977+977+977+977+977+977+977+977+9V++/ve+/ve+/vXXvv70f77+9Re+/vVnvv70d77+9c++/ve+/vVpg77+977+9MO+/ve+/ve+/vTPvv71qO++/vSVtS++/vToiQSPvv71ZEe+/ve+/ve+/ve+/vVteYxERRO+/ve+/vWvvv70777+977+977+9cu+/vUjvv71lYe+/vSLvv71eMO+/vQ/vv73vv73vv71/R++/ve+/vXtB77+977+9AO+/ve+/vWoJCTbevGHvv73vv73vv73vv73vv73vv71U77+9LSfvv71977+9K++/ve+/vUU9Ne+/ve+/vQTvv71Y77+9WHnvv73vv70YLO+/ve+/ve+/vRHvv70U77+977+9K++/vTfMlkDvv73vv73vv70w77+9Bu+/vTDvv70E77+977+9AwIBAgIQDcesVwXvv70h77+9LkBDIgw6Se+/vTANBgkq77+9SO+/ve+/vQ0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMO+/vQIiMA0GCSrvv71I77+977+9DQEBAQUAA++/vQIPADDvv70CCgLvv70CAQDvv714Me+/vQrvv71Bcu+/vTxG77+9HO+/vXXbo0ZodO+/vVEX77+9Te+/ve+/vQ3vv73vv73vv73vv73vv70sVO+/vUNqEe+/vTUXMmxC77+977+9G++/vTpz77+977+977+977+9Xi4aPCPvv73vv73vv70S77+9Iu+/vQvvv73vv73vv73ap++/vSXvv71aDO+/vTXvv73vv73vv71n77+9HUjvv73vv73Tqu+/ve+/vUPvv70B77+9Se+/ve+/vQHvv70d77+9Z0Ma77+977+9GO+/ve+/ve+/vWDvv71QXSZH77+977+9Le+/vT7vv73vv73vv71h77+9BO+/ve+/vQRuQO+/ve+/vUF2w4QJLVTvv70QbzIBHe+/vUFiDO+/vSI5PHg62IVwxKTvv707Re+/vRfvv73vv71877+9Skvvv71a77+977+9fDReb++/ve+/ve+/vWdg77+9Nxpq77+9bO+/vQjUju+/vW/vv70BZO+/vSLvv73vv71C77+977+977+9PO+/vVjvv71xKTVV77+92ZQ8Be+/ve+/vRUUFREmDu+/vTFI77+9a++/ve+/vQnvv71F77+9du+/vVRS77+9Gkvvv73vv71477+9PO+/ve+/vRpoYGk877+977+9Fifvv70+77+9L2gdFu+/vU/vv73vv718Se+/ve+/vRLvv71/GcalNe+/vVDvv70u77+9cu+/ve+/vc+n77+977+977+9Ne+/vWZQHkrvv70l77+9ZA4x77+9ce+/vUvvv73vv70G77+977+90LJAQQZx77+977+91b8Aw4wJ77+9FTUm77+977+9Fe+/vVbvv70G77+977+9fTJn77+977+977+9Re+/vUHvv71877+9OO+/ve+/ve+/vXrvv71YMQnvv73vv73vv71e77+9Vu+/ve+/vS/vv70nT++/ve+/ve+/ve+/ve+/ve+/vXM8M++/ve+/vS7vv73vv707Yk/ehe+/ve+/vVsf77+977+9yogxG++/vQQ8eu+/vVfvv73vv73vv71sNO+/vWAk77+9Iu+/ve+/ve+/vRtmXUrvv70bU2rMku+/ve+/vUPvv73vv71GKe+/vWzvv70OLu+/vUEw77+9Zu+/vUUl77+9We+/vT7OgWnvv73vv71a77+977+9SjNm2qA+77+977+9VHhGNO+/vVjvv70o5a6D77+9X++/ve+/ve+/vSnvv73vv70b77+9ayBjUwIDAQAB77+977+9AV0w77+9AVkwEgYDVR0TAQHvv70ECDAGAQHvv70CAQAwHQYDVR0OBBYEFO+/vW9TSu+/ve+/vQZ8eu+/ve+/vVbvv70v77+9Se+/ve+/vU4wHwYDVR0jBBgwFu+/vRTvv73vv73vv73vv71xXWRM77+9Lmc/57qY77+9HA9PMA4GA1UdDwEB77+9BAQDAgHvv70wEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB77+9GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAu+/vTVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDjvv70277+9NO+/vTJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmfvv70MAQQCMAsGCWDvv71IAe+/ve+/vWwHATANBgkq77+9SO+/ve+/vQ0BAQsFAAPvv70CAQAX77+977+9Fu+/vRzvv70HPRF2cTDvv73vv70LyLU077+9f++/vdCHxYgaMH9Pw5tcBnPvv73vv73vv71MY2nvv71d77+977+9DO+/vVBr77+977+977+9M2rvv70k77+977+977+9PBtI77+977+9S++/ve+/vX7vv713YTjvv70hCFAT77+977+977+9Re+/vStJ77+9ee+/ve+/ve+/ve+/vRrvv70Z77+977+9LAUt77+977+9cu+/vVMDPjTvv73EuBd/77+977+977+9YxDCvwzJv2sRUu+/ve+/vXzvv73vv70377+977+9Qe+/vRfvv73vv70EGCvvv71Hau+/ve+/vXtu77+9Hu+/vVjvv70A77+9A++/vVjvv73vv73vv70Z77+9ID/vv73Rtu+/vR9y1IsA77+9AXx1Ne+/ve+/vdOa77+977+9Qh3vv73vv73vv73vv70I77+977+9Nu+/vVQf77+9dADvv71k77+977+977+9Cdmu77+9LzXvv70277+9V++/vTF0SQzvv71TSlPvv73vv71Bwp9nEC8EAu+/vTFb77+977+977+9M++/vXoD77+9zr4EWj7Ptu+/vUgcGV00Te+/ve+/vS7vv73vv73vv73aiO+/vTbvv73vv71Ed2p877+977+9W++/vWYo77+9fTPvv70t77+977+9Ru+/ve+/vWIN77+9OlV8cipD77+977+977+977+977+9Y++/vVzvv70bFzLvv73vv71TTO+/ve+/vWXvv70Bdu+/ve+/vToWd2UQ1KYT77+9SRnvv71OGO+/ve+/vQ9vODRzW++/vTHvv73vv71l77+977+9dHLvv71G77+977+9AWE6bTEm77+9dhHvv70O77+977+977+977+9FO+/vWTvv71377+9aUfvv70aQe+/ve+/vSXvv70377+977+977+9LO+/vSVn77+977+9zIg977+9L++/vSbvv73vv73vv73vv70+77+9Fe+/vVgo77+977+977+9Dizvv73vv70xHe+/vcif77+977+9EO+/ve+/vSHvv73vv73vv715TO+/ve+/ve+/vT/vv70w77+977+9MO+/vXQt77+9E3rYku+/vUtQ77+977+9De+/vXQb77+977+9Blrvv73IiOWCne+/vVbvv70S77+977+9EA/vv73vv73vv71SM++/ve+/vSZs77+9xaFt77+9Nu+/ve+/vdaQ77+9T++/ve+/vVww77+9Be+/vTDvv70Ede+/vQMCAQICEA7vv70Y77+977+977+9Le+/ve+/ve+/vVDvv70IQBhaMA0GCSrvv71I77+977+9DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDDvv70CIjANBgkq77+9SO+/ve+/vQ0BAQEFAAPvv70CDwAw77+9AgoC77+9AgEA77+977+9c2jeu++/vV1KPDAiMGkz77+9wqclLu+/vSE977+977+9We+/ve+/vSnvv709WO+/vXbvv73Nrnsb77+9De+/vTAf77+9G++/vTgW77+9VsaXbR3vv73vv71577+977+9Ee+/ve+/vV/vv70FPFIPUh/GnhXvv71+77+977+977+9VxZZVXLvv71o77+9cMKy77+9de+/vWpzMu+/ve+/vRBEEC7fgu+/vQfvv73vv710O21x77+9LQwb77+9IO+/ve+/vSAdYykt77+977+9Xk7Ik++/vSFh77+9NO+/vQXvv71e77+9Wxrvv73vv73vv73vv73NrDRAX++/vXpm77+9d++/vUjvv71mV1fvv71UWO+/vQwr77+9T++/vTDvv71W77+977+9e13vv73vv71PXu+/vTXvv70x77+92pNe3I7vv73vv73atu+/ve+/vUDvv71577+9eMe277+9xLVqGDgDEO+/ve+/ve+/vTfvv70uBX3vv73vv73vv70+EO+/vXDvv71V77+9QTLvv73vv70Ecypu77+9AXwhTNS877+9GwN1XXhm77+9OjFE77+9M0Dvv70I77+9Wknvv73vv73mqaBn3aQn77+977+9Tznvv70RWBfvv70kXEbvv71k77+977+9ae+/vXbvv712PVldQnbvv73vv73vv71pekjvv73vv70SG2bvv71077+977+9Sx7vv70OY++/ve+/ve+/ve+Skjrvv70977+9AO+/vUUl77+977+977+9RBkrfu+/ve+/ve+/ve+/vWFt77+9M++/ve+/ve+/vUsEAO+/vX0c77+9w4/vv70h77+977+9Ee+/ve+/vX/vv73VjHAsQWDvv73vv71jGETvv70admJ+77+977+977+977+977+9ZO+/vTPRiQfhvbfvv71D77+9GO+/ve+/vXcB77+9D++/vQwhHe+/vVQpJe+/vWzvv70OUlFHdO+/vSbvv73vv71Bde+/vXrvv71f77+9P8m877+9QRESW++/vRBQ77+9Me+/ve+/vXIWIgnvv718THU/Y++/vSFf77+9IFFrb++/ve+/ve+/ve+/vU/vv73vv71FX++/vSDvv73vv70e77+977+977+977+977+9fgom77+977+977+9aS/vv70dLe+/vdmp77+9He+/vRsCAwEAAe+/ve+/vQE6MO+/vQE2MA8GA1UdEwEB77+9BAUwAwEB77+9MB0GA1UdDgQWBBTvv73vv73vv73vv71xXWRM77+9Lmc/57qY77+9HA9PMB8GA1UdIwQYMBbvv70UReuir++/ve+/vcuCMS1R77+977+977+9Ie+/ve+/vW3vv70PMA4GA1UdDwEB77+9BAQDAgHvv70weQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzAB77+9GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAu+/vTdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOu+/vTjvv70277+9NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSrvv71I77+977+9DQEBDAUAA++/vQEBAHDvv73vv71DXFXvv704X++/ve+/vXQbPe+/vRbvv73vv73vv71XB++/ve+/ve+/ve+/ve+/vSzvv71e77+9Gu+/vSLvv73vv70aaVQi77+977+977+9d23vv70aFO+/vRNKei8t77+9OO+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vXLvv70k77+9UgPvv71O77+9Ku+/ve+/vS1W77+977+977+977+977+9MHrvv73vv73vv71e77+977+977+9Q0Tvv71DIe+/vXLvv71I77+977+9y51P77+9BgMTdydE77+977+9f++/vVnvv73vv70vC++/ve+/ve+/vTQ877+977+9A8eH77+977+9TEAZNUZqaVTvv73vv73vv71W77+977+977+9Pe+/ve+/ve+/vRzvv73vv713WlxU77+9b++/vVA977+9dglo77+977+9b++/ve+/vSDvv701YBwCA++/vSDvv73vv71Y77+9DkBjxZgi77+977+9We+/vVVr77+9J++/vWx277+9byMt77+9fnFqI2si77+9Eu+/vVQtJ37vv70677+98LaHlu+/vVvvv71c77+9GO+/vU3vv71z77+9Ae+/ve+/vVfvv71eKOK5lDHvv70DfDDvv70DeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP77+9M09+RU7vv73vv70P77+977+977+9GDUwDQYJYO+/vUgBZQMEAgEFAO+/ve+/ve+/vTAaBgkq77+9SO+/ve+/vQ0BCQMxDQYLKu+/vUjvv73vv70NAQkQAQQwHAYJKu+/vUjvv73vv70NAQkFMQ8XDTI2MTAwMTE1MzQxNlowKwYLKu+/vUjvv73vv70NAQkQAgwxHDAaMBgwFgQUUdmr77+9A0lz77+9T0Jm77+977+977+9SO+/vWnvv705MC8GCSrvv71I77+977+9DQEJBDEiBCAC77+9Yu+/ve+/ve+/vRzZku+/ve+/ve+/vXgLb++/ve+/vXgv0Zfvv71T77+977+9dO+/vSkz77+977+9ZjA3Bgsq77+9SO+/ve+/vQ0BCRACLzEoMCYwJDAiBCAt77+977+977+977+9Ex/vv73vv70t77+977+977+977+977+9ZWdV77+9BD8e77+9Qu+/vQ0hIO+/vUHvv73vv70wDQYJKu+/vUjvv73vv70NAQEBBQAE77+9AgDvv70PKAcd77+977+9Me+/vQbvv73vv73vv70Y77+977+9Mu+/ve+/vVDvv73vv70U77+977+9TDZ3A++/ve+/ve+/ve+/vRLHi++/ve+/vRlL77+9eDbvv71oWuK7jwM8UjRw77+9IFfvv70r77+9a2fvv70jIUxYcnw577+977+977+9Ze+/ve+/vWsiGuONlQsBz67vv73vv71h77+9agHvv73vv71g77+9NTvvv73vv70+77+9yqcx77+977+977+9K++/vVAT77+9MWVT77+90YMpOe+/vSzvv70b77+9OV1L77+9Ce+/ve+/vS0+77+9zpDvv73vv73vv73HtAfjl7vvv70Z77+9ZSHvv70bQnDvv70iAe+/ve+/ve+/vVfvv73vv70gDWnvv71z77+977+977+9PFRh77+9EnM/77+9On7vv73vv71a77+977+977+9f++/ve+/ve+/ve+/vW3vv73vv70t77+9G++/ve+/vTDHp1Hvv73vv73vv73vv70P77+9QlXvv73vv73vv73vv70O77+9b++/vQ3vv70YazJkP++/vdGr77+9d9OXFu+/ve+/vVBYUu+/vSnvv73vv71m77+9cWhDNlBTSu+/vV/vv73vv73vv71B77+9DO+/vUto77+9CO+/ve+/vXJL77+9T0/vv73vv70KxpXvv70N77+9y4vvv71777+977+977+9Iu+/ve+/vRsI77+9E2zvv73vv73vv73vv73vv73vv73vv71W77+977+9Akjvv73vv70rZe+/ve+/ve+/ve+/ve+/ve+/vXEhTO+/vRHMqiPvv73vv70j77+9ae+/ve+/vWAV77+9Zu+/vQHvv71kHg7vv71jQQlw77+9Y++/vWsQ77+977+977+9e++/vRsl77+977+9KWPvv73vv70cRO+/vTnfoR0877+9dDFtYO+/vWLvv70d77+9WyFjTu+/vWnvv73vv73vv73vv70dYm1JKu+/ve+/ve+/vRMn77+9Ce+/vRDbnWTvv71V77+9aHfvv71dDu+/ve+/vTXvv70g77+9UO+/vVvTp++/ve+/vTcV77+977+977+9LlHvv73vv71YQO+/ve+/ve+/vT7vv73vv73vv70nBlfvv70R77+9b++/vT7vv73vv70077+977+977+977+977+977+977+9ZB/vv73vv70n77+92Kt2QWvvv73vv70aL++/ve+/ve+/ve+/ve+/ve+/ve+/vTIX77+977+977+9On3vv71jcGFkWRTvv70AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA77+9WGDvv73vv70QPjrvv73vv702L3Lvv73vv70x77+977+9Ju+/ve+/ve+/vSkC77+9aO+/ve+/vQTvv71kGu+/ve+/ve+/ve+/ve+/ve+/ve+/vS4o77+9D01277+9eil877+9ce+/ve+/ve+/vURY77+9eQnvv73vv70q77+9eSwC77+977+9Te+/vTTvv70YRTLvv73vv71W77+9XO+/vUrvv70H77+9RRLvv73vv71g77+977+9N++/ve+/ve+/ve+/ve+/ve+/ve+/vQAAD1V477+9TDzvv71K77+977+9XUHHpDgA77+9fO+/ve+/vSlA77+977+9Ae+/vWgoHiESQQd7Jkzvv71wQiDvv70f77+977+977+977+977+977+9CCBCIiM/77+977+9NO+/vQjvv73vv71777+977+9Jk7vv73vv70jHu+/vUXvv70nd3d777+91ogxBO+/ve+/ve+/ve+/ve+/vQYhERF3d++/ve+/ve+/vRDvv73vv73vv73vv73vv73vv73vv73vv73vv71aIiIi77+977+977+977+9Ee+/vR4gLT3vv70YenkRCBhA77+9I++/vQ9YAABB77+9RO+/vSMCGVHvv71mYVM6QkkJ77+9ZO+/ve+/vSTdiO+/vV5a77+9eNKL77+9Qe+/vUnvv71FKe+/vQLvv71FJO+/vRFw77+9KGpY77+9BO+/ve+/vUhn77+9ODJMYe+/vUNAMe+/vRRCDO+/ve+/vcuKHRbvv71g77+9IChp77+977+9Bu+/ve+/vR8o77+977+9Hgbvv71IB++/vVNe6IaZ77+9KO+/ve+/vRFVMXczA2cnAlbvv73vv70KaBVZPu+/vRIl77+9F++/vWllTBp077+9bO+/ve+/vVZE77+977+9S8iLE++/vUrvv703Mibvv71N77+977+9UO+/vWF/J10HxL9l77+977+9Ce+/ve+/veKgqCpH77+9AgAA77+9Cu+/vTTvv73fpu+/vSLvv73Coe+/vS7vv73vv71e77+977+9Du+/ve+/vRV877+977+977+977+9HO+/ve+/ve+/ve+/ve+/vVjvv71hCULThe+/vWgQYu+/vW/vv73vv73vv71yIu+/vXsJNWk/77+9I3Dvv70fJQBoF++/vQTvv71277+9YC3vv73vv71c77+977+93aFM77+9He+/ve+/vVp977+977+9UiRd77+977+977+977+9MQLvv70V77+977+9Pe+/ve+/vRjvv71dBcew77+9Fg7vv71gfO+/vXTvv70g77+9eg0P77+9fO+/vWdy77+9e++/ve+/vWHQsO+/ve+/vRXvv73SvFcP77+977+9Qwzvv70q77+977+9PRDvv70t77+977+9NikwU05SWj4YZCI5fO+/vUhGS1Tvv73vv70hOu+/ve+/ve+/vTEQe0I8LgkQ77+977+977+9CVTvv71wTO+/vT8pL++/ve+/ve+/vVzvv73vv71TK++/vQbvv70R77+9cu+/ve+/vXTvv73vv73vv73vv71o77+977+9fnp3CVnvv71XEHjvv73vv73vv73vv73vv73vv70cR++/ve+/vXZSKGPvv704Xwrvv73vv71dVylzEO+/vR8IUWMhau+/ve+/vXwP77+977+9xoccy5JCO0/vv70AMAbvv73vv73vv73vv73vv702JhXvv71vBO+/vSgLWO+/veGhou+/vSgRD++/ve+/vURqLRbvv73vv73vv73vv71EUznvv73QhFYyMml677+977+9esWp77+9KFx877+977+977+9cH7vv70qYk05Oe+/vQLvv71ZIu+/vXfvv71kDjjvv71jJy1acmJNPUVjcmHvv71C77+9dCES77+977+977+977+977+977+9yIpFPETvv73vv70wQjonIO+/ve+/ve+/ve+/ve+/ve+/vThc77+977+977+9U1dvNXlS77+9Vu+/vXJZLO+/ve+/ve+/vSYqVEBkenrvv70CCwBlae+/ve+/ve+/vRkF77+9M17vv73vv71cfu+/ve+/vRLvv71f77+977+91qkXU++/ve+/vUJCS++/vTVX77+977+9eUUy77+977+9PhZO77+977+9yqVw77+90qcY77+9dO+/ve+/vQPvv71G77+977+977+9MQzvv70JZmzvv73vv73vv73vv70kAhvvv73vv73vv70t77+977+977+9Ku+/vR7lp7I5Khrvv70YU++/vQZpVu+/vXUdaDXDou+/ve+/vW5677+9OO+/vVfvv71UMCsV77+9Eu+/ve+/ve+/vXQCSXTvv70fPjjvv73vv70uIxfvv70iMu+/vQAACSjvv73vv73vv71F77+9B++/vQLvv73vv73vv71I77+9Qu+/vWzvv73vv71kIhIQ77+9O0Pvv73vv73vv73vv73vv71cNB5XHe+/vVgTT0Xvv700aO+/ve+/vTDvv73vv73ctDwN77+977+977+9BicS77+9TiIf77+977+977+9MO+/vU8L77+9EitF77+977+9HCMm77+9FTcfAlLvv71l77+9JO+/vVXvv71VZO+/vWrvv73vv73vv73Kke+/ve+/vXM977+977+977+9Jigice+/vUQFHe+/ve+/ve+/ve+/vRFjQ++/ve+/ve+/vRglKnE4cirvv71IH++/vUvvv73vv73vv70+U++/vTpV77+977+9He+/vV8+77+977+9Nwk+aQ4E77+977+977+977+977+9Fu+/ve+/vRMEDH/vv70N77+90rDvv73vv73vv71Q1pVZ77+9a++/vV5Q77+9IRtD77+977+977+9Ie+/vcysUjbvv712dG49GBDvv71H77+977+9IGRI77+977+977+9JO+/vSHvv73vv73vv73vv73vv73Eke+/ve+/vXDvv70W77+977+9Ol9lWO+/vW7vv73vv73vv73OnFpLD++/ve+/vdKZGxbvv73PrnLvv70NJe+/vQbvv73vv71477+977+9fO+/ve+/vSrvv71+NO+/vS9oe0lL77+977+9IO+/ve+/ve+/ve+/vQHvv70oIe+/vRAk77+9be+/ve+/ve+/vXfvv73vv73vv71u77+977+977+9eu+/vWFp77+9B++/vS8Py6E077+977+9VHcj77+977+9cw/vv73vv70+77+977+977+977+977+9Fu+/vVk177+977+9DO+/vTHvv70777+977+9Je+/vRvvv73vv71NYu+/vSjvv7000ooJG++/ve+/ve+/ve+/ve+/vWVJIVVn77+9RDdQByAYBO+/vV/vv71hKB4KIDUhYRhiAFFs77+9GFvvv70PLQLvv71o77+9Ne+/ve+/vUzvv71J77+9STvIuu+/vWQHJ++/ve+/ve+/vTfvv71577+91onvv70I77+9VFZQLu+/vWBWUe+/vRk2WO+/ve+/vR7vv73vv70i77+9QULvv73vv71G0KxKAQV2REpp77+9elBWWe+/ve+/vWcI1ZLvv70LWi3vv71HTc+i77+977+977+9Ry7vv71vLu+/vdu0KO+/vTfvv73vv70qI0xgCADvv70B77+9EgUkcu+/vRsg77+977+977+9H1AHNgHvv73vv73vv71y77+9FO+/ve+/ve+/vWIx77+977+9ezfvv73vv73vv73vv73Zs1tXTEYL77+9JO+/ve+/vWFAJO+/vXk677+9RTxSdlnvv71T77+91p5pXE5a77+9Pyo677+977+9Re+/vQdt77+9BO+/vWBv77+9Mm7vv73vv71Q77+9QTMCR++/vQ7vv73Nve+/ve+/ve+/vcOCCu+/vQfvv708Vu+/vQXvv70M15vvv73vv70XLO+/ve+/ve+/ve+/vUvYle+/ve+/ve+/ve+/ve+/vXDvv70Jx4po77+9d++/ve+/vcqHMu+/vUIA77+9dDhw77+9Ge+/ve+/vTRCMxMT77+9dHNW77+977+9Mu+/vVrDte+/ve+/ve+/vXHvv73vv71L77+977+91rIPT++/ve+/ve+/vWolE++/vXPvv70mOHDvv70ABO+/vQAC77+977+9Qu+/vTfvv73vv73ag1AybO+/ve+/vVAxDBQARXgJFB9377+977+977+977+977+977+977+9EO+/ve+/vXXvv70NDmHvv73vv71MJyMR77+9ZFBi77+9Yh1r77+9flbvv73vv73vv70R77+9bFJS77+9NO+/vS4jXWHvv71Rau+/vR7vv73vv70Nclsu77+977+9BO+/vV3bmO+/vTNiNu+/vSchZgEIMCDho4Tvv70x77+9ajHvv71WGRLvv70BUO+/vQIA77+977+9w7dW77+977+977+977+93qvvv73vv71LdFke77+977+9E++/ve+/vQ3vv71fXSxW77+977+977+9dO+/vVNnQu+/vSLvv73vv70YWO+/vRAg77+9BEVl77+977+977+9ce+/vdGb77+977+977+977+9FH1bc2s377+9ee+/vWXvv70m77+977+9de+/ve+/vV7vv73vv73vv71F25rvv710NgAA77+9AWDvv70xAM6B77+977+92Jzvv73MmO+/vQNTa++/ve+/vSrvv70y77+977+977+9KxDvv73vv73vv73vv71RHSjciO+/ve+/ve+/ve+/ve+/vRxCcjUUA++/ve+/ve+/vQzTohrvv70/yK5l77+9ae+/vWbvv71h77+9XHnvv71vLjrvv71FdTd977+9eB4f77+9Q++/vStEKSxX77+977+977+977+9BiNICDEpByXHg++/ve+/vU0A77+9QhML77+9XO+/vWEyF++/ve+/vV0P77+9OSzvv73vv73vv73vv73vv73vv73vv71z77+9Pu+/ve+/ve+/vVPvv71nPu+/ve+/ve+/vRY1e++/ve+/ve+/ve+/vTPPuu+/ve+/ve+/vUnvv70A77+977+977+9DBDvv73vv70ELjrvv703Ne+/vU0n77+977+9fyXvv73vv71yUe+/vVvvv70l77+9XDgb77+9De+/vQvvv73vv73vv70377+977+9LBhFYBrvv71xQgDvv70M77+9TO+/vQnvv73vv70WTETvv73vv71+MO+/vVLvv73vv73vv73vv70L77+9GO+/ve+/vS/vv73vv71t77+93LEl77+97KW4IE08Jg3vv71Ezobvv70N77+9OAxUA0wjD1Bgw7MI77+90Jzvv73vv73vv73vv710DMiAM0x377+9LRrvv73vv73RtSxk77+977+977+9de+/ve+/ve+/vTHvv73vv73vv71g77+966al77+9I++/vSLvv71rLe+/ve+/ve+/vS7vv73vv70GWyLbhUhC77+9VRBf77+977+977+9cggZIAB6TCUWMTnvv73vv73vv70c77+977+9cWxM77+977+977+9b++/vdqC77+9ae+/ve+/ve+/ve+/vQ1x77+9IO+/vRAAfFx41Kzvv73DoUTvv73vv70E77+977+977+9Ae+/vSZpMmZq77+9Nu+/vV/vv73HoU1W77+9bjrvv73vv73vv73vv73vv716cEU+cAYAAAAgFDAwAe+/vQPvv71yMipM77+9AO+/vXIwFAHvv70QYO+/vQEA77+9FBTvv71p77+977+9Ojzvv70JATtfBl7vv73vv73vv71G77+9Nnzvv73vv71Q77+977+977+9de+/ve+/vWvvv70MKBQI77+9NO+/vW06zIhB77+977+977+977+977+977+9b1Pvv70y77+9Ju+/vVLvv70U77+977+977+9KForEO+/vRgR77+9dCEANG3vv71oIyzvv73vv714X++/vV4nK++/vTUa77+977+977+977+9T2zvv73vv73vv73Dp15e77+9UTDvv73vv70A77+977+977+9Ru+/ve+/ve+/vTJqae+/vSUJ77+977+9Gu+/ve+/ve+/ve+/vX/vv73vv73vv70fCzpoKh7vv70vc++/vdeb77+977+977+9XO+/vQAAMu6YsD0fL++/vR/vv706BhXvv73vv73vv70OAO+/vQFB77+977+9KxFd77+977+9PDoOAEnvv73vv73vv73vv73vv73vv70T77+977+9Se+/vShO77+977+977+977+9Le+/ve+/ve+/vQ/vv70OYVANGmVI77+9D++/vTHvv73vv70rZO+/vUnvv71g77+977+977+9Ae+/vWQr77+9HXfvv73vv73vv71377+977+9Wu+/ve+/ve+/vXrvv73aue+/ve+/ve+/ve+/vWltbO+/vQEYCAQg77+977+977+9WUp8Lu+/vRXvv70QByJYehbvv73vv73vv71SOO+/ve+/ve+/vXHvv73vv73vv73vv70X77+9Hjvvv70saz7vv73Gqe+/ve+/vUjvv71+77+9FiLvv73vv73vv73vv71O0bQgWw8RbBFTBDrvv73vv73vv70977+9TO+/ve+/vWzvv73vv70Z77+9ZXPvv71n77+9Xz9vJTdt77+9Ixsh77+9EEVZdwzvv71S77+9Ee+/ve+/vUHvv73vv71IFxgfA++/ve+/ve+/ve+/ve+/vQTvv70QPe+/vXIL77+9QF3vv70IEA4c77+977+9NAXvv73vv73vv70YAe+/ve+/vUAZZkvvv71x77+9PDLvv71q77+977+9UteA77+9Umbvv73vv71F77+977+977+9Qu+/vSnvv70k77+9Be+/vX9eeO+/vWrvv73vv73vv70kFS85bD3vv73vv73Xku+/vUHvv70T77+977+977+9de+/vRfvv73vv73vv73vv71I77+9XhwEQkLbr++/ve+/ve+/ve+/ve+/ve+/vX0TN++/ve+/ve+/ve+/vX57be+/vdC977+977+9CQsWHhfvv70277+977+9FNCTDkJ477+9EO+/vQRB77+9aW1577+9DE7vv71477+977+977+9QRt777+9de+/ve+/ve+/ve+/vVIw77+9Bu+/vWx/Le+/ve+/ve+/vQAABGAAAO+/vQbSiu+/vUnvv73vv71p77+977+977+977+9AO+/ve+/vWNgOO+/vW4rbh5lD0zvv70AQwfvv73vv70t77+977+9L3Lvv73vv73vv73vv70WAO+/ve+/ve+/vT3vv73vv73vv73vv73vv70o77+9Me+/vR5877+9Nz1qWu+/vUon77+9woTvv73vv71k77+9dChsFBDvv73QjTXvv73vv73vv70j77+9Az/vv73vv73vv719HQfRuiDvv70w77+9He+/vUDvv73vv73vv73vv71O77+9Y3Lvv71+dlcG77+9OO+/vQcEQdCw77+9Y++/ve+/vTs377+977+9aO+/ve+/ve+/ve+/ve+/vU7vv71PYu+/ve+/vVDvv71LJ++/vTsS77+9RQnvv70077+9GDBY77+977+9ZXHvv73vv71wJkTvv73vv73vv70zNO+/vVLvv71177+9UWLvv71N7rCQYO+/vW7vv73vv73vv70j77+9AgAQAgIh77+9IBvvv71g77+9Ce+/vXBuZu+/ve+/ve+/veaQrzte77+977+9AGZA77+9YwVLYxDvv70SYlNSAENvF1J0TQ3vv718Xgfvv70r77+977+9O2rvv71qXXLvv73vv73vv73vv71577+9P++/ve+/vSDvv70C77+9SzYtRA0CPhgX77+9OgPvv73vv73QmNCaUwjvv71+77+977+977+977+977+977+9Ne+/vUXvv73vv71eNxLvv70677+9RmhK77+9VO+/vWlFcO+/vRLUre+/ve+/ve+/ve+/vT9p77+977+977+9d++/ve+/vTNp77+977+9Y++/vU8dR++/ve+/vTIRPSnvv73vv73ui49W77+9Re+/vTLvv71n77+9T++/ve+/vX7vv73vv71+77+977+977+97Z+XNW7vv73vv73ItWvvv70JbUHvv70KIRhC77+977+9R++/vRVS77+977+9He+/vVzvv73vv73Uq1bvv71bDu+/vQBiUABdKA4w77+9fO+/vUxhYsmIQe+/vWxUJENx77+977+9FBYk77+9FFHvv73IgTN9ae+/ve+/ve+/ve+/vRLvv73vv715bT8OZe+/ve+/vQstZ++/ve+/vSXvv717fgTvv71x77+9F17vv71k77+9QO+/vSvvv73vv73GiAXvv70xWinsn5Xvv71nfu+/vWHvv71M77+9CO+/vX3vv70SzKDvv70wMO+/vQceOAJxBBjvv71Z77+9WHZY77+9OQLvv73vv711He+/vVVWJxIlDO+/vTDvv70k77+977+9Vu+/ve+/ve+/ve+/ve+/ve+/vd6tPn/vv71z77+977+9P++/ve+/vSFc77+9MgHQkj0h77+977+977+977+977+977+9CjYLI9iaaGzvv70LJUPvv73vv73bvnPvv716dtWk77+9ZWxF77+977+977+977+977+9be+/vV7vv73vv71a77+977+977+977+9Eu+/ve+/vXzvv73WlAAnBwDvv70BAhHvv70977+9MRgI77+9GmZxMe+/vQDLve+/vQcAIe+/ve+/vQB077+977+9eO+/ve+/vV5Kbe+/vWPvv71UVe+/vSRQ77+9Ju+/ve+/ve+/ve+/ve+/ve+/vUzvv73QojPvv73vv70MfO+/vWYA77+9WFA477+9BFFZ77+977+977+977+9HgHvv73Uqe+/vQkF77+977+9LDsgZRDvv71F77+9VO+/vQBs77+9EB1jIu+/ve+/ve+/vU1SRO+/ve+/ve+/vXfvv73vv73vv73vv73vv73vv73vv73vv73vv73vv71z77+90ozvv71I77+977+977+9YRAMRg4qKQRCRceQ77+977+977+9bAwJBO+/vQhV77+9F1Hvv73vv73vv73vv73vv73vv73vv701FkRl77+9RAvvv73vv712Be+/ve+/ve+/ve+/ve+/vT5t77+9Tu+/ve+/vXR477+9QAAFJCHvv73vv70WKjAZ77+9KBjvv70KIe+/ve+/vWhnQCjvv73vv70gMgBB77+9W++/vUAQXO+/vWojLO+/vVMO77+977+977+977+977+9Fe+/ve+/vW1jPO+/ve+/vW/vv70m77+9J23vv70l77+977+977+977+977+90qwszq1JY++/vSoSExfSnzx8OQYx77+9M++/vSbvv73vv70YQe+/vRxg77+977+977+9YBho77+977+977+9Je+/vS/KtCTvv70g77+9fe+/ve+/ve+/ve+/ve+/vRct77+977+9JiBl77+9Tu+/vWId77+9T0vvv70yPO+/ve+/vR/vv73vv73vv71C77+977+977+977+9Ve+/vRw+STYwEELvv71YUSgbS0jvv73vv71KJCTvv73lhIAc77+9OO+/vT4XCO+/ve+/ve+/ve+/ve+/vWZt77+977+977+977+977+9zqtj77+9GO+/ve+/vcmycRPvv71Y77+9B++/vQnvv71GPSQAAQ7vv73vv73vv73vv70BQEAwGGUc77+9ZO+/vS4GA++/ve+/ve+/vWTvv73vv70HEwTvv71E77+9THLvv71cChICJ3jvv70PNe+/vWDvv70b77+977+9MCl977+9He+/ve+/ve+/ve+/vTJk77+9bgoCYe+/ve+/vRFh77+9THRT77+9QO+/vQwMSmTvv73vv73vv71u77+977+9AQJHxI0xAO+/vQUZAEjvv70kCQse77+977+9T++/vQDvv73vv71Hy4bvv73vv70YYAbvv71O77+9Ze+/vXR0EzHvv73vv70877+977+9Pu+/ve+/ve+/vVrvv73vv71SDu+/vXHvv71zcRDvv73vv70nPm0QGAIARG0qYO+/vUU6QEp/UO+/vUJY77+9Skrvv73vv70/77+977+977+9wpjvv73vv73vv73vv71TDXbvv73vv71A77+9EXjvv71i77+9A++/ve+/vQDvv70BXe+/ve+/vRYD77+9K++/vWzvv71Y77+9GWnvv70A77+9EG8v77+9WQgFL0xeICguH++/vXjvv70UYzzvv71S77+977+977+977+9Fe+/ve+/ve+/ve+/vTsOaW/vv73vv70rZ++/ve+/vSMQ77+977+9Ye+/ve+/ve+/ve+/ve+/vWLvv73vv71gACPvv71SMu+/vQ1AUioGGO+/ve+/ve+/vRjvv70fIAREbO+/ve+/vTDvv71AIe+/vQxHyIAoUXEUEO+/vRLvv71cZe+/vVYRfu+/ve+/vRjvv73vv70WBgQ8GWJGJXMR77+9XT02Oe+/ve+/vR1877+9ITQhYe+/ve+/vXo377+9L2pzTQTvv73vv71G77+977+977+9AO+/vWDvv73vv73vv73UqD0P77+9ZO+/vUkyNWom77+9XO+/ve+/ve+/vX/vv73vv73vv70b77+9OTs7RcySayHvv71977+9cmIn77+9Ve+/ve+/vX1677+9AAAC77+9AO+/vUDvv70mKjxnXe+/vXIoFQEZBjDToO+/vTbvv73vv70w77+9Igjvv706ZO+/vWQdOXXvv73vv73vv73vv71rMu+/ve+/ve+/vU47TF3vv70877+9VHDvv70E77+9BAzvv70o77+9Se+/vWDvv71c77+9BsyIGO+/vUDvv70i77+9Ju+/vTAwCXpgOTjYonzvv70C77+9DQEVWO+/vULvv71g77+977+9SE/vv71zUBjvv73vv73vv715TVjvv71j77+9c++/vXnvv73vv73vv71bIEAcZe+/ve+/ve+/vSvvv73vv71GEQkRQWg+dSrvv71k77+9Ce+/vSbvv71HMWTvv73vv73vv73vv73vv73vv73vv73Wg++/vduscTXvv73vv71wNHgr77+9ClDvv71U77+9AO+/vUQAAFww77+9K++/vSzvv718T0Pvv70OGWwMBDnvv71+77+977+9eQsl1LHvv73vv73vv71dSu+/ve+/vSvvv73vv70577+9OnF7FCglVnHvv73vv73vv73vv73vv73vv73vv70cAO+/ve+/vVtB77+977+9D8K977+9J++/ve+/vQvvv70o77+9IQwRRHMT77+977+9EgVA77+9Ye+/ve+/vUh3We+/vUQY77+977+9KBg4Ju+/ve+/veG4mzVc77+9DWbvv70BNBBpW++/vVlE77+977+9Gu+/vWsd77+9X++/ve+/vcOIZyDvv70C77+977+977+9DQPvv73vv71K77+9Yu+/vXjvv73vv71i77+9cg/vv73vv70PJe+/vUY8QhHvv73vv71/77+977+977+977+977+977+977+977+9Y1/vv73vv73vv701Jzbvv712CUMU77+9IGAmAO+/ve+/ve+/vUoJCg8MKQtH77+977+977+9HAvHoFfvv73vv70WIEPvv73vv71H77+977+9K++/vSl2bh52ZzUA77+9aiPvv70bEe+/vQoj77+977+9dhsG77+977+977+977+93agX77+977+9YQIhAl/vv71oFu+/ve+/vWkpVTLvv73vv71R77+9VO+/vS/vv70v77+9bu+/vVzvv70p77+9JO+/vVbvv71h77+9Au+/vRQ/77+9V++/vdOfSe+/ve+/vUPvv70z77+9XTpyyZth77+9TVfvv71y77+9Zmnvv71USDUR77+977+9YO+/vTcbP2Xvv71M77+977+9YWPvv73vv73vv71z77+977+9aH7vv71S77+9Uu+/ve+/ve+/ve+/ve+/ve+/ve+/vSAq77+9Au+/vUAAADhhCO+/vXF9TG0077+9bwbvv73vv71LB2Xvv70b77+977+9SEPvv73vv71iIO+/ve+/vWvvv73vv73vv71X77+9K++/vSQ777+9Xe+/ve+/vVJ477+977+977+977+9Be+/vTjDsO+/ve+/ve+/vVXvv73vv712Ze+/vSw0OO+/vVTvv70cy6/vv71V77+977+9S++/vTgL77+977+977+9NALvv73vv71EZW/vv70PTO+/vX5nazMr77+977+977+977+9NO+/ve+/ve+/vXdB77+977+9Wwpx77+977+9Ze+/vQ9h77+9S0Jqd0Tvv71V77+977+92ZZd77+977+9Vz7vv71K77+977+977+977+9bSZO77+9ejQlyqV677+977+9Z37vv70877+9PNy7Gnbvv73vv73Usu+/ve+/vSlVRO+/vRPvv71A77+9TO+/vWQCDu+/ve+/vWx0SO+/vSNNaAAwNDAs77+9Bu+/ve+/ve+/vemXs++/vXoMCu+/vcal77+9anNaeGXvv71JVO+/vXdg77+91YkxJx/LgmAAau+/vSFf77+9Je+/vUkWfO+/vRjvv71fWFjvv73vv707LO+/vRVvJEJw77+977+9UGhMEe+/vSTvv70qaDpy77+9GzR677+977+9zqrvv73vv73vv70xZO+/vU7vv73vv71F77+9ezUNQtyh77+9HQ/vv73vv71YHu+/vQjvv73vv73vv71cTXPvv70pNn8v77+9Iu+/vXDvv73vv70e77+977+977+9YWHvv70177+977+977+9ACAAA33vv73vv70l77+977+9au+/ve+/vWYUYCBgUSDvv73vv70yXClqQijvv73vv73vv73dt++/vSdiSQ1A77+977+9KlkNLO+/ve+/vXRc77+9cO+/vRQR77+9FkTvv70377+9HWvvv73vv73vv70QAMqqQ++/vT/vv73vv70177+9Q++/vTnvv709T2wzLe+/ve+/ve+/ve+/vUrvv73vv73vv701H++/ve+/vW5vWWXvv73vv73vv71/77+9Ye+/vXMe77+977+9N++/ve+/vX43cO+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vTVablBb77+9RNClE0zlsr3vv71M77+977+9LGnvv71H77+977+977+977+977+977+977+9Wg7vv70AAAAB77+977+9R++/vTjvv71BB++/vXMY77+9bHLvv73vv73vv73vv71aABQk77+9JxXvv70ADO+/ve+/vSLvv70577+9AO+/ve+/ve+/vQfvv70BAQ7vv70MVgcx77+977+9DCIxeBDvv70OUEIYBO+/vWANIVZldu+/ve+/vQjvv73vv718WgBY77+977+9Ru+/ve+/vQnvv73vv70AcO+/ve+/vSPvv73Euizvv73vv705MV7MsO+/vQkjCGAMeO+/vQo0Iu+/vUpM77+9Q0oI77+9HVzvv70cOO+/ve+/ve+/ve+/vVQg77+9EEAi77+977+9AQTvv71HOciySQ8DXGrvv73vv73vv73vv73vv71IKHnvv70oEHDvv70MMu+/vQcB77+9ACMA77+977+9HXDvv711ABJHKO+/ve+/vU1iPDh5Re+/ve+/vVlc77+9TUfvv70i77+9Ne+/ve+/ve+/vciX77+977+9JiIQ77+9FO+/vUDvv716du+/ve+/ve+/ve+/ve+/vTbvv70AF++/ve+/vTDvv71e77+9S++/vSMd2Znvv73vv71IHldT77+977+9Uj1NQe+/vW0gORPvv70r77+977+977+977+977+9LFVjXBHvv73vv70O77+9Xybvv73vv70dS++/ve+/ve+/ve+/vRTvv73Ys0/vv73vv70kOO+/vWVz77+9flxt77+9aO+/vRzvv71d77+977+9T8Wz77+977+9L++/vQfvv705De+/ve+/vWDvv73vv70kBAADAAAA77+9AVlmAu+/vREYbmYGVVPvv71sRDHvv70aTO+/vTLvv71gJO+/ve+/vQvvv70ccBhGbTI077+9IO+/ve+/ve+/ve+/vVXvv73vv71577+9eB02Hu+/ve+/ve+/vX3vv71E77+9Tu+/ve+/ve+/ve+/vS9s77+9akHvv70177+977+9Bu+/ve+/vVLvv71477+977+9Eu+/ve+/ve+/vW3vv71dDO+/vQbvv70677+977+9Ye+/ve+/vUBm77+9DO+/ve+/ve+/ve+/ve+/vTgAJDHvv705ee+/ve+/vQMF77+977+9e++/ve+/vQFbZBAaY++/ve+/vSrvv71BYxrvv70WBg7vv73vv73vv70OGTpISVZAw4Dvv70rcu+/vWHvv73vv73vv73vv70077+9Le+/vdWnPe+/vQvvv73vv70ZKe+/vS7vv70sSSjvv70E77+977+9BhV177+9GkDvv70abkDvv70N77+9ae+/vT3vv71iDXLvv70377+9cFvvv71cAu+/ve+/vUUs77+977+977+9Fe+/vQQGRO+/ve+/ve+/vQIUcAIJ77+9KAg577+9Cgbvv71B0bXvv73vv71FH3Z3J++/vUUpHXnvv70f77+9MHfvv71+Jy0S77+9Xe+/vQbvv70X77+9ChE9TV9bY0Xvv73vv70eLe+/vTXvv70K77+977+9Su+/vRPvv73vv70pNBl977+9NXfvv71GY++/vQABZCbvv73vv73vv71hTlNad++/ve+/vSlk77+9Au+/ve+/vTpsGO+/vVjvv71C77+977+977+977+9Wu+/vcW+77+937/vv71tPe+/ve+/vWJYd++/vX/vv71+77+977+9azDvv70R77+977+9F9yQbsa877+9cWLvv71/77+977+977+9D1BLFjXvv73vv73vv703HisXajduUlk/He+/vc2hPmAd77+9Ge+/vU/vv73vv70e77+977+977+9Pu+/vUhbSu+/vWXvv71W77+9R++/ve+/ve+/ve+/vRcz77+9AHLvv71E77+9fO+/ve+/vXpR77+9Lk0Lal3vv71M77+977+977+977+977+9fgnYsO+/ve+/ve+/vVzvv73vv73vv73vv73vv71kw5Tvv73vv73Mq++/ve+/vU5q77+9XO+/ve+/vRnvv73vv702Kw3vv70+4K2577+977+977+9d30pAAACYe+/ve+/vUVLy5kLH++/vQHvv71ey4rvv73vv73vv73vv73vv70NAFYZf1/vv73vv73KlDErMO+/ve+/ve+/vdCN77+977+977+9Nu+/ve+/vSYw77+9cUTvv70H77+9ZRZBdHDvv71XYe+/ve+/vRTvv70x77+977+977+977+9zbnvv71Y77+9JFvvv73vv73dtm3vv73vv71G77+9Xe+/ve+/vToS77+9Au+/vTxK77+9Swnvv71SCu+/vXUqXu+/vW8Z77+977+977+977+9O++/vUJZdGnvv73vv73vv71i77+9P1As77+977+9GO+/ve+/vQla77+9W++/ve+/vc+s77+9Vu+/vVXvv73vv71y77+9OO+/ve+/ve+/ve+/ve+/vUnco0zvv73vv73vv71o163vv71vF++/vXfvv71c77+977+9T23rn4nvv71qRe+/vQsD77+9W++/ve+/ve+/vSBMSghBBBNCECwD77+977+9Qu+/ve+/vWvvv70o77+977+977+977+977+9R++/vVfvv71X77+9Pe+/ve+/vWM777+977+977+9X++/ve+/vUvvv71+Eu+/ve+/vVHvv70eP++/ve+/vURDVe+/ve+/vWPvv71TIhQm77+977+9Me+/vRZqFTrvv73vv70aS++/vQkLQu+/ve+/vVbvv73vv70lJe+/vUTGlFLvv70p2K4STyssGE9dE++/vcSjRO+/vXVE77+9cX96QmPvv71577+9fO+/ve+/ve+/vV8xK++/ve+/ve+/vTYvOO+/vRzvv73vv73vv73vv73Rsybvv71F77+977+977+9J8+I77+9fzMx77+977+977+9Ge+/vRNdEyA1F++/vUDvv70977+97ouKGGJKW0tqGu+/vcSHFu+/vWxde27vv70fVxbvv70a77+9EHHvv70677+977+977+977+9FCs+cu+/ve+/ve+/ve+/vXZ4HUxq77+9UTpncVbvv71CxJ4877+9Tu+/vVLvv73vv71iEe+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vSjvv73vv70F77+9RO+/ve+/vXXKlu+/vSbvv73Hm++/ve+/vVzvv70mCe+/vQ1zEFnvv73vv70zNMuz77+977+977+9Lyrvv73MtH7vv73vv73vv73vv707He+/vV1CSSjvv71VPO+/vULvv73vv73vv73vv73vv71577+9Wu+/vRkjQe+/vSzvv71kfQYN77+9EDPvv70q77+9eCrvv71x77+9Mmbvv73vv71R77+9Lxrvv73vv71cGO+/vVHvv70iJO+/vTYXCS7vv71A77+977+9AAATGANF77+9agcs77+977+9ae+/ve+/vRXvv71f77+977+977+9Xu+/vdas77+9EO+/ve+/ve+/ve+/ve+/vXwhKgJF77+977+977+9fe+/vXNpVu+/vSkG77+977+9Qu+/ve+/ve+/vWfvv70cKu+/vTTvv73vv70U77+9UmJK77+977+9HO+/vRoc77+977+977+9U++/vc2D77+977+977+9CiXvv73vv73Kmivvv73vv71w77+9zqZ3SO+/vTcY77+9W1Xvv73vv73vv73vv70w355Q77+9cu+/ve+/ve+/vUvvv73vv71XT++/ve+/vTM1I++/vWtR77+977+977+977+9En4rZ++/vUteX++/ve+/vcin77+9eu+/ve+/ve+/vTUIG++/vUg+djjvv71I77+9ak7vv73vv73vv71yWA/vv70zEu+/vTMAyafvv73vv70l77+977+9W29T77+92bDvv73vv71s77+9NGHvv73vv70q77+9JSPvv73vv70m77+977+9ZO+/vVII77+977+9Bgok77+9P++/vcq577+9VmLvv73vv73vv70QdCTvv73vv73vv70x77+9Se+/vTsH77+9GFBK77+9L9CDLQ8v77+9Au+/vUh3NigT4r6e77+9ZzTvv71I77+9JwxE77+977+977+9EQxNB1nvv73vv71BQF3vv702Se+/vVUQWBDvv71YUWlY77+977+977+977+9SADvv73vv71VLO+/ve+/ve+/ve+/vXgoJVHvv70977+9EO+/ve+/vUgt77+9ew3vv73vv73vv71S77+977+91qFnOO+/vSd477+9ajrvv71p77+9Yu+/vSsg77+977+977+9BO+/ve+/ve+/vdGI77+9Xe+/vU/vv73vv70bEe+/vRnvv70T77+9AwkHBAov77+9DC1W3bbvv73vv71LLe+/vUpp77+977+9bl/vv71JSO+/ve+/vRHvv73vv73vv70CMu+/ve+/vUhV77+977+9aO+/vWxWMu+/vVHvv73Egx8R77+9cRQnE2nvv71nPhpzJe+/vXjvv714fu+/ve+/vUzvv71077+977+977+9Synvv71377+977+977+9YO+/vR/vv70ZzZkUYu+/vRzvv71Kb0kO77+977+977+927RSWe+/ve+/ve+/vVbvv73vv73vv70GWFxa77+9WxXHrW8x77+977+977+977+9JO+/ve+/ve+/vQhLKmTvv70pT1ISMe+/vQnvv70uMn3vv70iUUTvv73Io++/ve+/vWIQ77+9eO+/vWzvv73vv73vv73vv73vv70477+9HO+/vVrvv73vv70+77+9e++/ve+/ve+/vTxweO+/vQZvAU7vv71/Wumuk2ItcnIZ77+9G++/vWHvv73vv70WRC1GeBQN77+9U0gS77+977+9CStUJu+/vTpkT0p9Ju+/vdKJZirvv73vv71GY++/vWfvv70See+/ve+/ve+/vUbvv70I77+9blpm77+9d3AX77+977+9Y++/vRhwW28R77+9A2rvv73vv70Y77+977+9e17vv71277+977+9T++/ve+/vQIl77+9M++/veukoe+/ve+/vWYQAAc577+9MO+/vTMBDjV977+9Me+/vUBiI++/vTBB77+977+977+9KcmUFiwkMmHvv70AIwFUc++/vW0ULO+/ve+/ve+/ve+/vWgAFDk7Ku+/ve+/ve+/vQTvv73vv70l77+9N++/vQDvv73vv73vv73IqzpjDO+/vRNGBGBhVEDvv73vv71GIFHvv73vv70I77+9WUUvQBIaOu+/ve+/vQ9M77+977+977+9HO+/vceQMmYMC++/vWrvv73vv71/HO+/ve+/vQEA77+9GAAAYe+/ve+/vWABFmQqaBBABETvv70D77+9ae+/ve+/vdu677+977+977+977+977+9eRfvv70A77+977+9GO+/vQIYZCLvv70y77+977+977+9f2d+Ru+/vQBA77+9CDBQdBxAIu+/vQcCBAlIAHBiEu+/ve+/vUHvv73vv73vv73vv73vv73vv73vv70K77+9aO+/vQPvv73vv70uw4AgIO+/vQXvv71B77+977+977+9ZENW77+9Ee+/vTFg77+9VcS0U++/ve+/ve+/vXZ177+977+977+977+977+977+977+9EO+/ve+/vW0a24/vv70Y77+977+977+9Ne+/vQAsMO+/vTsqCATvv71pQX/vv73vv73vv73vv73vv73vv73vv73vv73vv71E77+9Nw5OW++/ve+/ve+/ve+/ve+/vRTvv70nEFoHUxXvv73Lr++/vQzvv73vv73vv70T77+977+9Sm8qBCAAAAHvv71c77+9NHFp77+977+977+977+9LDLvv71i0pQEeE3vv71N1azvv70SAe+/vQMsPgHvv73vv71yFO+/ve+/vQ/vv71J77+9Be+/ve+/vWHvv70R77+9eyLvv70qEO+/ve+/vUjvv73vv70xJ01OFU1LRO+/vUjvv71uM0RYdu+/vTPvv73vv73vv73vv71uZO+/vRdrdAwdFNaJ77+9Xu+/ve+/vWpnPHHvv70v77+977+9xLps77+977+9MWY7Y++/vVQNTRR9I++/ve+/vRgW77+9Su+/ve+/vRk2bu+/vVtZ77+977+977+977+977+977+977+9RwDvv71Z77+9Qz3vv70ACu+/ve+/vSdt77+977+9Ye+/vXQ177+977+9Ve+/vUfvv73vv73Wkkrvv711F++/vWrvv73vv71sQgAgABQQ77+977+977+977+9Te+/ve+/ve+/vVN/77+9NBYiPuu0mBgqPDgQ77+977+9E2Tvv70JRznvv70G77+9HHHvv71qYO+/ve+/ve+/vUwn77+9DEty77+9W++/vQzvv70X77+977+977+9Lnrvv73vv73vv73vv73vv70DSu+/vXQddu+/vSDvv73vv71GVEQgGu+/vWAnBiIkaUbvv70e77+9Ju+/vVEL77+9Ke+/vUbvv73vv71tFe+/ve+/vTLvv70pOj8zPnvvv73JpSbvv71oQu+/vVrvv70w77+9Fe+/vWfvv73vv704bO+/vWTvv73vv73vv73vv70077+9KyjKiu+/vSMl77+9EQfvv70p77+9I3jvv70ZNVUSAAQAAkQbDu+/ve+/ve+/vUTvv70Gz5jvv71xIAIA77+977+977+9ce+/ve6RjB1bEkDkkZHvv71yRO+/vV7vv70nDO+/vQHvv73vv71dzoBE77+9LgZoKABOIe+/vQfvv70SNADvv73vv73vv70Z77+9Ou+/ve+/vXrvv70KG3wY77+9R2zvv73vv73vv73vv73vv71cORFZWu+/ve+/ve+/ve+/vUXvv71177+9eu+/ve+/ve+/vTbvv71ANjBa77+9Hu+/vUod77+9PO+/ve+/vW4777+957qp77+9fu+/vW/vv73vv73vv73vv73vv70y77+9WO+/vUjvv73vv73vv705aS7vv70AAAFA77+9bu+/ve+/vQrvv71xGgbvv70O77+9JRUDA++/vRAx77+977+977+9SBEg77+9WgkS77+977+977+9cEjvv70D77+9xIgFFgQHMe+/vQUFV0NHZCDvv70Q77+9HO+/vS3vv73vv73vv73vv73vv73vv71q77+9Eu+/ve+/vUHvv70lFMKg77+977+92bHvv73vv73vv73vv73vv71Tce+/ve+/vTty77+9XXgGEzdNWe+/vWcq77+977+9c++/ve+/ve+/vV/vv71677+9FO+/vWrvv70WMu+/vWTvv70g77+9YQ7vv73vv73vv73vv73vv70KLu+/ve+/ve+/vV/vv71w77+9bu+/vRvvv73vv71Sbe+/vUUSza0T77+9CANw0LQT77+9BO+/vXUaWUZu77+9Uu+/vUxHXO+/ve+/ve+/vcuc77+9ANe1HWrvv70AADFdSO+/vcuA77+9AVzvv70sJO+/ve+/vUA477+977+977+9WDFPIu+/vTgWEAxEAO+/ve+/vVQB77+946iUOe+/ve+/ve+/ve+/ve+/vX5u77+9J03vv73vv73vv70qUO+/ve+/vRDvv71DVkfvv73vv70CeWLvv70S77+9KxjMtkFaYe+/ve+/ve+/vV4K77+977+977+91L3vv71v77+926fvv73vv73vv702aybvv70LFu+/vWHvv73vv73vv73vv73vv70jHO+/vUYzNVXvv71l77+9Xe+/vQ8UKggH77+977+977+9IO+/vSTvv73vv70uJjDvv73vv71Qw50cWVMi77+9RDHvv73vv71g77+977+9DCrvv73vv70QSEAAGxoK77+9TG04OwJE77+9QGZWIRDvv73vv73vv71KAlvvv71AMznvv73vv70A77+9NBQA77+9Q++/vQgTBAHvv73vv71TSu+/vU4S77+9eB/vv73vv71G77+977+9UzUrFO+/vWtL77+9RTbvv70p77+9Y++/ve+/vWXvv73vv73Mnu+/vSMYDErvv73vv70TeTMge++/vWXvv73vv71G77+9KWbvv73vv71+77+977+9X++/vU/pu6nvv71M77+977+917dNee+/vTzvv71D77+9D++/ve+/ve+/ve+/vUUA77+977+977+9xJLvv73vv70tTzcO77+9wooxZu+/ve+/vRYoRA4VXDpHNDp4dO+/vVYp77+9Uu+/vVhEQEFdSO+/vWFM77+9b++/ve+/ve+/vVMA77+9NTVXRUA5Dyjvv73vv73vv70YIXTvv71IHm5geO+/vQkMCEhmJk4B77+9cu+/vVB477+9RSoR77+977+9ZMOtPe+/ve+/vT0WFgcB77+977+977+977+9bO+/ve+/vQ4GGGwAypsw77+9Be+/ve+/vUrvv73vv73vv73vv71i77+9ee+/ve+/vXjvv73vv71m77+9ZDHvv70O77+977+977+977+977+9zb9u77+977+9L3/vv73vv70NZTnvv73vv707DhMMBO+/vVnvv71O77+977+977+977+9d++/ve+/ve+/vQ7vv73vv73vv70+CO+/vT4+77+9U3dz77+977+9X++/ve+/ve+/vW0V77+977+9Z11H77+977+9f++/ve+/ve+/ve+/ve+/vX7vv71uAAACzKjvv73vv71BFO+/vTHvv73vv73vv70gADDvv73vv73vv70LyJXvv73vv73vv70h77+90IBUYWVg77+977+9THLvv70aYDtI77+9CQsALRjvv73vv73vv71m77+977+977+977+9Eu+/vRF02rRn77+977+9GzAbI++/vWMMLwbvv73Xoe+/vRDvv71j77+9AyxXdVLvv70vGe+/ve+/vXNI77+977+93ZXvv70777+9YmTvv73vv70m77+9Mu+/vRlUSO+/vWnvv73vv71977+9MVRiTCLvv71DAFMJGO+/vWYx77+9Y++/vVbvv73vv71WVu+/vVN+77+977+977+9K3Mq77+9W++/ve+/vQABCO+/vQLvv70gOe+/vUHvv70877+977+9Re+/ve+/vWDvv73vv70QMe+/vUkw77+9ES7vv71L77+9RXMbAVYcBQ/vv71HCO+/ve+/vSIAde+/ve+/ve+/vcS3ARR177+9NE4FHO+/vWYx77+9ae+/vRXvv73vv70tYRjvv71RyYXvv71N77+977+9Q++/vVrvv71BIg7vv70X77+977+9Ewjvv73vv701Ye+/ve+/vWoe77+977+9Uw4DBC5QyYhICnET77+9PR1ZSu+/ve+/vSVC77+9HO+/vUVg77+977+9chpCM++/ve+/vWRC77+977+9V3Lvv73vv73vv73vv73vv71DKu+/vQDvv70UQO+/ve+/vQ7vv70J77+977+9bwIP77+9T86HZCZDBAA9MB0EIwlA77+9NVtRc0gBFzB7BO+/vWg377+977+977+9EDgb77+977+9VgUANGQwGQDvv70AIO+/vTMyQwwhMEDvv71Z77+9KycR77+977+9Ae+/ve+/ve+/vVrvv73vv73vv73vv70ADe+/vUYC77+9AgBe77+9dhUOd++/ve+/ve+/vVPvv71yae+/vUhJ77+9X1kJQO+/ve+/ve+/vSTvv73RrgwRGRkJ77+977+977+977+977+90JDvv73vv70eGu+/vWHvv73vv70YcSHvv70PGXHvv73vv73vv73vv71YyY/vv73vv70Y77+9VmLvv73vv71077+9Su+/vXUz77+93brvv73vv73vv701He+/ve+/ve+/vXzvv71zD++/vWTKh0jvv71EGDBuCQFRWO+/vW8lE0di77+9Ve+/ve+/ve+/vTnvv73vv73vv70NQ++/vRlWAVR1DnMvFTcAEO+/ve+/vSgDQwcwJjVoUe+/vQzvv70/MDQB77+9A1EbMO+/vQXvv70QC++/ve+/vQQAHEQB77+977+977+9JAhMD++/vXFT77+9ADQYDQfvv71QGO+/ve+/vSJq77+9IGM/Me+/vVd6Yu+/ve+/vTPvv71B77+977+977+9Ju+/vQ3vv73vv73vv73vv73vv73eg++/vVEJMm7vv71P77+9Re+/ve+/ve+/ve+/ve+/ve+/vXDvv70q77+977+9QBYm77+9E++/ve+/vU3vv73vv70Y77+9Ju+/vVjvv70Z77+9QnLvv73vv71jFBgjAe+/vTolAO+/vUYsETTvv73vv70J77+977+9YBbvv71UIe+/vQkIYe+/vWVv77+9aSUX77+9c3/vv73vv73vv70l77+977+977+9fe+/ve+/ve+/vV/vv702fk0N2JsQTEMR77+9aO+/vQPvv71PAe+/ve+/vUDvv73Injd5Ph7TiO+/ve+/ve+/ve+/vTnvv73vv73vv73vv73vv73vv71L77+977+9Qu+/ve+/vULvv71gRO+/vSDvv70HGBjvv73vv73vv71ZbQsKEAAI77+9FcS0FAbvv73vv701AgDvv71G77+977+977+9K2os77+9RBnvv73vv71CNO+/ve+/vS/vv70vI++/ve+/vUrvv73vv70RBAct77+977+9aAHvv73vv73vv71F77+977+9zYbvv73vv71LSmHvv73vv73vv73vv70277+9bBQqNFQIfMWI77+9AgoRBETvv71e77+977+9YCXvv70s77+9RO+/vSMl77+9X8qjKAAYSO+/vW0/77+977+9I++/ve+/ve+/ve+/vWQ077+9R++/ve+/ve+/ve+/ve+/ve+/vTzvv70F77+9YGoUD++/vQ7vv71g77+9G++/vUHvv71Meu+/vTZjciwYcVXvv73vv70nYGEh77+9eQ9BeRQqACDvv70EQCUwQwbvv70P77+9BTjvv70X77+9DyBDMC8E77+9HCEyJgfvv73vv70NDgEiYEIeAQBADBgb77+9URAB77+9QxsQa8i077+9Mu+/ve+/vXBg77+977+977+977+9G++/vWEABiZQRVYHJe+/vRfvv73vv70J77+977+9TElf77+9agLvv70p77+977+977+977+977+9Ae+/ve+/vU8oT2lv77+9x6Tvv70d77+9Ie+/vXNtDu+/ve+/ve+/ve+/ve+/ve+/vQzvv73vv702IO+/vQgucu+/vUl2ESNi77+9Q0Hvv73vv70pAQJB77+977+9DO+/vVEAAwIA77+9HS0n77+9Me+/ve+/vR4uX9y277+9GXUN77+9P++/ve+/ve+/ve+/ve+/ve+/vRZsXk0RUQQi77+9LRcuPBstFF5NMD/vv717WO+/ve+/vWsl77+9Te+/vX/vv73Nju+/vVXvv73vv70RUk5UOu+/ve+/vQAB77+9Kx4C77+9EBfvv71fG++/ve+/ve+/ve+/ve+/vSUA77+977+977+9SRga77+977+97pOC77+9RO+/vUFQAzAXAAXvv71c77+977+9Ye+/vRDvv73vv71FJ++/vVdCaS1iDDDvv71Bfxjvv73vv70kAAky77+9C++/ve+/vWcZBO+/vTEh77+9U0N177+977+9Y8qq77+977+977+9Su+/vVjvv73vv73vv71OPu+/ve+/vU3vv71YVGpA77+9CRbfu0wPB++/vXjvv73vv71o77+9RDrvv73vv71WJu+/ve+/vRjvv73vv73vv71/Me+/ve+/ve+/vdinae+/ve+/vWFh77+9B2Tvv73vv73vv73LiO+/ve+/vXHvv70+77+93pc/PCI9Tu+/vUYxflQ477+977+977+9GyDvv70AMO+/vREO77+9yYHKoxloBAHvv70wIRgZ77+977+977+977+9Me+/vRHvv71B77+9MCIBAD0gTADvv73vv70VyoAEYBQCR++/vSrvv73vv73vv70L77+9Tu+/ve+/ve+/vQgM77+9AQAGGSHvv73vv73vv70JMmZT77+9EC0J77+977+9aknvv70KMQUOGe+/vWxdAu+/vRjvv71GKDJy77+9eu+/vUHvv73vv73vv73vv73vv73vv70Z77+9UyhPaW3vv73vv70q77+977+97KG4SSHvv70KCR5c77+977+9XBh4xYFSTu+/vXFhLO+/vVvvv70V77+977+9UTXvv73vv73QuEYGAwXvv71weDbvv70CMgIzEFFiXu+/vRANDEHvv70nU3U377+977+9YyIYHe+/vXAoMO+/ve+/ve+/ve+/vU8w77+9MO+/vQxK77+977+9ezXvv70wUu+/ve+/ve+/vWrvv73MpO+/vT9T77+977+977+977+977+9fO+/vSDvv73vv73vv71C77+977+9Egox77+9QxkARGbvv73vv70k77+9EF7vv73vv71HAFEECh3vv73vv71577+977+977+9ZCFlUQgpLiAoXxXvv70XBmvvv70DRu+/ve+/ve+/vSzvv71iTjAV77+977+9Du+/vRYI77+977+9Ggnvv71kZiRZ77+9IO+/vUUBAe+/vSolKC3vv70I77+9TwlBRTYkEdygAe+/vQJx77+9L++/ve+/vX3vv70vellAMXHvv73vv73vv71gSe+/vTcn77+977+9DGhiMXM7fe+/vR1+ckrvv71W77+9dnnvv71P77+9E++/ve+/vW5m77+9N0hFa++/vTQ+E2vvv70gQ++/vXnvv73vv70Xbu+/vVsA77+9Ikrvv70lVTl8YC3vv73vv71e77+9B++/ve+/vceyKh3vv70N77+9R++/vSkADkPvv73vv71rQu+/ve+/vSDvv71277+9Ve+/vTY8ZiPvv73vv71q77+977+977+9XO+/ve+/vUoe77+977+977+9cu+/vTnvv70I77+977+977+9de+/vQzvv71R77+977+9bCpHW2E/bnLvv70P77+9AAAABGt477+9Chjvv70MXnTvv71WxZjvv73vv73vv71xISnvv71R77+977+977+977+977+977+977+977+977+977+977+977+9USxPaQ3vv70LMicd77+9Pe+/vSIu77+977+977+9BWTvv73vv702B++/vcKtPO+/vS7vv73vv70mUyML77+977+9fe+/ve+/vdSZ77+9V++/ve+/vXBKFO+/vQtw77+9UO+/vQtBaO+/vWBHBdS+77+977+9Re+/vW3vv70+77+9QUjvv71tYRvvv70k77+9FgLvv70DUAlXMwDvv73vv73vv73vv73vv73vv718ay/vv716Yu+/vXMeS2Hvv71H77+9c++/ve+/ve+/ve+/ve+/ve+/vV7vv71V77+9bO+/ve+/vSIV77+9Wu+/ve+/ve+/ve+/ve+/ve+/vWp077+9KO+/ve+/ve+/vSV9Zjfvv70CaHsT77+977+9Xe+/vQJ+77+9OAXvv73vv71DG++/vTLvv70NIO+/ve+/ve+/ve+/ve+/ve+/ve+/vS/vv70xy7Ud77+9VC3vv70u77+9U3DZk++/vWLvv71d77+9NDkj77+9AGHvv73vv70c77+9BQ4r77+9HB0icu+/vSBWVu+/vQsM77+977+977+9AO+/vSzvv73vv73vv73vv719aXNoUO+/vTQFAe+/ve+/ve+/ve+/ve+/vRLvv73vv71wYu+/ve+/vRYC77+9FWIGBCUSIAEF77+9Ke+/vQUO77+977+9DB7vv73vv73vv71/FFVSPe+/ve+/vcWSEh4HDu+/ve+/vWTvv71DCu+/vRoA77+9CO+/ve+/ve+/vXAw77+9El/vv73vv70Q77+977+9f25NLe+/ve+/vW/vv73vv73vv73vv73vv71nGe+/vVrvv73vv71H2pJC77+977+9Ae+/vXDstI0mRFNZRWnvv71JPTdOPTPvv71x77+9X++/ve+/ve+/vRck77+9de+/ve+/vQEAAADvv704ZmsV77+9ae+/ve+/vQXvv71nYCLZv++/vUTvv71WHgUPMgbvv70WZWrvv73vv709AO+/ve+/ve+/ve+/vdWB77+9fe+/vUlN77+977+9wp/vv73vv70V77+977+9yK1M77+9AW5c77+9Iyta77+9LmI/OwJHaAzvv70U77+9XFwz77+977+977+977+977+9yZbvv73vv70i77+977+977+9VFdg77+9MEQADRXvv71G77+9ew4j77+9QX4L77+977+977+9Eu+/vU5E77+977+977+9SO+/vW7vv73vv717Y++/vc26fu+/ve+/ve+/vTZTVGrvv71xSO+/vT4cEUvvv73vv73vv73vv73vv70w77+977+977+9PFDvv71Q77+9Ue+/vVHvv73vv70lEe+/ve+/ve+/ve+/vUrvv707bO+/vSRR77+9Ce+/vRgLNH3vv71KDRgSMSYVICMTIhDvv73ahwtaIAJf77+977+977+977+9fe+/ve+/ve+/vdms77+977+977+977+977+977+977+9EADvv70j77+9Qe+/ve+/vQBQ77+94q2r77+9VcKFZ++/vTHvv70kfSLvv70DBgwLOwgLUGfvv71o77+977+9bULvv71BAkXvv73vv73vv73vv71h77+977+9Y++/vXkm77+977+9fu+/vWRGa2jvv73vv70vdMS677+977+977+977+977+9Bw4taVXvhKleahxce++/vTvvv73vv73vv73vv71BUkJzBe+/ve+/ve+/vRTvv71s77+977+977+977+9YtWsVHFi77+977+9D2hZSg7NhV4/77+977+9eV1j77+977+977+9HSV877+977+977+9AAAASu+/ve+/vQnvv70h77+9Je+/vSAa77+9NGjvv70E0KXvv71qTe+/vU3dj1lv77+977+9MUjvv70zZjkXYe+/vUMwAu+/ve+/ve+/ve+/vREWEAlQB9mJ77+977+9ae+/ve+/vQwyKAnvv71jOe+/vXHvv73vv70g77+9AmEF77+977+9A++/ve+/ve+/ve+/ve+/ve+/ve+/vQDvv73vv71rSy1g77+977+977+9aEnvv70h77+9AHgU77+977+9E03vv70wQu+/ve+/ve+/ve+/ve+/vTloTu+/vXUtMDdFS24u77+9Ilrvv73vv71MEjrvv73vv71K77+9x5UsJGZfI++/vdib77+977+9G9a277+944+paTBIMB7vv71oR++/ve+/ve+/vUs3MHFh77+9Ce+/vSNYcO+/ve+/vWHpmbvvv73vv70j77+9Ae+/vTF577+9V++/vTZ277+9e++/vXnvv73vv73vv73vv73vv71u77+9Ou+/vQtO77+977+977+9AR/vv71b77+977+9AO+/vVxR77+9Ru+/ve+/vUPvv71SHAAGAO+/ve+/ve+/vUTvv70177+977+977+977+9OiDvv73vv70177+9TBkB77+977+977+977+9Se+/ve+/ve+/ve+/vQxIUiAF77+9ARIlEgAI77+9LAxwEAkh77+9LmIUGkfvv70uCe+/vSxj77+9Ge+/vSbvv704K3rvv70K77+9O++/vQxR77+9Bu+/ve+/vQo177+9zLPTlu+/vc6rGVIaDNOJBwgoCChQ77+9aFARZxlIUChkRGrvv70m77+977+9SDbvv73vv73vv73vv73vv70LAmjvv70c77+977+9GQAAUu+/vUNRGUYq77+9SG3vv70Y77+9MUAL77+977+9bO+/ve+/vXlmCO+/vRxg77+9fO+/vRQiNyUBTO+/ve+/vUJJIO+/vTjvv700DO+/vQzimoLvv71RAwIyFDJAcRoZEABE77+977+977+9S0bvv71w2qZIBu+/vQXvv71377+977+9MDTvv70wO++/ve+/ve+/vUtiYu+/vVw177+9UO+/vXnvv73vv71xYE4h77+9Qu+/vWUk77+977+9Ve+/ve+/vXDvv709TBXvv73vv73vv73vv73vv73vv73vv70pQT0N77+977+9xrLvv71V77+977+977+9zYjvv73YnTnvv73XjO+/vW49BO+/ve+/vUbvv70sRnho77+9ce+/vXXvv73vv70H77+9Nznvv70y77+9RyIAEwVN77+9Lmnvv73Sg++/ve+/ve+/ve+/ve+/ve+/vXNe77+9Ru+/vR1477+9JWxsWO+/vX7vv71K77+9RhTvv73vv70s77+9E3Aya019PVkZ77+9BELvv73vv70/AhsGKGDvv71Y77+977+9LlTvv71IHhQcdNmjFkhnQe+/ve+/vQ7vv70Z77+977+9DgcBQ++/vQBUIQTvv712LFnvv70g77+9JUDvv71maSbvv73vv73vv73vv73vv73vv71sAu+/vUJb77+977+9S++/vTbvv707GTNE77+9RH4HdAIS7ZqMM++/ve+/vSp077+9VWYx77+9LO+/ve+/vQsS77+977+9Te+/vRfvv71SOe+/vUpG77+977+9WUUDC++/vUDvv73vv71677+9YhDvv73vv70Zfu+/ve+/ve+/vTs877+9Shvvv73vv73vv70777+9Bu+/ve+/ve+/ve+/vV8c77+9Q++/ve+/ve+/vXASKkzvv70eGl4I77+9AkNVMgIw77+9VSzvv73vv71S77+9EQhL77+9bT8jHO+/vSoJ77+9Ze+/ve+/ve+/vVkFNTzvv73vv73vv70677+977+9JO+/ve+/vQDvv70E77+9ICwE77+9ACrvv70W77+977+9OhLvv71VK1Yj77+9Ne+/vUVy77+977+9SRbvv73vv70C2Yzvv71kbO+/ve+/ve+/ve+/vXnvv73vv70c77+9N++/ve+/vQgXEcy5E1VqdO+/vTvVp++/vQcn77+9BGUlA++/ve+/ve+/vWZp77+977+9Mwvvv71077+9SVnvv70U77+9IyHvv73vv71HIu+/vTHvv71I77+977+977+9xLXvv73vv73Vj0bvv71hPMqNKyt477+9C++/vUAMSe+/vRMW77+9LBkpT3JLa++/vV0xOjvvv73vv73vv710KSvvv73vv71p77+9U++/vT/vv73vv73vv71877+9L0bvv71nVUfvv73vv71I77+9aO+/vTYfGS3vv71JaGRlAAABFTEP77+9G++/ve+/vVwd77+977+9E9mNUyrvv73vv73vv70077+977+977+9Fu+/vVzvv73vv71577+977+9bks/VFDvv70e77+9cWYj77+977+9US/vv70m77+977+9eS7vv71477+9Nu+/ve+/vRHvv71m77+9VBEo77+977+9OSfvv70T77+937kT77+9Zgfvv71t77+9Me+/vUUf77+977+9xLpfTRTvv73vv70/EO+/vS0WUO+/ve+/vWZu77+9IGJgJGzvv73vv70jIO+/vTAlMO+/vSHvv73vv73vv71kBUwX77+977+9Oe+/vXdYUlHvv73vv73vv71XNO+/ve+/vXbvv70fwp1677+9b9+iG++/vSIo77+9F++/vTt177+9WxXvv73vv73vv73vv706AARRR1Xvv73vv73vv71LXGbvv70oYnXvv71477+9M07vv70wJR3vv71FKTfvv73vv73jjrLvv7151rvvv73vv73Fp3JL77+977+9JO+/vSV677+9R1fvv70GUO+/vSV0J++/vVlhHCpY77+977+977+977+9Ghrvv71G77+9YDRU77+9A++/vXUk77+977+977+977+9Re+/vWZT77+9Ze+/ve+/ve+/ve+/ve+/ve+/vWgHVRJI77+977+977+9Uu+/vVDvv71Ofu+/vV0qEhLvv704Tn7vv70O77+92KDvv70577+9fT3vv71177+977+977+977+9E3RD77+977+9Lu+/ve+/vXbvv71z77+977+9FO+/vRvvv73vv73vv73vv73vv71WMQDvv73vv73vv73EqwDvv73vv70zV++/ve+/vTjKiO+/veu5hgvvv70AAAnvv73vv705WVDvv73vv71ScBLvv71w77+9ZVDvv713NO+/ve+/ve+/ve+/vVLvv73vv70777+977+977+977+9aO+/ve+/ve+/vS7vv71Hch4M77+977+9BnoCRe+/ve+/vQvvv71IAljvv70SEhDvv70URe+/vQLvv73vv70qQO+/vSsJKWAx77+977+9Ae+/vW7vv70Y77+977+9ae+/vXYz77+977+9JEHvv71977+977+9Cu+/vRAj77+977+9Kknvv73vv700Xu+/ve+/vT1c77+9Mhtr77+977+977+977+977+977+9Uz9R77+92ZXvv71tL1Xvv70nAgIKQO+/vXdRIwo777+9Yu+/ve+/ve+/vQ1u77+9FO+/ve+/vQvvv73vv70IXu+/vQ7vv70dOQrvv71N77+9NDsrGAAg77+9V++/ve+/ve+/ve+/vSDvv71Jcy3vv73vv70iEO+/ve+/ve+/ve+/vSrvv71h77+9dlpa77+977+977+977+9LQpaPmVW77+9PkLvv70C77+9fibvv70+77+9bVcOMA1D77+9L0gpDAPvv70o77+977+977+9ae+/vU/vv71+77+9O++/vSIY77+977+9RO+/ve+/vXV477+9ZEQr77+9ATHvv70COe+/ve+/vTtdYO+/ve+/vU7vv70QFRRND++/vUciee+/vVNOUzReeiUGTx/vv71677+9AkMACAVF77+977+9BjLvv71H77+977+9PDdr77+977+9c++/ve+/vUtx77+977+9Jkrvv70rFHrvv73vv700YyEQAAAAU1jvv73vv71FTO+/ve+/vdKGVO+/vVHvv70n77+977+9Ke+/vcOyPC7vv73vv70a77+977+9NO+/vQrvv73vv73vv71kZu+/ve+/vRnvv71fJO+/vQDvv71077+977+97Z2G77+9NO+/vXdZ77+977+977+977+9yYDvv73vv70nV8e8c8qN77+977+9OO+/vQ/vv73vv73vv73vv70J77+977+977+977+9OFdUGu+/ve+/vUXvv73vv73vv71VI++/vTUjcO+/vQUy77+977+9Ie+/vWnvv73vv70c77+9Jyvvv73RlRnvv706IkZj77+9OCXvv70LcXUYAO+/vSRJ77+9Iu+/ve+/vV9PRVJA77+977+977+9bWVyRO+/vRtYUkvvv73vv70c77+9au+/vSzvv73vv73vv70rZmjvv73vv71cZu+/vVdH77+977+977+9RO+/ve+/vTFd3L5w77+9Rm7vv706Au+/vSsu77+9Qe+/ve+/vQoqPFAMDGUBa3gIUhAi77+9zJfvv73vv70D77+977+977+9W++/ve+/vUoK77+9JRHvv715VHnvv73vv73vv73LpW7vv71uCO+/vQ3vv73vv70n77+9UEdDRO+/vSnvv73vv71OYyDvv71AQAkw77+9MFDvv70D77+9QhHvv73vv70Beu+/vWHvv73vv73vv71EcFrvv73vv71p77+9ERjvv71Z77+9CUITaEnvv71cXu+/vQc5MiDvv71W3rQr0JXvv70xENOZDjTKou+/ve+/vSMp77+977+977+9eBLvv73TpO+/vTknV1Hvv73vv71t77+9Y++/vUbvv71pVSLvv71k77+9zrLvv71877+977+9xZbvv73bte+/ve+/vTZ277+977+9PO+/ve+/vSDvv73vv712L++/vSnvv71S77+9NO+/vUg177+9Ve+/ve+/ve+/ve+/vR7vv73vv70KSgAAAAAAG++/vWBx77+9Axxm77+977+9cnBCJmYeGD4GIGbvv73vv713Ke+/ve+/vQPvv71DFHTvv73vv73vv70T77+977+9LzMA77+9WO+/vUUADO+/ve+/vVjvv70S77+9P++/vVbvv70+THUu27ASJO+/ve+/ve+/ve+/veaAmBV7Tcy8ewsR77+977+91Zfvv73vv73vv71eAO+/vRfvv73soZkv77+9IO+/ve+/vXrvv73vv73vv73vv73vv70g77+977+9MnQX77+977+977+977+9AO+/ve+/ve+/vdWZFB/vv71+77+9J2pdKe+/ve+/vR3vv70K77+977+9cikkP2JZLu+/ve+/ve+/vWLvv71h77+9ae+/vX12YUFm77+9a++/ve+/vXt+77+977+9Xyrvv73vv73vv73vv73vv73vv71677+9IQXvv71z77+9R++/vW9xd2Vh77+9MAHvv73vv71IW++/vQMe77+9EQdo77+9RO+/vQUBCO+/ve+/ve+/vVAu77+9ZO+/vcOnJk5EDgYyEDdEFEDvv71IAO+/ve+/ve+/vX0yG++/vRNCFu+/ve+/vVJpXk43FO+/vUXvv701HdSk77+9BuylvHI677+977+9LjQK77+9aO+/vTQWY++/ve+/vXwX77+9dO+/vUhF77+977+9V++/vRMA77+977+9Iu+/vVgFGhhA77+9CR4K77+9Mu+/vQsIae+/ve+/ve+/vQo077+9aWLvv71YE++/vQnvv71DT2Pvv70idO+/vSQoE++/ve+/ve+/vSMBWxDvv70q77+977+9SBNXe++/vS9V77+977+977+977+977+977+937Xvv70m77+9Kkpp77+9eB/JpUXvv73vv73vv70Scgbvv70k77+9LmXvv71RWe+/ve+/vWXvv71LOnnvv73vv73vv73vv71/77+9fU0177+9fHwm77+9dAAAUVZQSu+/vUvvv70MFRgsFUkW77+9NCnvv70RCe+/ve+/vdaPRO+/ve+/vWzvv701G++/vc6r77+92ZVN77+9PG5jW++/ve+/ve+/vUzvv71Y77+977+977+92rAw77+977+9DAzvv73vv707I++/vUbvv70j77+977+977+977+96oGYVS0/77+977+977+977+9MTDvv71J77+9LxPvv70OV++/vVjvv71Q77+9JRBr77+9EiMMLu+/vSkh77+9EWbvv73vv73vv71i77+977+977+977+977+9JO+/vQsrbzbvv73vv73vv73vv71yZBpZNiDvv71Z77+91bXvv71/77+977+977+9c++/vWLvv70jTC0V77+9cQzhp4dmBO+/vUcK77+977+9KUMIYXomCe+/ve+/ve+/ve+/ve+/vVc/NEvvv70tDcaP77+9Le+/vQXvv73vv71o77+977+9Su+/veChse+/vRLvv73SqDjvv71y77+9DyDvv73JgQcA1Irvv70iE++/vRjvv715bsWTNe+/ve+/ve+/ve+/vdOBF1bvv70c77+977+977+9DzXvv70Z77+9T++/vcqtKH7vv70QdO+/vWHvv70DRDDvv73vv73vv71fZnzvv71JOBIhGxNZH++/ve+/vSjFjDjvv70A77+9K0AhxbZVZDVD77+977+977+90q1n77+977+9a++/vVds77+977+9F0EDLEl277+977+977+9JhQeLu+/vSjvv71U77+9Ne+/ve+/ve+/vQlv77+977+914x677+9Pu+/ve+/vUEU77+9Xe+/ve+/ve+/vQYiKFVoNu+/vTnvv73vv73vv73vv70J77+9Ln0q77+9Ye+/ve+/vQjjhpsAAAgVdu+/ve+/vU3vv70FHe+/ve+/vRQGIEPvv73vv70BBe+/vRxc77+94oqB77+9B1JWTO+/vQPvv73vv71U77+977+9Ne+/ve+/vV3vv73vv71UBMieOBwrXwwF77+977+9R3Up77+977+977+9Y++/ve+/vXIMImDvv70jUlzJkS1Q77+977+9FEl1ITk177+977+9Ie+/vVnvv70I77+977+9Fu+/ve+/ve+/ve+/vQnvv70O77+9Wu+/ve+/ve+/ve+/ve+/vemDle+/ve+/vURtJRxa77+977+9De+/vSXvv73vv71U77+9REPvv70KPC5LDQvvv73vv73Up1Hvv73vv71bPVhTPz95G++/ve+/vRXvv70j77+977+9QXYic++/ve+/vRk/77+9fu+/vW3vv73vv73vv73vv73vv73vv73vv73vv70mL2Hvv70jRe+/vRYP77+977+977+944yyUz0eyaPvv711DO+/ve+/ve+/vVvvv71N77+977+92Kcn77+9Yu+/ve+/vXTvv73vv73vv713bO+/vWsRJF7vv71wQe+/ve+/vSPImmhWZgZJ77+977+977+9Oh/vv70W77+9Ie+/ve+/ve+/ve+/vToYAQYC77+9Ku+/vU1gSFEkw4Bx77+9NX9X77+9wqRZ77+977+9CzhC77+9BAkD77+977+977+977+9bVwgd++/ve+/vUhpIlsnOWhf77+9AyFW77+9Gu+/vSrvv73vv73vv73vv70ES2Xvv73vv70u77+9FO+/vXkv77+9KO+/vVXvv73vv73vv73vv73vv701ZO+/vRPvv70e77+9NXMOYz3vv70fE1YJQlHvv70MWO+/ve+/ve+/vRJEVxM877+9NHTvv71r77+977+9Wu+/vRcu77+977+977+977+915l777+977+9368X77+9R+WTlQoXEu+/ve+/vUh6a25aFwjHrO+/vWcXW++/vWzvv73vv73Wsu+/ve+/vV3vv73vv70KXe+/vd2J77+977+9AADvv70AACHvv73vv70l77+977+9TMWk77+977+9UO+/ve+/vULvv70cE++/vURW77+9E0IAIQAlUAIAQ++/ve+/vUBsBu+/vUrvv71077+977+9Nmrvv73Ohh5Ga19R77+977+9RDzvv73vv71/2K3vv70C77+9ZErvv73vv70Q77+977+9S++/vQXvv73Rme+/ve+/ve+/ve+/ve+/ve+/vQPvv73RgTJuZe+/ve+/vSor77+977+977+9Me+/ve+/vcKbOlIt77+9aHxO77+977+977+9U++/ve+/vQjvv701Kx/vv70477+9GO+/vVU9VO+/ve+/ve+/ve+/vUXvv73vv73ErO+/ve+/ve+/vUoj77+977+9b++/vVfvv73vv71I77+977+977+9asWM77+9M++/ve+/ve+/vdudN++/ve+/ve+/ve+/vWQOJVbvv70cDO+/ve+/vVs3UO+/ve+/vSZUMR3vv71P77+9Sm9u77+977+977+9Hu+/vduC77+9We+/ve+/vSkLM2R0GO+/vUVAExDvv71wVkxkR++/vWc477+9Y1nvv713EBnvv73vv73vv71jJhc577+9Iu+/vRkCce+/vdKMIHULQFJVWe+/ve+/vWck77+9cwDvv73IhO+/ve+/vX5GBA0E77+977+977+977+9L++/vTLvv73vv71w77+9CO+/vdiK1IhU77+9Fl3vv73vv71UCO+/ve+/ve+/vUTvv73vv71h77+9CC9SQzQyQUPvv71RTGHvv73vv73vv717OnAS77+9Lu+/vUoy77+9O1cLU++/vTsX77+9Ne+/vVsYWO+/vRvvv71qZtyjW++/vRnvv71qZjVB77+93rXvv70n77+977+977+977+9e3st77+9VW/vv710ZTJ877+9KCHvv73vv71qfikn77+977+936lrG3NUdSXvv73vv73vv707Ysei77+9FO+/vSvvv73vv71rAADvv70AACDvv73vv71hQ++/vVHDmO+/vUMaYBwYWmLvv70Z77+9AgdCQO+/ve+/ve+/ve+/vQDvv73vv73vv71QYkxg77+9MQFg77+977+9BD7vv70fVnESV2F877+9bR0gEO+/ve+/ve+/vRTvv71hLu+/ve+/ve+/ve+/vVfvv73vv71MRO+/vSzvv73vv70477+977+977+977+977+9Au+/vTVrKU7vv73vv70d77+977+9Re+/vWTvv71u77+977+9Whx277+9Blbvv73vv70WXMWU77+9YCbvv70hdtui77+977+977+9CSo977+9H++/ve+/ve+/vQw877+9bu+/ve+/vTPvv73vv73vv73vv73vv73vv70n77+977+9GO+/ve+/vSwvEe+/ve+/vSzvv73vv73vv73vv73vv73vv73vv71q77+977+9Gu+/vSBfaO+/vRYt77+9WO+/vWnvv71o77+9HO+/ve+/ve+/vWsSP++/ve+/ve+/ve+/ve+/vTfvv71PW0bzlKK5bxBT77+977+977+9ARpZ77+9S0nvv70jGe+/vWrvv73vv70A77+977+977+9WDQPMARcDAYS77+977+9DO+/vUnvv706EO+/vdKoWQYK77+9Yu+/vR0jFX7vv70KUu+/vQgGDQBGEO+/vUHvv73vv70wBUIw77+9BO+/vRAC77+977+977+9Y31cZu+/ve+/vQDvv70NZe+/vRDvv73vv73vv71m77+977+9Ju+/vSxKBe+/vWjvv70AAcOAFAc977+9BO+/ve+/vS3vv70077+977+9JUUd77+9JXwM77+9Qu+/vWDvv70MFu+/ve+/vdq1O++/vVPvv70u77+977+977+977+977+977+9MO+/ve+/ve+/vVfZtBtJbH/vv71w77+9Wu+/vXBjOkfvv73vv71R77+977+9WNyr77+977+9UFAKLmEWQys/77+9P++/ve+/ve+/ve+/vV02KlXvv73vv71tRe+/vQzvv70AWio577+9A2Lvv73vv70mVS4BxKFCWe+/vQHvv71QMO+/vSXvv73vv73vv713JjsJBQIb77+977+977+9bO+/vVgNSO+/vd+rTu+/vc6ABCrvv70ZHBbvv71IQe+/ve+/vVzvv71mejs877+9CA5s77+977+9Qe+/ve+/vXkg77+9eO+/ve+/ve+/ve+/ve+/vQLvv715XSdO77+977+977+9LTFk77+915fvv73vv73vv71AMx0ea++/ve+/vUoy77+977+9BAo7HR/vv73vv70sPO+/vWls77+9du+/vQYJ77+977+9Klzvv70Kak7RvO+/vS0r77+977+9Qy7vv73vv73vv70h77+9Xg7vv71wVC4kPkY177+977+977+9cu+/vc2NTe+/ve+/vUTvv73vv73vv70fHO+/ve+/ve+/ve+/vU3vv70v77+9MQfvv70V77+9cQBMAgDvv73vv70FHO+/vStB77+977+9XF/vv73vv712Re+/vWPvv70D77+9MBhkKEQqARdU77+9Au+/vQt6ae+/ve+/vQnvv71IURwoVSJeVWrvv71b77+9bQIA77+934Am77+9ECDvv73vv73vv73vv71Y77+9EGli77+9VVoa77+9VmZM77+9MlgkNu+/vc6EXiDvv73vv73vv73vv705Pu+/vQwiAmTvv73vv73vv70w77+977+9JO+/ve+/ve+/ve+/vS3vv73vv73vv73vv70iAlV477+977+9Lu+/ve+/vX/vv70177+9c++/vTlQUu+/ve+/vVrCtS7vv73vv73vv73vv71J77+9a++/ve+/ve+/ve+/vX8677+9Xu+/vR4W77+977+977+977+9Yk7vv73vv71lT++/vXED77+9Alzvv73vv71w77+9OO+/ve+/vTVDbu+/ve+/vU5fE++/vWrvv70r77+9HO+/ve+/vRlf77+977+977+9NQNF77+9PO+/vQoiQe+/vQAwQAAKIlIQSEFP77+977+9blLvv70SUBgOIhgyNe+/vQBDDgDvv73vv73vv70Vce+/vSBK77+9CwIr77+9ZAhEdWXvv70777+977+925tI77+9KAYB77+977+977+977+9XXYD77+977+9NdKycmzIqe+/ve+/vRI677+9YhTvv73vv71s77+977+9Ru+/ve+/ve+/ve+/ve+/vQAV77+9dTDvv709dO+/vV3vv73vv73vv73vv73vv71S77+9aQsece+/ve+/vdC177+977+977+9Te+/ve+/vRbvv73vv70/SycNPu+/vXIbJilPN14477+9TO+/ve+/vc6u77+977+977+9O33vv73vv73vv70nB++/vUHvv70T77+977+9PBFB77+977+977+9U3Pvv73vv70477+9Ju+/ve+/vVBsa++/vSfvv73vv73vv73vv73vv71m77+977+977+9cu+/vSvvv73Slu+/ve+/vVV0EAADRO+/vSQLGVV877+977+977+977+9CAkZTgIYAjsZKi4YLgYZdCMh77+9Qu+/vTDvv70077+9Ge+/vU7vv73vv70Gee+/ve+/vU8LSe+/vT9u77+9WDLvv71AKwxr77+9AO+/ve+/vXYnZe+/ve+/vU1ZOyJ977+977+977+9FMSjfxEPT++/vQzvv73vv73vv71PRyBL0q3vv73vv73vv73vv73vv73Tie+/vUY+Vu+/vW3vv73vv73Grnjvt7A277+977+9XGlR77+9Iu+/ve+/vTFb77+9eBTvv73vv70Q77+977+9eO+/ve+/vVh9DnkaJ++/vWzvv73vv73Rsu+/vTRg77+9D0nvv70+Me+/ve+/vXst77+9WR9H77+9GVLvv71277+977+977+977+9MO+/ve+/vX7vv71a3rB+Pmvvv70KS++/vWt577+977+9bF4tMQfvv70477+9zLxr77+9BAAAEg4f77+977+9Snfvv73vv73vv71QZ1sD77+977+9agJQ77+977+9ICHvv73vv70q77+9TAoFAgEMIAUdAALvv73vv73vv73vv70N77+9We+/ve+/ve+/vWjvv71877+977+977+977+977+977+9Eu+/vSzvv73vv70IclPvv73vv71TWUvvv70E77+9Ym7vv73vv71l77+977+977+977+977+977+977+977+9UXXvv73vv73vv73vv73vv70AFu+/vX0pTu+/vXTvv71RMO+/vR3cvO+/vVMZG++/ve+/vU9L77+977+9RFXvv70oM++/ve+/vWEy77+9FO+/ve+/ve+/ve+/vVTvv71jVta677+977+977+977+9Yu+/ve+/vXIGbO+/vQ/vv73vv71VKu+/ve+/ve+/vUxmLz5O77+9cu+/vQfvv70Peu+/vRRw77+9Ew0977+9Uu+/ve+/ve+/ve+/vXwJ77+9IytHJu+/vUrvv73vv70XIe+/vUnvv73vv70z77+9F++/ve+/vUU0cu+/ve+/ve+/vX/vv73vv73vv73vv73vv70gPmrvv703aO+/vVpy77+9f2fvv73vv73vv73vv70OcAACAO+/vSoDCErvv73vv73vv73vv73vv73vv73vv70MIO+/ve+/vUnvv73vv71IdO+/ve+/vSQyDO+/ve+/vQLvv73vv71IMEgM77+9D++/ve+/ve+/vUwSA++/ve+/ve+/ve+/ve+/vcWoQgkOG++/vXBIASLvv70MXgkJAO+/ve+/vQQNA++/ve+/vSAEO3Ms77+9ACYhFe+/vRQkYO+/vUnvv73vv71p77+9QAUw77+9HO+/vQHvv70hau+/vQbvv73vv73vv73vv70RBu+/ve+/vQkQ77+977+9HkgEZQYLE++/vUBAUHgoGO+/vQRg77+9Ee+/vUFF77+9NCzvv70ECzM4eN2LI2jvv73vv73vv73vv70x77+9TO+/ve+/vXN777+9TVzvv70y77+94puj77+9Iww0OzJh77+9zINCQAsf77+977+977+977+9LUnvv73dne+/ve+/vTrvv73Lku+/vXzvv70435Xvv73vv70rWF3vv73vv70O77+977+977+9QzHvv71N77+9DB0b77+9T0fvv71i77+9I++/vRnvv71a77+977+977+9Vu+/ve+/ve+/vX42a++/vTsT77+9LWFnLDdfLuu7uU3vv73vv71sZ++/ve+/ve+/ve+/ve+/vQAa77+9FO+/vWHvv73vv71+Me+/ve+/ve+/vQFjf2rvv73vv71rDHPvv73vv715cu+/ve+/ve+/vWAQEAIBAAAgAAgAERXvv71f77+9CBQA77+977+9QO+/vTIG77+977+9AhJKBmYoDzARGSHdlu+/vQzvv705EDjvv73vv73vv73vv73vv73vv70bKWvvv73vv71H77+977+9Ye+/vSLvv73vv73vv70A77+977+9AkMAcnVvThjvv73vv73vv73vv709de+/vUgVXe+/vQ0lAFxS77+9VO+/vUvvv71hQO+/vRRc77+9BDDvv70RJu+/ve+/vQchW++/ve+/vUDvv70ZAe+/vQbvv73vv70G77+9EO+/vVLvv71L77+977+9DO+/vQZEC++/vRRWOO+/ve+/ve+/vRHvv70xARnvv73vv73vv704RGARAEBA77+9EjTvv70M77+9IQAFH38a77+9CO+/vS5GSSzvv73vv70a77+9Y++/ve+/vUPvv71BBgjvv73vv70G77+977+977+977+977+977+9EhARFFZm77+9ABnvv70hQUDvv73vv71hMe+/vX/vv73vv71u77+977+977+9Je+/ve+/ve+/ve+/vT5TSCVP77+9O++/vSly77+977+9KhTvv73vv70c77+9QQ9h77+9EO+/ve+/ve+/ve+/vWwhA++/vVzvv71b77+9Yu+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vXHvv73vv73vv70M77+977+977+977+9w6ki77+977+9WFoNHe+/ve+/vQpfTu+/ve+/vVjMnWvvv73vv70hy6Lvv73vv73vv73vv71GAgASAEB6P++/ve+/ve+/vWgYCO+/vUQC77+9EXTvv73vv73vv71IIcOz77+9bWFa77+977+977+977+9Yu+/vRd377+977+9DDd377+9V1Lvv73vv71y77+9WWXvv73vv71LPe+/vWLvv71u77+9OO+/ve+/ve+/ve+/vcS/ACfvv73vv70977+977+9AANjMWnTme+/vQBp77+9OO+/vT5KGUPvv73vv73vv73vv71NNDEJRe+/vQEIae+/vRUc77+9au+/vRLvv71U07E5VB1277+977+9ABnvv73vv73vv73vv70N77+9OFAS77+9KVJx77+977+9BgNcMe+/vR0w77+977+977+9NO+/vXrvv70i77+9Ymnvv70/OUUfJu+/ve+/vSRM77+9Tu+/vVvvv73vv71B77+977+9CTzvv71dVydmOu+/vWXvv70y77+9RiLvv70ZYwHcldetJe+/vXPvv73vv71a77+9Yu+/ve+/ve+/ve+/vVfvv73vv70r3rvvv73vv73vv73vv73vv70z77+9V03csM6l77+9BO+/ve+/vWTvv70oB1EsVhdy77+9YDnvv71MJNq1Uu+/ve+/ve+/vduZ2pnvv71dz5tK77+9Ye+/vdumb++/ve+/ve+/vcaCxLBfXe+/vQ7vv73vv73KuF/vv70rMi3vv71a77+9dBzvv73vv70l77+9ZVV5Be+/vSVjAcSSKQAVEu+/vXkPDhQg77+9DBM177+977+977+9Elx0djzvv71AeSvvv71mI++/vQTvv705ABAaXlYvD++/vRvvv73vv71177+91I9A77+977+9Je+/vQLvv71RI0wkWEgo3otzUe+/vS3vv73vv73vv71l77+977+977+9Je+/vWceW++/vS5NLO+/vXHvv73vv70r77+9Ie+/vQAIAADvv73vv70x77+9O3MHHO+/vQEl77+977+977+977+9UO+/vSpuee+/ve+/ve+/ve+/vUIvOVY/77+9K++/vRxT77+9Bu+/ve+/vRwCIO+/vSgO77+977+9cx7vv73vv70OOhxb77+9TMqNH++/ve+/vULvv70rKe+/vW8pQ++/ve+/ve+/ve+/vXsA77+9LVNO77+977+977+9SsuoKC3vv73vv73vv73vv71oMgfvv73vv73vv71vF++/vQRr77+9He+/ve+/vVhi77+9Be+/ve+/vRvFm3tRBe+/ve+/vUNU77+9Cu+/vRvvv73vv71pNiHvv70wSe+/vdKicTEhM++/vSwfPu+/vWtJVe+/ve+/vcqaaxPEpH3vv70y77+977+977+9NwV1Ou+/vSHvv71mBQgo77+9JHbvv71L77+977+977+9Ztm177+9XQrvv73fsWpU77+9MDnvv73vv73vv71JCe+/ve+/ve+/vW7vv73vv73vv70Q77+9Qu+/vSATKQLvv73vv73vv70V77+977+977+9EBsu77+977+9Gu+/vV4LCw7vv73vv71F77+9C++/ve+/ve+/ve+/vURKbu+/ve+/ve+/ve+/vSfvv73vv70gcu+/vTLvv73vv71DBjVPGFDvv70EQDLvv71d77+9cO+/ve+/vc27NgTvv71K77+977+9de+/ve+/vUkwQ0ocdQAAHO+/vRA9NO+/vTPvv70ISCrZmnIOGEkEBjIIOTfvv71G77+977+9H++/ve+/vVwX77+9cO+/vXxLSkXvv73vv71c77+9LO+/vXPvv70lUO+/vWZXPu+/ve+/vVwq77+9ZiMk77+977+977+977+9fEzvv711I++/ve+/ve+/ve+/vQgt77+9Mu+/vWnvv73vv71q77+9FhYU77+9aHM/Qu+/ve+/vTLvv70677+977+9GiTvv73vv70NQF9Z77+977+9LO+/vWvvv73vv70e0b7vv71K77+90LUCNVhDd3fvv73vv70Q77+9CG8oVCzvv71yBO+/ve+/ve+/vUbvv71i77+977+9PgDvv70Q77+9Ru+/vXPvv71s77+9G2dPy6rvv73Rh++/ve+/ve+/ve+/vVbvv70JFO+/vQYSJFNxDCEOO2Pvv73vv73vv73EkwDvv71tXTYOZe+/ve+/vRgr77+977+9Pe+/vRpCM++/ve+/vWLvv73vv71qGu+/vU5UVu+/vWh+KO+/ve+/ve+/ve+/ve+/vUPQoUnvv70k77+9eO+/vdSUNAnvv71a1L4G77+977+977+9Mk4b77+977+9OULvv73vv73vv73WiR3vv709X++/vTQ477+977+977+977+977+977+9I31gMu+/vSnvv71P77+9Re+/ve+/vW3vv73vv73vv70LD19A77+977+977+9de+/vWwK77+9Ve+/vRozfMyMUO+/ve+/vTInYO+/vTzvv71L77+9Uu+/vd2V77+9Nu+/ve+/ve+/vT3vv71a77+9e++/vUcA77+90Z/vv711ADZAAHnvv73vv71PQXLSmgbvv73vv73vv73vv70BXu+/ve+/vTgqFu+/vUdkMWrvv70T77+9Re+/vU0a77+9OlBrAe+/vTEBFGQD77+9Nu+/ve+/vQdM77+9MO+/vQMy77+977+9YzLvv71Y77+977+9Lu+/ve+/vVNW77+9c++/vRdk77+977+9dhpA77+9WRdVK1s777+977+9Nu+/ve+/ve+/vVhXCe+/ve+/ve+/ve+/vVlMOycGUu+/ve+/vQ/vv73vv73vv71p77+977+977+9xpQxYe+/vS9qO1N277+977+9W3Pvv71bAlds77+977+9NWjvv71wWmbOsu+/ve+/vWB5CO+/ve+/vRRl77+9I2Jo77+9NAHvv73vv71lEmVNQu+/vTXvv73vv71+77+9eu+/vd2g77+977+9TUXvv70dQe+/ve+/vUrvv73EoO+/ve+/vUPvv73vv70zeu+/ve+/ve+/vSPvv73vv73vv71Z77+977+977+977+9xq87by3vv71l77+9T++/vQRh77+977+977+977+9A++/vQvvv71X77+9Zu+/ve+/ve+/vXTvv73vv70UNRvvv70m77+9GHoMZC7sublD77+977+977+977+9xIDvv73vv71RWTkNYe+/vcqp77+9JRXvv70b77+977+977+977+9AEMz77+9XO+/ve+/vWcmcQFI77+977+9Te+/vXTvv73vv73vv73vv73vv73vv73vv71iBEvvv70qIgnvv71F77+977+977+977+9fO+/vWLvv70Q77+977+977+967G777+977+977+977+977+9IO+/vWwD77+9KO+/ve+/vSUeRO+/vRV977+9CO+/vT/vv70dEu+/ve+/vQlgE++/vTDvv70C77+9Ii4877+9KgBrAAB21YjJglnvv70BDxh377+9CFNRLxok77+9d++/ve+/ve+/vXhx77+9Wu+/ve+/vSPvv705PUbvv70XYO+/vQvvv70777+9Oe+/vRzvv70VAxMo77+9PmlW77+9Ye+/vWPvv71GyrLvv73vv73vv73vv70W77+977+9VUBbEWzvv70x77+9UxYC77+977+9JFjvv73vv73vv70HUe+/vX7vv71cAu+/vVMOLB0IBu+/vXgu77+9cDDvv73vv73vv71UIWJS77+977+9RCUl77+9Wci+Ue+/ve+/vTsEVSx0X2nvv71577+9YlPvv70fJ25m77+977+9fu+/vXbvv73vv73vv73vv73vv70ABO+/vUB3UO+/ve+/vUNDFznvv70U77+977+977+977+9Ue+/vTDssKrvv73vv73vv70O77+9VzRA77+9Be+/vS0nCh8A77+9LuK0lwI0BO+/ve+/ve+/ve+/vXzvv71C77+977+977+9be+/ve+/ve+/vXMJee+/vVTvv71+ee+/ve+/ve+/vTTvv71C77+9DEtuBO+/ve+/vUbvv71MBXHvv71k77+9UN6EHSXvv73QnCsXFivvv70MIAHvv73MqjIJD++/ve+/vThUQmHvv70DWFnvv73vv71c77+9dhDvv71vEO+/vVBubO+/ve+/vRjvv71jNu+/ve+/ve+/vcSY77+977+9HU8lDT0v77+9f++/ve+/vVHvv73vv73vv73vv73vv73vv71I77+977+9byvvv73vv71i77+977+977+9P++/vQAN77+9AAIgMu+/vUcsHBgBCnTvv73vv73vv73vv71277+977+977+90ZQ7De+/vTHvv70rAu+/vU9C74iBIWRtf++/vXLVuO+/vTDvv71w77+9ICZk77+977+977+9SO+/ve+/vTRE77+9WO+/vQDvv73vv70MAO+/vS1877+9VBPvv71k77+977+9Le+/vWQl77+9de+/vVlaXe+/vULvv71FXu+/ve+/ve+/vQbvv71hTNC877+977+977+977+9BQYI77+91rrEiu+/vXvvv71f77+9du+/vWEE77+9LXo1bu+/ve+/ve+/ve+/ve+/vUPvv73vv701PUjvv70d77+9S2Lvv71d77+977+977+977+977+977+977+9cu+/vTjvv73vv73vv71W77+9Xe+/vX/vv73vv73vv71z77+977+977+9bxzvv73vv73vv71177+977+977+977+977+977+9G++/ve+/ve+/ve+/ve+/vSYMXBVu77+9U++/vWXvv70fd++/ve+/vQ0GAwDvv70AAAgAQgHvv73vv73vv70S77+9d++/ve+/vUBB77+9Smsobu+/vQrvv73vv71YWNOC77+9NwHvv70a77+977+977+9UFMVBTDvv71DNz4z77+9ZkTvv73vv73vv73vv73vv71MTEQgxYDvv70QZcuT77+9QhBY77+9F++/vSjvv70UYG7vv70mTu+/vWHvv70mRG5kIu+/ve+/vThlYO+/ve+/ve+/vShp77+977+977+9y4zvv73vv71B77+9SWHvv73vv70DQO+/ve+/vSEB77+977+9L0rvv73vv73vv73vv70iGO+/vTtCR++/vTMqCu+/ve+/ve+/vQTvv700cO+/vUhMACTvv73vv71UaO+/vUYMVDAwMO+/vQld77+977+9E++/ve+/ve+/ve+/ve+/ve+/vcS+77+9Ge+/vUMjNe+/vQANE++/ve+/ve+/vTPvv70A77+9ax0hW9Ws77+977+9F1UxU++/ve+/vUpfKO+/ve+/vU7vv70lDu+/vQfvv73vv73vv73vv71MRe+/ve+/vS5l77+977+9WO+/vQrvv73vv70i77+977+9Su+/ve+/ve+/vRtrd++/vRjvv71r77+9LWvvv73vv70677+9Pe+/ve+/ve+/vUNY77+977+91pEU77+977+977+977+9DtSV77+9S++/ve+/vWVA77+9bu+/ve+/vSXvv704Je+/vVN3Lkbvv70777+9GHYZYBgNB9WN77+9SyPvv71T77+977+977+977+977+977+9Yg16Zlcd77+9c++/vSLvv71c77+977+9ejnvv73vv71h77+91acd77+977+9VQDvv71bCAAAFO+/vTzvv71UOwEBKy0WWe+/ve+/ve+/vU/vv73vv71m77+9N24TGjxw77+9SO+/vS/vv71q77+977+9EkDvv73vv71R77+9EBh277+977+9IxBu77+977+9HQQIbO+/ve+/vUkT77+977+9RO+/ve+/vTNE77+9ZiYqMCLvv71E77+9XO+/vRnvv70eIiRU77+9WRXvv73Mjmk0Re+/vQdICVDvv70NZFbvv73vv71lJe+/vUUT77+977+977+9aO+/vSsk77+977+9be+/vRdTJHTvv71NKUYrJ01d77+977+977+977+9UiYo77+977+9Zu+/ve+/vW7vv71Z77+9CO+/ve+/ve+/vRTvv73vv73vv71SVkXvv73vv71lMFbvv70qAFEAO++/vVtA77+9MGVr77+9Y++/ve+/vX5eFFTvv71s77+977+977+977+9xKncue+/vUls77+977+977+977+977+977+97KKs77+9TB/vv718AAMgRgNG77+977+9VgTvv71PBzXvv73vv71jBO+/vRp877+977+9ehjvv71h77+9L++/ve+/ve+/ve+/vXrvv73vv701f0Xvv73vv70ACu+/vS7opbEn77+977+977+977+977+9OitZ77+9N++/vRNP77+977+9cO+/vcqx77+977+9OCgNJRXvv70BAD/vv71n77+977+977+9MO+/vV3vv73vv73vv70k77+9f++/ve+/vQVacm0277+977+9TloRemXvv71VSEVFGkYjWRvvv70j77+977+9KRpBTj0u77+977+9Q++/ve+/vT3vv73vv71/77+977+9z7YI77+9fSoAEhAAIO+/ve+/ve+/vWrvv71iSysoAhbvv71GFCY877+9c++/vcmb77+9Fe+/ve+/vWvFq2cW77+9RWbvv73vv73vv70HABEFYVPvv71q77+9du+/vdyp77+9NGkPH3jvv73vv71HL++/vWhk77+9GQMza++/ve+/vUpfD++/ve+/vU1177+977+9Pmzvv73vv73vv73vv70hxYHvv73vv73vv70DYjPvv73vv73vv73vv70LLO+/vTMZ77+977+977+9ONKq77+9Xmkq77+9Qu+/vQjvv70T77+9VhUP77+977+9Iu+/vRlpRe+/vUVwWi/vv73vv73vv703E++/ve+/vWZM77+9XO+/vS3vv71A77+9Tu+/ve+/vTc1KgDvv73vv73vv70fYUJc77+9HO+/vWhkJW7vv71NbO+/ve+/ve+/vVA777+977+9Iu+/ve+/vVvvv73vv71jXO+/ve+/vUzvv73vv73vv70sXTbvv73vv70777+9BXIp77+977+977+977+9WO+/vSjvv70d77+9NO+/vVLvv71qNO+/vTXvv73vv70Kb++/ve+/vW9i77+977+977+9fu+/vS9177+9dGHvv71q77+9Ne+/ve+/vTLvv73vv70E77+9KcuN77+9f++/ve+/ve+/vWUICCsI77+9YG3vv719dETvv70OCu+/vUlS77+9Je+/ve+/vVdxfVEL77+9aTbvv73vv71SPkpR77+977+977+9xJfvv73vv71BR0kt77+9PkJb77+9aO+/ve+/vSfvv70L77+9MjXvv71T77+977+9PycAVSpZ77+977+977+9GFowcRA5NTAQAkvvv714Zihg77+9Knzvv73vv73vv71seAdW77+977+9cWzvv71ADWbvv70U77+9dO+/ve+/vSgq77+9Xu+/ve+/vUnvv73vv70v77+9dljvv73vv73vv73vv70wFO+/ve+/vVVPHXlgGGjvv71M77+9AgYYHCAB77+9cw3vv73vv704Q++/vRXvv70ASAkuK1I477+9H8ipDT8qE++/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vQEuegBAaRbvv70RGiYVEzTvv73vv71ZRERA77+9MRE377+9F++/ve+/vTcVWe+/ve+/vc2VOjrvv73vv706RAAiIO+/vUl1Q++/vQQlO2NoaFow77+9LhPvv70cIQIAW++/vURcXu+/vVnvv70LcUXvv73vv70O77+9ae+/ve+/vRLvv71J77+9UA0G77+9N++/vU7Sj++/vQ3vv73vv71z77+9cxc177+977+977+977+9y5Tvv73vv70hKkcZ77+9TmQ8HhIFKWNiaGdhI8eX77+977+977+9be+/vXfvv70gQBgGAFhB77+977+9MQHvv73vv71o77+977+9DRTvv70E77+977+977+977+977+91JXvv70AIHMGBBDvv70Uas+uMjgaKmMZ77+9DhgKHQPvv73vv73vv71NSCwQFAhjYBAEWB5gYyLvv70QFO+/ve+/vUPvv71X77+9SDXvv73vv73vv73vv70BAu+/vQt+77+9He+/ve+/ve+/vRjvv70fVO+/vT0G77+9AGXvv71c77+977+977+9Qe+/vRzvv70977+977+9bijvv70W77+977+977+977+977+977+9AO+/vVk9Ni5FOu+/vQkgZzXHle+/vXkmAO+/vTzvv73vv70AJGB577+977+9BGTvv73vv73vv715Hu+/vSRVb3NlVu+/ve+/vW/vv73vv70De++/vW3vv71a77+977+91IXvv71bGe+/ve+/ve+/vQ1bamUTC0ohLk/vv71B77+9FO+/vSlhQwgb77+9cxMNWe+/ve+/vV7vv71LFu+/vTfvv70HHRBd77+9U0zvv71/77+9V2/vv73vv713NT3vv70RTu+/ve2fnO+/vWNl77+9CQowMAADCe+/vTY7Mu+/vQ3vv709MO+/vSjvv70DYDUwBAfvv71wMu+/vUAEOAPvv73vv71+F9i477+9ASAI77+9DA3vv709FkJQcO+/ve+/vVzvv73vv71ODmZg77+9SO+/vULvv73vv71dGSTvv71d77+977+9WhIS77+977+977+977+9FQ3vv70syqDvv73vv73vv73vv70l77+9eUvvv73fte+/vQnvv70B77+977+9HO+/ve+/vWHMscmBGlrvv73vv71L77+9aj87Ju+/vXLvv71U77+9Njrvv73vv71s77+9R++/ve+/ve+/vThza++/ve+/vVjvv73vv73vv73vv71DVe+/ve+/ve+/ve+/vTU0NgHvv70k77+9RgzMh3Dvv71JEn9nJO+/vXnvv73vv73vv73IrzRZa++/vT3vv73vv73vv73vv71t77+977+9Se+/vSvvv73vv73cogAOaBYA77+9De+/ve+/ve+/vXkMTe+/ve+/vTjvv70wOc2777+9DGcBQSHvv73vv70SCO+/ve+/vRBVVe+/vUfvv71HJi5t77+9KGEU77+9US4EAtyf1abvv73vv71E77+9EiIRAu+/vVUDEAbvv73vv71r77+9Xjrvv73vv73vv71Jf++/vSrvv73vv73vv73vv73vv73vv73vv70B77+9Se+/vSRO77+977+977+9Oy5kJe+/ve+/vTsoa++/vSVZFO+/ve+/vd2J77+9Zu+/vcOELS5wU2nvv73vv73Pig/vv73vv73vv73vv73Kmu+/vX4awprvv73vv70Vde+/vUrvv71z77+9cu+/vR5zdu+/ve+/vXHvv712Pu+/vTdjGzYzzq1977+9Hu+/vSRy1Zfvv71RCu+/vS7vv73vv73vv73vv73vv73vv73vv719QO+/ve+/ve+/vTPvv71G77+9PCbvv73vv73vv73vv70U77+9Xu+/vTTvv71577+977+9Lmvvv73vv71fVtqb77+977+9b3zvv73vv71mAAPvv70sJSdXJ2Ii77+977+9QQQEPA8BYu+/vRjvv70Q77+977+9IAlpRgHvv70C77+9AwsA77+977+977+977+9AUDvv713KTtL77+977+977+9Ce+/ve+/vQHvv700Ogfvv73vv73vv71E77+9cFYyW++/vUrvv70V77+977+9Zu+/vVnFuRF2LTPvv71hT++/ve+/vSzvv73vv71S77+977+977+9I++/ve+/vR7vv73vv71gSO+/vQAide+/vU1b77+9QMiYWO+/ve6PjDzvv7032YgY77+9Be+/vQFL77+9Ke+/vRhf77+977+977+9YigmYO+/ve+/vQdQ77+9Su+/ve+/vSwK77+9RWJgVA4S77+977+9xI3vv71Y77+977+9CEpkS++/ve+/vVLvv71X77+9N++/ve+/ve+/ve+/vdyf77+977+9d++/ve+/ve+/ve+/vSHvv71M77+9fu+/vQBY77+9IO+/vd2ZD++/vWDvv73vv73Hre+/ve+/ve+/ve+/ve+/ve+/vWnqsKvvv71QGFTvv73vv73vv70oUl4nIe+/vWHvv70tM++/ve+/ve+/vSAqEu+/vRRuWBhVDSrvv70KWu+/vSTvv71977+9YAgi77+9HG3vv73vv709FBPvv73vv73vv73vv73vv70D77+9eTsaL3ciSx4w77+9Be+/vSXvv70LZu+/ve+/ve+/vUoE77+9L++/ve+/ve+/vWEx77+9BlwM77+977+977+977+9BGDvv73vv70Z77+977+9KWhqYUlf77+977+9LENyeG7vv71377+92pZK77+9fMa1Ju+/ve+/vVjvv73mtY7vv71XbXLvv70d77+9Ye+/vRVt77+9KsusS++/ve+/ve+/vRR1NSPvv73vv71L77+977+977+977+9e++/vX/vv73vv73vv70Nf3/vv73vv73vv73vv73vv73vv73vv73vv73vv73vv73vv71v77+977+9du+/ve+/ve+/vXd3NyLvv70AEAAAAO+/vTXvv73LtEDvv71E77+977+9Mu+/ve+/vXnvv73vv71077+977+9cxEAYBBM77+9FjDvv70dMhAAMO+/vQ8xPAww77+9EzDvv71AMe+/ve+/vTM0UTDvv73vv73vv71i77+9QCnvv73vv70G77+9GO+/ve+/ve+/vUw5FhoZTEbvv73vv70FBQrvv70GBWbvv71OGO+/vRYhHe+/vXxGYEJ477+977+977+9BO+/vQECYe+/vURIbO+/ve+/vVvvv71RGRpIfFwDDQnvv71JQEfvv71pQmBhECAOBRPvv73vv70M77+9SjJA77+9yaLvv70kA++/vQPvv709AO+/ve+/vQwONe+/ve+/vVd4JDwGCe+/ve+/ve+/vWLvv73vv73vv71GDg/vv73vv71qYu+/vTnvv71KJhEA77+9AkYtF++/vUzvv70cDVUX77+977+9Ru+/ve+/vVDvv70Z77+9QO+/vTXvv73vv73vv73vv73vv70aBu+/vXUY77+9dmTvv73ZnUvvv70dEBkQORLvv73vv71o77+9TXzvv70S77+977+9ST1WQwU/0atPWe+/ve+/vUgFCAHvv73vv70177+977+977+977+977+977+977+9GO+/vSg177+9AA15Mu+/vTvvv70AAwYAGe+/ve+/vcOR77+9Pu+/ve+/vdqUS++/vWtT77+977+9fGrvv73vv73Gp28GBxLvv71n77+977+977+9LF3vv71r77+92Yrvv71n77+91aTvv73vv73vv73vv73vv70s77+977+977+977+977+977+977+977+977+934Ed77+9He+/vWIo2Z/vv73vv71577+9Ze+/vQIEAAQEAAEEMHfvv71hGFHvv73vv71JT++/vSjvv73vv70a77+9A38aXO+/vQHvv71wzIdyHO+/vSMQJiFb77+977+9KWzvv73vv71pxYFeV0UO77+977+9ZGDvv70hTlDvv70hJVVR1Yzvv70T77+977+9UihS77+9X++/ve+/vQ7vv73vv70677+9AO+/ve+/vS4M77+977+9EO+/vREp77+977+9NgBVAV7vv71Z77+9DTrvv71sLWoAAALvv70A77+977+9F0xgMQHvv70PGGkB77+977+9GO+/vRhhIizvv73vv71AYu+/vU5zDTM677+9Y1w+MVPvv70JGjLvv73vv70jI3BBPUjvv70/KAEu77+977+977+9c++/ve+/ve+/vTI777+9xYsKD++/vSfvv73vv73vv73vv73vv71A77+977+9AO+/vQBA77+977+90JwzdTwDHO+/vQJD77+977+977+9Qu+/vUICYUDvv71QeDXvv71xKChh77+977+977+9JyYUPQPvv70+QBJdJO+/vVDvv700IB5uMmMhQO+/vXYa77+977+9WRUyFSsOQHhg77+9Ie+/vXcsQO+/vV/vv71scu+/vSRu77+9H0Lvv70R2oxN35h177+977+977+9He+/vS/vv73vv70nFn07IER4diBmMu+/ve+/ve+/ve+/ve+/vcSfACjvv73vv70/Oe+/ve+/vQLvv70x77+977+977+977+9AO+/ve+/ve+/ve+/ve+/vXnvv70Y77+9Ru+/vSDvv73vv709Lu+/ve+/vU/vv70CY++/ve+/vSrvv70H77+977+977+977+977+977+9Gu+/vSHvv73vv73vv73vv73vv73vv71R77+9a++/ve+/vWoi77+9cwIe77+9w7ki77+9VWnvv73vv71bO0Lvv73vv70W77+9YydWGBx077+9Se+/vTTvv73vv70DKFcAFR9mEQBJ77+9L0dS77+977+977+977+977+9bTsKY++/ve+/ve+/ve+/ve+/vU5CUu+/ve+/vRPvv71g77+977+9ZO+/vS0J77+977+9ZnsR77+9K1njvIVY77+977+9ZnZa77+9V2Xvv71i77+9exl1HgTvv71t77+92bQs77+9clouNO+/vW3vv71uWu+/vdS+77+977+9ce+/ve+/ve+/vcyTe3xnEu+/ve+/ve+/ve+/vSQlEAoifG7vv73vv73vv71j77+9R++/vSzfiu+/vV3Dj++/ve+/vUR/77+977+9Ve+/ve+/ve+/vXRzFDPvv70Y77+9Cu+/vSnvv71177+9JHrvv71m77+9KnZVUyrvv73vv71VGe+/vQ0f77+9dRx/I2Lvv70X77+977+9Su+/vR3vv71xdFo077+977+9Uu+/vRDvv71UN0Xvv73vv73vv70fTO+/ve+/ve+/ve+/ve+/vcOUFXR077+9Lhvvv73vv70y77+9b2rvv73vv73vv73vv70Wc++/vcKJ77+9a++/ve+/vXXvv70h77+9AxtS77+977+977+9HO+/vTLvv73vv73vv73vv73vv73vv73vv71rcXjvv70u77+9cu+/vScfI++/vXM177+9zZ5777+977+977+9SkQAHu+/ve+/ve+/vVnvv73vv73vv73vv71AL++/ve+/vXAs77+9bO+/vUbvv73vv71FLO+/vTYmZO+/vUtcRO+/vXU0ZiAB77+977+977+977+977+9agDvv70l77+9UO+/ve+/ve+/vcqcKSjRhhvvv71G77+9L++/ve+/vRhzG0sE77+9Uzbvv70C77+977+9Le+/ve+/vTTvv73vv71sAu+/vTnvv73vv71w77+9NgMU77+977+9cO+/ve+/vUIc77+977+977+9OUPvv73vv71XKgIiAAETPsuUHe+/vRcSyaDvv73vv70TEe+/vRJtY++/vXEt55yNcu+/vWtX77+977+977+9cu+/vTQb77+9Ze+/vTUt77+9LNyW77+9SUPvv70b77+977+9Hy/vv702ehU/I2p/77+9Ek/vv73vv70q77+977+9SQAAO++/vQo677+9060177+977+977+9eQ3vv71977+9de+/vSbvv71sNu+/vRvvv70N77+92LDvv71YPO+/ve+/vRB+77+977+977+977+9Ie+/ve+/ve+/vR0F77+9Ce+/vRLvv71+77+977+9S++/vUjCpBXvv70h77+977+9B++/vQQ/77+9du+/vTjvv73vv70M77+9TAJj77+9QO+/vWhs77+9HgwBRMqR77+9KgVF77+9Ru+/ve+/vXRwVkrvv70jM92k77+9LO+/vVpd77+977+9M++/ve+/ve+/ve+/ve+/vRtBcM2VIU7vv717Le+/ve+/vVBZNg54UQwxZe+/vVPvv73vv70dPO+/vRhJ77+9QO+/vWzvv70UVe+/vU9XEe+/vWMO77+977+9et6H77+977+9axMReGYlOTN577+9fSTvv73vv70177+977+9LcSMIwAFBO+/ve+/vRfvv70/Aijvv71lWCAx77+9A++/vR3vv73vv73vv71DcO+/ve+/vSfvv73vv71x77+9Gu+/vUJj77+977+9cu+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vVvvv73vv71Tbu+/vWkoDl3vv73vv70nE1RSCSNA77+9UO+/ve+/ve+/ve+/ve+/vcSIAe+/vXEjRWw9LcKFJO+/vRHvv73vv73vv73vv71KTgzvv71477+9XO+/ve+/vXXvv70777+9dAHvv70F77+977+9Dnvvv71UeHhI77+9UnDvv73vv70S77+977+9f++/vXTvv73vv73vv71977+977+977+9Au+/vSAAABQAYiRmQTxp77+977+977+9xIdFOBnvv73vv73vv73vv73vv73vv73vv73vv71c77+9N3pdUmrvv73dje+/vWbvv73vv73vv71I77+977+9Qe+/vTsTNO+/vdOi77+9X++/ve+/vQYR77+9YDNSEu+/vU0y77+977+977+9zKgwZ++/vSEnBDU+77+9Q0/vv73vv702DiPvv73vv71C77+977+977+9GsSOZW7vv73vv73vv73vv70/77+977+977+9ce+/vdmFBe+/vVJe77+9JO+/vX48TGAj77+977+977+977+9MO+/vXgIDihT77+977+9Ve+/vSBgfO+/vVFF77+9aO+/vdq3TO+/vS7npKPvv70W77+977+9AADvv70GEADvv71kJGTvv70QOO+/vSYVKO+/vRPvv71S77+9ARZ+SRpl64W9dDHvv70Y77+9BO+/vRtxfu+/vSjvv70u77+977+9EyvJlM6sNe+/vQ1j77+9Re+/ve+/vUYo77+977+9Pu+/vcSe77+9EkDvv70h77+9Ne+/vUPvv70ATBXvv70vQmjvv73vv73vv71eITEuFO+/vWFFFD3vv73vv70X77+977+9Ah3vv73vv70W77+9MO+/vT3vv71l77+977+977+977+9b++/ve+/vXc/77+977+977+977+9N++/ve+/vQLvv71KAQTvv73vv73vv70A77+9a++/ve+/ve+/vUbvv73vv73vv70CHijDo++/vWEiQu+/vWXvv71077+977+9AkPvv70B77+977+9MO+/vTDvv70lAu+/ve+/vSQcBu+/ve+/ve+/ve+/ve+/vcSwANSp77+9Qe+/ve+/ve+/vQrvv70naBHvv70Z77+977+977+9WO+/vdSjclUYa++/vRVo77+977+977+9dSrvv73vv70b77+9XSRfbO+/ve+/vQNE77+977+9XO+/vQAn77+977+9azJoMHQW77+9KHAqAe+/ve+/vU9W77+977+9aTZI77+977+9Su+/vXtWWEAp77+9QDgoJO+/vVIB0YYC77+977+9a3Tvv70jLm4v3Ibvv73vv71aX2vvv706O++/vdW/77+977+977+977+977+977+9DO+/vVXvv71gUwAI77+977+9IO+/ve+/ve+/vU0MV++/vVzckNut77+977+9OXh/77+977+9enrvv73EgALgsYwIPO+/ve+/vU4AfBoQau+/vS4OL24iLO+/ve+/vWLvv71Rd++/vUjvv71oZRFbN++/vWdpa19W15Fd77+977+9fO+/ve+/ve+/ve6WsGgVR++/vSwJ77+9IBJcMWUXZO+/vSAX77+9VO+/ve+/ve+/vVcWXe+/vUA177+977+9Gu+/vSVo77+977+977+9MO+/vU9l77+9fO+/vV1a77+977+9b++/vQHvv70t77+977+977+9VGYeNFg877+9FO+/ve+/vTJWUe+/vRYCSO+/vTrvv73vv710FVPvv71EFAwNEe+/ve+/ve+/vSIfc++/ve+/ve+/vQMMEAABBVBgChgO77+9Oe+/vVJ977+977+9ee+/ve+/vREY77+9De+/vUAGAu+/ve+/vQnvv71R77+9BH5T77+9OATvv73vv70p77+9W1NY77+977+9xZsCeO+/vVrvv73vv71FJO+/ve+/ve+/vSfvv70FTBEQWSralu+/ve+/ve+/ve+/ve+/vWQS77+9yoMpbBzvv71RGAIZZjJ1ZVzvv70CCe+/ve+/ve+/ve+/ve+/vQDvv70FO0MOCT5CZiZn4bKb77+9Alnvv73vv70X77+977+977+9Ye+/ve+/ve+/ve+/vQ3vv70rHxzvv701K++/ve+/ve+/vRLvv70/Ku+/vXlr77+977+9OO+/vXHvv73vv70a77+977+9f1fvv73vv70eNu+/vSAfHAzvv70477+9Q++/vQbvv70y77+9Ge+/vS95HO+/vShc77+9X++/ve+/ve+/ve+/vdWv77+9bCtP77+9d31iPG7vv71t77+977+977+977+9P9qzWe+/vRvvv73vv73vv73vv73vv70877+977+977+977+9Mmbvv70AAkDvv70LAO+/ve+/vRwlDO+/ve+/vRDvv73vv70gDA7vv70A77+9JHNMCQAA77+9DAJDAQpAOAMIWO+/ve+/vQAGLu+/vTMD77+9JmPvv70gOjQGUu+/vfG4t58v77+977+977+9bHQz77+9TO+/vUzvv70777+977+9De+/ve+/ve+/vQrvv73vv73vv73TmeaMt++/ve+/ve+/vQ7vv73vv71aYu+/ve+/vWALeRHvv70TDw4AM++/ve+/ve+/ve+/vSQFdVTvv73vv71h77+977+977+977+9IyLvv73vv73vv719fe+/ve+/vVnvv70177+9fTXvv73vv71pTO+/ve+/ve+/ve+/vTl2TAAKG++/vWsB77+9AT7vv73vv73RpQ8q77+9SA1K77+977+9TVNR77+977+9QO+/ve+/vRBc77+9Gu+/ve+/ve+/vVsEYCYgEU5C77+977+9JQl277+9AEAA77+9We+/vUwZ2qtR77+977+9RBgk77+9ee+/ve+/vR4Zd++/vRMrRRvvv73vv70NEu+/vULvv71D4rWG77+92oANEu+/vRAZ77+977+9dil+KS3vv70a77+977+9Xu+/vWDvv70Ez4bvv71N77+9fVsVRc6kZe+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vTXvv70tT2Xvv73vv70u77+9JVnni5nvv71K77+977+9YO+/ve+/ve+/ve+/vQrvv71N77+9CO+/ve+/vTgk77+9Lu+/vTZZ77+977+9Ge+/vS7vv71aQe+/vWnvv71Z77+977+9WW0j77+9Vu+/ve+/ve+/ve+/ve+/vX/vv73vv71f77+9d++/vQx577+9Ye+/vVXvv71G77+9WyliYGPvv70BaggNagzvv70H77+9Qu+/ve+/ve+/ve+/vX/vv71dK++/ve+/vVtW77+977+9Lh9277+977+9He+/vWpg77+9AO+/vT7vv73vv70u77+9Su+/ve+/vQBgAe+/vQHvv71QEDACB++/vQdUJzBkBTAALBjvv70F77+9GBIAID7vv71xUu+/vQXvv73vv70h77+9Ae+/vSPvv70ZbAxZ77+9UCFb77+977+9J++/vVUe77+9Se+/ve+/ve+/ve+/vRbvv71IaUAk77+977+9C0jvv71h77+977+977+91YdnS++/vXLvv70w77+977+9STrvv71s77+977+977+9BO+/ve+/vU0177+9Ie+/vSA377+9cu+/ve+/vVXvv71lA1QH77+9yZPvv73vv73vv70x77+977+977+977+93o5SKO+/ve+/vXJUPO+/ve+/ve+/vSQCde+/ve+/vWo177+9W++/ve+/vQhpypnvv73vv73vv73vv73vv73vv73vv70VVnfvv73vv73vv73vv73vv73vv73vv71i77+977+9BFrvv73vv70WSmzvv73vv71WKO+/vRXvv70AADAAAgFAMATvv71h77+977+9YQI0RgQpHWTvv700Gh0V77+9Bu+/vVEACh1n0L3vv70Ebe+/ve+/ve+/ve+/ve+/ve+/vRTvv70K77+9TFLvv71w77+9b++/ve+/vUTvv71c77+9Fe+/vWxTSS3vv71vUO+/ve+/vRZRPt+l77+977+977+9I++/ve+/vW7vv71277+9HVvvv71FARzvv70w77+977+977+977+977+977+9AO+/ve+/vS0m77+977+9IFLvv71l77+977+9Le+/ve+/ve+/vRMF77+977+9C++/ve+/ve+/vUEjQu+/vQg677+9NO+/ve+/vWrvv71477+9E++/ve+/vUZxViMge++/vdm8fe+/ve+/ve+/ve+/ve+/vSnvv73vv70x77+977+977+977+977+9Uu+/vSdoUe+/ve+/ve+/vUrvv73vv71577+9fFXvv71877+977+9BE1C77+9ce+/vSXvv73vv73vv70U77+9d++/vWt/77+977+977+9379X77+9YEMiz61HZ37vv70l44qO0pEkIAw4AzDvv73vv73vv73vv71jSAfvv70+77+9Ne+/vWjvv73vv73vv73YhgzTnFQPRO+/vSUT77+9Ye+/vTV477+977+977+9V++/ve+/vdu9Q2/vv71277+977+977+977+9clnvv73vv70iA++/ve+/vUHvv73vv73IkDHvv71L77+9MHLvv70O77+9Ye+/vUbvv70A77+977+977+9EigqDEZA77+9CjHvv73vv70mDBoAAO+/ve+/vVFjEO+/vWBg77+9c++/vc6CFO+/vRTvv73vv73KuO+/vX1zBgLvv73vv70r77+9Wu+/vV/vv73vv73vv73vv73vv73vv73vv71X77+977+9Q1wp1Kcpee+/vVcY77+9DVTvv73vv717M0sSA2NT77+977+9xYU177+9Yu+/ve+/ve+/vUca77+977+977+9GU7vv70s77+977+9U3jvv73vv73vv73vv73vv73vv73vv71e77+977+977+9a++/ve+/vXvvv73vv73vv71SeNmDcu+/vQAAAO+/vQAA77+9BsaIQlMc77+977+9QCTvv73vv73vv73vv70A77+977+9AQsBCTUdXO+/ve+/vVHvv73vv73vv705cjkQ77+9a3AtNN2P77+9Mu+/ve+/vURbO++/ve+/vQzvv71y77+9GHRy77+9UgEhIiY6NO+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vXsxTmHvv71R77+9Zhnvv70977+977+9Qe+/ve+/vURyGBEFSe+/ve+/vWgB77+9EWh5EnozZhzvv71IUwDvv70M77+9Eu+/ve+/vWjvv73vv71EDw/vv71b77+977+977+977+977+977+9c++/ve+/vVVx77+977+977+977+91JHvv73SlO+/ve+/ve+/ve+/vQDvv70wc04977+977+977+977+9Ye+/vSB+Y2Pvv70+X1B177+977+977+9Te+/vX/vv73vv70X77+9Oe+/vRlm77+9ehfvv73vv73vv73vv70gYQEEACYC77+9RnBNQu+/vTHvv73vv70B77+977+977+9GBQwHD4WAAvvv71e77+9BuCzpQXvv73vv73vv70e77+9Uu+/ve+/ve+/ve+/vc6y77+977+9S2cM77+9V++/vTHvv71c77+977+977+9c++/vQHvv70c77+9cmoVB1Zl77+9IXlBxrIiAu+/vQwQ77+977+9Vu+/vS0x77+9FiASBjpp77+9A++/vSZAGCrvv70yRG4E77+977+9XO+/vUIB1Ifvv70UbArvv73vv73vv73vv73vv73vv73vv73vv73vv73vv71977+977+9X++/ve+/ve+/vWnvv73vv70E77+9R3oa77+9Vgc577+9wq4bKu+/vSVA77+977+977+9He+/ve+/vUsd1bsCGO+/vXDvv700HO+/vceq77+9Eu+/ve+/vTPvv715ee+/ve+/ve+/ve+/vUzvv70/77+977+977+977+977+93pnvv73vv73vv71d77+9AADvv70A77+977+9CRpv77+9CBgyIHkZEBbvv70MGjV+77+977+9zpQh77+9AlXvv71E77+9ae+/vXjvv71P77+9P++/ve+/vULvv70P77+9bWcb77+977+9BFQs77+9NDHvv70D77+9AwRq77+977+9Ee+/vXjvv73vv71vbO+/ve+/vWkwIu+/ve+/ve+/ve+/ve+/vQDvv73vv719Ne+/ve+/vW/vv71H77+9Je+/ve+/vT3vv71PMGVnMO+/vQrvv70577+977+9DhJz77+977+9JyMMDiTvv70w77+977+9QCxAIu+/vVDvv73vv71OExk377+977+977+9KWpJTu+/ve+/ve+/vSzvv71o77+9Je+/ve+/vUrvv71k77+977+9AHcN77+9GAXvv70A77+9Du+/vQjvv71E77+9fO+/ve+/ve+/vUTYpmRePOecrO+/vSTvv70nR++/ve+/vR83OO+/ve+/vSp977+977+9WeWus1nvv73vv71r77+977+9XVDvv70I77+9EULvv73vv73vv73vv70w77+9Ae+/vQIEQStA77+977+9ZO+/ve+/vWJrWu+/vWvvv707FhXvv73vv71IB0da77+9Ae+/vUhT77+977+977+977+977+9Ozjvv71S77+977+9NEFg77+977+9JVzvv73vv73vv73vv70s77+9OO+/ve+/vXwQGO+/vUPvv70t77+9WXDvv73vv73vv73vv70h77+9BO+/vQAV77+9XO+/vSFh77+977+9eu+/vWHvv73vv73vv73vv71j77+9Ou+/vTXvv711K++/vV7vv73vv73vv70y77+9Hc+dJRBR77+9cu+/ve+/ve+/vSDvv70ZAO+/vTwF77+9Tu+/ve+/vSYS77+9Ku+/vWIbJO+/vRjIj++/vRczeX0077+9MD7vv73vv73vv71477+9LA1j77+9MO+/vcyJ77+9IO+/vV9Te1R5Wu+/vUosQVbvv73vv70I77+9YAAA77+9Ku+/ve+/ve+/vU48DO+/ve+/vQQ0fO+/vWjvv71CEO+/ve+/vXoYBRNO77+977+977+9AGnvv70IP2kfG++/vWt0ajUXbO+/vQsy77+9G0gp0qVpLu+/vVN53arvv73vv73vv73vv73vv71G77+9Zu+/vQXvv71h77+9Je+/ve+/vdq1Ke+/ve+/ve+/ve+/ve6CmEF5My5l77+977+9GDBmCcy177+977+9Qu+/ve+/ve+/ve+/vX1UFe+/ve+/ve+/vXDvv71BWBjvv73Zq++/vXvvv73vv73vv71H77+977+9VO+/vUxs77+977+9ZgQoM++/vQEgaTXvv73vv73IjEsv77+9PtOOSm4p77+977+9QXTNnO+/vRsiO86aLu+/vVvvv73vv73vv70377+977+977+9OGcRWu+/ve+/ve+/ve+/ve+/vQAABGUg77+9HTHvv71hEAnvv73vv71n77+9Vhjvv73vv71677+9TAoLEe+/vRAO77+9TO+/ve+/vTzvv70kTwIE77+977+9EHTvv70G77+9Ku+/vQvvv71J77+9REjvv73vv73vv73vv70K77+9L++/vWTvv70uPO+/ve+/vQk677+9Ee+/vXXvv73vv73vv73vv71U77+9zZYp77+9Wu+/ve+/ve+/ve+/vUrvv71DA2xrKe+/vQIqQSHvv70Y77+9FCIgLO+/vWoF77+977+977+977+977+977+9W++/vXXvv73vv73vv71PLMeb77+9fhzvv73vv71KMe+/ve+/ve+/vW4beO+/vdeV77+9fe+/vUggRyJa77+9Ju+/vVTvv708BO+/vVpa77+9fgvvv708QjTvv71U77+9f1/vv70QFu+/vSbvv70yRu+/vUte77+9QQvvv73vv73vv73vv73vv71X77+977+9G++/ve+/ve+/vRYU8amMscqud3Hvv717W8KX77+9QVwDOgAj3q7vv73vv714AQACRO+/vQEfa++/ve+/ve+/vRrvv70YdEFqSO+/vRbvv708Ye+/ve+/vTk777+977+977+977+9Ou+/vTXvv73vv73vv70y77+9EFLarAN2RSTvv71TVnjvv70qZO+/vV0q77+977+977+977+9ASrvv70Hwrvvv73vv73vv73vv70zSx5377+9bO+/ve+/ve+/ve+/ve+/ve+/vQDvv73vv73vv70/77+977+9fkvvv70qZmHvv71kCe+/vSgycu+/ve+/vQAZ77+9Ae+/vQrvv71YB1nvv73vv73vv71kSe+/ve+/vWFZ77+9R++/vQHvv73vv715K++/ve+/ve+/vXNP77+9Fd2cFu+/vVDvv73Imu+/vRVIae+/vVDvv73vv70DcElLcu+/vRkc77+9Qh8l77+9MlLvv73vv71x77+9TAZ6GOy+te+/vWHvv71OGO+/vRrvv71Yezvvv70EOu+/ve+/vQZFEgsnMe+/vVLvv70A77+9BnAZR++/vUjvv71Y24Q677+9Yu+/vUHvv70LcTbvv70NFCPvv71A77+9LS3vv70kM++/ve+/ve+/ve+/vWzvv73vv71qBu+/ve+/vUF277+9U0hk77+977+9RO+/vVDvv70V77+9yZ4u77+9XRjvv73vv73vv70x77+9be+/ve+/vW8777+9ee+/vTlGOO+/veqxnQ1XIu+/ve+/vRjvv73vv73vv70nNwfvv73vv73vv71fJe+/vXLvv717BntR77+9BxxHZ++/vRbvv71jUe+/vW3vv71YP++/vSdK77+977+9DO+/vW1y77+9bVzvv73vv73vv71r77+9Ru+/vRRy77+9MBnvv73vv73vv73vv71ZMCHmkaTvv73vv71H77+977+9b++/ve+/vQvvv71jSu+/ve+/ve+/ve+/vXZ277+9EkDvv73vv73vv70gO3BWPG/vv73vv71977+9x57vv71977+977+9OO+/ve+/vSgjMu+/vW/vv70AAEIEAAAA77+9NXNZJwwj77+9MmlMypLvv70JKe+/vUIE77+9KDjvv70BTBoHFgfvv73vv73vv71l77+977+9QwkMAUHvv70B77+9CHFiA++/ve+/vShw77+9HhkG77+9QAkT77+9LO+/vUUJITTvv71UBFjvv73vv73vv73vv73vv73vv73vv73vv73ZkXU277+977+9fO+/ve+/ve+/ve+/ve+/ve+/vQHepu+/ve+/vRYsMTtMWO+/vTjvv73vv70DDHTvv73vv713be+/vXLvv71RYkhE77+977+9CAYMbO+/vRMZMu+/vcy4EUDvv70xIBnvv71+UGUtAO+/vRpq77+977+93ZMqJO+/vSLvv70j2ZAs77+9Uu+/ve+/vUMMFmJNZVvvv73vv71NNFnCqCxiQO+/vRwwQu+/ve+/vWBK77+90p5277+9cn0w77+9a1Lvv73vv70I77+9GFDvv70277+977+9aibvv70H77+9Klvvv70APO+/vQIlCExlXe+/vWDvv71iyqxkaFcK77+977+977+977+9U3FgYO+/vQTvv73vv73vv71c77+9bxwG77+9X++/vQVd77+977+977+9XWhCMGjvv70cSnNG77+92K8x77+977+9Ee+/vUzvv73vv70OOyPvv71ACHnvv73vv71M77+977+9UO+/vSnvv70z77+9dS3vv73vv71v77+9ClLvv70raSfvv71dVu+/vU8077+9Wu+/vRgARjzUkzDvv71H77+9DAgFODUiQQID77+9Gu+/vSPvv70J77+9KQvvv73vv73vv73vv71wagAAABAYaO+/vSJg77+9ATTvv70KZ++/ve+/vSQD77+9BO+/vQJEGQ7vv73vv71JNG9W77+977+9IFXvv73vv71S77+9HxEaTu+/vWjvv73vv73vv73vv70gMO+/vcKl77+9Ye+/vTzvv73vv716Ru+/vUpezovvv73vv70W77+977+9LQVhUHTvv71j6a6sMADvv70K77+9OBsreu+/vdKpQ++/ve+/vSkxWhITExTvv70NzZUh77+977+977+977+977+9CBEA77+977+9Au+/ve+/vSTvv70i77+977+977+977+977+9K++/ve+/vSLvv73vv70ABO+/vTMmFzPvv70ADe+/ve+/vQHvv70477+977+9UwfZnihA77+9LD4HeiHvv73vv71K77+9VRkV77+9Agli77+9cGNFUEdHLjtHMQALBxIYGO+/vQnvv70jSO+/ve+/vUTvv71r77+9YO+/vdKsXu+/vQ0yDQwhIu+/ve+/vQ4K77+977+9FwMUBjLvv70BTQNEHHDvv73vv73vv73OtQkSAQoiZe+/ve+/ve+/ve+/vQDvv70D0Khw77+977+977+977+9EV0ATQIqDlTvv70LRSwZMu+/vWwJeu+/vUneumV1Z++/ve+/vQ0G77+977+9KHLvv73vv70oUnPvv73vv70kfu+/vVNyfhwFVUIo77+977+977+977+9HHhVLSQtAe+/ve+/vUwZ77+9C++/ve+/ve+/ve+/ve+/ve+/ve+/vQARRu+/ve+/vVBMex7vv73vv70cEAoA77+9Cz8v77+9IO+/vUwU77+977+977+9R2MT77+9zLViGe+/ve+/ve+/vUPvv70lPBIO77+9HO+/ve+/vQ3vv73vv71INVzvv73vv71d77+977+977+9Ye+/ve+/ve+/ve+/vUVmGFDvv73vv73vv73vv73vv71F77+9Ew/VrUTvv73vv73ZiS1TVF7vv73vv71OVC/vv71M77+9NRjvv70Q77+9UO+/vQPvv70H77+9dO+/ve+/ve+/vUrvv71q77+977+96JGV77+9Ghfvv70z77+9BO+/ve+/vULvv71H77+9DO+/vS4qENWJJBkc27No77+9be+/vSHvv73vv71377+9bO+/ve+/vSJD77+9Vu+/ve+/ve+/ve+/vQvvv70l77+977+977+977+9D++/vTvvv73vv73vv71BNgEgSe+/vRXvv73vv73vv73vv71GK0vvv71Z77+9Zksw77+9VA4y77+977+977+977+977+9aO+/vdah77+9RO+/ve+/vQAC77+977+9KO+/ve+/ve+/vW59TCbvv73vv73vv73vv70p77+9Um4qFu+/vWUwZXQtEu+/vRnvv73vv70YEjLvv73vv71bQu+/vQDvv70SWRvvv70Samjvv73vv73vv73vv70uJe+/ve+/ve+/vSQG77+977+9ZAETLu+/vQlO77+9VO+/ve+/vSrvv73vv70pIe+/vRPvv70qRConUVk3BO+/vUTvv70n77+9CE4kXFIpSe+/vS9oQu+/vXck77+9Ve+/vSJG77+977+977+9VO+/vVxy77+9Ye+/vR9x77+977+977+9cFVVOe+/vURLB++/vSJxRhoOWmzvv73vv70OdO+/ve+/vQzvv7145JCZ77+9EDgUIu+/vQAhNQFCUu+/ve+/vQQhDHAB77+9Ukzvv70ND++/ve+/vTQGGUfvv73vv71FSAwBOO+/ve+/ve+/ve+/ve+/vcWYQSPvv73vv71QZO+/vUMGK2Pvv70BXQFGW3EiFe+/ve+/vXsa77+977+9JEnvv73vv73vv71KNAHvv73vv71SRyLvv70i77+9Lu+/vSPvv71L77+977+977+977+9MxXvv73vv73vv71mPVLvv70u77+977+9UisZXTbvv73vv73vv73vv73vv73vv73vv70Hb2Lvv70v77+977+977+977+9HysY77+977+9JsyrLwTvv706Ce+/ve+/vSNM77+9Nm0CfwN8FXDvv73vv73vv718Xe+/vVFQGdCFSnXvv71VFO+/vSc077+9DAsx77+9Se+/ve+/vS3vv73vv70177+977+9NO+/ve+/ve+/vW/vv70a77+9ee+/ve+/vQt277+977+9U++/vW4KFO+/vQAgBAHvv73vv71hYSNd77+9HmPvv70oVmDvv70A77+977+977+9dF4E77+9fu+/vUbvv710xajvv73vv73vv73EhADvv73vv713Ng3vv73vv73vv73vv70u77+977+977+9Je+/vRrvv73vv70W2bgu77+9SDUI77+9GBMMUS7vv71GWxluV++/ve+/vVnvv73vv70ZOu+/vTXvv702BiLvv71BMCvvv70H77+9b++/ve+/ve+/ve+/ve+/vRFT77+9CO+/vXrvv71kyZbvv73vv71t77+977+9B0rvv73vv73vv70677+977+977+977+9Gu+/vTFr77+9Y++/vc+X77+977+977+9Ru+/vXc877+9SgNM77+977+9Qu+/ve+/ve+/vWTvv71OKg3vv70wJ++/vTkySzLvv70q77+977+977+9HxYa77+9HGZt77+977+977+977+977+977+977+977+9Ke+/ve+/vU4R77+9Hu+/ve+/ve+/ve+/vQAYAAABAELvv70677+977+9IRgo77+977+977+9BisYQ1hya11X77+9yaTvv70QdiLvv70377+977+9KSZQKRPvv73vv70QQu+/ve+/vSDvv70877+9IO+/ve+/ve+/vVUdYu+/ve+/vdmD77+9au+/vUrvv70EDO+/vdOl77+977+9Vm7vv73vv73vv71S77+9HWlHG++/vRJnwqDvv70C77+9Uu+/vV0p77+9Se+/ve+/ve+/vWXvv71n77+977+9Xu+/vRbvv73vv73vv73vv73vv73vv73vv712Pw/vv73vv73vv71777+977+977+977+977+977+977+977+977+9Gu+/vVbvv73vv71y77+977+9FDzvv71y77+9NTVe77+9We+/ve+/ve+/ve+/vVzvv71jWu+/vT/vv73vv71w77+977+977+977+977+977+9f++/ve+/ve+/ve+/ve+/ve+/ve+/vSzvv73vv70HamHvv71L77+9RO+/vTMDR++/vQdNQxUDEwMJ77+9ACpIIBLvv73vv71I77+9EAxh77+9ZiAEQ++/vXgg77+977+977+9WUwOJBIKD1jvv71jaBB8AVQE77+9GO+/ve+/ve+/ve+/vX3vv70YMWk/Ve+/ve+/vQzvv70y77+9O++/vQAoMe+/ve+/ve+/vQHvv73vv71Q77+9YmBh77+9xoLvv73vv73vv70wMWbvv73CnDdlA2QJ77+9ChVD77+9GVbvv71V77+9cHzvv73vv70EJe+/vRTvv71lTsy9be+/vVvvv70EYu+/vSUVVQQA77+9DETvv73vv73Moe+/vWTvv71Y77+9Eihh77+9JgYM77+977+9aCoBBu+/ve+/vTnvv71wOAEW77+977+977+977+977+9B++/ve+/vQjvv70PTCTvv73vv71KCEnvv71FFhpQ77+9Qu+/vTTvv71UEu+/ve+/veWPrXfvv73FnVfvv73vv71E77+9BEVA77+9JCAABu+/vcWWLAXvv70AGe+/ve+/ve+/vX9oIBk1elRvbRvvv70V77+9du+/ve+/vW7vv71O77+9KzDvv71YOEAwQQjvv71B77+9QDfvv70dQUlAMu+/vSnvv71qRRJ477+977+9W++/vS92KSjvv70R77+9Wu+/ve+/vWccPu+/ve+/vWsPC++/vQ4y77+9Ig3vv71/ZXRS77+9dO+/vTLcqu+/vWUa77+9Vy7vv71yEO+/ve+/ve+/vRHvv73vv73vv71477+9JO+/ve+/vcOM77+977+9We+/vTrvv71DIgzvv73vv73vv73vv70r77+977+9VO+/ve+/vTfvv73vv70677+9aO+/vRzvv73vv71n77+9B0V477+977+9Vu+/vSZf77+9Lu+/ve+/vWVV77+977+977+9LsqjVjfvv73vv71vG++/vS1R77+9DO+/ve+/ve+/vRjvv73vv70K77+9LQXvv73vv71WWhrZgO+/ve+/vXvvv70e77+92pdDMe+/vWd677+9HO+/vU9QQ++/vWPvv73ct08o77+977+9VjU1Uu+/ve+/ve+/vVbvv73vv71Wa++/vVbvv73vv73vv73vv73vv73vv71GAta1Ix4d77+9AALvv73vv73jlafvv73vv719yatU77+9Xx1+GWVm77+9XHDvv73vv705U1vvv713ee+/ve+/vQDvv71B77+9CsKC77+9yaEFHW1o77+9fGYBQQEm77+977+977+9JcaF0q04cUXvv70I77+977+977+977+9Iu+/vQtDSRtJ77+977+977+9We+/vWXvv71d77+9Du+/ve+/vRkeBmzvv73vv73vv73XnO+/vSHvv71K77+9LWIbIu+/vUIUR++/vWrvv70X77+977+977+9JCPvv71aau+/vcO1Tu+/vSdPTNOo77+9QDTvv71cDu+/ve+/ve+/ve+/vTzvv73vv73vv73vv73vv70VZADagyUzI++/vRcz77+9Ye+/ve+/vQFVAu+/vdqU7JSBZu+/vSV20Jrvv73vv73vv70sfSPvv73vv71vMFMl77+9Ze+/vVvvv71f77+9a++/ve+/ve+/vW5O77+977+977+977+9de+/ve+/vRLvv71CZO+/ve+/vXgF77+9cu+/vQACACAwIu+/vUZMKQDvv73vv71B77+9zbXSoO+/vWlwcXV277+9az3vv73vv73vv71g77+977+977+9UkLVpBs4WEfvv70SQAJj77+977+9IXTvv70CABd877+9QMmG77+9Wu+/vWDvv71m77+977+977+9AO+/ve+/ve+/vRggAgAMBFTvv71ZHwxY77+9DFBg77+9RkZiBB4eGQME77+9eGQkEAQ6ImHvv71GIDJEZu+/ve+/vUHhgYNBRUDvv70DAzQI77+977+9EAAR77+9EB9l77+977+977+977+9SO+/vQcLDhkIee+/vREA77+977+9AgPvv70ZPGLvv73vv70NX++/vW7vv71b77+977+9dysVKe+/vVNEP1jvv73vv73vv73vv71bAB1hPx0V77+977+9BO+/vSZzNe+/vQDvv717d3Hvv73vv73vv70bVO+/vVnvv73Wre+/vWfvv73vv70777+977+977+9Xu+/ve+/ve+/ve+/ve+/vT3vv70v77+9Ge+/vRwz77+924Tvv70ERQBCw4Dvv73dre+/ve+/vSAQMRAAAAAAEO+/vQADBgAGFkzvv71YVWHvv70K77+977+9cu+/vTBBDWRTSnM477+9Pu+/ve+/vWbvv73vv73vv711b1Dvv70cCu+/vUAMMigpYu+/vS7vv73vv71AGAggYUDQgBAVAu+/vRcy77+977+977+977+9BDgxKFTvv73vv73vv70I77+9TCgbRQFCCe+/vQhtbT/vv71077+9DwtQTu+/vQPvv70DDgsMEEwyGlDvv70iZB0w77+9ee+/vX9hA++/vQJAE++/vWMA77+977+977+9ZiUQ77+9THpsQwHvv73vv70GAAnvv70gNhJs77+977+977+977+977+9Qe+/vXJZ77+977+977+9EQMA77+977+9ZAgCGFweYO+/vQrvv70DFe+/vVzvv70i77+9Ju+/vciIBe+/vTAoRxvvv73vv73vv73vv70uNMeNXe+/ve+/vQBk77+9Te+/vTrvv70QAe+/ve+/ve+/vSBC77+977+9NAYkHzDvv71o77+977+9EF7vv73vv73vv73vv73vv73vv73vv71hSO+/ve+/vTfvv73Ese+/vX42GABfCiJAFUV077+9BgAR77+9VyY6Se+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vXteX++/ve+/ve+/vVnvv70P77+9Eu+/ve+/ve+/ve+/vT7vv703UW/vv71u77+9zp/vv73vv71QyZXvv73vv73vv71KxIwAABwR77+9dO+/ve+/vRFhTR8EGOmEl2lm77+9RBQm77+977+977+977+9De+/ve+/vVXvv71T77+977+9AArvv73vv71pUO+/vTPvv701ajFFS2Lvv71677+9M++/ve+/vXnvv73vv73vv70877+977+9Pu+/vTDvv73vv71N77+977+9KnLvv71TFzDvv73vv73vv71i77+9fO+/vW8I77+9Te+/vc2yWBRr77+9aO+/ve+/vdmCRF3vv73vv73vv73vv73vv71h77+9bjLvv73vv73vv73vv71G77+9Z0Xvv716Yk/vv73ToTXvv70T77+9VW5Z77+9XGXvv73vv71e3bXvv713O0l+77+977+9Gu+/ve+/vSVsL2fvv71e77+9e++/vR/vv71Pbe+/vQ3lv7Hvv73vv73vv73vv73vv71fY1/vv71+fe+/vUkv77+977+9Wu+/vTcnPu+/vS5lWu+/vTvvv70Teu+/vVYGKiJCAQge77+977+977+977+9Q0lqOe+/vfC2q5lXPT85f05CY++/vXBafe+/vSLvv70Z77+9fzISRiYm77+9N++/vUwW77+977+977+9Bu+/vT5WGe+/ve+/vW5l77+977+9DO+/vTjvv716MzMsWe+/vRzvv73vv70JJe+/vTEVXe+/vSB277+977+9Ju+/vRrvv73vv73vv71ERh9a77+977+9WhDvv73Eo++/vUsV77+977+9dO+/vXnvv73vv7100ZhW77+977+9KWhRbF8r77+93q/vv73vv73Lrz1TFe+/ve+/veamvu+/vdqt77+9Z++/ve+/ve+/ve+/vW0777+9bXp677+9FFUlZ++/vUw337Xvv70AAAFI77+977+977+9XmwrTu+/ve+/vVLvv71OyZENFe+/vWJOdC0NPVXvv73vv73vv71QSghJUiEj77+977+9Axgsw6zvv70yVkoJ77+9M3VQX++/ve+/vVPvv71IUVzCnENQ77+9U++/vUXvv73vv73vv73vv70j77+977+977+9e0MH77+9eu+/ve+/vS/vv73vv73vv73vv71hL++/vR3vv73vv70aFe+/vWXvv70bMEEAFe+/ve+/vXJ6OO+/vVU3UeSyue+/ve+/vWh1WO+/vW1+24Mc77+9OO+/vRnVmu+/ve+/vRFJ77+977+9Wu+/ve+/vUrvv70oGe+/ve+/vX1f1Z7vv73vv71+X++/vR5eRFkX77+9Su+/ve+/ve+/ve+/ve+/vQBAIAp077+977+9dO+/ve+/vXBISQscZu+/vTwrTCNRWD0IB0rvv73vv71FGldt77+9IyRTx6nvv70JVhbvv73vv71hOxjvv73vv73vv73vv70U77+977+977+9Xu+/ve+/vWhM77+9M++/vRLQue+/ve+/ve+/ve+/vRMh77+9Ee+/vT3vv73vv71777+9KW/vv73vv73equ+/vUkGJu+/ve+/ve+/vSDvv73vv71adu+/vcKudu+/ve+/vQ1077+9cu+/ve+/vVYtAGMf77+977+9IO+/vU5J77+9bxgWAO+/vU7vv73vv73vv70zdj9d77+9D++/ve+/vTDvv71+yZTvv718e++/vXkY77+977+9au+/vUUAAAAAAAFpCu+/vRloTRocbBHvv71eIO+/ve+/vRrvv73vv73vv70FWnrvv71l77+9SO+/vUJpEe+/ve+/vQTvv73vv70Oanvvv73vv70AOO+/ve+/vSRELDQL77+9RkU877+9A1gc77+9VzLvv73vv71l77+977+977+977+9USMJYnE0YO+/vQ0fFe+/vRtg77+9NihC77+9Bu+/vXBQSEocbQk5AO+/vU3vv70ZWwrvv71o77+977+977+92Ifvv73vv73vv71P77+977+9Ku+/vVbvv71W77+9NWbvv71D77+9VGoR77+9AwRp77+977+977+977+9zL7vv70277+9GEtg77+9cHzvv73vv73vv73vv71O77+977+977+9R0fvv709NO+/vXcuaO+/vVHvv73vv71O77+977+9Ue+/vXACK2zav++/vVbvv73DqQA9Ku+/vWJz77+9PSzYgkfvv71LCO+/ve+/ve+/vSxf2Js+77+977+977+9U++/ve+/vWMyKc22RO+/vQPvv71W77+9XRbvv73vv70y77+9NkHvv716MtaS77+977+977+9J++/ve+/ve+/vTLvv71LaWMu77+977+9LO+/vWozRBsE77+9KgHvv70xWxTvv71V77+977+977+9Ce+/ve+/vR0NIDDvv70g77+9XTsx77+977+9GDbvv706Ou+/vXwk77+9Ou+/ve+/vTLvv71J77+977+9WUYRCOCose+/vXZWOlXvv71q77+9JUnvv71J77+977+977+977+977+977+9bxMba1tjKtW977+9Fe+/vQAMdVsMcUVp77+9M++/ve+/ve+/ve+/vRDvv73vv73vv73vv73vv73vv73vv70yFMiJ77+9Ynrvv70WHibvv71S77+977+9YCgsIwLvv73vv70G77+9U++/vUzvv71S77+9EdSCAu+/ve+/vVjvv73vv71W77+9AFzvv73vv73vv70b77+9Iw7vv701GnAdUu+/vU7vv73vv73vv71hbe+/vX7vv73vv70k77+9TDN077+977+977+9HMqh77+977+9YxZ8GVUTESjvv70SNu+/ve+/vXbvv702V3rvv73vv71X77+9VyELGXHvv73vv70RCO+/ve+/ve+/vW7vv73vv73vv73vv73vv71hFl8pVGXvv70b77+9MO+/ve+/vTwsMO+/vRHvv73vv70X77+9ShAAXF/vv71+6quMAFDvv73vv71ZHVUwL0IYMO+/vUjvv70AVADvv73vv73vv73vv70xXmvvv73vv71577+977+9HBQC77+9VzAyN0A0bCow77+977+977+977+9bwHvv73vv709QO+/vTE6QnwlKCXvv70xOO+/vQXvv70UKu+/vWVNJsK3N++/vQ4BEtSj77+9ZGJBDgTvv73vv70w77+9GdqLWe+/ve+/ve+/ve+/vUTVg++/vQ4877+9Ve+/vWVlWXJa77+92r8tX++/ve+/vXpm77+9Od2z77+977+9Z2/vv73vv70j77+977+977+9aO+/vR/vv73dmAnvv73vv73vv73vv73Xp++/ve+/vUPvv73vv70jMhIc77+9KTPUlu+/vUILQAAAA2FpMO+/ve+/vS0CShPvv70EbWrvv73vv73vv70CEQVf77+9dO+/ve+/vX0T77+977+9Lhrvv71G77+9Ie+/vQjvv71IEmLvv73vv73fuSwZQCJo77+9XXbvv73vv70CSGxLQmbvv73vv70Tae+/vVM6bu+/vRdsShEC77+9Je+/vXzvv71o77+977+9zLTvv70YWO+/ve+/vULvv70he3Vc1odp77+925rvv73vv73vv73vv73vv73vv73vv71SZu+/vRUI77+9Du+/vQ4EUe+/vSFC77+977+9J18v77+9fHPvv71VEO+/ve+/vXXvv70n77+977+977+9PE/vv71/77+9Z0vvv70F77+9Eu+/ve+/vVloXAvvv73vv70q77+9OEM6GVPvv711AxxV77+9G++/ve+/vVDvv73vv73vv70VZO+/vQDvv73vv73vv73vv73vv70I77+9HHjvv73vv71DFCYvdDZPZO+/vSzvv71dWBDvv70mbGFsEmHvv73vv73vv70p77+977+9RmIvHCHvv73OtRfvv70q77+9JArvv73vv73vv73vv71A77+977+977+977+9P++/ve+/vTUu77+9Ve+/ve+/vUvvv70277+9al3LnWbvv712fO+/ve+/ve+/vcKZ77+9f++/ve+/ve+/ve+/vWwXAu+/vV/vv71E77+977+977+977+9xJIB77+9ZX9JTDEY77+9eCJoTe+/ve+/ve+/vWosNu+/vS/vv71K77+9Se+/vR8gJDQK77+9FlZa77+9C++/vQAYOHDvv71hNSDvv71BE++/vWzvv71YDHzIgEgDWFgd77+91IIyBe+/vWHvv71C77+9wrHvv73vv70a77+977+977+9Iu+/ve+/ve+/vRDvv73vv71C77+9Eu+/vWgICGbvv71mABDvv70+77+9bO+/vQvvv73vv73FsBkDfe+/ve+/ve+/vQEF77+9dNKyH2rvv71E77+9Gn7vv71bY++/vWDvv73vv716MhYhG++/vT0P77+977+9RWrvv70XUu+/ve+/vVDvv73vv71Q77+9VWFvWe+/ve+/vS7vv73vv73vv73vv70/77+977+977+9E++/ve+/vT3vv70WEAkaBTDvv73vv70wVe+/ve+/vQIU77+977+9De+/vUPvv73vv71c77+977+9ADbvv71UyIAB77+977+977+977+977+9FwxYMQgg77+977+9chHloolMCCMy77+9UFPvv71aUe+/ve+/vXnvv70+77+9KmpMxZINDi5S77+9YO+/vUMzy6rvv73vv73vv73vv71FK0Lvv73vv73vv73vv71x77+977+9Mm4iATA+77+9amTvv73vv73vv73vv73vv70y77+9RnlDLe+/ve+/vd6tUEZi77+9WO+/vS/vv73vv73vv73vv71CDu+/vXrvv73vv70i77+9IUTvv73vv73vv73vv70jfU7vv70mRe+/ve+/ve+/vTNs77+977+977+9EABtBu+/vSsmUu+/vSoAAO+/vREyTe+/vWPMtO+/ve+/vTkJ77+9VA0qSu+/vSDvv73vv73vv71E77+977+9ee+/vQRk77+977+9zIfMmd+sbRzvv73vv70w77+977+9I++/vQQZ77+9Ru+/ve+/vTwgOFkLBe+/vTEW77+977+977+977+977+9xLvvv70UcRE8TW0N77+9Ru+/vWfNpO+/vRAx77+9SO+/vVFHdO+/vRJy77+977+9bUbvv73vv73vv73vv71xXCkENRHvv73vv73vv70J77+977+9Eu+/ve+/ve+/vXPvv71mGO+/ve+/ve+/vWBA77+977+977+9Ue+/vSok77+9R++/ve+/ve+/ve+/vVnvv73vv73vv71x77+9KDUP77+977+9Mg4P77+9FO+/ve+/ve+/ve+/ve+/vX/vv73vv70JEu+/ve+/vVroirTvv73VmSLvv73vv71aQGkGYAcUQQ7vv71t77+9D++/vTXvv73vv70CUSJ4M1Jh77+977+9KT8477+9EzNiCizvv73vv73vv73vv73vv73vv73vv73vv73cju+/vRFp77+9Ve+/vRrvv70lTgEg77+9SO+/vRjvv70C77+977+977+977+9BClW77+9UO+/ve+/ve+/vVAw77+9TTkLXmLvv71hZFDvv73vv73vv73vv73vv70CAO+/ve+/ve+/ve+/ve+/vURnU++/ve+/vRdJ77+9WCfvv70fSEPvv73vv71g77+9QQAo77+9We+/vQ5EdO+/vVXvv70rMu+/vVt+VO+/ve+/vV3vv71NR++/vXHvv73vv73vv71p77+9UADvv71p77+9FO+/vcmd77+9Fe+/ve+/ve+/vXHvv71BMErvv70NAe+/ve+/vQAREStT77+9WiEo77+977+9ZS0077+977+977+977+977+9Mu+/ve+/ve+/ve+/ve+/vS3vv73vv714XAMTfUbvv70QAAUMYCIGYRNOZO+/vcenUu+/vUhwSCYwxoDvv70RTu+/vRQB0o7vv708IHciOUjvv70x77+9CETvv70UOO+/vTVA77+9bFV777+9KO+/vVLvv73vv70kIu+/vVFQSCRc77+9a++/vQw177+9Qu+/vRl0AO+/vcKSXe+/vWBtEVM377+977+977+977+977+9A++/vSFPNm0VHO+/vS/vv71lSe+/ve+/ve+/ve+/vRzvv70rW8eZ77+9Le+/ve+/vVlHN++/vRjvv71MAnDvv70x77+977+9Ee+/vSkYUu+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vWfvv70sBngWNX8SMu+/vVLvv73vv71GRO+/vVcnFwTvv73vv71Z77+9Ze+/vX3vv73vv73vv73vv71t77+9M++/vVlh77+977+9De+/vRNb77+9PFfvv70277+9BgXvv73Nqu+/ve+/ve+/vVrvv71977+977+9eO+/vRXvv70QKDonNEUw77+977+9UHMswqPvv71R77+977+9BgcC77+9JjEy77+9FhsyaUwE77+9CCrvv73vv73vv71gIe+/vQgF77+977+9KTLvv71I77+9EiDvv73vv70GYFFqPxlc77+977+9JRvvv70w77+977+977+9D++/vVDvv70AEu+/ve+/vQHvv73vv702M++/ve+/vREg77+977+9Mu+/vVB1eu+/vU3vv70JSAXvv70qACEkZjLvv71HJQMWbO+/vUJhyoEF77+9d++/ve+/ve+/vQsj77+9A2cN77+977+9RWc777+977+977+977+9Uu+/ve+/vVrvv71K77+977+977+9Ve+/ve+/vR1iKe+/ve+/vQ56Ywg977+977+9QwdQ77+9DlDvv70OAwNRNC1E77+9dO+/vdWW77+977+9N2rQsznvv73vv73vv71SUe+/vU0jE++/vT1s77+977+977+9DBtW77+977+9ADwRUO+/vRMTM++/vQBSAS0g77+9aCBsKC4BFk3vv71AcHHvv73vv70Y77+9cBnvv71077+977+9Ge+/vRHvv73vv71A77+9ee+/vQ/vv71J77+9Ygo9ECkJQBUF77+977+9Fu+/vVLvv70DQA/vv714QSFBYEMIOO+/ve+/ve+/ve+/ve+/vQHvv73vv73vv70szJnvv73vv71E77+977+9Bcy2aTAh77+9ce+/vWTvv70k77+977+977+977+9EH3vv73vv71XbUBRBO+/ve+/vWFM77+977+9bO+/ve+/ve+/ve+/ve+/vWUV77+977+9xL5X77+9J++/vW1B77+9L0sh77+90ovvv71177+977+9FAzvv71VdW/vv73vv73vv73vv71a77+977+977+9Mu+/vSrvv73vv73vv70jYwzvv71SJ++/vcqU77+9V05R77+977+9ee+/vW/vv71/77+977+977+977+977+977+9TXvvv73WsStOOFrvv73vv71z57+KCwdA77+977+977+9Qe+/vSRxGO+/vXwz77+9DAgTPCwYAO+/vRMxIe+/vSExGO+/vSZQQCTvv70ME2wqLO+/vSZMcBoT77+9Egnvv70IIFB977+977+977+9ZO+/ve+/vUPvv71R77+9FEpWQAnvv71K77+93KTvv71h77+9Y++/vShMVWHZu+qsiu+/vSNW77+977+9MGLvv73vv71N77+9d++/ve+/vT8zz6vvv73vv71fNcym8b2Fn++/ve+/ve+/ve+/ve+/ve+/ve+/vVtdK2/al0Zm77+9SwcE77+9FwTvv70DzbzUvO+/vVrvv73vv73bvu+/ve+/vW0I77+9Eu+/vW5E77+9du+/ve+/vTk877+9V2zvv73vv73vv71vRe+/ve+/vQIVyZTvv73vv70F77+977+9EUnvv73vv70Y77+9We+/ve+/vRIW77+9N++/vRDvv71oLO+/vWHvv73vv70w77+9TAzvv73vv73vv73vv73vv73vv70MTO+/ve+/ve+/vUzvv70077+977+977+977+9NmUKUDXvv70sMu+/ve+/ve+/ve+/vVDvv70m77+977+93Izvv70iA++/vX0G77+9bxDvv71M77+977+9FS4C77+9MTVgXu+/ve+/ve+/ve+/ve+/ve+/ve+/vQHvv73vv71bKk3vv73vv71K07FmKe+/vS/JiO+/vQEI77+977+977+9CEzvv71LItWVWTph77+9YFhzJe+/ve+/ve+/vTxPW3nvv71677+9aO+/vVbvv70h77+9SyxLLO+/ve+/vVVI77+9X++/vSp+77+977+977+9VXXvv73vv73Lo++/vWMTBAhhQTAy77+9IO+/vR5FMu+/vSo2D2Mh77+9TO+/ve+/vUnvv71rQTvvv71J77+9KO+/ve+/vR3vv73vv70j77+9w6jvv73umqt+bu+/vUjvv71QOe+/ve+/vQHvv71YEQlSAe+/ve+/vQ01QFTvv70ALjnvv71GLwQ5Ie+/vSwKZmfvv73vv73vv73vv71V77+9BUxq77+9CFQMRO+/vVDvv73vv70MWkrvv71f77+9FGAC77+9ae+/ve+/ve+/vRhBY2Z1w5ZE77+9GDQoElJaEu+/vTlJ77+977+9Su+/vTAjKlVlIBBwEBlEFe+/vWAMAO+/ve+/vW3vv71IYU8177+9ZkEt77+977+977+977+9Re+/vXbvv70z77+977+9FDTvv713CBxKKQ/vv73fo3bvv73vv73vv73vv73vv70bJO+/vWRSEkokUg/vv73ZmO+/vSPvv73vv71bMzZmzJTvv71d77+9Hu+/ve+/ve+/vTHvv715Ih7vv71n77+9Hmbvv73vv73vv73vv73vv71b77+977+977+9O++/ve+/ve+/vSnvv73vv70CIiTvv73vv70lE8aQ77+9IzAH77+977+977+9JMqBUMKL77+9OhNRCRUB77+9De+/vQ0gF2E2Y++/vQXvv704ZD5fOkcwSVVi77+9EO+/ve+/vW9h77+9ICwR77+9QkoICANIfu+/vTVp77+977+9YALvv70WUhkKCGPvv73vv73vv73vv73vv73vv73vv715cSYt5bGbITEk77+977+9P++/vQjvv73vv70v77+9ZnNV77+977+9HO+/vSY4LQg4OhDphYxfypc377+977+9esuOHmrvv73vv73vv70O77+977+9MTV7OO+/vTAyTWJK77+9JHPvv71l77+977+9N++/ve+/ve+/vRc9W++/vR/vv73vv73vv73vv70MNg0H77+9Rhjvv73vv70/HhQmFe+/vWbvv71577+977+977+977+9K++/vUvvv73vv71C77+977+977+9I++/ve+/vSHvv70J77+9Ny/vv73vv70+77+977+977+9AO+/ve+/vTl4Au+/ve+/vQEu2bB477+9MVDvv71F77+9Y++/ve+/ve+/vVvvv70zHzAX77+9Le+/vR3vv70PL3gZKO+/vQTvv715YUbvv70zBlkJdS96Gu+/vW0T77+90qYWHe+/vUx0IBE0EULvv70YQO+/vQMOXWoK77+977+9Ue+/vSY4Wu+/vVgQJkzUlO+/vRJMQ++/vTALEu+/vXpkdu+/vWUDWh55OO+/vVzvv71DIe+/ve+/ve+/vR7vv70jfVDvv706PREkAiHvv70y3LDvv73vv70677+9L++/vW9077+977+9a++/vWt477+9KO+/vVvvv71S77+977+9Ukbvv73vv73vv73vv70YDVPvv71XT07vv73vv71xee+/ve+/vSBx2aDvv71E77+9P2Pvv71/77+977+9H3bvv73vv71oJ++/vXTvv73vv73vv70AAy1wHu+/vSdG77+977+977+9KhVV77+9FxQA77+9BRMxU0kSN0vvv73vv73vv73vv73vv71y77+9au+/vSHvv70ACwYGRGPvv73vv73vv71VRu+/ve+/vWxRSlso77+9VFQMHO+/ve+/vQbvv71UAu+/ve+/vUsCdy0r77+9A0o3Ie+/ve+/ve+/ve+/ve+/vQHvv71xeyotZW3vv70RMe+/vVXvv73vv73vv71X77+977+9Ne+/vWPvv73vv73vv7111aXvv708bBLvv70HH3fvv71OHe+/ve+/ve+/ve+/vXvvv71wY1AC77+9ae+/ve+/ve+/vVrvv73vv73vv70SAwBl77+9FAbvv73vv70K77+9KO+/vQYTR2Pvv73vv70REEQBd++/vTHNo++/ve+/vXDvv70jEGTvv73vv712R++/vUXvv71eSARMQu+/vT8xZQBob++/vQ3vv73vv70F77+9dRRRNRnCmCLvv73vv70GKSZ/37fvv70hHlcOJUUzbmxEM17vv70QB++/vVnvv70E77+977+9dBvvv73vv73vv70yCO+/vWDvv73vv712FcaQ3ovvv73vv71/77+977+9RhLvv73vv73Nuu+/vU/RrFjvv73vv704KREMSe+/vS7vv73vv71OUlUu77+9Fhbvv73vv73vv70f77+977+977+9dMiPVe+/vQjvv70CXlrvv73vv71277+977+977+9XTooThQ077+9CTHvv73vv71t2Yg706JO77+9F0F00KXvv73vv71xIO+/ve+/vUkNZDkGE2jvv70nZG7vv73vv70jC++/ve+/vWFwcu+/vVgEQu+/vREnGk8KEQclKj3vv73FoTJrwqbvv73hjJ0Q77+9Ee+/ve+/ve+/vQgVHu+/ve+/vQER77+9UmoR77+9FgIH77+9Au+/vQkIUe+/ve+/ve+/vQbvv71t77+9AA/vv73vv70mLAly77+9UQzvv70zDhQgUnwF1Znvv70mbHgI77+977+977+9I++/vWcQ77+9UCHvv71KBwbvv70KQO+/vQkQ77+977+9GO+/vRnvv70B77+9CgIc77+977+9Be+/vUfvv73Vpxzvv70nfh3vv73vv73vv73vv73vv73vv70F77+9Ku+/ve+/vcye77+977+9IO+/vWfvv73vv73vv71c77+9bu+/vdSocO+/ve+/ve+/ve+/ve+/vQ4jRUZ2TO+/ve+/vVjvv73vv73GpQ3Fk++/ve+/ve+/vTAw77+9YciR77+977+9WVjvv71b77+977+9QzHvv71SHGgXLVXvv73vv701N++/vWXvv73vv70e77+9PxB7KO+/ve+/vSzvv709eu+/vUAAExI3Au+/ve+/vSYg77+977+977+9MO+/ve+/ve+/vdOtNyLvv71A77+9Ue+/vTXvv71+Iy93JVTvv70p77+977+9a++/ve+/vWnvv73vv71z77+977+977+9RRPvv71I77+9V34fay/vv71g77+9du+/vc6677+9dO+/ve+/ve+/ve+/vTzvv70bS14477+9CO+/vTgiUGXvv73vv73vv71C77+9Me+/vWQgcAYB77+9M++/ve+/vQQCCTFozLLvv70QQO+/ve+/ve+/vSnvv70UTu+/ve+/vQPvv70677+9RFcAW82oMAhjQXDvv71oEu+/vW3vv70OPDw0Te+/ve+/vR0hTEcI77+9Shjvv73arDDvv70N77+977+9QAjOn0Pvv73vv71Wad+CTgQgMu+/vVwQaCMiXVoM77+977+9Ue+/vQQA77+9FghK77+9QFDGkO+/vUIx77+9AAfvv71xUADvv70GEGp0F8i377+977+977+9IDxAEgvvv70GGu+/vQPvv70V77+977+977+977+9RXXUke+/vRAu77+977+9a2zvv71VxqZVAClg77+9Mhbvv73vv70U77+977+977+977+9W++/ve+/ve+/ve+/vUdCFB3vv70oPHl/77+977+977+977+977+977+9Cl0f77+977+9W++/vT8t77+977+977+9H17vv73vv71j77+9Pu+/vV1bMgHvv73vv73vv73EoQBnSe+/vTTvv71rHu+/ve+/ve+/ve+/ve+/vTPJie+/vTc577+977+977+977+977+9Ru+/vWxP77+977+9He+/ve+/ve+/vVzgvZdY77+977+977+977+977+977+977+9au+/ve+/ve+/ve+/ve+/ve+/vRnvv73vv73vv73vv73vv70377+977+977+977+9I++/vcKuZe+/ve+/vQLvv70j77+9QO+/vR3vv73vv71DVu+/vXDvv71X77+9FSvvv71TQ3Dvv70Y77+977+9a3tK77+9TO+/ve+/ve+/ve+/vQ/Mglzvv73vv73vv707Ge+/vUdq77+9w4Tvv71HBgnvv73vv70xCO+/ve+/ve+/vXjvv71a77+977+9eu+/ve+/vQQGEOq+kcOH77+9N++/ve+/vVDvv71q77+9LnLvv73vv71477+9Odi6Xu+/vRbvv71mTu+/vTE577+977+9H1J977+977+9RE4AACIu77+9XEnvv71m77+9bh3vv73vv70LKRPvv71xFe+/vV7vv71e77+9U++/vS8bL++/ve+/vUtvTX3vv700xJjWvO+/ve+/ve+/ve+/vXnvv706wo9L2o3vv71mWW9g77+977+9GnF3MU7vv73vv70c77+9G++/vTPvv71+77+977+9ee+/vUkrNkBa77+9Fu+/vTrvv71077+9zY1KVcKX77+977+977+9bO+/ve+/vVQNee+/vWYMKe+/vXfvv73vv73vv73El1MA77+9QO+/vXQ977+9OO+/vU9077+9GC7vv71If2QP77+93K3vv71d77+977+9YO+/vRlZQEYmB++/vTDvv73vv71sRjbvv71SDO+/ve+/ve+/vWzvv71gaO+/vXsMFe+/vTXvv73vv73vv73vv70777+9xadu77+9X2Xvv70zW++/ve+/vciA77+9UlrIte+/vW5O77+977+977+977+9Ou+/vQpr77+9BjMkeSnvv73vv70X2a/vv71p77+977+977+977+977+9c++/ve+/vV3vv71P77+977+9Pu+/ve+/vWo477+977+977+9aO+/vTvvv73vv71r77+977+9Y++/ve+/vSNvd++/vXXvv70177+9MCM4KmMyKGA577+9MjNT77+9JTQO77+9RWHvv73vv73vv73vv73Jt0nvv71QVO+/vVESyokI77+977+977+9Cu+/ve+/ve+/vRE+V1Pvv73vv73vv70IJX/vv71YzaTvv71gYSxR77+9ZyxB0rDvv70077+9dO+/ve+/ve+/vVrvv71F77+977+977+9UkpcWWRO77+977+9ahggCwEE77+977+9K++/vWBh77+9LBtGaTDvv73agNyb77+9FwZk77+977+977+9b1FX77+9ISXvv73vv71NHO+/ve+/ve+/vdyadE8AAAdO77+9RTlHUe+/vXfvv70n77+9E3Rr77+9JVTvv71nYO+/ve+/vWZzRiByYO+/vWrHnUMyYt2lKSZ+cRXvv711RUQsRe+/ve+/ve+/vXDvv73vv70z77+977+9be+/vSoR77+977+9f++/vQxT77+977+9EO+/vWHvv70rUxFhChNSTgjvv70lUATvv73vv71dBe+/ve+/vVTvv73vv73vv70WI++/vUgt77+977+9BQgu77+977+9MDcZDu+/ve+/ve+/vTpP77+9LV5rOl3vv73vv71Lajp4au+/ve+/vUMy77+9dwXvv70p77+9eO+/vdubCnFBK++/vX1gyavvv73vv73vv71N77+977+9cu+/vQs+77+9ZNyyQu+/vWTvv73qu7wzKhnvv70A77+9cC7vv718fh0j77+977+9I0Tvv73vv703GAXFpe+/ve+/vRXvv70u77+977+977+9MXNEO1ZV157vv73vv73vv713aO+/ve+/vRzvv73WuVHvv71Q77+977+9QO+/ve+/ve+/ve+/ve+/vXsAVu+/vX1Tx43vv70K77+9Me+/vXjvv70+Ku+/ve+/ve+/vUQ9HO+/ve+/vXQpTnTvv71OAyDvv71N77+9Qe+/ve+/vRPMhw/vv73vv70nx6gF77+9XQN4eC4H77+977+977+905lYTe+/vWXvv70I77+9QXRd77+9BEkuJELvv70u77+977+9bTwIKXZ0SRpY77+977+9UnXvv71V0ple77+977+977+9eu+/vV5877+9K2w2aO+/vRnvv70KAyPvv71U77+977+9Ce+/ve+/ve+/vXvPth1b77+977+977+9MO+/vQHvv73vv73vv71577+977+977+977+9zLvvv71CKAAAFDdMQ++/ve+/ve+/ve+/ve+/vW/vv73vv73vv73vv71sI++/vQEFUe+/vSTvv70nOe+/ve+/vS8mMijvv71+c2Lvv71W77+9OCPvv73vv71I77+9NO+/ve+/ve+/vSFQ77+977+977+9JyPvv73vv71O77+977+9Ru+/vWkxS++/vVwfJe+/vTBu77+9Ce+/vdSrLiTvv71HU++/vTAJ77+9cgDvv70HMDVB77+9UQ1VAEbvv73vv73vv71i77+90oTvv73vv70a77+9DDrvv73vv73vv70dQu+/vXAwJ++/vQplAVrvv71o77+977+9WBHvv73vv73vv71KS++/vRNp77+977+9GwVTKwLvv73vv70777+977+9WGzvv71l77+9Iu+/vTN777+9MUjvv73vv71777+9UH7vv73Ksw7vv73vv70xSe+/vSkGMXzvv73vv71m77+9au+/vUhEABHvv73vv73vv70ME2zvv70a77+9cnDvv70777+9WEvvv71+EzgA77+977+9Wu+/vSjYl++/vUZz77+9H96abiVR77+9KAxpNO+/ve+/vQbvv73FgRh5Je+/vQI577+9Xyzvv73vv73vv71e77+9HQHvv71S77+977+977+9xIcAWGltT8el77+977+98a2puO+/vT3vv70C77+9QQQE77+9G++/vdaIFhci77+9bxIQG++/ve+/ve+/vQDvv70K77+9RS3vv71kHSDvv70SEu+/ve+/ve+/vQvvv71U77+9KO+/vUTvv70mTu+/vXI4IkXvv73vv71SR1ErXu+/ve+/ve+/ve+/vc6EIe+/vWpX77+9au+/ve+/vTLbk2ZOVxjvv71277+9LAg577+977+9b++/vTXvv70jY++/vVd777+977+9eO+/ve+/ve+/ve+/vTrvv70yaDTvv71wS++/ve+/vXnvv71qcQEAAAAv77+9GO+/ve+/vUhkLe+/vRh3Ve+/ve+/ve+/vSfvv73vv71c77+9Qiw4fO+/vXzvv73vv70na1Jo77+977+977+9eWPvv70477+977+9Cu+/ve+/ve+/ve+/vXnKuO+/vWfvv70zVXTvv713LO+/vU1q77+9ee+/vV7vv73vv73vv70/TxDvv70MYXxy77+977+9Cu+/vV46RglgFe+/ve+/vQxQEU5LPmoJMCfvv73vv71k77+9Qu+/vU8D77+977+9OO+/ve+/vV4177+9K2jvv73vv73vv71m77+9VlgHMzwILRvvv703Wn12GO+/vWFaFGtl77+977+9FF1BxaDvv70v77+977+9a3zvv73vv70uF++/vRVi77+9X++/vSZz77+9AO+/ve+/vRY8WRR1Ie+/vSPJhe+/ve+/vQZZfu+/ve+/vVUy77+9J++/ve+/ve+/ve+/vWda77+9W03vv73vv73vv71fVu+/vXcu77+977+9fWcH77+9KzLvv71b77+977+9exHvv70GZe+/vRjvv71D77+9Su+/vRLvv70vFe+/vTHvv73vv70rVUpZ77+977+915dsDO+/vWzvv70G77+977+977+977+9EO+/vVctPCDvv70677+977+9DO+/vXfvv73vv73vv73Eje+/ve+/ve+/vU1Hx5nvv70K77+9KmYQ77+9M8iHV++/vXrvv73vv73vv713Gu+/vdif77+9Ze+/vTDdlQdQCGzvv73vv71O77+9CioeGUDvv71177+9aO+/ve+/vTPvv71KHS3vv71Z77+9UzHvv73vv712W3Pvv73vv70q77+977+9Au+/vWsGGO+/vSTvv71yFnDvv70x77+93YtE77+977+9PhTvv71HBGfvv73vv73Smu+/ve+/vXcZVO+/ve+/vT3vv71w77+977+977+977+9VO+/ve+/vXvvv70h77+977+977+977+9RD1d77+9fO+/ve+/ve+/vSVKVe+/vRPvv70177+977+9YO+/ve+/vXc7LjPvv73vv73vv71NHR4H77+9IlN2Cu+/ve+/vdqB77+9JS4q77+977+977+9au+/vVTvv73vv71g77+9DSR+77+977+977+977+9akzvv71uMu+/vUHvv73vv71FL++/vVjvv73vv71+77+977+977+9aty377+977+9bO+/ve+/vSwBNHJA77+977+9ee+/ve+/vdq6OO+/ve+/ve+/vUxEN++/ve+/vSJB77+9XEAV77+9DD7vv73vv73LlO+/vRvwkKqG77+977+9O++/ve+/ve+/vS/vv73vv71ZU9uv77+9Je+/vWN7Le+/ve+/vS3vv73vv71/77+977+9bu+/vU9LWu+/vSx377+977+9YgHvv70z77+9fgbvv71o77+977+92JTvv73svavvv73PtFnvv71F77+977+9K2ZgNu+/vXEx77+9PRxFAO+/ve+/ve+/vT9qZO+/ve+/ve+/vQPvv71U77+9ZO+/ve+/ve+/ve+/ve+/vdS177+9Qe+/ve+/vVF1yrPvv70tMh7vv73vv73vv705D++/vSUWKX7MtkEr77+9U13vv73vv73vv71q77+977+9fu+/vXbvv73vv70vM++/ve+/vWHvv70n77+9EO+/vWrvv71V77+977+977+9xKfvv73UrVEs77+977+977+9wqQoJRLvv73vv70AAO+/vVFhAAAB77+977+9M2lyQhlnE++/ve+/ve+/ve+/ve+/vQ4y77+9GHxOEOqfqgBlL0J8Ju+/vW4HOBnvv73phYjvv71GQwDvv71I77+977+977+9BUfvv73vv73vv70k77+92pjvv71R77+977+977+977+977+977+9SwTvv70SG2zvv70STO+/vXjvv71K77+9Ju+/ve+/vR3vv73vv70R77+977+9TyfNtWvvv71WKgUIQkLvv70IAe+/ve+/vUDvv73vv70q77+977+9CALvv71V77+9WRDvv73vv73vv70A77+977+977+9Bu+/vQrvv73vv70J77+977+977+977+977+9QQxcJCpCCQJ777+977+9yJo6Ag0AIgYiAA4HeVcCFEBM77+977+9Ahvvv73vv73vv71E77+9AEFBV++/ve+/ve+/ve+/vSkwSAg277+9awoC77+9Mg1XBEDvv71AOHzvv71oc3vvv73vv70gIBgh77+9Le+/vW1NWe+/vSpuYjjvv73vv73vv73vv70pU9OqF2dx77+977+9du+/vXDvv70IxYHvv71a77+977+977+9Bmjvv73vv73vv717Cknvv70V77+977+9T++/ve+/ve+/ve+/vXfvv73vv73vv71/Px5j77+977+977+9Eh/vv73vv73vv70nJe+/vTrvv73vv73vv73vv73vv73vv70QAAAAAABqRxvvv73vv73vv71Y77+977+9AGYN77+9L2Y977+9GO+/vQQJBe+/vSkkezkF77+9Igxwcu+/vRsz77+9YGYWAzIAdW4ZFiIGMhUjae+/vTLvv71xUO+/vXBp77+9CO+/vQIC77+9Bh44cO+/vcagXu+/vWYODAxOCu+/vQjCi++/vWbvv71mRO+/ve+/ve+/ve+/vcaAJWXvv70e77+977+977+9BO+/vTMl77+9Ne+/vQIuBgwRAe+/vQgEFO+/ve+/vSLvv70kGEzvv73RtnZb77+977+9GVnvv73vv70QAO+/ve+/vTAoWAAUCu+/ve+/ve+/vXQI77+977+9IGUUQ++/vV9a77+9VDoIFSwIC0Ykfu+/vTMWau+/vSrvv71I77+977+977+977+9Z2lE77+9DCAt77+977+977+9eBN577+9SkZs6qSS77+977+9Yu+/ve+/vdSqLRRyWlAO77+977+9AO+/vUDvv70tQ++/ve+/vUFU77+9U2rvv71QfBwS77+977+9QStKcjEDO++/ve+/ve+/vQLvv71b77+9WlXvv73vv70pbu+/ve+/ve+/vW5ADQAu77+977+977+9Wu+/vWV777+9Z++/ve+/vXMm77+9Se+/ve+/vRpY77+9ZlVLalXvv71e77+977+977+9De+/vXLvv73vv73vv73vv71j77+9Ke+/vcKpIO+/ve+/vU0b77+9Ae+/vUHvv73vv73vv73Yvu+/vVgAADZJ77+977+9fO+/vSrvv70477+977+9Vu+/vWtT77+977+9UCHvv713VMmG77+9Y10w77+977+9Le+/vVnvv70tJiDvv73vv73vv70d77+9RQIxNHdHJ++/vUN477+9cu+/vWYEOO+/ve+/ve+/vVPvv70VYkVh77+9Ye+/vQk3MwXvv73vv73vv73vv71C77+9DRXvv73vv73vv73vv73vv71v77+9Q++/ve+/vXDvv70xR++/vXHvv73vv70E77+977+92Yvvv71L77+9bHgzR09bemR/77+977+9VO+/vULvv73vv73Vqxvvv71377+977+9eu+/vfGltK3vv70h77+9dzTvv73vv71k77+977+9KN2OLFXvv70gBO+/ve+/vTxOQ3jvv70lI++/vVMEanRlHWkxSe+/ve+/ve+/ve+/vVoA0701PRzvv73vv70KZ++/ve+/vSHvv70PKETvv71N77+9xJpb77+9PxTvv71977+977+9IUfvv71FCCZMWBTvv73vv73vv71U77+9cn8o77+9NQ/vv70CSEgrDe+/vcOw77+9d2Hvv71n77+9fO+/ve+/vQtfeu+/vX5aOWU4FQXvv71H77+9bWkq77+9XUvvv71b6Yu9xrLvv73vv73vv71f77+977+977+9Fmt377+9b++/ve+/vQtg77+9dHjvv70qS++/ve+/ve+/vTM377+977+977+9IxPvv73vv71m77+977+9JO+/vXIa77+977+9TO+/ve+/ve+/vSrvv70EAAHvv710X1fvv73vv703de+/ve+/vRElQe+/vVl8Gu+/vSfvv73vv71u77+977+9ateXLljvv71977+9bu+/ve+/ve+/vQDvv70a77+977+977+9EMmHCu+/ve+/vdWF77+9U3Tvv70977+9Uj/FmAbvv71odh7vv73vv71C77+9BRbvv73vv73vv70v77+9cO+/vR8sCcqhUmHvv71eCO+/vSoSYmTvv73vv71e77+977+9Ve+/vScT77+9KC7vv73vv70lUO+/ve+/vW3vv73vv70v77+9E1Xvv73vv70uBu+/ve+/vR5SXu+/ve+/ve+/vWHvv73vv73vv71saljvv73vv71p77+977+9Zlnvv73vv71n77+9fxMnKu+/vRDvv71r77+9QQAAKu+/vWDvv71477+9ISXvv70L77+977+9WC8O77+977+9DkTvv701UzAZZe+/ve+/vRkl77+977+977+977+9ARfvv704GiAqHmDvv70277+977+9JlHvv71VBFFwEyQpDgXvv71iVQ4J77+977+9A3Ih77+977+977+9ME8aRO+/ve+/vVDvv71VVu+/ve+/ve+/ve+/ve+/vV7vv73vv73vv70Ayosv77+977+977+977+977+977+977+9xITvv73vv715aTUMMO+/ve+/vXcjJe+/ve+/vRsZcQ4p562L77+9awcj77+9Xcie77+9UUzvv71z77+977+977+977+9NEnvv71aIu+/vWnGkhPRjO+/vTZe77+9WO+/vR9aLmM0Ku+/vWjvv70177+977+977+9Tu+/vXDvv70AAAAAe++/vVHvv71xeO+/vQ9ETWZMWe+/vcqHCO+/ve+/vSTvv70u77+977+9YzlYd++/vWkqdu+/vXYWVUBG77+9aWkX77+9DGEM77+977+977+9ae+/vQTvv70U77+977+9ICHvv71HDUlQ77+977+977+977+977+93LJidmrvv73vv73vv73vv73RnC5S77+977+9Wk1o77+977+9GH7vv73vv70p77+9NFnvv73vv73vv71cae+/vQTvv70577+977+9au+/vVVi77+9cu+/vTbvv70677+977+9D0nvv73vv73vv71r77+977+977+9M8WF77+977+977+9KnUf6KmE77+9wovvv73vv73vv73vv71p77+9XUApW1nvv70p77+9R++/vUws77+977+9Xu+/ve+/ve+/vVfvv71P77+9TWbvv71L77+9G13vv71o77+9UO+/ve+/ve+/vVDvv73vv70nE1gpC++/vRLvv71RMSbvv70g77+9Fu+/ve+/vTrvv71JahTvv71OYO+/vVnvv71U77+977+977+9He+/vRZ0Bu+/ve+/vW/vv70a77+9Ewpy77+977+977+9WSgW77+9bV5E77+977+9Q++/vSJA77+9ZO+/ve+/ve+/vSXvv71FDXNpVe+/vQ5UUe+/vT7vv73vv70W77+977+977+9Pkzvv73vv73vv70WXiFH77+977+977+9SV0A77+9eldbSHLvv73vv73vv709RAAACu+/vUvvv702yZjvv70KFxZI77+977+9LAsBZwzvv70A77+977+9UO+/vQtI77+977+977+9xKoA77+977+9TSvvv70xGO+/vV3vv73vv70p77+977+9Ic2kTu+/ve+/vSxhShrvv70w77+9Eu+/ve+/vRTvv73vv70677+977+9Lu+/ve+/vU1Z77+9NO+/ve+/ve+/vSTvv71O77+9IyA+GiMnZO+/vQDvv71E77+977+977+9fu+/ve+/ve+/vUNU77+9Lirvv71p77+9aRxG77+9Jxrvv73vv71c77+977+9Nijvv70gde+/ve+/vVZr77+977+977+977+977+977+977+9Jh7vv71Kwpjvv707eu+/vXPvv73vv73vv73Iku+/ve+/vWzvv73vv70a77+977+9cu+/vVZy77+9eO+/vVEdC0kkEe+/vRktU++/vUxA77+9GMmC77+9ZiTvv71BMxoA77+977+9Du+/vWI0LkLvv70a77+9GBTGhC3vv73vv71RKWDvv70mHO+/ve+/vRZlShgmBu+/vWnvv71a77+9JjUASO+/vWcgMO+/vXF0HDXvv73vv71w77+9ae+/vWHFjyDvv73vv73vv73vv73Eou+/vd2JO++/ve+/vTlX77+9Yu+/ve+/ve+/ve+/ve+/vVYh77+9Wjbou64eHBnvv71AaD3Qqhzvv70977+9ATrvv73vv70w77+9NO+/vWoOUu+/vUsM77+977+9Yu+/ve+/vWHvv71v77+977+977+977+9UHkS1ptlZ++/ve+/vT3vv70s77+977+977+9Eu+/vSrvv73vv73vv73vv73vv71kQlrvv73vv70JIWbvv73vv73vv70NRU/vv71QYl/vv71sKiwD77+9AO+/ve+/vcadFlHvv70T77+9FUfvv73vv70mM++/vSDvv70h77+977+9UGFc77+9SEzvv71h77+9Sjk7Eynvv70y77+9VO+/vVRaYnTvv73vv70wUAp4K1Es77+9IHoZwrzvv73vv71zd3Ep77+977+977+9DBzvv70Ywr7vv70m77+977+977+977+91YHvv70BdSDvv70kWUMI77+9Ye+/ve+/vQ/vv70o77+977+9Se+/ve+/vQHvv73vv73vv73vv70sN1pEEO+/vXE277+9TVJaMjgcQ0l0U++/vWLvv70c77+977+9L2cP77+9VHrvv73vv71TY2Dvv73vv70VeXTvv73vv71z0qVZUWDvv73vv73vv71bBO+/ve+/vVXdpC7vv71n77+9Xsmq77+977+9el7vv70c77+977+9Un1Nfu+/ve+/ve+/ve+/vWzvv71s77+977+977+977+977+9AAJM3ZcDFAcyElgY77+977+9ATQW77+977+977+977+95oioCijvv73Zvn5777+9HBMLDO+/vQEN77+9EO+/ve+/vci277+977+9F0zvv73vv71Q77+977+977+977+9AULvv73vv70p77+91rI377+977+9MO+/vWXvv70qYu+/vVozGO+/vTARGO+/ve+/vSpZ77+9Ou+/ve+/ve+/vWsdZzLvv71877+9B++/vVrvv70u77+977+9JRPvv71ZWELZgMi977+9UOK0qO+/ve+/vc2X77+977+9I++/vUfvv71s77+9Zk5PFypT0rIXMVHvv73vv73vv71GWz1fDAvvv73vv73MrXkJGy7vv73vv73vv73vv71v77+9I++/vXRd77+977+9De+/vULvv71jdO+/ve+/vVgY77+9XFzvv70XV++/vVrvv71iVe+/ve+/ve+/vVYXYu+/vRbvv73vv73vv71DFh7Kp13vv70qI++/vXTvv71XFu+/ve+/vQMKNAQZBO+/vR8i77+977+9AO+/ve+/vSjvv71o77+9JO+/vSgcQlJP77+977+977+9QBLvv73vv73vv70v77+9dV7vv70Q77+9UWchCe+/vQTvv73Iiu+/ve+/vQ8CLkDvv714cUDvv73vv73vv71Z77+977+9He+/ve+/ve+/vTrvv714alNR77+977+977+977+977+977+9Fu+/ve+/vRVMMTjvv71QMiAV77+977+977+977+9XsuH77+977+977+977+9au+/vRMn77+977+977+977+977+977+9bgkuWO+/ve+/ve+/ve+/vRYKI++/vRTvv73vv73vv71S77+91ao+77+977+9fO+/ve+/vVY/dMik77+977+977+9Ke+/vdCvdDbvv73vv70e77+977+9a++/ve+/ve+/vS9A77+977+977+9KO+/vUzvv71777+9Ou+/vSk/ZhN177+977+9XWUO77+9R1saV++/vTrvv73Vr++/vWPvv70SG++/vX7vv70s77+977+9WO+/vS90V++/ve+/veC7txIK77+9QDJG77+9ZEtna++/ve+/vVBw77+977+9Mu+/ve+/vTDvv71g77+9ETUBVu+/vVZHHu+/vXJU77+977+9TTPvv73vv71j77+977+977+9b0Pvv73vv70M77+9Ce+/ve+/vTYS77+9Ze+/ve+/vU7vv73vv73vv73vv711EhBOHFpmOdaJVmFU77+977+9G2RzZ01fRGUSBGPRnHXvv73vv73vv70XIl3vv712a++/ve+/vXtJJyfvv70hy5fvv73vv73vv73vv70e77+977+977+977+9G++/ve+/ve+/ve+/vTNpTO+/vSYe77+9dlbvv73vv71pKe+/ve+/vV4Q77+9fWnvv71XQXFz77+9B++/ve+/vXta77+9IxVAA++/vQLvv709TO+/vUHvv70gEu+/vQcmBgcMFO+/ve+/vRhy77+9eF3vv71i77+977+9He+/vRpI77+9RStVyo/vv70CEe+/vVBnde+/ve+/vWrvv718HXtl77+9YO+/ve+/vUjvv70D77+9TO+/ve+/ve+/ve+/vTlUJGzvv70cR++/ve+/vSjvv70y77+977+9Gm5u77+977+9Yu+/ve+/vRbvv70j77+9Bkty77+977+9RO+/ve+/ve+/vW/vv73vv73vv73vv73vv73vv73vv73vv70Z77+977+977+9DO+/vQrvv70xYWnvv70a77+9IO+/vV9IB1Hvv71bEcqj77+977+9D0sC77+977+9Eu+/vTIQYzYiS++/vThP77+977+977+9HXJacu+/ve+/vWwrK++/vSl1GQhyJ05OKGzvv70rSu+/vRTvv73vv70D77+977+9I++/vQ43UO+/ve+/vSHvv70o77+977+9GglI77+9MCZ077+977+9SXlkfh3vv71B77+977+9PnPvv73vv73vv73vv71naO+/vTx6IF3vv73vv73vv73vv708SC8bXe+/vTVIR0fvv71eX2d877+9KTnvv73vv70w77+9YSVTTu+/ve+/vWVRGlvvv71w77+9cu+/vRrvv71YZ3zvv71GOe+/vTbvv70LCT85amnvv73vv71oNe+/vWRjM++/vVfLkg5/MtGpXmkcDWjvv71URTrSju+/ve+/vQZ3yZPvv71lQO+/vVQyL8iccnUR77+977+977+9eStq77+9EwtoOe+/vXTvv70Hbu+/vR/vv70rL1bvv70Y77+977+9Ne+/ve+/ve+/vQrvv73MrBFcWmA4IxZe77+977+977+9De+/vVHvv71R77+9e0Jleu+/vWNq77+977+977+9Nu+/vcqs77+977+9GRzvv73vv70ZUTNUBSs8Bu+/ve+/ve+/vU7Yu2Fm77+977+9VjDvv715CyY777+977+977+9cz7vv73vv73vv73vv73ij4Dvv71M77+9YQBAAAAA77+9Eu+/vTnvv71E77+9IFND77+9DO+/vQbvv73vv71C77+977+977+977+9Fe+/vWHvv71pMRnvv73vv73vv70mIRPvv71A77+9F++/vWvvv70g77+9ZRMR77+9Au+/vSA4VO+/vRDvv71U77+977+977+9WFrvv73vv70L77+9BlDvv73vv73vv73vv73vv73vv73vv70CHVnvv73vv70tPe+/vUMYMl7vv73vv73vv70BIiks77+977+977+977+9DTJS77+9GRhgMO+/ve+/vQjvv73vv70077+977+9Yu+/ve+/ve+/ve+/vS8Rdu+/vTUaQe+/vQjorIXvv70Q77+9f2saWM2s77+977+977+9XO+/vXsXbFHvv73vv70yFBRcSGAYO++/vSwV77+9UENQNDFa77+9Xu+/ve+/vR9y2ozvv70cYe+/ve+/ve+/vVJh77+977+9CGBzFiUjDO+/ve+/vRDvv70E77+977+977+977+9aO+/vS/vv73vv71pLm/vv71McVIo77+9DBYAZ++/vQXDo1vvv73vv73Ms++/ve+/vQdqAe+/ve+/vWjvv71m77+92Y4ka8SB77+9Gu+/vXI777+9dO+/vUrvv73WsO+/vUZlNu+/vXjvv73vv73hubVO2KEP77+977+9Ku+/vWtu77+9TwLvv73vv71oRmgB77+9DgI+HO+/vXhgKQhQEkgj77+9J++/ve+/vWDvv70/77+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+9Ru+/ve+/ve+/vSksS++/ve+/ve+/vSksU++/vduk77+977+9IAAD77+9AO+/ve+/vQPvv70SA8Wt77+9K0xMRO+/vQQa77+9VXRv77+9W++/ve+/ve+/vVgvYu+/vRbVnz7vv73vv71rbe+/ve+/vVfvv71t77+9WhPvv73vv73vv71z2LXvv73vv73vv70bVnzvv73vv73vv71r4L2LWta177+977+977+9a++/vS9e77+9esKtVu+/ve+/vWtX77+9Ku+/vWrvv73vv73vv73vv73vv70t77+977+9De+/ve+/vUxHMQYQ77+977+9HTAQ77+9VO+/vVtEJDUl77+9OnUNQ00T77+977+977+977+977+9ACrvv70u77+977+977+9AALvv70v77+915jvv70BRO+/ve+/vRUW77+9XFvvv717d++/vV7Wr1Xvv71rNu+/vQXvv71dWe+/vX4ta0J877+977+9HRQUKCgoKUxBTUU0LjBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQ==';
/** The full data URI, built once. */
function approvalChimeDataUri() {
    return 'data:audio/mpeg;base64,' + APPROVAL_CHIME_BASE64;
}
return { APPROVAL_CHIME_BASE64,approvalChimeDataUri };
}

__mod['ui/web/sound.js'] = M67();

function M68() {
const { approvalChimeDataUri } = __mod['ui/web/sound.js'];
/**
 * Embedded web UI (Phase 7): the entire professional interface lives in this
 * module as template strings — zero external assets, so it survives Node SEA
 * .exe packaging with no path resolution issues. Served by ui/web/server.ts.
 */

const CSS = `
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #1f2630; --border: #30363d;
  --fg: #e6edf3; --dim: #8b949e; --accent: #e64c8d; --accent2: #bc3f76;
  --ok: #3fb950; --warn: #d29922; --err: #f85149;
  --mono: ui-monospace, 'Cascadia Mono', 'Cascadia Code', Consolas, 'SF Mono', 'Roboto Mono', monospace;
  /* TYPOGRAPHY (2026-10-01): a real type scale instead of one 14px size
     everywhere. The old UI used the platform UI font at a single size, which is
     why long answers read as a wall. Segoe UI Variable ships with Windows 11 and
     is noticeably better than the legacy Segoe UI; the rest are fallbacks so the
     stack degrades cleanly on Windows 10, macOS and Linux. No web fonts: this
     page must render instantly and offline, and a downloaded font would be a
     network dependency plus a flash of invisible text. */
  --sans: 'Segoe UI Variable Text', 'Segoe UI', system-ui, -apple-system, 'Inter', Roboto, 'Helvetica Neue', Arial, sans-serif;
  --fs-xs: 11.5px; --fs-sm: 12.5px; --fs-base: 14px; --fs-md: 15px; --fs-lg: 17px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  background: var(--bg); color: var(--fg);
  font: var(--fs-base)/1.6 var(--sans);
  /* Tabular figures keep numbers from jittering as they stream in, and proper
     ligatures/kerning make body text look typeset rather than typed. */
  font-variant-numeric: tabular-nums;
  font-kerning: normal;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  display: flex; flex-direction: column;
  /* App shell, not a document: the window never scrolls. Only #chat (and the
     sidebar) scroll. Without this the composer could still be pushed below
     the fold by tall content — the 2026-09-28 "send is not working" report. */
  height: 100vh; overflow: hidden;
}
header {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 18px; background: var(--bg2); border-bottom: 1px solid var(--border);
  /* LAYOUT BUG FIX (2026-09-28): the header held a long router string and a
     wrapping route tray, so it grew to ~230px and pushed the composer off the
     bottom of the window — the Send button became unreachable. The header must
     never take part in the vertical distribution: fixed height, no wrapping,
     and its text truncates instead. It now holds only the logo and the
     connection dot — the model name and the route chips moved to the sidebar
     "Connected routes" section (2026-09-30) so the chat surface stays clean. */
  flex: 0 0 auto; flex-wrap: nowrap; overflow: hidden;
}
header .logo { font-weight: 700; letter-spacing: .5px; color: var(--accent); font-size: 16px; flex: 0 0 auto; }
header .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--warn); margin-left: auto; }
header .dot.on { background: var(--ok); }
#app { display: flex; flex: 1; min-height: 0; }
aside {
  width: 268px; background: var(--bg2); border-right: 1px solid var(--border);
  padding: 10px 8px; overflow-y: auto; flex-shrink: 0;
  /* slim, professional scrollbar rather than a fat OS bar */
  scrollbar-width: thin; scrollbar-color: var(--border) transparent;
}
aside::-webkit-scrollbar { width: 8px; }
aside::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
aside::-webkit-scrollbar-thumb:hover { background: var(--dim); }
/* collapsible sidebar folder (each group is a <details>) */
.grp {
  border: 1px solid transparent; border-radius: 10px;
  margin-bottom: 2px;
}
.grp[open] { background: rgba(255,255,255,.02); border-color: var(--border); }
.grp > summary {
  display: flex; align-items: center; gap: 7px; padding: 8px 9px; cursor: pointer;
  list-style: none; user-select: none; border-radius: 9px;
  font-size: 11px; text-transform: uppercase; letter-spacing: 1.1px; color: var(--dim);
  font-weight: 600;
}
.grp > summary::-webkit-details-marker { display: none; }
.grp > summary:hover { color: var(--fg); background: var(--bg3); }
.grp > summary::before {
  content: '▸'; font-size: 10px; line-height: 1; color: var(--dim);
  transition: transform .16s ease; flex: 0 0 auto;
}
.grp[open] > summary::before { transform: rotate(90deg); }
.grp > summary .gcount { margin-left: auto; font-family: var(--mono); font-size: 10px; font-weight: 400; }
.grp .body { padding: 3px 4px 7px; display: flex; flex-direction: column; gap: 4px; }
.stat { display: flex; justify-content: space-between; padding: 4px 0; color: var(--dim); font-size: 13px; }
.stat b { color: var(--fg); font-family: var(--mono); }
aside button {
  width: 100%; margin: 4px 0; padding: 8px; text-align: left; cursor: pointer;
  background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 13px;
}
aside button:hover { border-color: var(--accent); }
aside button.accent { border-color: rgba(230,76,141,.55); color: var(--accent); background: rgba(230,76,141,.07); }
aside button.accent:hover { background: rgba(230,76,141,.14); border-color: var(--accent); }
aside button.danger { border-color: rgba(248,81,73,.5); color: var(--err); background: rgba(248,81,73,.06); }
aside button.danger:hover { background: rgba(248,81,73,.14); border-color: var(--err); }
aside button[disabled] { opacity: .5; cursor: default; }
/* min-height:0 + overflow:hidden is REQUIRED (not just min-width): without it
   main keeps its full content height inside the flex row, #chat cannot shrink,
   and the composer + Send button slide out the bottom of the window — which
   is exactly the "send is not working" report on 2026-09-28. overflow:hidden
   makes the invariant hold even if some future child refuses to shrink. */
main { flex: 1; display: flex; flex-direction: column; min-width: 0; min-height: 0; overflow: hidden; }
#chat { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: 20px 26px; display: flex; flex-direction: column; gap: 14px; }
/* Message typography: AI answers are long-form prose, so they get the larger
   reading size and a measure that is comfortable to scan. 78% of a wide window
   is far too long a line; capped so it reads like a document column. */
.msg { max-width: 78%; padding: 12px 16px; border-radius: 12px; white-space: pre-wrap; word-break: break-word; }
.msg.user { align-self: flex-end; background: var(--accent2); border-bottom-right-radius: 4px; max-width: 68%; }
.msg.ai { align-self: flex-start; background: var(--bg3); border: 1px solid var(--border); border-bottom-left-radius: 4px;
  font-size: var(--fs-md); max-width: min(78%, 68ch); }
/* Rendered emphasis from the markdown pass. */
.msg.ai strong { color: #fff; font-weight: 650; }
.msg.ai em { color: #c9d1d9; }
.msg.ai code {
  font-family: var(--mono); font-size: .88em; padding: 1px 5px; border-radius: 5px;
  background: rgba(110,118,129,.28); border: 1px solid var(--border);
}
.msg.ai pre {
  margin: 8px 0 2px; padding: 10px 12px; overflow-x: auto; border-radius: 8px;
  background: #0b0f14; border: 1px solid var(--border);
  font-family: var(--mono); font-size: var(--fs-sm); line-height: 1.5;
  white-space: pre; /* code must NOT wrap like prose */
}
.msg.ai pre code { background: none; border: 0; padding: 0; font-size: inherit; }
/* ---- Rendered answer typography (2026-10-01) ----
   The complaint these address: replies read as a wall of text with random
   symbols in them. Two separate causes, both fixed here and in renderRich():
   stray * / _ / # markers that were never valid markdown, and block elements
   laid out by pre-wrap. The rules below give a document-like rhythm —
   paragraph spacing instead of blank lines, a real heading scale, hanging
   list markers, and quotes set off from the body. */
.msg.rich { white-space: normal; line-height: 1.68; }
.msg.rich > :first-child { margin-top: 0; }
.msg.rich > :last-child { margin-bottom: 0; }
.msg.rich p { margin: 0 0 .85em; }
.msg.rich ul, .msg.rich ol { margin: .3em 0 .9em; padding-left: 1.5em; }
/* Hanging indent, so a wrapped list line aligns under the text and not under
   the bullet — the single biggest readability win in a bulleted answer. */
.msg.rich li { margin: .3em 0; padding-left: .25em; }
.msg.rich li::marker { color: var(--dim); }
.msg.rich ul > li::marker { font-size: .9em; }
.msg.rich ol > li::marker { font-variant-numeric: tabular-nums; font-size: .9em; }
/* Nested lists sit tighter and are not double-indented by the parent's padding. */
.msg.rich li > ul, .msg.rich li > ol { margin: .3em 0 .2em; }
.msg.rich blockquote {
  margin: .5em 0 .9em; padding: .1em 0 .1em 1em;
  border-left: 3px solid var(--border); color: var(--dim);
}
.msg.rich hr { border: 0; border-top: 1px solid var(--border); margin: 1.1em 0; }
.msg.rich strong { font-weight: 650; }
.msg.rich del { color: var(--dim); }
.msg.rich a { color: var(--accent); text-underline-offset: 2px; }
.msg.rich pre + p, .msg.rich p + pre { margin-top: -.4em; }
/* A real heading scale. Previously every heading rendered at the same size as
   the body, which flattened the structure of an answer — the # characters were
   stripped but the visual hierarchy was thrown away with them. */
.msg.rich h1, .msg.rich h2, .msg.rich h3,
.msg.rich h4, .msg.rich h5, .msg.rich h6 {
  color: #fff; font-weight: 650; line-height: 1.3;
  margin: 1.3em 0 .45em; letter-spacing: -.01em;
}
.msg.rich h1 { font-size: 1.3em; }
.msg.rich h2 { font-size: 1.18em; }
.msg.rich h3 { font-size: 1.08em; }
.msg.rich h4 { font-size: 1em; color: var(--fg); }
.msg.rich h5, .msg.rich h6 { font-size: .95em; color: var(--dim); }
/* A heading immediately after a paragraph needs less air above it. */
.msg.rich p + h1, .msg.rich p + h2, .msg.rich p + h3,
.msg.rich p + h4, .msg.rich p + h5, .msg.rich p + h6 { margin-top: 1em; }
.msg.ai.thinking { color: var(--dim); font-style: italic; }
.activity {
  align-self: flex-start; max-width: 90%; font-family: var(--mono); font-size: 12px;
  color: var(--dim); padding: 2px 0 2px 10px; border-left: 2px solid var(--border);
}
.activity b { color: var(--warn); font-weight: 600; }
.activity button {
  margin-top: 6px; padding: 6px 12px; font-size: 12px; cursor: pointer;
  border-radius: 8px; border: 1px solid var(--accent); color: var(--accent);
  background: rgba(230,76,141,.10); font-family: var(--mono);
}
.activity button:hover:not(:disabled) { background: rgba(230,76,141,.22); }
.activity button:disabled { opacity: .55; cursor: default; }
#inputbar { display: flex; gap: 10px; padding: 14px 26px; border-top: 1px solid var(--border); background: var(--bg2); flex: 0 0 auto; }
#inputbar textarea {
  flex: 1 1 auto; min-width: 0; resize: none; background: var(--bg3); color: var(--fg);
  border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px;
  font: inherit; outline: none; min-height: 44px; max-height: 160px;
}
#inputbar textarea:focus { border-color: var(--accent); }
#send {
  padding: 0 22px; border: none; border-radius: 10px; cursor: pointer;
  background: var(--accent); color: #fff; font-weight: 600; font-size: 14px;
}
#send:hover { background: var(--accent2); }
#send:disabled { opacity: .5; cursor: default; }
#attach {
  padding: 0 14px; border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; background: var(--bg3); color: var(--fg); font-size: 16px;
  line-height: 42px; flex: 0 0 auto;
}
#attach:hover { border-color: var(--accent); color: var(--accent); }
/* Full-window drop target: drag & drop works ANYWHERE on the page, not just
   on a thin strip in the composer (which is how it behaved before — dropping
   on the chat area silently did nothing). */
#dropveil {
  position: fixed; inset: 0; z-index: 70; display: none;
  align-items: center; justify-content: center;
  background: rgba(11,10,13,.82); backdrop-filter: blur(2px);
}
#dropveil.show { display: flex; }
.dropveil-inner {
  text-align: center; font-size: 15px; line-height: 1.9;
  border: 2px dashed var(--accent); border-radius: 16px;
  padding: 34px 54px; color: var(--fg);
}
.dropveil-inner span { color: var(--dim); font-size: 12px; }
#mic {
  padding: 0 16px; border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; background: var(--bg3); color: var(--fg); font-size: 18px;
  line-height: 42px; flex: 0 0 auto;
  /* the mic is a headline feature — never let flex squeeze it flat */
  min-width: 52px; font-weight: 600;
}
#mic:hover { border-color: var(--accent); color: var(--accent); }
#mic.listening {
  border-color: var(--accent); color: var(--accent);
  background: rgba(230,76,141,.12); animation: mic-pulse 1.2s ease-in-out infinite;
}
@keyframes mic-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(230,76,141,.35); }
  50% { box-shadow: 0 0 0 6px rgba(230,76,141,0); }
}
#session-list { margin-top: 2px; }
.sess {
  display: flex; align-items: center; gap: 6px; padding: 7px 8px; margin: 2px 0;
  background: transparent; border: 1px solid transparent; border-radius: 8px;
  cursor: pointer; color: var(--dim); font-size: 12.5px;
}
.sess:hover { background: var(--bg3); color: var(--fg); }
.sess.active { background: var(--bg3); border-color: var(--accent); color: var(--fg); }
.sess .t { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sess .d { font-family: var(--mono); font-size: 10.5px; flex-shrink: 0; }
.sess .x {
  flex-shrink: 0; width: 18px; height: 18px; line-height: 16px; text-align: center;
  border-radius: 50%; border: 1px solid var(--border); background: transparent;
  color: var(--dim); cursor: pointer; font-size: 11px; padding: 0;
}
.sess .x:hover { color: var(--err); border-color: var(--err); }
/* Route list (moved out of the header into the sidebar "Connected routes"
   section on 2026-09-30): one stacked row per gateway route, each with a state
   dot, the route name, the model it serves and any failure detail. */
#route-list { display: flex; flex-direction: column; gap: 4px; }
.route-row {
  display: flex; align-items: flex-start; gap: 7px; padding: 6px 8px;
  border: 1px solid var(--border); border-radius: 8px; background: var(--bg3);
  font-size: 12px; cursor: default;
}
.route-row .rd {
  width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex: 0 0 auto;
  background: var(--dim);
}
.route-row.ok .rd { background: var(--ok); box-shadow: 0 0 6px rgba(63,185,80,.7); }
.route-row.degraded .rd { background: var(--err); box-shadow: 0 0 6px rgba(248,81,73,.7); }
.route-row.down .rd { background: var(--warn); box-shadow: 0 0 6px rgba(210,153,34,.7); }
.route-row .rt { min-width: 0; flex: 1; }
.route-row .rn { font-family: var(--mono); color: var(--fg); word-break: break-word; }
.route-row .rm, .route-row .rdetail {
  font-family: var(--mono); font-size: 10.5px; color: var(--dim);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.route-row.ok .rn { color: var(--ok); }
.route-row.degraded .rn { color: var(--err); }
.route-row.down .rn { color: var(--warn); }
/* unknown = not probed yet / gateway hides /models — visually "idle", not broken */
.route-row.unknown { opacity: .72; }
.route-row.unknown .rn { color: var(--dim); }
.route-row .ra { display: flex; gap: 4px; flex: 0 0 auto; align-items: center; }
.route-row .rb {
  font-family: var(--mono); font-size: 10px; padding: 2px 6px; cursor: pointer;
  background: var(--bg2); color: var(--dim); border: 1px solid var(--border);
  border-radius: 5px;
}
.route-row .rb:hover { color: var(--fg); border-color: var(--dim); }
.route-row .rb:disabled { opacity: .3; cursor: default; }
.route-row .rb:disabled:hover { color: var(--dim); border-color: var(--border); }

/* Learned sources as rows, not a wall of text (2026-10-02): the inspector used
   to hand one unbroken block to a <pre>. One div per source, tight rows, with
   the newest item readable at a glance. The pale footer line is informational
   by design — like the B7 dedup report, not a warning. */
.learned-list { display: flex; flex-direction: column; gap: 0; }
.learned-row {
  padding: 3px 8px; font-size: 11.5px; line-height: 1.45;
  border-bottom: 1px solid var(--border); word-break: break-word;
}
.learned-row:last-child { border-bottom: none; }

/* Fallback chain editor rows: position, name, key count, then the actions. */
.chain-row {
  display: flex; align-items: center; gap: 8px; padding: 6px 8px;
  border: 1px solid var(--border); border-radius: 8px; margin-bottom: 5px;
  background: var(--bg2);
}
.chain-row .cp {
  font-family: var(--mono); font-size: 11px; color: var(--dim);
  min-width: 18px; text-align: right; flex: 0 0 auto;
  font-variant-numeric: tabular-nums;
}
.chain-row .cn { flex: 1; min-width: 0; font-family: var(--mono); font-size: 12px; word-break: break-word; }
.chain-row .cb {
  margin-left: 7px; font-family: var(--sans); font-size: 10.5px;
  color: var(--dim); border: 1px solid var(--border); border-radius: 5px; padding: 0 5px;
}

/* B7 dedup report: a read-only summary, deliberately quiet so it reads as
   information rather than a warning. */
.dedup-report {
  margin: 10px 0 4px; padding: 10px 12px; max-height: 210px; overflow-y: auto;
  border: 1px solid var(--border); border-radius: 8px; background: var(--bg);
  font-family: var(--mono); font-size: 11.5px; color: var(--dim);
  white-space: pre-wrap; word-break: break-word;
}
#routes-model { font-family: var(--mono); font-size: 11px; color: var(--dim); word-break: break-word; }
#routes-empty { font-size: 12px; color: var(--dim); }
#drop-zone {
  border: 1px dashed var(--border); border-radius: 10px; color: var(--dim);
  font-size: 12px; text-align: center; padding: 6px 10px; margin: 0 0 8px;
  cursor: pointer; user-select: none;
}
#drop-zone.over { border-color: var(--accent); color: var(--accent); background: rgba(230,76,141,.06); }
#drop-zone.hidden { display: none; }
#btn-trust.on { border-color: var(--ok); color: var(--ok); font-weight: 600; }
/* Voice discoverability: the 🎤 is a headline feature and users reported
   "where is my mic" — the button existed but was easy to miss. This hint sits
   under the composer and disappears once the mic has been used once. */
#voicehint { font-size: 11px; color: var(--dim); padding: 0 26px 10px; }
#voicehint b { color: var(--accent); }
#voicehint.gone { display: none; }
#overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.6); display: none;
  /* MUST outrank every other overlay. This is the approval dialog, and it
     was z-index 10 — the LOWEST — so the resume chooser (#launch, 60) and
     the confirm modal (#modal, 30) rendered on top of it. The dialog was
     visible but its Allow/Deny buttons could not be clicked, which looked
     to the user like "the app asked and then hung". */
  align-items: center; justify-content: center; z-index: 90;
}
#overlay.show { display: flex; }
.dialog {
  width: 440px; background: var(--bg2); border: 1px solid var(--border);
  border-radius: 14px; padding: 20px;
}
.dialog h2 { font-size: 15px; margin-bottom: 10px; color: var(--warn); }
.dialog p { font-family: var(--mono); font-size: 12.5px; color: var(--dim); margin-bottom: 16px; word-break: break-word; }
.dialog .row { display: flex; gap: 10px; justify-content: flex-end; }
.dialog button { padding: 8px 18px; border-radius: 8px; border: 1px solid var(--border); cursor: pointer; font-size: 13px; }
.dialog .deny { background: transparent; color: var(--dim); }
.dialog .allow { background: var(--ok); border-color: var(--ok); color: #fff; font-weight: 600; }

/* EVERY overlay modal, in one rule.
 *
 * BUG FIXED 2026-10-01 — the cause of "Cancel does nothing and the chat area is
 * invisible". There was no .hidden rule at all; each modal had its own
 * per-id one (#keys-modal.hidden, #panel.hidden, #launch.hidden) and the ones
 * added later were never given theirs. So #chain-modal, #prov-modal and
 * #bulk-modal rendered VISIBLE on load, sitting on top of the whole page at
 * z-index 58. Clicking Cancel did add the class — and changed nothing, because
 * no CSS read it. The page looked broken with no error anywhere, which is the
 * worst kind of bug: it looks like a rendering fault, not a missing rule.
 *
 * A per-id rule is a trap: adding a modal means remembering a second, separate
 * edit in a different part of the stylesheet, and nothing warns you when you
 * forget. One shared rule cannot be forgotten.
 *
 * Specificity note: the per-id rules are kept below as harmless redundancy.
 * This selector is (0,1,0) and theirs are (1,1,0), so if one is ever missing
 * the others still cannot accidentally un-hide anything.
 */
.hidden { display: none !important; }

/* Shared overlay look, so a new modal is correct by default rather than by
   remembering to copy six declarations. */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.7); display: flex;
  align-items: center; justify-content: center; z-index: 58;
}
.modal-overlay .dialog.wide { width: 720px; max-width: 92vw; }
#keys-modal {
  position: fixed; inset: 0; background: rgba(0,0,0,.7); display: flex;
  align-items: center; justify-content: center; z-index: 58;
}
#keys-modal.hidden { display: none; }
#keys-modal .dialog.wide { width: 720px; max-width: 92vw; }
.key-item {
  display: flex; flex-direction: column; gap: 4px; padding: 10px;
  border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px;
  background: var(--bg);
}
.key-item .top {
  display: flex; justify-content: space-between; align-items: center;
  font-family: var(--mono); font-size: 12px;
}
.key-item .lbl { color: var(--fg); font-weight: 600; }
.key-item .var { color: var(--dim); font-size: 11px; }
.key-item .status { font-size: 11px; padding: 2px 6px; border-radius: 4px; }
.key-item .status.ok { color: var(--ok); border: 1px solid var(--ok); }
.key-item .status.missing { color: var(--warn); border: 1px solid var(--warn); }
.key-item .input-row { display: flex; gap: 8px; margin-top: 6px; }
.key-item input {
  flex: 1; padding: 6px 10px; background: var(--bg3); color: var(--fg);
  border: 1px solid var(--border); border-radius: 6px; font-size: 12px;
  font-family: var(--mono);
}
.key-item input:focus { outline: none; border-color: var(--accent); }
.key-item button {
  padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border);
  cursor: pointer; font-size: 11.5px;
}
.key-item button.save { background: var(--accent); border-color: var(--accent); color: #fff; }
.key-item button.clear { background: transparent; color: var(--dim); }
.key-item button.clear:hover { color: var(--err); border-color: var(--err); }
/* Multi-key rotation (B26): one provider may hold several keys; each chip
   shows its own health and remaining cooldown. */
.key-item .keys {
  display: flex; flex-direction: column; gap: 4px;
  margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--border);
}
.key-item .keys-head {
  color: var(--dim); font-size: 11px; font-family: var(--mono);
  display: flex; justify-content: space-between; align-items: center;
}
.key-item .key-chip {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--mono); font-size: 11.5px; color: var(--dim);
}
.key-item .key-chip .idx { color: var(--accent); min-width: 52px; }
.key-item .key-chip .pv { flex: 1; }
.key-item .key-chip .dot {
  font-size: 10px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--border); white-space: nowrap;
}
.key-item .key-chip .dot.ok { color: var(--ok); border-color: var(--ok); }
.key-item .key-chip .dot.quota { color: var(--warn); border-color: var(--warn); }
.key-item .key-chip .dot.parked, .key-item .key-chip .dot.down { color: var(--err); border-color: var(--err); }
.key-item .key-chip button.rm {
  background: transparent; border: 1px solid var(--border); color: var(--dim);
  padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 11px;
  font-family: var(--mono);
}
.key-item .key-chip button.rm:hover { color: var(--err); border-color: var(--err); }
/* Stop button + queued messages. */
#stop {
  background: var(--err); border-color: var(--err); color: #fff;
  padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;
}
#stop:hover { filter: brightness(1.1); }
#queue {
  max-height: 22vh; overflow-y: auto; margin: 0 12px 6px;
  padding: 6px 8px; border: 1px dashed var(--border); border-radius: 8px;
  background: var(--bg3);
}
#queue .q-item {
  display: flex; align-items: flex-start; gap: 8px;
  font-size: 12px; color: var(--dim); padding: 3px 0;
  border-bottom: 1px solid var(--border);
}
#queue .q-item:last-child { border-bottom: none; }
#queue .q-item .q-text { flex: 1; font-family: var(--mono); word-break: break-word; }
#queue .q-item .q-drop {
  background: transparent; border: 1px solid var(--border); color: var(--dim);
  border-radius: 4px; cursor: pointer; font-size: 10.5px; padding: 1px 7px;
}
#queue .q-item .q-drop:hover { color: var(--err); border-color: var(--err); }
#queue .q-head { font-size: 10.5px; color: var(--dim); margin-bottom: 3px; }
/* Capability inspector panel: shows a read-only tool's output (skills,
   missions, knowledge, jobs, tool catalogue). Reuses the dialog look. */
#panel {
  position: fixed; inset: 0; background: rgba(0,0,0,.66); display: flex;
  align-items: center; justify-content: center; z-index: 55;
}
#panel.hidden { display: none; }
#panel .dialog.wide { width: 720px; max-width: 92vw; }
#panel h2 { color: var(--accent); }
#pn-body {
  font-family: var(--mono); font-size: 12.5px; color: var(--fg);
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px; margin: 0 0 16px; max-height: 56vh; overflow: auto;
  white-space: pre-wrap; word-break: break-word;
}
/* launch chooser (UI remodel): continue previous conversation / new chat */
#launch {
  position: fixed; inset: 0; background: rgba(0,0,0,.66); display: flex;
  align-items: center; justify-content: center; z-index: 60;
}
#launch.hidden { display: none; }
#launch .dialog { width: 520px; }
#launch h2 { color: var(--accent); }
#launch-list { max-height: 220px; overflow-y: auto; margin-bottom: 16px; }
#launch-list .lrow {
  display: flex; justify-content: space-between; gap: 10px; padding: 8px 10px;
  border: 1px solid var(--border); border-radius: 8px; margin-bottom: 6px;
  font-family: var(--mono); font-size: 12px; cursor: pointer; color: var(--dim);
}
#launch-list .lrow:hover { border-color: var(--accent); color: var(--text); }
#launch-list .lrow .lt { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* generic prompt dialog (export password, import file, shutdown confirm…) */
#modal {
  position: fixed; inset: 0; background: rgba(0,0,0,.62); display: none;
  align-items: center; justify-content: center; z-index: 30;
}
#modal.show { display: flex; }
#modal h2 { color: var(--accent); }
#modal .dialog { width: 460px; }
#modal .field { margin-bottom: 12px; }
#modal input[type="password"],
#modal input[type="text"] {
  width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg);
  border: 1px solid var(--border); border-radius: 8px; font-size: 13px;
  font-family: var(--mono); box-sizing: border-box;
}
#modal input:focus { outline: none; border-color: var(--accent); }
#modal input[type="file"] {
  width: 100%; padding: 8px; background: var(--bg3); color: var(--dim);
  border: 1px dashed var(--border); border-radius: 8px; font-size: 12px;
  font-family: var(--mono); box-sizing: border-box;
}
#modal .hint { font-family: var(--mono); font-size: 11.5px; color: var(--dim); margin-bottom: 10px; }
#modal .err { color: var(--err); font-family: var(--mono); font-size: 12px; margin-bottom: 10px; display: none; }
#modal .err.show { display: block; }
#modal .dialog button.allow { background: var(--accent); border-color: var(--accent); color: #fff; }
`;
const BODY = `
<header>
  <span class="logo">⬥ BlackRose</span>
  <span class="dot" id="status-dot" title="connecting"></span>
</header>
<div id="app">
  <aside>
    <!-- Grouped and ordered by how often they are actually used:
         Conversations and Knowledge are the two things you reach for first,
         so they start open; everything administrative is collapsed below.
         Skills + Tools were merged into one "Automation" folder — two
         one-button folders read as clutter, not as structure. -->
    <details class="grp" open>
      <summary>💬 Conversations<span class="gcount" id="g-count"></span></summary>
      <div class="body">
        <button id="btn-new" class="accent">＋ New chat</button>
        <div id="session-list"></div>
      </div>
    </details>
    <details class="grp" open>
      <summary>🧠 Knowledge</summary>
      <div class="body">
        <div id="stats"></div>
        <button id="btn-klist">📚 Learned sources</button>
        <button id="btn-kforget" title="Remove a learned source and its vectors, so it can never come back in search">🗑 Forget a source…</button>
        <button id="btn-ksearch">🔎 Search knowledge</button>
        <button id="btn-msearch">🧠 Search memory</button>
        <button id="btn-projects">📁 Project notes</button>
      </div>
    </details>
    <details class="grp" open>
      <summary>🎯 Workspace</summary>
      <div class="body">
        <button data-mode="goal">🎯 Run a goal → execute → verify</button>
        <button data-mode="chat">💬 Normal chat mode</button>
        <button id="btn-clear">🧹 Clear conversation</button>
      </div>
    </details>
    <details class="grp">
      <summary>🧰 Automation</summary>
      <div class="body">
        <button id="btn-skills">🧩 Skills</button>
        <button id="btn-missions">⏰ Scheduled missions</button>
        <button id="btn-jobs">⚙️ Background jobs</button>
        <button id="btn-toolcat">🧰 Tool catalogue</button>
      </div>
    </details>
    <details class="grp">
      <summary>💾 Data</summary>
      <div class="body">
        <button id="btn-export">⬇ Export state (.aistate)</button>
        <button id="btn-import">⬆ Import state (.aistate)</button>
      </div>
    </details>
    <details class="grp">
      <summary>⚙️ Settings</summary>
      <div class="body">
        <button id="btn-keys">🔑 API keys &amp; gateways</button>
        <button id="btn-trust" title="Trust mode: run ordinary tools without asking. Shell commands, installs, scheduling, file writes, the mic, the screen and anything that sends data off this machine STILL ask.">🛡 Trust mode: OFF</button>
      </div>
    </details>
    <!-- Connected routes (2026-09-30): the model badge and route chips used to sit
         in the header, where the long router chain crowded the title bar. They
         live here now, expanded by default (2026-10-02): this is the one
         always-on health signal a long-running agent needs, so hiding it behind
         a click is wrong. Collapse it freely — the choice is not persisted. -->
    <details class="grp" open>
      <summary>🔗 Connected routes<span class="gcount" id="routes-count"></span></summary>
      <div class="body">
        <div class="stat"><span>Model</span><b id="routes-model">loading…</b></div>
        <div id="route-list"><div id="routes-empty">reading gateway routes…</div></div>
        <button id="btn-routes" title="Show the full route chain with each gateway's live state">📋 Route details</button>
<button id="btn-chain" title="Choose which gateways are tried, and in what order">↕️ Edit fallback chain</button>
      </div>
    </details>
    <details class="grp">
      <summary>🖥 System</summary>
      <div class="body">
        <button id="btn-update">🔄 Check for update</button>
        <button id="btn-shutdown" class="danger">🛑 Shut down</button>
      </div>
    </details>
    <details class="grp">
      <summary>❓ Help</summary>
      <div class="body">
        <div class="stat"><span>Send</span><b>Enter</b></div>
        <div class="stat"><span>New line</span><b>Shift+Enter</b></div>
        <div class="stat"><span>Attach file</span><b>Drag anywhere</b></div>
        <div class="stat"><span>Talk to it</span><b>🎤 Mic</b></div>
      </div>
    </details>
  </aside>
  <main>
    <div id="chat"><div class="msg ai">Hello — I'm BlackRose. What should we work on?</div></div>
    <div id="inputbar">
      <button id="attach" title="Attach a file — or just drag &amp; drop anywhere on this window">📎</button>
      <textarea id="input" placeholder="Ask anything, or describe a goal… (drop a file anywhere to attach it)" rows="1"></textarea>
      <button id="mic" title="Voice input — press to speak. Uses the LOCAL offline Windows dictation engine (audio never leaves this machine). Click once, then talk for up to 8 seconds.">🎤</button>
      <button id="send">Send</button>
      <button id="stop" title="Stop the current work — cancels the in-flight request so no further tokens are spent" hidden>⏹ Stop</button>
      <input type="file" id="audio-input" style="display:none" />
    </div>
    <div id="queue" hidden></div>
    <div id="dropveil" aria-hidden="true"><div class="dropveil-inner">📎<br><b>Drop the file to attach it</b><br><span>BlackRose saves it and puts the path in your message</span></div></div>
    <div id="voicehint">🎤 <b>Voice input</b> — press the mic and talk (offline, nothing leaves this machine) · 📎 drop a file anywhere to attach it</div>
  </main>
</div>
<div id="overlay">
  <div class="dialog">
    <h2 id="dl-title">⚠ Approval required</h2>
    <p id="dl-reason"></p>
    <div class="row">
      <button class="deny" id="dl-deny">Deny</button>
      <button class="allow" id="dl-allow">Allow</button>
    </div>
  </div>
</div>
<div id="keys-modal" class="hidden">
  <div class="dialog wide">
    <h2>🔑 API Keys & Gateway Configuration</h2>
    <p style="margin-bottom: 12px; color: var(--dim); font-size: 12px;">Configure keys for cloud routes. Saved to the encrypted key vault (keys.enc) — never as plain text. Takes effect immediately in process memory. Add a second key per provider so one hitting its limit does not stop work.</p>
    <div id="keys-list" style="max-height: 52vh; overflow-y: auto; margin-bottom: 16px;"></div>
    <div class="row" style="margin-bottom: 14px;">
      <button id="btn-provider-add" title="Add a new OpenAI-compatible gateway — pick a preset or type any base URL. No code change, no restart.">➕ Add provider</button>
      <button id="btn-keys-bulk" title="Paste or upload many keys for ONE provider at once — one per line, a JSON array, KEY=value lines, or comma-separated. Validates before saving.">📥 Bulk import keys…</button>
      <button id="btn-keys-validate" title="Check whether the stored keys for a provider actually work. Uses /models, so it costs no tokens.">✓ Check keys</button>
    </div>
    <div class="row">
      <button class="allow" id="keys-close">Done</button>
    </div>
  </div>
</div>
<!-- Add a new OpenAI-compatible gateway (B27): no code change, no restart. -->
<div id="provider-modal" class="hidden">
  <div class="dialog wide">
    <h2>➕ Add a provider</h2>
    <p style="margin-bottom: 12px; color: var(--dim); font-size: 12px;">
      Any OpenAI-compatible <code>/v1</code> endpoint. Saved in the encrypted vault and
      available on the next message — no restart. Built-in providers (Gemini, Anthropic,
      1min.ai, keyless routes) are code and are not listed here; pick one of those from
      the route list instead.
    </p>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Preset</label>
      <select id="prov-preset" style="width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 13px;"></select>
      <div class="hint" id="prov-preset-note" style="margin-top: 5px;"></div>
    </div>
    <div class="row" style="gap: 10px;">
      <div class="field" style="flex: 1;">
        <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Route name</label>
        <input type="text" id="prov-name" placeholder="openai7" autocomplete="off" />
      </div>
      <div class="field" style="flex: 1;">
        <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Label</label>
        <input type="text" id="prov-label" placeholder="My gateway" autocomplete="off" />
      </div>
    </div>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Base URL</label>
      <input type="text" id="prov-base" placeholder="https://api.example.com/v1" autocomplete="off" />
    </div>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Model</label>
      <input type="text" id="prov-model" placeholder="model-id" autocomplete="off" />
    </div>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: flex; align-items: center; gap: 7px;">
        <input type="checkbox" id="prov-needskey" checked style="width: auto;" />
        This gateway needs an API key
      </label>
      <div class="hint" style="margin-top: 4px;">Uncheck only for a gateway that needs no credential — it will then be sent no Authorization header at all.</div>
    </div>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: flex; align-items: center; gap: 7px;">
        <input type="checkbox" id="prov-inchain" checked style="width: auto;" />
        Add to the fallback chain
      </label>
      <div class="hint" style="margin-top: 4px;">Appended to the end, so it is tried only after everything already in the chain. Reorder or remove it any time in Connected routes.</div>
    </div>
    <div class="err" id="prov-err"></div>
    <div class="row">
      <button class="deny" id="prov-cancel">Cancel</button>
      <button class="allow" id="prov-save">Add provider</button>
    </div>
  </div>
</div>
<!-- Fallback chain editor: which gateways are tried, and in what order. -->
<div id="chain-modal" class="hidden">
  <div class="dialog wide">
    <h2>↕️ Fallback chain</h2>
    <p style="margin-bottom: 10px; color: var(--dim); font-size: 12px;">
      BlackRose tries these from top to bottom. The first one that answers wins, so put the
      cheapest and most reliable gateway at the top. Routes with no working key are skipped
      automatically, so a broken entry costs you a warning, not the turn.
    </p>
    <div id="chain-note" class="hint" style="margin-bottom: 8px;"></div>
    <div id="chain-list"></div>
    <div class="field" style="margin-top: 10px;">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Add a gateway</label>
      <select id="chain-add" style="width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 13px;"></select>
    </div>
    <div class="err" id="chain-err"></div>
    <div class="row">
      <button class="deny" id="chain-cancel">Close</button>
      <button class="allow" id="chain-save">Save chain</button>
    </div>
  </div>
</div>
<!-- Forget a learned source: a picker, not a text box. -->
<div id="forget-modal" class="modal-overlay hidden">
  <div class="dialog wide">
    <h2>🗑 Forget a learned source</h2>
    <p style="margin-bottom: 10px; color: var(--dim); font-size: 12px;">
      Removes the stored document <em>and</em> its vectors, so it can never come back
      in search results. This cannot be undone — the only copy is the original file.
    </p>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Source</label>
      <select id="forget-pick" style="width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 13px;"></select>
    </div>
    <div class="hint" id="forget-hint"></div>
    <div id="dedup-report" class="dedup-report hidden"></div>
    <div class="err" id="forget-err"></div>
    <div class="row">
      <button class="deny" id="dedup-scan" title="Report duplicates and what a cleanup would reclaim. Deletes nothing.">Find duplicates</button>
      <button class="deny" id="forget-cancel">Cancel</button>
      <button class="allow" id="forget-go">Forget it</button>
    </div>
  </div>
</div>
<!-- Bulk key import: paste or upload many keys for one provider. -->
<div id="bulk-modal" class="hidden">
  <div class="dialog wide">
    <h2>📥 Bulk import API keys</h2>
    <p style="margin-bottom: 10px; color: var(--dim); font-size: 12px;">
      Add many keys for ONE provider at once. Accepts one key per line, a JSON array,
      <code>KEY=value</code> lines, or comma-separated runs. Comments and blank lines are ignored,
      duplicates are skipped, and a bad line never blocks the rest. Keys go to the encrypted
      vault and are never shown back.
    </p>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Provider</label>
      <select id="bulk-provider" style="width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 13px;"></select>
    </div>
    <div class="field">
      <label style="font-size: 12px; color: var(--dim); display: block; margin-bottom: 4px;">Keys (paste, or choose a file)</label>
      <textarea id="bulk-text" rows="7" placeholder="sk-…&#10;sk-…&#10;# comment lines are fine" style="width: 100%; padding: 9px 10px; background: var(--bg3); color: var(--fg); border: 1px solid var(--border); border-radius: 8px; font-size: 12px; font-family: var(--mono); resize: vertical;"></textarea>
      <input type="file" id="bulk-file" style="margin-top: 6px;" />
    </div>
    <div class="hint" id="bulk-hint"></div>
    <div class="err" id="bulk-err"></div>
    <div class="row">
      <button class="deny" id="bulk-cancel">Cancel</button>
      <button id="bulk-validate" title="Check these keys against the provider before saving them">✓ Check first</button>
      <button class="allow" id="bulk-save">Add keys</button>
    </div>
  </div>
</div>
<div id="panel" class="hidden">
  <div class="dialog wide">
    <h2 id="pn-title">Panel</h2>
    <pre id="pn-body"></pre>
    <div class="row">
      <button class="allow" id="pn-close">Close</button>
    </div>
  </div>
</div>
<div id="launch" class="hidden">
  <div class="dialog">
    <h2>⬥ Welcome back</h2>
    <p>You have previous conversations. Continue where you left off, or start fresh.</p>
    <div id="launch-list"></div>
    <div class="row">
      <button class="deny" id="launch-new">＋ New chat</button>
      <button class="allow" id="launch-continue">▶ Continue latest</button>
    </div>
  </div>
</div>
<div id="modal">
  <div class="dialog">
    <h2 id="m-title"></h2>
    <p id="m-msg"></p>
    <div class="hint" id="m-hint"></div>
    <div class="err" id="m-err"></div>
    <div class="field" id="m-file-field" style="display:none">
      <input type="file" id="m-file" accept=".aistate" />
    </div>
    <div class="field" id="m-pass-field" style="display:none">
      <input type="password" id="m-pass" placeholder="password" autocomplete="new-password" />
    </div>
    <div class="row">
      <button class="deny" id="m-cancel">Cancel</button>
      <button class="allow" id="m-ok">OK</button>
    </div>
  </div>
</div>
`;
const JS = `
const chat = document.getElementById('chat');
const input = document.getElementById('input');
const send = document.getElementById('send');
const dot = document.getElementById('status-dot');
let mode = 'chat';
let busy = false;

// ---- Approval chime ----
// Plays when BlackRose needs a permission decision. The point of it is that the
// user is often looking at something else when the prompt arrives: without a
// sound, an approval request is a silent stop, and the turn just looks stuck.
//
// Browsers refuse to play audio until the page has been interacted with. That
// matters here more than usual, because the very user who needs the chime is
// the one who has Alt-Tabbed away and has NOT clicked anything this session. So
// the element is unlocked on the first interaction, and — because that may never
// come — a blocked play() retries on visibilitychange, the moment the user comes
// back to the tab. A notification that only works if you were already looking is
// not a notification.
let CHIME = null;
let CHIME_READY = false;
let CHIME_BLOCKED = false;

function primeAudio() {
  if (CHIME_READY) return;
  const src = window.__APPROVAL_CHIME__;
  if (!src) return;
  try {
    CHIME = new Audio(src);
    CHIME.preload = 'auto';
    CHIME.volume = 0.9;
    // A very short silent clip is what actually unlocks playback in Chrome and
    // Edge: playing it inside a user gesture is what flips the autoplay gate.
    const unlock = CHIME.cloneNode();
    unlock.volume = 0;
    const p = unlock.play();
    if (p && p.catch) p.catch(() => {});
    CHIME_READY = true;
  } catch (e) {
    CHIME = null;
  }
}

function playChime() {
  // INSIDE THE DESKTOP SHELL, let Windows play it. The webview route is a dead
  // end for this notification: even with --autoplay-policy=no-user-gesture-required
  // the chime stayed silent for the one user who needs it — the one who has
  // Alt-Tabbed away and clicked nothing (verified live on 0.9.13). The shell's
  // approval_chime command routes through PlaySound to the active audio session,
  // so it is audible regardless of focus or autoplay. The web Audio below stays
  // as the path for a plain browser, where there is no shell to ask.
  // NOTE the origin problem, which is why this stayed silent for so long: the
  // real UI is NOT the bundled splash. boot_core navigates the window to the
  // loopback core, so this code runs on a REMOTE origin. Tauri injects the
  // globals there only because remote-updater.json declares a remote capability
  // for the loopback host — and that capability names the updater and shutdown
  // commands. Anything not covered simply fails, and the previous code caught
  // the rejection and discarded it, which made a denied invoke look identical to
  // a working-but-autoplay-blocked web fallback: no sound, no error, no way to
  // tell which happened. A chime that cannot report why it is silent is how
  // this survived four releases.
  //
  // So: try the IPC entry points explicitly and LOG failures instead of eating
  // them. __TAURI_INTERNALS__.invoke is the one that exists on a remote origin.
  const invoke = (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke)
    || (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
  if (invoke) {
    try {
      const p = invoke('approval_chime')
      if (p && p.catch) {
        p.catch((e) => { console.error('[chime] native approval_chime failed:', e) })
      }
      return
    } catch (e) {
      console.error('[chime] native approval_chime threw:', e)
      return
    }
  }
  console.warn('[chime] no Tauri IPC available; falling back to web audio')
  if (!CHIME) primeAudio();
  if (!CHIME) return;
  try {
    CHIME.currentTime = 0;
    const p = CHIME.play();
    // Rejection means the autoplay gate is still shut. Do not spam: remember it
    // and retry once the tab is next focused.
    if (p && p.catch) p.catch(() => { CHIME_BLOCKED = true; });
  } catch (e) {
    /* never let a notification break the turn */
  }
}

window.addEventListener('pointerdown', primeAudio, { once: true });
window.addEventListener('keydown', primeAudio, { once: true });
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && CHIME_BLOCKED) {
    CHIME_BLOCKED = false;
    playChime();
  }
});
// Per-tab session id: the server keys conversation memory on it, so two
// browser tabs don't bleed into each other. A page reload regenerates it and
// the server then reattaches to the latest persisted conversation (--resume).
let SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
// The persisted session file this tab is currently chatting in (the server
// may resume a different id than the tab key — tracked for the sidebar).
let CURRENT = null;

// Tauri updater hook: the shell calls this when a newer release is available
// (safe no-op in the plain browser UI). The shell may re-emit the same message
// while the page is still loading (it cannot detect whether the handler was
// present yet), so identical consecutive messages are shown only once.
window.__blackroseUpdate = (msg) => {
  if (window.__lastUpdateMsg === msg) return;
  window.__lastUpdateMsg = msg;
  const ver = (msg.match(/v([0-9][^\s—]*)/) || [])[1] || '';
  el('activity', '⬆ ' + msg);
  // Offer the real install when running inside the Tauri shell. The shell
  // exposes the global Tauri API (withGlobalTauri) and grants the loopback
  // core UI only updater permissions (capabilities/remote-updater.json), so
  // this page can install an update and nothing else.
  const tauri = window.__TAURI__;
  if (!tauri || !ver) return;
  const row = el('activity');
  const btn = document.createElement('button');
  btn.id = 'btn-install-update';
  btn.textContent = '⬇ Install v' + ver + ' & restart';
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = '⬇ installing… (this can take a minute)';
    try {
      // The shell command does check → download → install → restart. It
      // never resolves on success: restarting replaces this process.
      await tauri.core.invoke('update_install');
      // Reaching here means the command returned an error string.
      btn.disabled = false;
      btn.textContent = '⬇ Install v' + ver + ' & restart';
      el('activity', '⚠ update failed: ' + 'see the app log for details');
    } catch (e) {
      btn.disabled = false;
      btn.textContent = '⬇ Install v' + ver + ' & restart';
      el('activity', '⚠ update failed: ' + (e instanceof Error ? e.message : String(e)));
    }
  });
  row.appendChild(btn);
};

// The startup update check races the page load: it can finish after the shell
// has closed its one-shot emit window (checked on this run — the notice was
// parked but never shown). So inside the shell, pull the parked notice until
// one is displayed instead of relying on a timed emit. Stops once a notice is
// shown, and the handler above dedupes anyway.
if (window.__TAURI__) {
  let pulls = 0;
  const pullNotice = () => {
    if (window.__lastUpdateMsg) return;
    // Never GIVE UP. The old code stopped after 120 pulls (~6 minutes), so an
    // app left open any longer than that could never show a late update
    // banner — which is exactly how a published release went unnoticed on this
    // machine. Poll fast while a notice is plausibly still coming (the shell
    // parks it during boot), then settle into a slow heartbeat so a notice
    // parked later is still picked up. It costs one IPC round trip a minute and
    // stops entirely once a notice has been shown.
    const delay = pulls < 20 ? 3000 : 60_000;
    pulls++;
    window.__TAURI__.core
      .invoke('update_notice')
      .then((msg) => {
        if (msg) window.__blackroseUpdate(String(msg));
      })
      .catch(() => { /* shell not ready yet */ });
    setTimeout(pullNotice, delay);
  };
  setTimeout(pullNotice, 1500);
}

// ---- Conversations sidebar ----
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? '' : (d.getMonth() + 1) + '/' + d.getDate();
}
async function refreshSessions() {
  const listEl = document.getElementById('session-list');
  let sessions = [];
  try {
    const r = await fetch('/api/sessions', { headers: authHeaders() });
    sessions = (await r.json()).sessions || [];
  } catch { return; }
  listEl.innerHTML = '';
  const countEl = document.getElementById('g-count');
  if (countEl) countEl.textContent = sessions.length ? String(sessions.length) : '';
  for (const s of sessions) {
    const row = document.createElement('div');
    row.className = 'sess' + (CURRENT && s.id === CURRENT ? ' active' : '');
    const t = document.createElement('span'); t.className = 't'; t.textContent = s.title;
    const d = document.createElement('span'); d.className = 'd'; d.textContent = fmtDate(s.updated);
    const x = document.createElement('button'); x.className = 'x'; x.textContent = '✕'; x.title = 'Delete conversation';
    x.addEventListener('click', async e => {
      e.stopPropagation();
      if (!confirm('Delete "' + s.title.slice(0, 40) + '"? (archived to disk, recoverable)')) return;
      await fetch('/api/sessions/delete', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: s.id, session: SESSION }),
      });
      if (CURRENT === s.id) CURRENT = null;
      refreshSessions();
    });
    row.addEventListener('click', async () => {
      const r = await fetch('/api/sessions/open', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: s.id, session: SESSION }),
      });
      const j = await r.json();
      if (!j.ok) { el('activity', '⚠ could not open ' + s.id); return; }
      CURRENT = j.id;
      chat.innerHTML = '';
      el('activity', '📂 opened ' + s.id);
      for (const m of j.messages) {
        const text = typeof m.content === 'string' ? m.content
          : Array.isArray(m.content) ? m.content.filter(b => b.type === 'text').map(b => b.text).join(' ') : '';
        // AI turns go through the markdown renderer; user turns stay plain text.
        if (text) {
          if (m.role === 'user') el('msg user', text);
          else elRich('msg ai', text);
        }
      }
      refreshSessions();
    });
    row.appendChild(t); row.appendChild(d); row.appendChild(x);
    listEl.appendChild(row);
  }
}
refreshSessions();
// Launch chooser (UI remodel): if a previous conversation exists, show a
// welcome-back dialog instead of silently resuming — Continue latest / pick
// from the recent list / New chat. No sessions → fresh welcome screen.
(async () => {
  let sessions = [];
  try {
    const r = await fetch('/api/sessions', { headers: authHeaders() });
    sessions = (await r.json()).sessions || [];
  } catch { return; } // offline — leave the fresh welcome screen
  if (!sessions.length) return;
  const launch = document.getElementById('launch');
  const list = document.getElementById('launch-list');
  launch.classList.remove('hidden');
  function openSession(id) {
    return fetch('/api/sessions/open', {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ id: id, session: SESSION }),
    }).then(o => o.json()).then(j => {
      if (!j.ok) { el('activity', '⚠ could not open ' + id); return false; }
      CURRENT = j.id;
      chat.innerHTML = '';
      for (const m of j.messages) {
        const text = typeof m.content === 'string' ? m.content
          : Array.isArray(m.content) ? m.content.filter(b => b.type === 'text').map(b => b.text).join(' ') : '';
        // AI turns go through the markdown renderer; user turns stay plain text.
        if (text) {
          if (m.role === 'user') el('msg user', text);
          else elRich('msg ai', text);
        }
      }
      refreshSessions();
      return true;
    });
  }
  function close() { launch.classList.add('hidden'); }
  // recent conversations to pick from (latest first, capped at 8)
  for (const s of sessions.slice(0, 8)) {
    const row = document.createElement('div');
    row.className = 'lrow';
    const t = document.createElement('span'); t.className = 'lt'; t.textContent = s.title;
    const d = document.createElement('span'); d.textContent = fmtDate(s.updated);
    row.appendChild(t); row.appendChild(d);
    row.addEventListener('click', async () => { if (await openSession(s.id)) close(); });
    list.appendChild(row);
  }
  document.getElementById('launch-continue').addEventListener('click', async () => {
    if (await openSession(sessions[0].id)) close();
  });
  document.getElementById('launch-new').addEventListener('click', () => {
    SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
    CURRENT = null;
    fetch('/api/new', {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ session: SESSION }),
    }).then(refreshSessions).catch(() => {});
    close();
  });
})();
// Optional auth token, delivered via the #token= URL fragment (fragments are
// never sent to the server in request URLs). Read once, then scrub the
// address bar so the token does not linger in visible UI or shared links.
const TOKEN = (location.hash.match(/token=([^&]+)/) || [])[1] || '';
const authHeaders = () => (TOKEN ? { authorization: 'Bearer ' + TOKEN } : {});
if (TOKEN) history.replaceState(null, '', location.pathname + location.search);

// ---- Rich text for AI answers (2026-10-01) ----
// Models emit markdown, and the page rendered it with textContent, so every
// answer arrived peppered with literal asterisks and backticks — the
// "unprofessional" look. Now it is rendered as real formatting.
//
// SECURITY: this is the one place in the UI that turns model output into HTML,
// so the order is fixed and must not change: escape EVERYTHING first, then
// apply markup to the escaped text. Escaping last (or never) would let a model
// — or a document it read from the web — inject <img onerror=...> and run
// script in the user's session. The tag allowlist below is deliberately short.
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderRich(text) {
  if (!text) return '';
  let out = escHtml(text);

  // Every tag we generate is stashed behind a NUL sentinel and restored at the
  // very END. This is what stops a later regex from matching inside markup we
  // just produced: the old code ran emphasis across the assembled <li>/<a>
  // tags rather than across text, so a URL containing an underscore could
  // rewrite its own href and break the link.
  const stash = [];
  const keep = (html) => { stash.push(html); return '\u0000S' + (stash.length - 1) + '\u0000'; };

  // Fenced code first: its contents must never be treated as markdown (a code
  // sample full of ** and _ would otherwise light up).
  //
  // An optional language tag on the fence (ts, python, ...) is dropped, but ONLY
  // when the first line is actually a bare language token. Stripping it
  // unconditionally — which is what this used to do — silently deleted the first
  // line of real code whenever no language was given, e.g. a shell snippet.
  out = out.replace(/\\x60\\x60\\x60([\\s\\S]*?)\\x60\\x60\\x60/g, (m, code) => {
    let body = code.replace(/^\\n|\\n$/g, '');
    body = body.replace(/^[A-Za-z0-9+#._-]+\\n/, '');
    return keep('<pre><code>' + body + '</code></pre>');
  });
  out = out.replace(/\\x60([^\\x60\\n]+)\\x60/g, (m, code) => keep('<code>' + code + '</code>'));

  /**
   * Inline pass, run on ONE LINE at a time so a marker can never pair across a
   * paragraph break (that is how a half-typed ** used to bleed into the next
   * line and turn a whole sentence bold).
   */
  const inline = (s) => s
    .replace(/\\[([^\\]]+)\\]\\((https?:\\/\\/[^\\s)]+)\\)/g,
      (m, label, href) => keep('<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + label + '</a>'))
    // Order matters: *** before **, and ** before *.
    .replace(/\\*\\*\\*([^*\\n]+)\\*\\*\\*/g, (m, t) => keep('<strong><em>' + t + '</em></strong>'))
    .replace(/\\*\\*([^*\\n]+)\\*\\*/g, (m, t) => keep('<strong>' + t + '</strong>'))
    .replace(/(^|[^*\\w])\\*([^*\\n]+)\\*(?![*\\w])/g, (m, p, t) => p + keep('<em>' + t + '</em>'))
    .replace(/(^|[^_\\w])_([^_\\n]+)_(?![_\\w])/g, (m, p, t) => p + keep('<em>' + t + '</em>'))
    .replace(/~~([^~\\n]+)~~/g, (m, t) => keep('<del>' + t + '</del>'))
    // ORPHAN MARKERS. Runs last, on the line AFTER emphasis conversion, so every
    // * that is still here failed to pair and is therefore a typo, not markup.
    // A model that starts a bold run and never closes it leaves a ** stranded
    // mid-sentence, which is exactly the "random symbols" complaint.
    //
    // Multiplication is the one thing that must survive: in "2 * 3" neither
    // operand is a word boundary, so it is left alone.
    .replace(/\\*\\*/g, '')
    .replace(/(^|[^0-9A-Za-z_])\\*(?![0-9A-Za-z_*])/g, '$1');

  // ---- Block pass, line by line ----
  const html = [];
  let para = [];
  let quote = [];
  let list = null;   // { tag, items }

  const closePara = () => {
    if (!para.length) return;
    // Prose becomes a paragraph; single newlines inside it survive as <br> so
    // the model's own line breaks are not reflowed into one blob.
    html.push('<p>' + inline(para.join('\\n')).replace(/\\n/g, '<br>') + '</p>');
    para = [];
  };
  const closeQuote = () => {
    if (!quote.length) return;
    html.push('<blockquote>' + inline(quote.join('<br>')) + '</blockquote>');
    quote = [];
  };
  const closeList = () => {
    if (!list) return;
    html.push('<' + list.tag + '>' + list.items.join('') + '</' + list.tag + '>');
    list = null;
  };
  const flush = () => { closePara(); closeQuote(); closeList(); };
  const addItem = (tag, body) => {
    closePara(); closeQuote();
    // Switching marker type starts a NEW list rather than merging into the
    // previous one, so a stray bullet between numbered items cannot corrupt
    // the numbering.
    if (!list || list.tag !== tag) { closeList(); list = { tag, items: [] }; }
    list.items.push('<li>' + inline(body) + '</li>');
  };

  for (const raw of out.split('\\n')) {
    const line = raw.replace(/\\s+$/, '');
    // A stashed BLOCK element (a code fence) must never be swallowed into a
    // paragraph: <pre> inside <p> is invalid HTML, and the browser closes the
    // paragraph early — which is what made code blocks appear to be glued to
    // the surrounding sentence with stray breaks around them.
    if (/^\\s*\\u0000S\\d+\\u0000\\s*$/.test(line)) {
      flush();
      html.push(line.trim());
      continue;
    }
    if (!line.trim()) { flush(); continue; }
    let m;
    // Headings 1-6. Only 1-3 were matched before, so every "#### Sub-heading"
    // reached the user with its hashes still attached.
    if ((m = line.match(/^\\s*(#{1,6})\\s+(.+?)\\s*#*\\s*$/))) {
      flush();
      const lvl = m[1].length;
      html.push('<h' + lvl + '>' + inline(m[2]) + '</h' + lvl + '>');
      continue;
    }
    if (/^\\s*(?:---+|\\*\\*\\*+|___+)\\s*$/.test(line)) { flush(); html.push('<hr>'); continue; }
    // Blockquote. NOTE: "&gt;" not ">" — the text was already HTML-escaped
    // before this pass, so a literal ">" no longer exists at this point. The
    // previous version matched ">" here and therefore never fired, leaving
    // quoted lines to render as visible ">" characters.
    if ((m = line.match(/^\\s*&gt;\\s?(.*)$/))) {
      closePara(); closeList();
      quote.push(m[1]);
      continue;
    }
    // "- ", "* ", "+ " and "/ " all get used as bullets by real models. A
    // leading slash followed by a space is a bullet and never a path — a path
    // would be "/usr/bin" with no space after the slash — so this is safe.
    if ((m = line.match(/^\\s*(?:[-*+]|\\/)\\s+(.+)$/))) { addItem('ul', m[1]); continue; }
    // Numbered lists render as <ol>. They used to be emitted as <li> inside a
    // <ul>, so "1. 2. 3." showed up as three identical bullets.
    if ((m = line.match(/^\\s*\\d+[.)]\\s+(.+)$/))) { addItem('ol', m[1]); continue; }
    closeList(); closeQuote();
    para.push(line);
  }
  flush();

  out = html.join('');
  out = out.replace(/\\u0000S(\\d+)\\u0000/g, (m, i) => stash[Number(i)] || '');
  return out;
}

/** Append an AI answer, rendered. Used for final + streamed text. */
function elRich(cls, text) {
  const d = document.createElement('div');
  // "rich" turns OFF white-space:pre-wrap for this message. renderRich now emits
  // real block elements (<p>, <ul>, <h3>…), and with pre-wrap still on, every
  // newline BETWEEN those tags rendered as a visible blank line — which is what
  // made answers look like they had random gaps and stray characters in them.
  d.className = cls + ' rich';
  d.innerHTML = renderRich(text);
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
  return d;
}

function el(cls, text) {
  const d = document.createElement('div');
  d.className = cls;
  if (text !== undefined) d.textContent = text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
  return d;
}

// ---- Connected routes (sidebar section): one row per gateway route ----
// Replaces the old header route tray (2026-09-30). Same data from /api/health,
// but rendered as a readable list: state dot, route name, model, detail.
let LAST_HEALTH = null;
/** envVar → number of keys stored, refreshed with the key roster. */
let KEY_COUNTS = {};
/** route name -> env var, straight from the roster (source of truth). */
let ROUTE_ENV = {};

function routeSummary(h) {
  const routes = (h && h.routes) || [];
  const ok = routes.filter(r => r.state === 'ok').length;
  // unknown is NOT "not ok" — it means not probed yet, or a gateway that hides
  // /models. Counting it as a failure made a healthy chain look broken.
  const bad = routes.filter(r => r.state === 'degraded' || r.state === 'down').length;
  return routes.length + ' route' + (routes.length === 1 ? '' : 's') +
    ' · ' + ok + ' ok' + (bad ? ' · ' + bad + ' not ok' : '');
}

/**
 * route name -> the env var its keys live under, as reported by /api/keys/roster.
 *
 * BUG FIXED 2026-10-01: this used to DERIVE the name as
 * BLACKROSE_<ROUTE>_API_KEY. That is wrong for anthropic, whose variable is
 * plain ANTHROPIC_API_KEY — so clicking "keys" on the Anthropic route targeted a
 * variable that does not exist and the modal could never preselect it.
 *
 * Deriving is the wrong shape regardless: the mapping is data the server already
 * owns (ROUTE_KEY_SPECS, plus providerKeyEnvVar() for custom providers), and a
 * client-side rule can only ever agree with it by coincidence. Two sources of
 * truth for one identifier is exactly how the two drift apart.
 *
 * Falls back to the old derivation only until the roster lands, so a slow first
 * fetch cannot make every count read as "unknown".
 */
function envVarForRoute(name) {
  return ROUTE_ENV[String(name)] || ('BLACKROSE_' + String(name).toUpperCase() + '_API_KEY');
}

/**
 * How many keys a route holds, or null when the roster has not loaded.
 *
 * Shown on the route row because "one key" is the reason a gateway starts
 * failing the moment it rate-limits, and that is invisible from the health
 * state alone. Null (rather than 0) until a roster arrives, so we never claim a
 * provider has no keys just because the fetch has not returned yet.
 */
function keyCountFor(name) {
  const n = KEY_COUNTS[envVarForRoute(name)];
  return typeof n === 'number' ? n : null;
}

function paintRoutes(h) {
  const list = document.getElementById('route-list');
  const model = document.getElementById('routes-model');
  const count = document.getElementById('routes-count');
  if (!list || !model) return;
  model.textContent = (h && h.model) || 'unknown';
  const routes = (h && h.routes) || [];
  if (count) count.textContent = routes.length ? String(routes.length) : '';
  list.innerHTML = '';
  if (!routes.length) {
    const e = document.createElement('div');
    e.id = 'routes-empty';
    e.textContent = 'No gateway routes reported — using the direct provider.';
    list.appendChild(e);
    return;
  }
  for (const r of routes) {
    const row = document.createElement('div');
    // Whitelist the state instead of trusting /api/health. A state we do not
    // recognise must paint as 'unknown' (grey = not probed yet), NOT 'down':
    // 'down' is the legend's "needs a key or a fix", so a missing field would
    // claim a human is required to act on a route we simply know nothing about.
    const state = ['ok', 'degraded', 'down', 'unknown'].includes(r.state) ? r.state : 'unknown';
    row.className = 'route-row ' + state;
    const dot = document.createElement('span');
    dot.className = 'rd';
    const text = document.createElement('div');
    text.className = 'rt';
    const name = document.createElement('div');
    name.className = 'rn';
    name.textContent = r.name;
    text.appendChild(name);
    if (r.model) {
      const m = document.createElement('div');
      m.className = 'rm';
      m.textContent = r.model;
      text.appendChild(m);
    }
    if (r.detail) {
      const d = document.createElement('div');
      d.className = 'rdetail';
      d.textContent = r.detail;
      text.appendChild(d);
    }
    row.title = (r.state || 'unknown').toUpperCase() + ' — ' + r.name +
      (r.model ? ' · ' + r.model : '') + (r.detail ? ' — ' + r.detail : '');
    row.appendChild(dot);
    row.appendChild(text);
    // Per-route actions. Key management lives HERE, next to the route it
    // belongs to: the Connected routes list is where you already are when you
    // notice a gateway is failing, so "add another key" is one click away
    // rather than a trip through Settings.
    const acts = document.createElement('span');
    acts.className = 'ra';
    const kc = keyCountFor(r.name);
    const keysBtn = document.createElement('button');
    keysBtn.className = 'rb';
    keysBtn.textContent = kc === null ? 'keys' : 'keys ' + kc;
    keysBtn.title = (kc === null
        ? 'Add keys for ' + r.name
        : kc + ' key(s) stored for ' + r.name + (kc === 1
            ? ' — add a second so a rate limit does not stop work'
            : '')) +
      '. Accepts one per line, a JSON array, KEY=value lines, or comma-separated.';
    // The env var comes from the roster map the server gave us, NOT from a
    // client-side derivation — anthropic's real variable is ANTHROPIC_API_KEY,
    // which no rule based on the route name could produce.
    keysBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openBulkFor(envVarForRoute(r.name), r.name);
    });
    acts.appendChild(keysBtn);
    const detailBtn = document.createElement('button');
    detailBtn.className = 'rb';
    detailBtn.textContent = 'details';
    detailBtn.title = 'Route details';
    detailBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      showRouteDetails();
    });
    acts.appendChild(detailBtn);
    row.appendChild(acts);
    list.appendChild(row);
  }
}

// Sidebar memory stats. Repainted on every health poll so an import (which
// changes these numbers) shows up without a reload.
function paintStats(h) {
  const s = document.getElementById('stats');
  if (!s) return;
  s.innerHTML = '';
  const rows = [['Memories', h.memories], ['Knowledge chunks', h.knowledgeChunks], ['Schedules', h.schedules], ['Skills', h.skills]];
  if (h.embed) rows.push(['Vector index', h.embed.indexed]);
  for (const [k, v] of rows) {
    const d = document.createElement('div');
    d.className = 'stat';
    d.innerHTML = '<span>' + k + '</span><b>' + v + '</b>';
    s.appendChild(d);
  }
  // B5 visibility: when the Gemini daily embedding quota is spent the backend
  // falls back to hashing and retrieval silently degrades to keyword matching.
  // Previously only a console line said so, and the desktop app has no console,
  // so search just quietly got worse. Say it in the sidebar instead.
  if (h.embed && h.embed.degraded) {
    const w = document.createElement('div');
    w.className = 'stat';
    w.id = 'embed-warn';
    const lab = document.createElement('span');
    lab.textContent = 'Search';
    const val = document.createElement('b');
    val.textContent = h.embed.quotaExhausted ? 'quota spent' : (h.embed.indexMismatch ? 'rebuilding' : 'lexical only');
    val.style.color = 'var(--warn)';
    val.style.fontWeight = '600';
    w.title = 'Semantic search is offline: retrieval matches keywords only until the embedding backend recovers. Run node scripts/warm-embed.ts to re-index.';
    w.appendChild(lab);
    w.appendChild(val);
    s.appendChild(w);
  }
}

function pollHealth() {
  fetch('/api/health', { headers: authHeaders() }).then(r => r.json()).then(h => {
    dot.classList.add('on');
    dot.title = 'connected';
    LAST_HEALTH = h;
    paintRoutes(h);
    paintStats(h);
  }).catch(() => { dot.title = 'offline'; });
}
pollHealth();
setInterval(pollHealth, 30000);

// "Route details" button — the full chain as text, in the shared panel.
// Named so each route row's own "details" button can reuse it.
function showRouteDetails() {
  const h = LAST_HEALTH;
  if (!h) { showPanel('🔗 Connected routes', 'no health data yet'); return; }
  const routes = h.routes || [];
  // NOTE: this page lives inside a TS template literal, so a JS newline escape
  // must be doubled (\\n) or the browser would receive a literal backslash-n.
  const head = 'Provider : ' + h.provider + '\\nModel    : ' + h.model + '\\nRoutes   : ' + routeSummary(h) + '\\n\\n';
  const body = routes.length
    ? routes.map(r => (r.state || '?').toUpperCase().padEnd(9) + ' ' + r.name +
        (r.model ? '\\n          ' + r.model : '') +
        (r.detail ? '\\n          ' + r.detail : '')).join('\\n')
    : '(none — the direct provider is in use)';
  // Legend, so a state name is never a puzzle. "unknown" in particular is easy
  // to misread as broken when it really means "not probed yet".
  // (Newlines must stay doubled: this page lives inside a TS template literal.)
  const legend =
    '\\n\\nok = reachable · degraded = throttled/quota (self-recovers)' +
    '\\ndown = needs a key or a fix · unknown = not probed yet (gateway hides /models)'
  showPanel('🔗 Connected routes', head + body + legend);
}
document.getElementById('btn-routes').addEventListener('click', showRouteDetails);

// ---- Fallback chain editor ----
// The chain decides which gateways are tried, in what order. It used to be
// reachable only by setting the BLACKROSE_ROUTES environment variable before
// launch, which a double-click desktop user cannot do — so the add-provider
// panel could create a route that was never actually used.
const chainModal = document.getElementById('chain-modal');
const chainList = document.getElementById('chain-list');
const chainAdd = document.getElementById('chain-add');
const chainNote = document.getElementById('chain-note');
const chainErr = document.getElementById('chain-err');
let CHAIN = [];
let CHAIN_EDITABLE = true;

function chainFail(msg) {
  chainErr.textContent = msg;
  chainErr.classList.add('show');
}

function paintChain() {
  chainList.innerHTML = '';
  if (!CHAIN.length) {
    const e = document.createElement('div');
    e.className = 'hint';
    e.textContent = 'The chain is empty — pick a gateway below.';
    chainList.appendChild(e);
  }
  CHAIN.forEach((name, i) => {
    const row = document.createElement('div');
    row.className = 'chain-row';
    const pos = document.createElement('span');
    pos.className = 'cp';
    pos.textContent = String(i + 1);
    const nm = document.createElement('span');
    nm.className = 'cn';
    nm.textContent = name;
    const kc = keyCountFor(name);
    if (kc !== null) {
      const badge = document.createElement('span');
      badge.className = 'cb';
      badge.textContent = kc + (kc === 1 ? ' key' : ' keys');
      nm.appendChild(badge);
    }
    const acts = document.createElement('span');
    acts.className = 'ra';
    const mk = (label, title, fn, disabled) => {
      const b = document.createElement('button');
      b.className = 'rb';
      b.textContent = label;
      b.title = title;
      b.disabled = !!disabled;
      b.addEventListener('click', fn);
      acts.appendChild(b);
      return b;
    };
    mk('↑', 'Try this one earlier', () => {
      if (i === 0) return;
      [CHAIN[i - 1], CHAIN[i]] = [CHAIN[i], CHAIN[i - 1]];
      paintChain();
    }, i === 0);
    mk('↓', 'Try this one later', () => {
      if (i === CHAIN.length - 1) return;
      [CHAIN[i + 1], CHAIN[i]] = [CHAIN[i], CHAIN[i + 1]];
      paintChain();
    }, i === CHAIN.length - 1);
    mk('✕', 'Remove from the chain (the provider itself is kept)', () => {
      CHAIN.splice(i, 1);
      paintChain();
    });
    row.appendChild(pos);
    row.appendChild(nm);
    row.appendChild(acts);
    chainList.appendChild(row);
  });
  // Only offer gateways that are not already in the chain — re-adding one would
  // just be a duplicate the server has to reject.
  if (chainAdd) {
    const inChain = new Set(CHAIN);
    const opts = Object.keys(ROUTE_ENV)
      .filter((n) => !inChain.has(n))
      .sort()
      .map((n) => '<option value="' + n + '">' + n + '</option>')
      .join('');
    chainAdd.innerHTML = opts || '<option value="">— all gateways are already in the chain —</option>';
  }
}

async function loadChain() {
  try {
    const res = await fetch('/api/routes', { headers: authHeaders() });
    const j = await res.json();
    if (!j.ok) return;
    CHAIN = Array.isArray(j.routes) ? j.routes.slice() : [];
    CHAIN_EDITABLE = j.editable !== false;
    if (chainNote) {
      chainNote.textContent = CHAIN_EDITABLE
        ? 'Order here is the order BlackRose tries.'
        : 'BLACKROSE_ROUTES is set in the environment and takes precedence, so this chain is read-only.';
    }
    const saveBtn = document.getElementById('chain-save');
    if (saveBtn) saveBtn.disabled = !CHAIN_EDITABLE;
    paintChain();
  } catch (e) {
    if (chainNote) chainNote.textContent = 'Could not load the chain: ' + (e instanceof Error ? e.message : String(e));
  }
}

const btnChain = document.getElementById('btn-chain');
if (btnChain) btnChain.addEventListener('click', async () => {
  if (chainErr) { chainErr.textContent = ''; chainErr.classList.remove('show'); }
  await loadChain();
  if (chainModal) chainModal.classList.remove('hidden');
});
if (chainAdd) chainAdd.addEventListener('change', () => {
  if (!chainAdd.value) return;
  CHAIN.push(chainAdd.value);
  paintChain();
});
const chainCancel = document.getElementById('chain-cancel');
if (chainCancel) chainCancel.addEventListener('click', () => chainModal.classList.add('hidden'));
if (chainModal) chainModal.addEventListener('click', (e) => { if (e.target === chainModal) chainModal.classList.add('hidden'); });
const chainSave = document.getElementById('chain-save');
if (chainSave) chainSave.addEventListener('click', async () => {
  if (chainErr) { chainErr.textContent = ''; chainErr.classList.remove('show'); }
  if (CHAIN.length === 0) return chainFail('Keep at least one gateway in the chain.');
  chainSave.disabled = true;
  try {
    const res = await fetch('/api/routes', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ routes: CHAIN }),
    });
    const j = await res.json();
    if (!j.ok) return chainFail(j.error || 'could not save the chain');
    CHAIN = j.routes;
    chainModal.classList.add('hidden');
    // The sidebar paints from live health, so repaint it to reflect the new
    // order. A restart is not needed: the server publishes the chain straight
    // into the environment for the next turn.
    pollHealth();
    el('activity', '↕️ Fallback chain saved: ' + j.routes.join(' → '));
  } catch (e) {
    chainFail(e instanceof Error ? e.message : String(e));
  } finally {
    chainSave.disabled = false;
  }
});
loadChain();

// ---- Drag-and-drop file input ----
// Accepts ANY file type; saves it and puts the path in the composer.
//
// BUG FIXED (2026-09-28): this used to bind dragover/drop to a thin strip
// inside the composer only, so dropping a file anywhere else on the page
// (i.e. everywhere a user would naturally try) silently did nothing. It is
// now bound to the whole window, with a full-page overlay while dragging.
(function setupDropZone() {
  const fileInput = document.getElementById('audio-input');
  const attachBtn = document.getElementById('attach');
  const veil = document.getElementById('dropveil');
  if (!fileInput) return;
  // Accept ANY file — no extension restriction
  const ACCEPT = /./i;
  let busy = false;

  async function uploadFile(file) {
    if (busy) return;
    busy = true;
    el('activity', '📎 uploading ' + file.name + ' (' + Math.round(file.size / 1024) + ' KB)…');
    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'x-file-name': file.name, 'content-type': 'application/octet-stream', ...authHeaders() },
        body: file,
      });
      const j = await res.json();
      if (!j.ok) { el('activity', '⚠ upload failed'); busy = false; return; }
      el('activity', '✔ saved → ' + j.path + ' (' + file.name + ')');
      // Hand the path over ready to use: appended to the composer but NOT sent,
      // so the next message can be "learn this", "summarise this" or
      // "transcribe this". Typing it by hand was the whole friction.
      input.value = (input.value ? input.value + ' ' : '') + j.path;
      input.dispatchEvent(new Event('input'));
      input.focus();
    } catch (e) {
      el('activity', '⚠ upload error: ' + e.message);
    }
    busy = false;
  }

  if (attachBtn) attachBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) uploadFile(fileInput.files[0]);
    fileInput.value = '';
  });

  // Drag & drop over the WHOLE window, not a strip. Without preventDefault on
  // dragover the webview would navigate to / try to open the dropped file, so
  // that is the part that actually makes it work.
  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') !== -1;
  window.addEventListener('dragenter', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth++;
    if (veil) veil.classList.add('show');
  });
  window.addEventListener('dragover', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });
  window.addEventListener('dragleave', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0 && veil) veil.classList.remove('show');
  });
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    if (veil) veil.classList.remove('show');
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });
})();

// ---- Push-to-talk mic (composer 🎤 button): local offline dictation ----
(function setupMic() {
  const mic = document.getElementById('mic');
  if (!mic) return;
  const hint = document.getElementById('voicehint');
  let listening = false;
  mic.addEventListener('click', async () => {
    if (listening) return;
    listening = true;
    // Discoverability hint has done its job once the mic is actually used.
    if (hint) hint.classList.add('gone');
    mic.classList.add('listening');
    mic.textContent = '●';
    el('activity', '🎤 listening… speak now (up to 8s, offline local engine)');
    try {
      const res = await fetch('/api/listen', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ seconds: 8 }),
      });
      // A 404 means this page is served by an OLD core that predates the
      // /api/listen route (a stale shell left over from a previous version).
      // Say so plainly — the old code just showed a generic failure, which is
      // indistinguishable from a dead microphone.
      if (res.status === 404) {
        el('activity', '🎤 voice input unavailable: this window is attached to an outdated BlackRose core. Close BlackRose completely (tray icon → quit) and reopen it.');
        return;
      }
      const d = await res.json().catch(() => null);
      if (!d) {
        el('activity', '🎤 voice input failed: the core did not return a result (HTTP ' + res.status + ').');
        return;
      }
      if (d.ok && d.text) {
        input.value = input.value ? input.value + ' ' + d.text : d.text;
        input.dispatchEvent(new Event('input'));
        input.focus();
        el('activity', '🎤 voice captured — edit if needed, then send');
      } else if (d.ok) {
        el('activity', '🎤 heard nothing. Speak during the 8s window, and check the mic is the Windows default input with a moving level meter in Settings → System → Sound.');
      } else {
        el('activity', '🎤 ' + (d.detail || 'voice input failed'));
      }
    } catch (e) {
      el('activity', '🎤 voice input failed: ' + e.message);
    }
    listening = false;
    mic.classList.remove('listening');
    mic.textContent = '🎤';
  });
})();

document.querySelectorAll('aside button[data-mode]').forEach(b => {
  b.addEventListener('click', () => { mode = b.dataset.mode; el('activity', 'mode: ' + mode); });
});
document.getElementById('btn-new').addEventListener('click', () => {
  // Non-destructive "New chat": rekey this tab to a brand-new empty
  // conversation. The previous conversation stays persisted and visible
  // in the sidebar. /api/new on the NEW key just allocates the fresh
  // conversation server-side (nothing to archive).
  SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
  CURRENT = null;
  chat.innerHTML = '';
  el('msg ai', 'Started a new conversation — the previous one is saved in the sidebar.');
  fetch('/api/new', {
    method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ session: SESSION }),
  }).then(refreshSessions).catch(() => {});
});
// 🧹 Clear conversation: rekey to a fresh conversation too (the id used to be
// a duplicate of btn-new, which made this button dead — fixed with btn-clear).
document.getElementById('btn-clear').addEventListener('click', () => {
  SESSION = 'tab-' + Math.random().toString(36).slice(2, 10);
  CURRENT = null;
  chat.innerHTML = '';
  el('msg ai', 'Conversation cleared — the previous one is saved in the sidebar.');
  fetch('/api/new', {
    method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ session: SESSION }),
  }).then(refreshSessions).catch(() => {});
});

// ---- Generic prompt dialog (export / import / shut down) ----
// Resolves with { file, password } on OK, or null when cancelled. The caller
// decides which inputs are shown, so one dialog serves every action.
const modalEl = document.getElementById('modal');
const mTitle = document.getElementById('m-title');
const mMsg = document.getElementById('m-msg');
const mHint = document.getElementById('m-hint');
const mErr = document.getElementById('m-err');
const mFileField = document.getElementById('m-file-field');
const mFile = document.getElementById('m-file');
const mPassField = document.getElementById('m-pass-field');
const mPass = document.getElementById('m-pass');
const mOk = document.getElementById('m-ok');
const mCancel = document.getElementById('m-cancel');

function askModal(opts) {
  return new Promise((resolve) => {
    mTitle.textContent = opts.title || '';
    mMsg.textContent = opts.msg || '';
    mHint.textContent = opts.hint || '';
    mErr.textContent = '';
    mErr.classList.remove('show');
    mFileField.style.display = opts.file ? 'block' : 'none';
    mPassField.style.display = opts.password ? 'block' : 'none';
    mFile.value = '';
    mPass.value = '';
    mOk.textContent = opts.ok || 'OK';
    mOk.className = 'allow' + (opts.danger ? ' danger' : '');
    modalEl.classList.add('show');
    (opts.password ? mPass : mOk).focus();

    const close = (value) => {
      modalEl.classList.remove('show');
      mOk.removeEventListener('click', onOk);
      mCancel.removeEventListener('click', onCancel);
      document.removeEventListener('keydown', onKey);
      resolve(value);
    };
    const complain = (text) => { mErr.textContent = text; mErr.classList.add('show'); };
    const onOk = () => {
      const file = (mFile.files && mFile.files[0]) || null;
      if (opts.file && !file) return complain('Choose a .aistate file first.');
      if (opts.password && !mPass.value) return complain('A password is required — state holds private data.');
      close({ file, password: mPass.value });
    };
    const onCancel = () => close(null);
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    mOk.addEventListener('click', onOk);
    mCancel.addEventListener('click', onCancel);
    document.addEventListener('keydown', onKey);
  });
}

// Shared driver for the sidebar actions below: ask, run with the button
// disabled, report the outcome in the activity feed.
const runAction = (btn) => async (opts, work) => {
  const p = await askModal(opts);
  if (!p) return;
  btn.disabled = true;
  try {
    el('activity', await work(p));
  } catch (e) {
    el('activity', '⚠ ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btn.disabled = false;
  }
};

const btnExport = document.getElementById('btn-export');
const askExport = runAction(btnExport);
btnExport.addEventListener('click', () => askExport({
  title: '⬇ Export state',
  msg: 'Writes an encrypted snapshot of memories, knowledge, skills and schedules.',
  hint: 'The .aistate file is sealed with this password — keep it, or the backup cannot be restored.',
  password: true, ok: 'Export',
}, async (p) => {
  const res = await fetch('/api/export', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ password: p.password }),
  });
  const j = await res.json();
  if (!res.ok || !j.ok) throw new Error(j.error || ('HTTP ' + res.status));
  return 'exported ' + j.files + ' file(s), ' + Math.max(1, Math.round(j.bytes / 1024)) + ' KB → ' + j.path;
}));

const btnImport = document.getElementById('btn-import');
const askImport = runAction(btnImport);
btnImport.addEventListener('click', () => askImport({
  title: '⬆ Import state',
  msg: 'Restores memories, knowledge, skills and schedules from an encrypted .aistate backup.',
  hint: 'Matching files in your data folder are replaced. Conversations are not touched.',
  file: true, password: true, ok: 'Import', danger: true,
}, async (p) => {
  // The bytes are posted to the local core (a browser file picker hands over
  // content, not a path), which writes them next to the data folder first.
  const buf = await p.file.arrayBuffer();
  const res = await fetch('/api/import', {
    method: 'POST',
    headers: {
      'content-type': 'application/octet-stream',
      'x-file-name': p.file.name,
      'x-state-password': p.password,
      ...authHeaders(),
    },
    body: buf,
  });
  const j = await res.json();
  if (!res.ok || !j.ok) throw new Error(j.error || ('HTTP ' + res.status));
  pollHealth();  // the memory counters just changed
  return 'restored ' + j.restored + ' file(s) from ' + p.file.name;
}));

// 🔄 Check for update — the shell owns the updater, so this is a shell command.
// Its answer is rendered through the same path as the automatic notice (which
// is also what adds the "Install vX & restart" button).
const btnUpdate = document.getElementById('btn-update');
btnUpdate.addEventListener('click', async () => {
  if (!window.__TAURI__) {
    el('activity', 'update checks run inside the desktop app');
    return;
  }
  btnUpdate.disabled = true;
  el('activity', 'checking for updates…');
  try {
    const msg = await window.__TAURI__.core.invoke('update_check');
    window.__lastUpdateMsg = undefined;   // a manual check always re-renders
    if (window.__blackroseUpdate) window.__blackroseUpdate(String(msg));
  } catch (e) {
    el('activity', '⚠ update check failed: ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btnUpdate.disabled = false;
  }
});

// 🛑 Shut down — stops the core and closes the shell, so no daemon is left over.
const btnShutdown = document.getElementById('btn-shutdown');
btnShutdown.addEventListener('click', async () => {
  const p = await askModal({
    title: '🛑 Shut down BlackRose',
    msg: 'Stops the assistant and closes the window.',
    hint: 'Conversations and memory are already saved to disk. Running work is interrupted.',
    ok: 'Shut down', danger: true,
  });
  if (!p) return;
  el('activity', 'shutting down — the window will close');
  if (!window.__TAURI__) {
    el('activity', 'close this browser tab to stop the UI (the core keeps running here)');
    return;
  }
  btnShutdown.disabled = true;
  try {
    await window.__TAURI__.core.invoke('app_shutdown');
  } catch (e) {
    btnShutdown.disabled = false;
    el('activity', '⚠ shutdown failed: ' + (e instanceof Error ? e.message : String(e)));
  }
});

// ---- Capability inspector ------------------------------------------------
// The sidebar can show what the agent already knows and can do, by running
// READ-ONLY tools through POST /api/tool. The server holds a fixed allowlist,
// so these buttons can never mutate state or touch the machine — anything that
// does belongs in chat, where it can ask for approval first.
const panel = document.getElementById('panel');
const pnTitle = document.getElementById('pn-title');
const pnBody = document.getElementById('pn-body');
document.getElementById('pn-close').addEventListener('click', () => panel.classList.add('hidden'));
panel.addEventListener('click', (e) => { if (e.target === panel) panel.classList.add('hidden'); });

function showPanel(title, text) {
  pnTitle.textContent = title;
  pnBody.textContent = text;
  panel.classList.remove('hidden');
}

async function runTool(btn, title, tool, input) {
  const restore = btn.textContent;
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const r = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name: tool, input: input || {} }),
    });
    const j = await r.json();
    // KNOWLEDGE_LIST is the exception to the wall of text. Every other panel
    // hands raw text to showPanel; learned sources are handed rows instead, so
    // a corpus of hundreds is browsable instead of one unbroken block. The
    // newline split happens HERE (page script) rather than in the tool, because
    // the tool must keep its output plain text for chat turns and probes.
    if (tool === 'knowledge_list' && typeof j.content === 'string') {
      renderLearnedList(title, j.content);
      return;
    }
    showPanel(title, j.content || j.error || '(no output)');
  } catch (e) {
    showPanel(title, '⚠ ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    btn.disabled = false;
    btn.textContent = restore;
  }
}

// Rowed renderer for the learned-sources panel. One div per source, newest
// first (the server already sorts them); the newest corpus has thousands of
// rows, so the footer line says which slice is on screen instead of the whole
// wall pretending to be complete. This is M item 3 of the 2026-10-02 design
// audit: the first panel that is a list instead of a paragraph.
function renderLearnedList(title, content) {
  pnTitle.textContent = title;
  pnBody.textContent = '';
  const host = document.createElement('div');
  host.className = 'learned-list';
  for (const line of String(content || '').split(String.fromCharCode(10))) {
    const row = document.createElement('div');
    row.className = 'learned-row';
    row.textContent = line;
    host.appendChild(row);
  }
  pnBody.appendChild(host);
  panel.classList.remove('hidden');
}

async function askQuery(btn, title, tool) {
  const q = prompt('Search query:');
  if (q === null) return;
  if (!q.trim()) { el('activity', '⚠ empty query — nothing searched'); return; }
  await runTool(btn, title, tool, { query: q.trim() });
}

const bind = (id, title, tool, input) => {
  const b = document.getElementById(id);
  if (b) b.addEventListener('click', () => runTool(b, title, tool, input));
};
const bindQ = (id, title, tool) => {
  const b = document.getElementById(id);
  if (b) b.addEventListener('click', () => askQuery(b, title, tool));
};

bind('btn-skills', '🧩 Skills', 'skill_list', {});
bind('btn-missions', '⏰ Scheduled missions', 'schedule_list', {});
bind('btn-jobs', '⚙️ Background jobs', 'job_list', {});

// ---- Forget a learned source (B6) ----
// Knowledge could be added but never removed. A dropdown rather than a free-text
// box on purpose: the tool resolves a partial reference, and a short or ambiguous
// reference deletes nothing and asks you to be specific. Picking the exact source
// means that ambiguity cannot arise here at all.
const forgetModal = document.getElementById('forget-modal');
const forgetPick = document.getElementById('forget-pick');
const forgetErr = document.getElementById('forget-err');
const forgetHint = document.getElementById('forget-hint');

// ---- B7: duplicate scan ----
// Report-only. It deliberately offers no "clean up" button that deletes in one
// click: the sweep names a redundant source and a keeper, and which one you want
// to keep is a judgement call about YOUR corpus, not something a similarity
// score should decide. The report hands you the names; forgetting stays an
// explicit, per-source action above it.
const dedupScan = document.getElementById('dedup-scan');
const dedupReport = document.getElementById('dedup-report');
if (dedupScan) dedupScan.addEventListener('click', async () => {
  dedupReport.classList.remove('hidden');
  dedupReport.textContent = 'Scanning…';
  dedupScan.disabled = true;
  try {
    const res = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      // knowledge_dedup is read-only: it reports and deletes nothing.
      body: JSON.stringify({ name: 'knowledge_dedup', input: {} }),
    });
    const j = await res.json();
    if (!j.ok) {
      dedupReport.textContent = 'Could not scan: ' + (j.error || 'unknown error');
      return;
    }
    // Offer the redundant sources in the picker, so acting on the report is one
    // click instead of a retype.
    const lines = String(j.result ?? '');
    dedupReport.textContent = lines;
    // No regex here on purpose: every backslash would have to be doubled to survive
    // the enclosing TS template literal, and a missed one silently corrupts the
    // pattern. Plain string scanning has no escapes to get wrong.
    const ids = []
    for (const line of lines.split(String.fromCharCode(10))) {
      const pct = line.indexOf('% of \"')
      if (pct < 0) continue
      const q1 = line.indexOf('"', pct + 6)
      const q2 = q1 < 0 ? -1 : line.indexOf('"', q1 + 1)
      if (q1 > 0 && q2 > q1) ids.push(line.slice(q1 + 1, q2))
    }
    if (ids.length) {
      const current = [...forgetPick.options].map((o) => o.value);
      const extra = ids.filter((id) => !current.includes(id));
      for (const id of extra) {
        forgetPick.appendChild(Object.assign(document.createElement('option'), { value: id, textContent: id }));
      }
      forgetHint.textContent = 'Pick a redundant source above to remove it. Nothing is deleted until you do.';
    }
  } catch (e) {
    dedupReport.textContent = 'Could not scan: ' + (e instanceof Error ? e.message : String(e));
  } finally {
    dedupScan.disabled = false;
  }
});

const forgetGo = document.getElementById('forget-go');

function forgetFail(msg) {
  forgetErr.textContent = msg;
  forgetErr.classList.add('show');
}

const btnKforget = document.getElementById('btn-kforget');
if (btnKforget) btnKforget.addEventListener('click', async () => {
  forgetErr.textContent = '';
  forgetErr.classList.remove('show');
  forgetHint.textContent = 'Loading…';
  forgetPick.innerHTML = '<option value="">loading…</option>';
  try {
    // knowledge_list is read-only, so this needs no approval dialog.
    const res = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name: 'knowledge_list', input: {} }),
    });
    const j = await res.json();
    if (!j.ok) throw new Error(j.error || 'could not list sources');
    const text = String(j.result ?? '');
    const items = text.split('\\n').filter((l) => l.startsWith('- ['));
    if (!items.length) {
      forgetPick.innerHTML = '<option value="">nothing learned yet</option>';
      forgetHint.textContent = 'Learn something first — then it can be forgotten.';
      forgetModal.classList.remove('hidden');
      return;
    }
    forgetPick.innerHTML = items.map((l) => {
      // Parse "- [kind] SOURCE (N chunks, saved DATE)" with plain string work instead of a
      // regex: every backslash here would have to be DOUBLED to survive the enclosing
      // TS template literal, and a missed one silently corrupts the regex. Splitting
      // on the fixed delimiters has no escapes at all.
      const open = l.indexOf('] ')
      const paren = l.lastIndexOf(' (')
      const src = open > 0 && paren > open ? l.slice(open + 2, paren) : l.slice(2)
      return '<option value="' + escHtml(src) + '">' + escHtml(src) + '</option>';
    }).join('');
    forgetHint.textContent = items.length + ' learned source' + (items.length === 1 ? '' : 's') + '.';
    forgetModal.classList.remove('hidden');
  } catch (e) {
    forgetFail(e instanceof Error ? e.message : String(e));
  }
});

const forgetCancel = document.getElementById('forget-cancel');
if (forgetCancel) forgetCancel.addEventListener('click', () => forgetModal.classList.add('hidden'));
if (forgetModal) forgetModal.addEventListener('click', (e) => { if (e.target === forgetModal) forgetModal.classList.add('hidden'); });
if (forgetGo) forgetGo.addEventListener('click', async () => {
  const source = forgetPick.value;
  if (!source) return forgetFail('Pick a source first.');
  // Built by concatenation, not a template literal, because a real newline in a
  // string inside the page's own TS template literal breaks the page script.
  if (!confirm('Forget "' + source + '"?' + String.fromCharCode(10, 10) +
    'Its text and vectors are removed. The original file is not touched, so you can learn it again later. This cannot be undone.')) return;
  forgetGo.disabled = true;
  try {
    // Destructive, so this goes through the normal approval path like any other
    // state-changing tool — it is deliberately NOT in the read-only allowlist.
    const res = await fetch('/api/tool', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name: 'knowledge_forget', input: { source } }),
    });
    const j = await res.json();
    if (!j.ok) return forgetFail(j.error || 'could not forget that source');
    if (j.approvalRequired) {
      forgetModal.classList.add('hidden');
      el('activity', '🗑 asked to forget ' + source + ' — approve or deny the request');
      return;
    }
    forgetModal.classList.add('hidden');
    el('activity', '🗑 ' + (j.result ?? 'forgotten'));
    pollHealth();
  } catch (e) {
    forgetFail(e instanceof Error ? e.message : String(e));
  } finally {
    forgetGo.disabled = false;
  }
});

bind('btn-klist', '📚 Learned sources', 'knowledge_list', {});
bind('btn-projects', '📁 Project notes', 'project_read', {});
bindQ('btn-ksearch', '🔎 Knowledge search', 'knowledge_search');
bindQ('btn-msearch', '🧠 Memory search', 'memory_search');

// Tool catalogue: metadata only, straight from /api/tools (no tool is run).
document.getElementById('btn-toolcat').addEventListener('click', async (e) => {
  const b = e.currentTarget;
  b.disabled = true;
  try {
    const r = await fetch('/api/tools', { headers: authHeaders() });
    const j = await r.json();
    // NOTE: this page lives inside a TS template literal, so a JS newline escape
    // must be doubled here — a single one emits a REAL newline into the script
    // text and breaks parsing.
    const rows = (j.tools || []).map(t => (t.readOnly ? '[view] ' : '      ') + t.name);
    showPanel('🧰 Tool catalogue (' + (j.tools || []).length + ')', rows.join('\\n'));
  } catch (err) {
    showPanel('🧰 Tool catalogue', '⚠ ' + (err instanceof Error ? err.message : String(err)));
  } finally {
    b.disabled = false;
  }
});

// In-app API Key Manager dialog
const keysModal = document.getElementById('keys-modal');
const keysList = document.getElementById('keys-list');
const btnKeys = document.getElementById('btn-keys');
const stopBtn = document.getElementById('stop');
const queueEl = document.getElementById('queue');

// ---- Trust mode ---------------------------------------------------------
// Lets the user stop answering "Allow" for ordinary tools. OFF by default and
// never persisted, so a restart always comes back fail-closed. The server
// decides what is exempt; the button just reflects the state and warns about
// what trust mode will NOT cover.
const btnTrust = document.getElementById('btn-trust');
let trustOn = false;
let trustAlwaysAsk = [];
function paintTrust() {
  if (!btnTrust) return;
  btnTrust.textContent = trustOn ? '🛡 Trust mode: ON' : '🛡 Trust mode: OFF';
  btnTrust.classList.toggle('on', trustOn);
  btnTrust.title = trustOn
    ? 'Trust mode is ON — ordinary tools run without asking. Still always asks: ' +
      (trustAlwaysAsk.join(', ') || 'nothing') +
      '. Click to turn OFF.'
    : 'Trust mode is OFF — every approval-gated tool asks. Click to turn ON.';
}
async function loadTrust() {
  try {
    const r = await fetch('/api/trust', { headers: authHeaders() });
    const d = await r.json();
    // The server returns { on, alwaysAsk } — the same key the POST body uses.
    // Reading d.trust here made the button permanently stuck at OFF.
    trustOn = d.on === true;
    trustAlwaysAsk = Array.isArray(d.alwaysAsk) ? d.alwaysAsk : [];
  } catch { trustOn = false }
  paintTrust();
}
if (btnTrust) {
  btnTrust.addEventListener('click', async () => {
    try {
      const r = await fetch('/api/trust', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ on: !trustOn }),
      });
      const d = await r.json();
      trustOn = d.on === true;
      trustAlwaysAsk = Array.isArray(d.alwaysAsk) ? d.alwaysAsk : [];
    } catch { /* leave the state as it was */ }
    paintTrust();
    el('activity', trustOn
      ? '🛡 Trust mode ON — ordinary tools run without asking. Still asks for: ' + (trustAlwaysAsk.join(', ') || 'nothing')
      : '🛡 Trust mode OFF — tools ask again');
  });
  loadTrust();
}
const keysClose = document.getElementById('keys-close');

if (keysClose) keysClose.addEventListener('click', () => keysModal.classList.add('hidden'));
if (keysModal) keysModal.addEventListener('click', (e) => { if (e.target === keysModal) keysModal.classList.add('hidden'); });

// ---- Add provider (B27) ----
// Adding a gateway used to mean editing ROUTE_KEY_SPECS and rebuilding. Now it
// is configuration: the registry is sealed in the same vault as the keys, and
// the server publishes it to the environment immediately, so the new route
// works on the NEXT message without a restart.
const provModal = document.getElementById('provider-modal');
const provPreset = document.getElementById('prov-preset');
const provNote = document.getElementById('prov-preset-note');
const provErr = document.getElementById('prov-err');
let PRESETS = [];

function provClear() {
  provErr.textContent = '';
  provErr.classList.remove('show');
}

function applyPreset() {
  const p = PRESETS.find((x) => x.id === provPreset.value);
  if (!p) return;
  provNote.textContent = p.note || '';
  if (p.baseUrl) document.getElementById('prov-base').value = p.baseUrl;
  if (p.model) document.getElementById('prov-model').value = p.model;
  document.getElementById('prov-needskey').checked = p.needsKey !== false;
  if (!document.getElementById('prov-label').value) {
    document.getElementById('prov-label').value = p.label;
  }
}

const btnProvAdd = document.getElementById('btn-provider-add');
if (btnProvAdd) btnProvAdd.addEventListener('click', async () => {
  provClear();
  for (const id of ['prov-name', 'prov-label', 'prov-base', 'prov-model']) {
    document.getElementById(id).value = '';
  }
  document.getElementById('prov-needskey').checked = true;
  provNote.textContent = '';
  try {
    const r = await fetch('/api/providers', { headers: authHeaders() });
    const j = await r.json();
    PRESETS = j.presets || [];
    provPreset.innerHTML = PRESETS.map(p =>
      '<option value="' + p.id + '">' + p.label + '</option>').join('');
    applyPreset();
  } catch (e) {
    provErr.textContent = 'could not load presets: ' + (e instanceof Error ? e.message : String(e));
    provErr.classList.add('show');
  }
  provModal.classList.remove('hidden');
});
if (provPreset) provPreset.addEventListener('change', applyPreset);
const provCancel = document.getElementById('prov-cancel');
if (provCancel) provCancel.addEventListener('click', () => provModal.classList.add('hidden'));
if (provModal) provModal.addEventListener('click', (e) => { if (e.target === provModal) provModal.classList.add('hidden'); });

const provSave = document.getElementById('prov-save');
if (provSave) provSave.addEventListener('click', async () => {
  provClear();
  provSave.disabled = true;
  try {
    const res = await fetch('/api/providers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({
        name: document.getElementById('prov-name').value,
        label: document.getElementById('prov-label').value,
        baseUrl: document.getElementById('prov-base').value,
        model: document.getElementById('prov-model').value,
        needsKey: document.getElementById('prov-needskey').checked,
        addToChain: document.getElementById('prov-inchain').checked,
      }),
    });
    const j = await res.json();
    if (!j.ok) {
      provErr.textContent = j.error || 'could not add the provider';
      provErr.classList.add('show');
      return;
    }
    provModal.classList.add('hidden');
    await loadKeysUI();
    await loadChain();
    // Say plainly what still needs doing, and nothing more. The old message
    // told the user to go edit BLACKROSE_ROUTES by hand, which was both manual
    // and — for a double-click desktop launch — not something they had any
    // natural way to do.
    let msg = j.added.label + '  (' + j.added.name + ')\\n\\n';
    if (j.inChain) {
      msg += 'Added to the END of the fallback chain, so it is tried only after everything already there.\\n\\n';
    } else {
      msg += 'Not in the fallback chain yet. Add it in Connected routes when you want it tried.\\n\\n';
    }
    if (j.added.needsKey) {
      msg += 'Next: click "keys" on its row in Connected routes to add an API key.\\n\\n';
    }
    msg += 'It takes effect on your next message — no restart needed.';
    if (j.chainNote) msg += '\\n\\n' + j.chainNote.trim();
    showPanel('✓ Provider added', msg);
  } catch (e) {
    provErr.textContent = e instanceof Error ? e.message : String(e);
    provErr.classList.add('show');
  } finally {
    provSave.disabled = false;
  }
});

// ---- Bulk key import + key validation ----
// A dead key is worse than a missing one: the rotating-key client walks its list
// in order, so one bad key costs a wasted round trip on EVERY turn, silently,
// forever. So the import flow can check first and the modal can re-check at any
// time. Nothing here ever renders a key — only masked previews and verdicts.
const bulkModal = document.getElementById('bulk-modal');
const bulkProvider = document.getElementById('bulk-provider');
const bulkText = document.getElementById('bulk-text');
const bulkFile = document.getElementById('bulk-file');
const bulkHint = document.getElementById('bulk-hint');
const bulkErr = document.getElementById('bulk-err');

function bulkFail(msg) {
  bulkErr.textContent = msg;
  bulkErr.classList.add('show');
  bulkHint.textContent = '';
}
function bulkClear() {
  bulkErr.textContent = '';
  bulkErr.classList.remove('show');
  bulkHint.textContent = '';
}

function renderVerdicts(j) {
  const rows = (j.verdicts || []).map(v =>
    (v.ok ? '✓ ' : '✗ ') + v.preview + ' — ' + v.detail).join('\\n');
  bulkHint.textContent = (j.summary || '') + (rows ? '\\n\\n' + rows : '');
}

async function fillBulkProviders() {
  if (!bulkProvider) return;
  try {
    const r = await fetch('/api/keys', { headers: authHeaders() });
    const j = await r.json();
    const opts = (j.keys || []).map(k =>
      '<option value="' + k.envVar + '">' + k.label + '</option>').join('');
    bulkProvider.innerHTML = opts;
  } catch (e) {
    bulkProvider.innerHTML = '<option value="">could not load providers</option>';
  }
}

const btnBulk = document.getElementById('btn-keys-bulk');
if (btnBulk) btnBulk.addEventListener('click', async () => {
  await openBulkFor(null);
});
const bulkCancel = document.getElementById('bulk-cancel');

/**
 * Open the bulk-import modal, optionally preselecting one provider.
 *
 * Called with an envVar from the Connected routes list ("keys" on a route row),
 * so adding a spare key to a gateway that is already failing does not require
 * finding it in a dropdown first. The dropdown is still populated and still
 * editable — this only chooses the starting point.
 *
 * routeName is passed only for the error message, so it can name WHICH provider
 * had no key slot. The server addresses providers by env var, never by label.
 */
async function openBulkFor(envVar, routeName) {
  bulkClear();
  bulkText.value = '';
  bulkFile.value = '';
  await fillBulkProviders();
  if (envVar) {
    // Match on value, not index: the list is built from a live fetch, so an
    // index captured earlier would silently target the wrong provider.
    let matched = false;
    for (const o of bulkProvider.options) {
      if (o.value === envVar) { bulkProvider.value = envVar; matched = true; break; }
    }
    if (!matched) {
      // The route is real but has no key entry — e.g. a keyless custom provider.
      // Say so rather than importing into whatever happens to be selected.
      bulkProvider.innerHTML = '<option value="' + escHtml(envVar) + '">' +
        escHtml(routeName || envVar) + '</option>';
      bulkProvider.value = envVar;
      bulkFail(routeName + ' has no key slot yet — check that it needs a key.');
    }
  }
  bulkModal.classList.remove('hidden');
}
if (bulkCancel) bulkCancel.addEventListener('click', () => bulkModal.classList.add('hidden'));
if (bulkModal) bulkModal.addEventListener('click', (e) => { if (e.target === bulkModal) bulkModal.classList.add('hidden'); });

// Read a chosen file straight into the textarea — the user can still edit it.
if (bulkFile) bulkFile.addEventListener('change', async () => {
  const f = bulkFile.files && bulkFile.files[0];
  if (!f) return;
  bulkText.value = await f.text();
});

const bulkValidate = document.getElementById('bulk-validate');
if (bulkValidate) bulkValidate.addEventListener('click', async () => {
  bulkClear();
  const text = bulkText.value;
  if (!text.trim()) return bulkFail('Paste some keys or choose a file first.');
  bulkValidate.disabled = true;
  bulkHint.textContent = 'Checking…';
  try {
    const res = await fetch('/api/keys/validate', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ envVar: bulkProvider.value, text }),
    });
    const j = await res.json();
    if (!j.ok) return bulkFail(j.error || 'validation failed');
    renderVerdicts(j);
  } catch (e) {
    bulkFail(e instanceof Error ? e.message : String(e));
  } finally {
    bulkValidate.disabled = false;
  }
});

const bulkSave = document.getElementById('bulk-save');
if (bulkSave) bulkSave.addEventListener('click', async () => {
  bulkClear();
  const text = bulkText.value;
  if (!text.trim()) return bulkFail('Paste some keys or choose a file first.');
  bulkSave.disabled = true;
  try {
    const res = await fetch('/api/keys/bulk', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ envVar: bulkProvider.value, text }),
    });
    const j = await res.json();
    if (!j.ok) return bulkFail(j.error || 'import failed');
    const rej = (j.rejected || []).length;
    bulkHint.textContent = 'Added ' + j.added + ' key(s) · ' + j.count + ' total for this provider.' +
      (rej ? '\\n' + rej + ' line(s) skipped as unusable (shown below).' : '');
    if (rej) {
      bulkHint.textContent += '\\n\\n' + j.rejected
        .map(x => 'line ' + x.line + ': ' + x.reason + ' (' + x.preview + ')').join('\\n');
    }
    bulkText.value = '';  // do not leave secrets sitting in the textarea
    await loadKeysUI();
  } catch (e) {
    bulkFail(e instanceof Error ? e.message : String(e));
  } finally {
    bulkSave.disabled = false;
  }
});

// Validate whatever is already stored for a provider.
const btnKeysValidate = document.getElementById('btn-keys-validate');
if (btnKeysValidate) btnKeysValidate.addEventListener('click', async () => {
  bulkClear();
  if (!bulkProvider || !bulkProvider.value) return bulkFail('Pick a provider first.');
  bulkText.value = '';
  bulkModal.classList.remove('hidden');
  btnKeysValidate.disabled = true;
  bulkHint.textContent = 'Checking stored keys…';
  try {
    const res = await fetch('/api/keys/validate', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ envVar: bulkProvider.value }),
    });
    const j = await res.json();
    if (!j.ok) return bulkFail(j.error || 'validation failed');
    renderVerdicts(j);
  } catch (e) {
    bulkFail(e instanceof Error ? e.message : String(e));
  } finally {
    btnKeysValidate.disabled = false;
  }
});

async function loadKeysUI() {
  keysList.innerHTML = '<div style="color:var(--dim); font-size:12px;">Loading keys…</div>';
  try {
    const r = await fetch('/api/keys/roster', { headers: authHeaders() });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'Failed to load keys');
    // Feed the Connected routes list too, so a route row can show how many keys
    // it holds. Rebuilt wholesale (not merged) so a provider that was deleted
    // stops being reported as having keys.
    const counts = {};
    const envs = {};
    for (const p of j.providers || []) {
      counts[p.envVar] = p.count;
      if (p.route) envs[p.route] = p.envVar;
    }
    KEY_COUNTS = counts;
    ROUTE_ENV = envs;
    if (LAST_HEALTH) paintRoutes(LAST_HEALTH);
    keysList.innerHTML = '';
    for (const raw of j.providers) {
      // Backward-compatible shape: the row below still reads hasKey/preview,
      // while the roster underneath uses the full key list with per-key health.
      const k = { ...raw, hasKey: raw.count > 0, preview: raw.previews?.[0] || '' };
      const item = document.createElement('div');
      item.className = 'key-item';
      const top = document.createElement('div');
      top.className = 'top';
      const lbl = document.createElement('span');
      lbl.className = 'lbl';
      lbl.textContent = k.label;
      const st = document.createElement('span');
      st.className = 'status ' + (k.hasKey ? 'ok' : 'missing');
      st.textContent = k.hasKey ? ('configured (' + k.preview + ')') : 'not set';
      top.appendChild(lbl);
      top.appendChild(st);
      item.appendChild(top);

      const vr = document.createElement('div');
      vr.className = 'var';
      vr.textContent = k.envVar;
      item.appendChild(vr);

      // Multi-key rotation roster (B26): every key this provider holds, with
      // its own health. Index 0 is the primary key, managed by the row below.
      const roster = document.createElement('div');
      roster.className = 'keys';
      const rh = document.createElement('div');
      rh.className = 'keys-head';
      rh.textContent = k.count > 1
        ? k.count + ' keys · rotation on failure'
        : k.count === 1
          ? 'add a second key so a rate limit does not stop work'
          : 'no keys yet';
      roster.appendChild(rh);
      for (const key of k.keys || []) {
        const chip = document.createElement('div');
        chip.className = 'key-chip';
        const idx = document.createElement('span');
        idx.className = 'idx';
        idx.textContent = key.index === 0 ? 'primary' : '#' + key.index;
        const pv = document.createElement('span');
        pv.className = 'pv';
        pv.textContent = key.preview || '(empty)';
        const dot = document.createElement('span');
        dot.className = 'dot ' + key.state;
        dot.title = key.state === 'ok' ? 'answering' : key.state;
        dot.textContent = key.usable
          ? key.state
          : key.state + ' · ' + Math.ceil(key.cooldownMs / 60000) + 'm';
        chip.appendChild(idx); chip.appendChild(pv); chip.appendChild(dot);
        if (key.index > 0) {
          const rm = document.createElement('button');
          rm.className = 'rm';
          rm.textContent = 'remove';
          rm.addEventListener('click', async () => {
            if (!confirm('Remove key #' + key.index + ' for ' + k.label + '?')) return;
            rm.disabled = true;
            try {
              const res = await fetch('/api/keys/rotate', {
                method: 'POST',
                headers: { 'content-type': 'application/json', ...authHeaders() },
                body: JSON.stringify({ envVar: k.envVar, op: 'remove', index: key.index }),
              });
              const resJ = await res.json();
              if (!resJ.ok) throw new Error(resJ.error || 'remove failed');
              el('activity', '🔑 removed key #' + key.index + ' from ' + k.label);
              await loadKeysUI();
              pollHealth();
            } catch (err) {
              alert('Failed to remove key: ' + (err instanceof Error ? err.message : String(err)));
              rm.disabled = false;
            }
          });
          chip.appendChild(rm);
        }
        roster.appendChild(chip);
      }
      // Add an extra key. Uses the rotate endpoint so the primary is untouched.
      const addRow = document.createElement('div');
      addRow.className = 'input-row';
      addRow.style.marginTop = '6px';
      const addInp = document.createElement('input');
      addInp.type = 'password';
      addInp.placeholder = 'Additional API key to rotate with…';
      addInp.autocomplete = 'off';
      const addBtn = document.createElement('button');
      addBtn.className = 'save';
      addBtn.textContent = 'Add key';
      addBtn.addEventListener('click', async () => {
        const val = addInp.value.trim();
        if (!val) return;
        addBtn.disabled = true;
        try {
          const res = await fetch('/api/keys/rotate', {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ envVar: k.envVar, op: 'add', value: val }),
          });
          const resJ = await res.json();
          if (!resJ.ok) throw new Error(resJ.error || 'add failed');
          el('activity', '🔑 ' + k.label + ' now holds ' + resJ.count + ' key(s)');
          await loadKeysUI();
          pollHealth();
        } catch (err) {
          alert('Failed to add key: ' + (err instanceof Error ? err.message : String(err)));
          addBtn.disabled = false;
        }
      });
      addRow.appendChild(addInp);
      addRow.appendChild(addBtn);
      roster.appendChild(addRow);
      item.appendChild(roster);

      const inRow = document.createElement('div');
      inRow.className = 'input-row';
      const inp = document.createElement('input');
      inp.type = 'password';
      inp.placeholder = k.hasKey ? 'Paste new key to update…' : 'Enter API key…';
      inp.autocomplete = 'off';
      const bSave = document.createElement('button');
      bSave.className = 'save';
      bSave.textContent = 'Save';
      bSave.addEventListener('click', async () => {
        const val = inp.value.trim();
        if (!val) return;
        bSave.disabled = true;
        try {
          const res = await fetch('/api/keys', {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ envVar: k.envVar, value: val }),
          });
          const resJ = await res.json();
          if (!resJ.ok) throw new Error(resJ.error || 'save failed');
          el('activity', '🔑 updated key for ' + k.label);
          await loadKeysUI();
          pollHealth();
        } catch (err) {
          alert('Failed to save key: ' + (err instanceof Error ? err.message : String(err)));
          bSave.disabled = false;
        }
      });

      inRow.appendChild(inp);
      inRow.appendChild(bSave);

      if (k.hasKey) {
        const bClear = document.createElement('button');
        bClear.className = 'clear';
        bClear.textContent = 'Clear';
        bClear.addEventListener('click', async () => {
          if (!confirm('Clear key for ' + k.label + '?')) return;
          bClear.disabled = true;
          try {
            const res = await fetch('/api/keys', {
              method: 'POST',
              headers: { 'content-type': 'application/json', ...authHeaders() },
              body: JSON.stringify({ envVar: k.envVar, value: '' }),
            });
            const resJ = await res.json();
            if (!resJ.ok) throw new Error(resJ.error || 'clear failed');
            el('activity', '🔑 cleared key for ' + k.label);
            await loadKeysUI();
            pollHealth();
          } catch (err) {
            alert('Failed to clear key: ' + (err instanceof Error ? err.message : String(err)));
            bClear.disabled = false;
          }
        });
        inRow.appendChild(bClear);
      }

      item.appendChild(inRow);
      keysList.appendChild(item);
    }
  } catch (e) {
    // Server-side error text lands in innerHTML here, so escape it: an upstream
    // message is attacker-influenceable and this is a raw-HTML sink.
    keysList.innerHTML = '<div style="color:var(--err); font-size:12px;">⚠ Error: ' +
      escHtml(e instanceof Error ? e.message : String(e)) + '</div>';
  }
}

if (btnKeys) {
  btnKeys.addEventListener('click', () => {
    keysModal.classList.remove('hidden');
    loadKeysUI();
  });
}
// Warm the roster once at startup, not only when the Keys panel is opened:
// the Connected routes list reads KEY_COUNTS to show each route's key count, and
// a route rendered as "keys" with no number would hide the very thing the count
// is there to reveal. The payload is presence + masked previews only.
loadKeysUI().catch(() => {});

input.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
});
send.addEventListener('click', submit);
input.addEventListener('input', () => {
  input.style.height = 'auto';
  input.style.height = Math.min(input.scrollHeight, 160) + 'px';
});

/* ---- Stop button + message queue --------------------------------------
 * Previously a message typed while BlackRose was working was silently
 * discarded by a guard on the busy flag, even though the input stayed enabled,
 * so it looked like it had been sent. Now it is queued and sent as its own
 * turn once the current one finishes. */
let activeController = null;
let halted = false;          // user pressed Stop: do NOT auto-drain the queue
const queue = [];

function renderQueue() {
  if (!queueEl) return;
  if (queue.length === 0) { queueEl.hidden = true; queueEl.innerHTML = ''; return; }
  queueEl.hidden = false;
  queueEl.innerHTML = '';
  const head = document.createElement('div');
  head.className = 'q-head';
  head.textContent = queue.length + ' message' + (queue.length === 1 ? '' : 's')
    + ' queued' + (halted ? ' — send to continue' : ' — will send when this turn finishes');
  queueEl.appendChild(head);
  queue.forEach((q, i) => {
    const row = document.createElement('div');
    row.className = 'q-item';
    const t = document.createElement('span');
    t.className = 'q-text';
    t.textContent = (i + 1) + '. ' + q;
    const drop = document.createElement('button');
    drop.className = 'q-drop';
    drop.textContent = 'remove';
    drop.addEventListener('click', () => { queue.splice(i, 1); renderQueue(); });
    row.appendChild(t); row.appendChild(drop);
    queueEl.appendChild(row);
  });
}

async function runTurn(text) {
  busy = true; send.disabled = true;
  if (stopBtn) stopBtn.hidden = false;
  const controller = new AbortController();
  activeController = controller;
  el('msg user', text);
  const think = el('msg ai thinking', 'working…');
  const route = mode === 'goal' ? '/api/goal' : '/api/ask';
  try {
    const res = await fetch(route, {
      method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ prompt: text, session: mode === 'goal' ? undefined : SESSION }),
      signal: controller.signal,
    });
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const ev = JSON.parse(line);
        if (ev.type === 'tool') {
          el('activity', '⚙ ' + ev.name + ' ' + (ev.detail || ''));
          if (ev.name === 'session') {
            const m = (ev.detail || '').match(/resumed (\S+)/);
            if (m) CURRENT = m[1];
          }
        }
        else if (ev.type === 'approval') await handleApproval(ev);
        else if (ev.type === 'text') think.innerHTML = renderRich(ev.text);
        else if (ev.type === 'final') { think.remove(); elRich('msg ai', ev.text); }
        else if (ev.type === 'stopped') {
          think.remove();
          el('msg ai', '⏹ stopped' + (ev.text ? ' — partial answer kept' : ''));
        }
        else if (ev.type === 'usage') {
          // Per-turn token spend. Without this there is no way to see which
          // turn actually cost something.
          const inK = Math.round((ev.input || 0) / 1000);
          const outK = Math.round((ev.output || 0) / 1000);
          el('activity', '◷ ' + (ev.calls || 1) + ' model call' + ((ev.calls || 1) === 1 ? '' : 's')
            + ' · in ' + inK + 'k · out ' + outK + 'k tokens');
        }
        else if (ev.type === 'error') { think.remove(); el('msg ai', '⚠ ' + ev.text); }
      }
    }
  } catch (e) {
    think.remove();
    if (e && e.name === 'AbortError') el('msg ai', '⏹ stopped');
    else el('msg ai', '⚠ connection error: ' + e.message);
  }
  if (think.isConnected) think.remove();
  busy = false; send.disabled = false;
  activeController = null;
  if (stopBtn) stopBtn.hidden = true;
  input.focus();
  refreshSessions();
}

async function submit() {
  const text = input.value.trim();
  if (!text) return;
  input.value = ''; input.style.height = 'auto';
  if (busy) { queue.push(text); renderQueue(); return; }  // queued, not dropped
  halted = false;
  await runTurn(text);
  // Drain one message per turn so each gets its own reply. Stop halts the
  // drain: remaining messages stay queued for the next send.
  while (queue.length && !halted) {
    const next = queue.shift();
    renderQueue();
    await runTurn(next);
  }
  renderQueue();
}

if (stopBtn) {
  stopBtn.addEventListener('click', () => {
    halted = true;                 // keep queued messages for a later send
    if (activeController) activeController.abort();   // cancel the in-flight request
    // Tell the server too, so it stops the model call rather than the socket.
    fetch('/api/stop?session=' + encodeURIComponent(SESSION), {
      method: 'POST', headers: authHeaders(),
    }).catch(() => {});
    renderQueue();
  });
}

function handleApproval(ev) {
  // Sound FIRST, before the dialog is built, so the chime is not delayed behind
  // any DOM work — the user is waiting on the other screen.
  playChime();
  return new Promise(resolve => {
    const ov = document.getElementById('overlay');
    document.getElementById('dl-reason').textContent = ev.tool + ': ' + (ev.reason || '');
    ov.classList.add('show');
    const done = allow => {
      ov.classList.remove('show');
      allowBtn.removeEventListener('click', onA);
      denyBtn.removeEventListener('click', onD);
      el('activity', (allow ? '✓ allowed' : '✗ denied') + ' — ' + ev.tool);
      fetch('/api/approve', {
        method: 'POST', headers: { 'content-type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ id: ev.id, allow }),
      }).finally(resolve);
    };
    const allowBtn = document.getElementById('dl-allow');
    const denyBtn = document.getElementById('dl-deny');
    const onA = () => done(true);
    const onD = () => done(false);
    allowBtn.addEventListener('click', onA);
    denyBtn.addEventListener('click', onD);
  });
}
`;
/** Full HTML page served at GET / by the web UI server. */
function uiHtml() {
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width, initial-scale=1">' +
        '<title>BlackRose</title><style>' + CSS + '</style></head><body>' +
        BODY +
        '<script>' +
        // The chime is injected as a JS string constant rather than fetched, so the
        // page stays a single self-contained document (this UI ships inside a Node
        // SEA .exe with zero external assets) and cannot fail with a 404 that would
        // leave the notification silently broken.
        'window.__APPROVAL_CHIME__=' + JSON.stringify(approvalChimeDataUri()) + ';' +
        JS +
        '</scr' + 'ipt></body></html>');
}
return { uiHtml };
}

__mod['ui/web/assets.js'] = M68();

function M69() {
const { runAgent } = __mod['core/agent.js'];
const { makeClient } = __mod['llm/factory.js'];
const { loadConfig } = __mod['config.js'];
const { alwaysAsk, alwaysAskList } = __mod['core/trust.js'];
const { runGoal } = __mod['core/taskEngine.js'];
const { loadSkills } = __mod['skills/skills.js'];
const { uiHtml } = __mod['ui/web/assets.js'];
const { saveSession, sessionFileId, loadLatestSession, listSessions, loadSession, deleteSession } = __mod['session/history.js'];
const { getRouteStates, registerRoute, routeEntriesFromClient } = __mod['llm/routeHealth.js'];
const { embedStatus } = __mod['memory/embedder.js'];
const { vectorIndexStats } = __mod['memory/vectors.js'];
const { exportStateIncremental, importState } = __mod['state/aistate.js'];
const { addProviderKey, listKeyStatuses, listProviderKeyStatuses, parseBulkKeys, addProviderKeysBulk, readProviderKeys, validateProviderKeys, summarizeKeyValidation, removeProviderKey, saveKey, } = __mod['core/keys.js'];
const { keyHealthSnapshot, resetKeyHealth } = __mod['llm/keyHealth.js'];
const { addProvider, removeProvider, allProviderSpecs, PROVIDER_PRESETS, readRouteChain, writeRouteChain, } = __mod['core/providers.js'];
const { runListenMic } = __mod['tools/voice.js'];
const pendingApprovals = new Map();
/**
 * Trust mode: when the user turns it on, ordinary approval-gated tools run
 * without a dialog. OFF by default and per-process (not persisted) — it dies
 * with the app, so a reboot never leaves an unattended agent behind. Tools in
 * the ALWAYS-ASK set still prompt (see core/trust.ts), so this can only
 * reduce friction, never remove the fail-closed default.
 */
let trustMode = false;
function countFiles(dir, suffix) {
    try {
        return fs.readdirSync(dir).filter((f) => f.endsWith(suffix)).length;
    }
    catch {
        return 0;
    }
}
/**
 * Total chunks across the knowledge base.
 *
 * BUG FIXED 2026-10-01: the whole loop lived inside one try/catch, so a SINGLE
 * unparseable file threw and the catch returned 0 — wiping out the count for
 * every other, perfectly good source. The knowledge directory also holds stray
 * files that agent runs have written there (a .ps1, a directory, a .md), and
 * the corpus had grown to 40 entries; one bad file made the sidebar read
 * "Knowledge chunks: 0" while 28 valid sources sat on disk holding hundreds of
 * chunks. A counter that reports zero when the answer is hundreds is worse than
 * no counter, because it reads as "nothing has been learned".
 *
 * Each file is now read in its own try. An unparseable one is skipped, exactly
 * as the list/search paths already did — the inconsistency between them is what
 * made this visible.
 */
function countKnowledgeChunks(dataDir) {
    const dir = path.join(dataDir, 'knowledge');
    try {
        let n = 0;
        for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
            try {
                const kf = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
                if (Array.isArray(kf.chunks))
                    n += kf.chunks.length;
            }
            catch {
                // Not a knowledge file (or corrupt). Skip it and keep counting the rest.
            }
        }
        return n;
    }
    catch {
        return 0;
    }
}
/**
 * Embedding subsystem health for /api/health (B5 visibility).
 *
 * The Gemini free tier caps embedding at freeTierDailyRequestQuota() requests
 * per day. When that cap is spent the app falls back to the hash embedder and
 * retrieval degrades from semantic to keyword matching — a real, live condition
 * observed on 2026-10-02. Until now it was invisible: only a console.warn
 * mentioned it, and the desktop app has no console. This puts the degradation
 * on the health payload where the UI can paint it instead.
 *
 * `indexMismatch` covers the second silent case: a store on disk whose model
 * does not match what the backend would produce now (e.g. a br-hash-v1 index
 * left behind by an outage while the API is healthy again). Those entries are
 * re-embedded lazily on first touch, so this is a coverage signal, not
 * corruption — the refuse-to-save guard in vectors.ts keeps the real index safe.
 */
function embedHealth(dataDir) {
    const s = embedStatus();
    const idx = vectorIndexStats(dataDir);
    const indexMismatch = idx !== null && idx.model !== s.activeModel;
    return {
        backend: s.backend,
        configured: s.configured,
        activeModel: s.activeModel,
        dailyRequestQuota: s.dailyRequestQuota,
        quotaExhausted: s.quotaExhaustedAt > 0,
        indexModel: idx?.model ?? null,
        indexed: idx?.entries ?? 0,
        indexMismatch,
        degraded: s.degraded || indexMismatch,
    };
}
function loadScheduleCount(dataDir) {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(dataDir, 'schedules.json'), 'utf8'));
        return Array.isArray(raw) ? raw.length : 0;
    }
    catch {
        return 0;
    }
}
/**
 * Tools the UI may run directly (see POST /api/tool).
 *
 * Restricted to tools that only READ persisted state. This is deliberately a
 * fixed allowlist rather than a "is it read-only?" heuristic: a new tool must
 * be added here by a human who has read its source, so widening what the web
 * UI can do is always a deliberate, reviewable act. Mutating tools
 * (memory_save, skill_save, schedule_task, learn_*, …) and machine-touching
 * tools (run_command, gui_action, screenshot, spawn_agent, web_fetch, …) stay
 * in the chat loop, where the approval dialog guards them.
 */
const READONLY_TOOLS = new Set([
    'skill_list',
    'schedule_list',
    'knowledge_list',
    'knowledge_search',
    // Reports duplicates and deletes NOTHING, so it is safe to run without an
    // approval prompt. knowledge_forget is deliberately absent from this list:
    // that one destroys data and must go through chat like any state-changing tool.
    'knowledge_dedup',
    'project_read',
    'memory_list',
    'memory_search',
    'job_list',
    'job_output',
]);
/** ToolContext that streams tool activity and interactive approvals. */
function streamingCtx(base, write) {
    return {
        ...base,
        log: (line) => write({ type: 'tool', name: 'note', detail: line.slice(0, 140) }),
        askApproval: (toolName, reason) => {
            // Trust mode: auto-approve anything not on the always-ask list. Still
            // reported as a tool event so the transcript shows what ran unattended.
            if (trustMode && !alwaysAsk(toolName)) {
                write({ type: 'tool', name: toolName, detail: `auto-approved (trust mode): ${reason.slice(0, 120)}` });
                return Promise.resolve(true);
            }
            const id = crypto.randomUUID();
            write({ type: 'approval', id, tool: toolName, reason: reason.slice(0, 200) });
            return new Promise((resolve) => {
                pendingApprovals.set(id, { tool: toolName, reason, resolve, ts: Date.now() });
                // safety: expire stale dialogs after 10 minutes (deny = fail-closed)
                setTimeout(() => {
                    if (pendingApprovals.delete(id))
                        resolve(false);
                }, 600_000).unref();
            });
        },
    };
}
const LOOPBACK = /^(127\.0\.0\.1|localhost|\[?::1\]?)$/i;
/**
 * The desktop shell's OWN hostnames. Tauri renders its splash on
 * `tauri://localhost` and then navigates to `http://127.0.0.1:<port>/`
 * (main.rs does `location.replace(...)`). That navigation is a
 * CROSS-SCHEME, CROSS-ORIGIN move, so Chromium sets `Sec-Fetch-Site:
 * cross-site` and sends an Origin on the resulting fetches — the shell then
 * refused its own UI and every call failed with
 * `{"error":"forbidden: cross-site request"}` (observed live on 0.9.9).
 *
 * A browser hitting 127.0.0.1 directly sends `same-origin` and is unaffected,
 * which is exactly why this survived browser-based testing and only broke the
 * shipped desktop app.
 *
 * MATCH ON SCHEME+HOST, IGNORING THE PORT. An origin identity is
 * scheme + host + port, but the port here is the core's ephemeral listener
 * (5514, 6751, 5190 …), chosen at runtime — a set containing the bare
 * hostname silently misses every real request. That was the first attempt's
 * bug: `Origin: http://tauri.localhost:5514` did not match
 * `http://tauri.localhost`, and 0.9.10 shipped still-broken. Measured live
 * against the installed app, not assumed.
 *
 * Allowing these is safe: `tauri.localhost` and `localhost` are names the OS
 * grants to THIS application's own webview, and a page the user visits on the
 * internet cannot set them. `tauri.localhost` is the Windows WebView2 spelling;
 * `tauri://localhost` is the scheme form.
 */
const SHELL_HOSTS = new Set(['tauri.localhost', 'localhost']);
/** True when `url` is one of our own webview origins (port ignored). */
function isShellOrigin(url) {
    try {
        const u = new URL(url);
        return SHELL_HOSTS.has(u.hostname.toLowerCase());
    }
    catch {
        return false;
    }
}
/**
 * Browser-context guard.
 *
 * The token gate (below) authenticates the USER. This guards a different
 * boundary: loopback is not a trust boundary once a browser is involved. On a
 * default local install main.ts passes token='' — the design assumed "only
 * processes on this machine can reach 127.0.0.1", which is true for sockets but
 * false for web pages: any site the user visits can send requests to this
 * port, and they all land. Measured before this guard existed: /api/health,
 * /api/keys, /api/sessions, /api/trust and POST /api/ask all returned 200 with
 * `Origin: https://evil.example`.
 *
 * Three independent checks, because each covers a case the others miss:
 *
 *  1. Sec-Fetch-Site: every modern browser sets it and the platform keeps it
 *     outside script control. 'cross-site' is exactly "a page initiated this",
 *     which no legitimate request here ever is. Non-browser clients (the CLI,
 *     the bridge, tests, fetch from node) send NO such header, so a missing one
 *     must be allowed — otherwise this breaks the project's own test suite.
 *  2. Origin: the older, still-widely-sent signal. A null origin is the file://
 *     page or a redirect chain; both are local enough to allow.
 *  3. Host: defeats DNS rebinding, which defeats checks 1 and 2 entirely — an
 *     attacker rebinds evil.example to 127.0.0.1, and the browser then reports
 *     it as same-origin and sends nothing suspicious. If we are bound to
 *     loopback, a request claiming a different Host is not ours. Skipped when
 *     bound wider than loopback, because there the token gate is already on
 *     (main.ts only leaves token empty for loopback) and a LAN address is a
 *     legitimate Host.
 *
 * Fails closed: an explicit hostile signal is refused even if the token is
 * valid, because a stolen token on the wrong origin is still a stolen token.
 */
function browserGuardBlocked(req, boundHost) {
    // Our own desktop webview, not the internet. Checked against Origin AND
    // Referer, because they are not both present on every request — and which one
    // arrives depends on the request type:
    //
    //   * subresource fetch  -> sends Origin, NO Referer
    //   * top-level navigate -> sends Referer, NO Origin   <-- what broke 0.9.11
    //
    // Keying on Origin alone (the first two attempts) therefore refused the page
    // LOAD itself. Captured from the live WebView2 request that was blocked:
    //
    //   url=/  origin=undefined  referer=http://tauri.localhost/
    //   sec-fetch-site=cross-site  sec-fetch-mode=navigate
    //
    // Referer is safe to trust here for the same reason Origin is: a browser sets
    // it to the referring page's own URL, so a page the user visits on the
    // internet cannot make it say `tauri.localhost`.
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const isShell = (typeof origin === 'string' && isShellOrigin(origin)) ||
        (typeof referer === 'string' && isShellOrigin(referer));
    if (!isShell) {
        const site = req.headers['sec-fetch-site'];
        if (typeof site === 'string' && site === 'cross-site')
            return 'cross-site request';
    }
    // A known shell origin has already been vetted above; do not re-test it
    // against the http/https rule. `new URL('tauri://localhost').protocol` is
    // 'tauri:', so the loopback test below would reject our own webview even
    // though the origin is exact-match trusted.
    if (!isShell && typeof origin === 'string' && origin !== 'null' && origin !== '') {
        let ok = false;
        try {
            const u = new URL(origin);
            ok = (u.protocol === 'http:' || u.protocol === 'https:') && LOOPBACK.test(u.hostname);
        }
        catch {
            ok = false;
        }
        if (!ok)
            return `origin ${origin.slice(0, 80)} is not this machine`;
    }
    const host = req.headers.host ?? '';
    if (LOOPBACK.test(boundHost)) {
        const name = host.replace(/:\d+$/, '');
        if (host && !LOOPBACK.test(name))
            return `host ${name} does not match the loopback bind`;
    }
    return null;
}
async function startWebUi(o) {
    // Pre-register router routes in the health registry so the tray shows every
    // route (as "unknown") before the first call instead of staying empty.
    // Only a COMPOSED client has a chain to pre-register; a single provider has
    // no per-route list (its one row appears on the first call or probe).
    // routeEntriesFromClient is shared with the background prober (ui/web/main.ts)
    // so a probe lands on this row instead of creating a second, differently-keyed
    // one for the same route.
    if (/^router\(/.test(o.client.name)) {
        for (const r of routeEntriesFromClient(o.client.name, o.client.model))
            registerRoute(r.name, r.model);
    }
    // Live UI conversations, keyed by the browser tab's session id. History is
    // threaded across /api/ask calls and persisted to dataDir/sessions so it
    // survives page reloads and server restarts (same behavior as the CLI).
    const conversations = new Map();
    // In-flight runs, keyed by UI session, so POST /api/stop can cancel the exact
    // turn that is running. Entries are removed when the run settles or the client
    // disconnects, so this never holds a stale controller.
    const activeRuns = new Map();
    // ---- Small-task agents ------------------------------------------------
    // spawn_agent was wired in the CLI and the remote bridge but NOT here, so in
    // the web UI it always failed with "Sub-agents are not available here" — the
    // tool was registered but unreachable from the main interface.
    //
    // BLACKROSE_SUBAGENT_ROUTE lets a small task run on a CHEAPER model than the
    // conversation (e.g. "kilo", which is keyless/free). That is the point of a
    // small agent: it should not cost what the main turn costs. Unset = same
    // client as the conversation.
    const subAgentClient = (() => {
        const sub = process.env.BLACKROSE_SUBAGENT_ROUTE?.trim();
        if (!sub)
            return o.client;
        try {
            return makeClient({ ...loadConfig(o.cwd), provider: sub });
        }
        catch (e) {
            // Never fail the parent turn because a sub-agent route is misconfigured.
            console.warn('[web] BLACKROSE_SUBAGENT_ROUTE ignored: ' + (e instanceof Error ? e.message : String(e)));
            return o.client;
        }
    })();
    // Live system prompt: rebuilt per agent run, so a memory or project note
    // written during THIS session is visible immediately instead of only after an
    // app restart (see WebUiOptions.buildSystem).
    const liveSystem = () => {
        try {
            return o.buildSystem?.() ?? o.system;
        }
        catch {
            return o.system; // a transient read error must never break a turn
        }
    };
    /** Depth-1 sub-agent: fresh history, reduced tool set, no further spawning. */
    function subAgentRunner(write, signal, dir) {
        return async (task, label) => {
            const who = label || 'task';
            write({ type: 'tool', name: 'sub-agent', detail: who + ' started' });
            // Same approval channel as the parent (so an approval inside a sub-task
            // still reaches the user), but WITHOUT runSubTask: depth-1.
            const subCtx = streamingCtx(dir, write);
            delete subCtx.runSubTask;
            try {
                const outcome = await runAgent({
                    client: subAgentClient,
                    // No spawn_agent (depth-1) and no skill_run: a small task should not
                    // be able to launch more agents or a whole recipe.
                    tools: o.tools.filter((t) => t.name !== 'spawn_agent' && t.name !== 'skill_run'),
                    system: liveSystem(),
                    history: [{ role: 'user', content: task }],
                    ctx: subCtx,
                    maxTurns: 10,
                    signal,
                    onToolCall: (name, input) => write({
                        type: 'tool',
                        name,
                        detail: '↳ ' + name + ' ' + JSON.stringify(input).slice(0, 100),
                    }),
                });
                write({ type: 'tool', name: 'sub-agent', detail: who + ' finished (' + outcome.turns + ' turns)' });
                return { content: outcome.text || '(sub-agent returned no text)' };
            }
            catch (e) {
                if (signal.aborted)
                    return { content: 'Sub-agent cancelled.' };
                return { content: 'Sub-agent failed: ' + (e instanceof Error ? e.message : String(e)), isError: true };
            }
        };
    }
    const writeNdjson = (res) => {
        res.writeHead(200, {
            'content-type': 'application/x-ndjson; charset=utf-8',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
        });
        return (ev) => {
            try {
                res.write(JSON.stringify(ev) + '\n');
            }
            catch {
                /* client went away mid-stream */
            }
        };
    };
    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', 'http://localhost');
        const route = url.pathname;
        // Browser-context guard runs BEFORE the token gate: a hostile origin must be
        // refused even when the token is valid, and refusing early means a
        // cross-origin probe cannot even reach the route table.
        const guarded = browserGuardBlocked(req, o.host ?? '127.0.0.1');
        if (guarded) {
            res.writeHead(403, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: `forbidden: ${guarded}` }));
            return;
        }
        // Optional token gate: every route (page, health, streams, approvals) is
        // protected when a token is configured. Hash + timingSafeEqual so token
        // bytes are never compared in a timing-observable way (same as the bridge).
        if (o.token) {
            const raw = req.headers['authorization'] ?? '';
            const given = raw.startsWith('Bearer ') ? raw.slice(7) : '';
            const ok = given.length > 0 &&
                crypto.timingSafeEqual(crypto.createHash('sha256').update(given).digest(), crypto.createHash('sha256').update(o.token).digest());
            if (!ok) {
                res.writeHead(403, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'forbidden: missing or invalid token' }));
                return;
            }
        }
        if (req.method === 'GET' && route === '/') {
            // no-store: the page must never be served from a stale browser cache —
            // an old page can't call newer endpoints (e.g. /api/new), which makes
            // "clear conversation" silently a no-op while the server still threads
            // history under the page-less `default` key.
            res.writeHead(200, {
                'content-type': 'text/html; charset=utf-8',
                'cache-control': 'no-store, must-revalidate',
                pragma: 'no-cache',
            });
            res.end(uiHtml());
            return;
        }
        if (req.method === 'GET' && route === '/api/health') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                name: 'blackrose-ui',
                provider: o.client.name,
                model: o.client.model,
                memories: countFiles(path.join(o.dataDir, 'memory'), '.md'),
                knowledgeChunks: countKnowledgeChunks(o.dataDir),
                schedules: loadScheduleCount(o.dataDir),
                skills: loadSkills(o.dataDir).length,
                // route-status tray: live per-route health (ok=green, degraded=red
                // quota-out, down=yellow needs-attention; see llm/routeHealth.ts)
                routes: getRouteStates(),
                // embedding health (B5): a spent Gemini daily quota silently downgrades
                // retrieval to lexical. Surfaced so the UI can say so. See embedHealth.
                embed: embedHealth(o.dataDir),
            }));
            return;
        }
        if (req.method === 'POST' && (route === '/api/ask' || route === '/api/goal')) {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 1024 * 1024)
                    req.destroy();
            });
            req.on('end', async () => {
                const write = writeNdjson(res);
                let prompt = '';
                let sid = '';
                try {
                    const parsed = JSON.parse(body || '{}');
                    prompt = parsed.prompt?.toString().trim() ?? '';
                    sid = typeof parsed.session === 'string' ? parsed.session : '';
                }
                catch {
                    /* fallthrough to error below */
                }
                if (!prompt) {
                    write({ type: 'error', text: 'field "prompt" is required' });
                    res.end();
                    return;
                }
                const runKey = route === '/api/ask' ? sid || 'default' : 'goal';
                const ac = new AbortController();
                activeRuns.set(runKey, ac);
                res.on('close', () => {
                    ac.abort();
                    if (activeRuns.get(runKey) === ac)
                        activeRuns.delete(runKey);
                });
                const base = {
                    cwd: o.cwd,
                    dataDir: o.dataDir,
                    runSubTask: subAgentRunner(write, ac.signal, { cwd: o.cwd, dataDir: o.dataDir }),
                };
                // Server-side conversation memory for /api/ask: the running history is
                // threaded exactly like the CLI does (this used to be stateless — every
                // UI turn forgot the previous ones). History lives in memory per
                // browser-tab key (the page sends a random `session` id) and is also
                // persisted under dataDir/sessions, so a page reload or a server
                // restart reattaches to the latest conversation (same as --resume).
                // /api/goal stays stateless by design: a goal is a fresh
                // plan → execute → verify run, not a chat turn.
                let conv;
                if (route === '/api/ask') {
                    const key = sid || 'default';
                    conv = conversations.get(key);
                    if (!conv) {
                        const resumed = loadLatestSession(o.dataDir);
                        conv = {
                            id: resumed?.id ?? sessionFileId(),
                            messages: resumed ? [...resumed.messages] : [],
                        };
                        conversations.set(key, conv);
                        if (conversations.size > 50) {
                            const oldest = conversations.keys().next().value;
                            if (oldest !== undefined)
                                conversations.delete(oldest);
                        }
                        if (resumed) {
                            write({ type: 'tool', name: 'session', detail: `resumed ${resumed.id}` });
                        }
                    }
                }
                try {
                    if (route === '/api/ask' && conv) {
                        conv.messages.push({ role: 'user', content: prompt });
                        const outcome = await runAgent({
                            client: o.client,
                            tools: o.tools,
                            system: liveSystem(),
                            history: conv.messages,
                            ctx: streamingCtx(base, write),
                            maxTurns: 16,
                            signal: ac.signal,
                            onToolCall: (name, input) => write({ type: 'tool', name, detail: JSON.stringify(input).slice(0, 120) }),
                        });
                        conv.messages = outcome.messages;
                        saveSession(o.dataDir, conv.id, conv.messages);
                        if (outcome.usage) {
                            // Make the cost of the turn visible: the adapter already reports
                            // usage, but it was discarded, so there was no way to see where
                            // tokens went without reading provider dashboards.
                            write({ type: 'usage', input: outcome.usage.input, output: outcome.usage.output, calls: outcome.usage.calls });
                        }
                        if (outcome.trimmed) {
                            // Say so out loud: the model is being sent less than the user can
                            // see, and a silent context cut is the worst kind.
                            write({
                                type: 'tool',
                                name: 'context',
                                detail: `trimmed ${outcome.trimmed.dropped} earlier message(s) to save tokens ` +
                                    `(~${Math.round(outcome.trimmed.before / 1000)}k → ~${Math.round(outcome.trimmed.after / 1000)}k chars sent)`,
                            });
                        }
                        if (outcome.aborted) {
                            // Be honest: a cancelled run did NOT finish. Emit a `stopped`
                            // marker so the client does not present a partial answer as done.
                            write({ type: 'stopped', text: outcome.text });
                        }
                        else {
                            write({ type: 'final', text: outcome.text });
                        }
                    }
                    else {
                        const r = await runGoal({
                            client: o.client,
                            tools: o.tools,
                            system: liveSystem(),
                            ctx: streamingCtx(base, write),
                            goal: prompt,
                            maxTurnsPerStep: 8,
                            onEvent: (msg) => write({ type: 'tool', name: 'goal', detail: msg.slice(0, 160) }),
                        });
                        write({
                            type: 'final',
                            text: `${r.report}\n\n— goal ${r.verified ? 'VERIFIED ✓' : 'NOT VERIFIED ✗'} · plan: ${r.plan.length} step(s) · turns: ${r.turns}`,
                        });
                    }
                }
                catch (e) {
                    // An aborted request surfaces as a throw from the fetch. Report it as
                    // a stop, not as a failure — otherwise Stop looks like a crash.
                    if (ac.signal.aborted) {
                        write({ type: 'stopped', text: '' });
                    }
                    else {
                        write({ type: 'error', text: e instanceof Error ? e.message : String(e) });
                    }
                }
                if (activeRuns.get(runKey) === ac)
                    activeRuns.delete(runKey);
                res.end();
            });
            return;
        }
        // Stop button: cancel whatever this session is currently running.
        if (req.method === 'POST' && route === '/api/stop') {
            const key = url.searchParams.get('session') ?? 'default';
            const controller = activeRuns.get(key);
            if (controller) {
                controller.abort();
                activeRuns.delete(key);
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, stopped: Boolean(controller) }));
            return;
        }
        if (req.method === 'POST' && route === '/api/new') {
            // ＋ New chat: replace the caller's live context with a fresh session
            // (new file id, empty history). NON-DESTRUCTIVE by design: the previous
            // session file STAYS under dataDir/sessions — it remains in the sidebar
            // (GET /api/sessions) and a fresh tab resumes it like any other
            // conversation (ChatGPT-style). Destructive removal happens only via
            // POST /api/sessions/delete, which archives to sessions/deleted/.
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 4096)
                    req.destroy();
            });
            req.on('end', () => {
                let key = 'default';
                try {
                    const parsed = JSON.parse(body || '{}');
                    if (typeof parsed.session === 'string' && parsed.session)
                        key = parsed.session;
                }
                catch {
                    /* default key */
                }
                conversations.set(key, { id: sessionFileId(), messages: [] });
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: true }));
            });
            return;
        }
        if (req.method === 'GET' && route === '/api/sessions') {
            // Sidebar list: every persisted conversation, newest first.
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ sessions: listSessions(o.dataDir) }));
            return;
        }
        if (req.method === 'POST' && (route === '/api/sessions/open' || route === '/api/sessions/delete')) {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 4096)
                    req.destroy();
            });
            req.on('end', () => {
                let sid = '';
                let tab = '';
                try {
                    const parsed = JSON.parse(body || '{}');
                    if (typeof parsed.id === 'string')
                        sid = parsed.id;
                    if (typeof parsed.session === 'string')
                        tab = parsed.session;
                }
                catch {
                    /* fail-closed below */
                }
                const key = tab || 'default';
                if (route === '/api/sessions/open') {
                    const loaded = loadSession(o.dataDir, sid);
                    if (!loaded) {
                        res.writeHead(404, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({ ok: false, error: 'session not found' }));
                        return;
                    }
                    // Bind the chosen conversation to this browser tab: context
                    // reattaches and new /api/ask turns continue that session.
                    conversations.set(key, { id: loaded.id, messages: [...loaded.messages] });
                    if (conversations.size > 50) {
                        const oldest = conversations.keys().next().value;
                        if (oldest !== undefined)
                            conversations.delete(oldest);
                    }
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, id: loaded.id, messages: loaded.messages }));
                    return;
                }
                // delete: archive to sessions/deleted/ (recoverable on disk).
                // If the live tab is chatting in that session, give it a fresh one.
                const ok = deleteSession(o.dataDir, sid);
                const live = conversations.get(key);
                if (ok && live && live.id === sid) {
                    conversations.set(key, { id: sessionFileId(), messages: [] });
                }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok }));
            });
            return;
        }
        if (req.method === 'POST' && route === '/api/upload') {
            // Drag-and-drop support (UI remodel): a raw audio/video body is uploaded
            // here (content-type: <mime>, X-File-Name: <name>), saved under
            // <cwd>/blackrose-uploads/ with a timestamped name, and the absolute
            // path is returned so the page can ask the agent to transcribe it.
            // Body cap: 25 MB (matches the STT API limit).
            const fileName = req.headers['x-file-name'] ?? 'dropped-audio.mp3';
            const safeName = path.basename(fileName).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
            const ext = path.extname(safeName) || '.mp3';
            const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            const uploadDir = path.join(o.cwd, 'blackrose-uploads');
            fs.mkdirSync(uploadDir, { recursive: true });
            const dest = path.join(uploadDir, `drop-${stamp}${ext}`);
            const chunks = [];
            let size = 0;
            let tooBig = false;
            req.on('data', (c) => {
                size += c.length;
                if (size > 25 * 1024 * 1024) {
                    tooBig = true;
                    req.destroy();
                    return;
                }
                chunks.push(c);
            });
            req.on('end', () => {
                if (tooBig)
                    return;
                fs.writeFileSync(dest, Buffer.concat(chunks));
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: true, path: dest, name: safeName, bytes: size }));
            });
            req.on('error', () => {
                res.writeHead(500, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: false, error: 'upload failed' }));
            });
            return;
        }
        // Encrypted state snapshot — the same code path as the CLI's /export, so a
        // backup taken from the UI restores through /import (and vice versa).
        if (req.method === 'POST' && route === '/api/export') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 4096)
                    req.destroy();
            });
            req.on('end', () => {
                let password = '';
                try {
                    password = String(JSON.parse(body || '{}').password ?? '');
                }
                catch {
                    /* reported below as a missing password */
                }
                try {
                    const r = exportStateIncremental(o.dataDir, password);
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, path: r.path, files: r.files, bytes: r.bytes, skipped: r.skipped }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // Restore from a .aistate backup. The browser sends the bytes (a file
        // picker hands over content, not a path), so they are staged inside the
        // run folder first: the core only ever reads a path it owns.
        if (req.method === 'POST' && route === '/api/import') {
            const fileName = req.headers['x-file-name'] ?? 'import.aistate';
            const password = req.headers['x-state-password'] ?? '';
            const safeName = path.basename(fileName).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80) || 'import.aistate';
            const chunks = [];
            let size = 0;
            let tooBig = false;
            req.on('data', (c) => {
                size += c.length;
                if (size > 200 * 1024 * 1024) {
                    tooBig = true;
                    req.destroy();
                    return;
                }
                chunks.push(c);
            });
            req.on('end', () => {
                if (tooBig)
                    return;
                const staging = path.join(o.cwd, 'blackrose-uploads');
                const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
                const staged = path.join(staging, `import-${stamp}-${safeName}`);
                try {
                    fs.mkdirSync(staging, { recursive: true });
                    fs.writeFileSync(staged, Buffer.concat(chunks));
                    const r = importState(o.dataDir, staged, password);
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, restored: r.restored, conflicts: r.conflicts }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
                finally {
                    // The staged copy is a temporary; never leave decrypted-adjacent
                    // leftovers around after a successful or failed import.
                    try {
                        fs.unlinkSync(staged);
                    }
                    catch { /* already gone */ }
                }
            });
            return;
        }
        if (req.method === 'POST' && route === '/api/approve') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 4096)
                    req.destroy();
            });
            req.on('end', () => {
                let id = '';
                let allow = false;
                try {
                    const parsed = JSON.parse(body || '{}');
                    id = typeof parsed.id === 'string' ? parsed.id : '';
                    allow = parsed.allow === true;
                }
                catch {
                    /* deny unknown payloads (fail-closed) */
                }
                const p = pendingApprovals.get(id);
                if (p) {
                    pendingApprovals.delete(id);
                    p.resolve(allow);
                }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: p !== undefined }));
            });
            return;
        }
        // ---- Trust mode toggle -------------------------------------------------
        // GET  → current state + the always-ask list, so the UI can warn about
        //        exactly what will still prompt.
        // POST → { on: boolean }. Per-process only; not persisted.
        if (route === '/api/trust') {
            if (req.method === 'GET') {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ on: trustMode, alwaysAsk: alwaysAskList() }));
                return;
            }
            if (req.method === 'POST') {
                let body = '';
                req.on('data', (c) => {
                    body += c.toString('utf8');
                    if (body.length > 1024)
                        req.destroy();
                });
                req.on('end', () => {
                    let on = false;
                    try {
                        const parsed = JSON.parse(body || '{}');
                        // Fail closed: anything but an explicit true turns trust OFF.
                        on = parsed.on === true;
                    }
                    catch {
                        /* deny unknown payloads (fail-closed) */
                    }
                    trustMode = on;
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, on: trustMode, alwaysAsk: alwaysAskList() }));
                });
                return;
            }
        }
        // ---- Trust mode: skip the dialog for ordinary tools -------------------
        // GET  reports the current mode + the tools that still always ask, so the
        // page can warn the user exactly what trust mode will NOT cover.
        if (route === '/api/trust') {
            if (req.method === 'GET') {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: true, trust: trustMode, alwaysAsk: alwaysAskList() }));
                return;
            }
            if (req.method === 'POST') {
                let body = '';
                req.on('data', (c) => {
                    body += c.toString('utf8');
                    if (body.length > 4096)
                        req.destroy();
                });
                req.on('end', () => {
                    let on = false;
                    try {
                        const parsed = JSON.parse(body || '{}');
                        // only an explicit `true` enables it; anything else turns it off
                        on = parsed.on === true;
                    }
                    catch {
                        on = false; // fail closed
                    }
                    trustMode = on;
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, trust: trustMode, alwaysAsk: alwaysAskList() }));
                });
                return;
            }
        }
        // ---- Capability inspector (Phase 8 UI) -------------------------------
        // The agent can already reach skills, schedules, knowledge, project notes,
        // memory and background jobs — but only through the chat loop. These two
        // routes surface them in the UI WITHOUT opening a general tool-execution
        // back door: /api/tools only lists metadata, and /api/tool only runs tools
        // on a fixed read-only allowlist. Anything that mutates state or touches the
        // machine (write_file, run_command, gui_action, spawn_agent, …) is
        // deliberately NOT reachable here — those belong in the chat loop, where
        // the approval dialog still guards them.
        if (req.method === 'GET' && route === '/api/tools') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                tools: o.tools.map((t) => ({ name: t.name, description: t.description, readOnly: READONLY_TOOLS.has(t.name) })),
            }));
            return;
        }
        if (req.method === 'POST' && route === '/api/tool') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 64 * 1024)
                    req.destroy();
            });
            req.on('end', async () => {
                let name = '';
                let input = {};
                try {
                    const parsed = JSON.parse(body || '{}');
                    name = String(parsed.name ?? '');
                    // Accept `args` as an ALIAS for `input`, and warn rather than silently
                    // ignoring it.
                    //
                    // BUG (2026-10-01, mine): the forget panel sent `{ name, args: {...} }`
                    // while this endpoint reads `input`. The result was a tool call with
                    // EMPTY arguments that still returned ok:true — so "forget the thing
                    // the user picked" silently did nothing, and the modal reported
                    // success. Nothing errored anywhere.
                    //
                    // The alias exists because a wrong key here is indistinguishable from
                    // a tool that ignores its input, which is exactly what happened. With
                    // both accepted, a caller can be wrong about the name but never about
                    // losing their arguments.
                    const argKey = parsed.input !== undefined ? 'input' : parsed.args !== undefined ? 'args' : 'input';
                    input = (parsed[argKey] ?? {});
                }
                catch {
                    /* reported below as a bad request */
                }
                if (!READONLY_TOOLS.has(name)) {
                    res.writeHead(403, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: false,
                        error: `"${name}" is not a read-only tool. State-changing and machine-touching tools run through chat, where they can ask for approval.`,
                    }));
                    return;
                }
                const tool = o.tools.find((t) => t.name === name);
                if (!tool) {
                    res.writeHead(404, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: `unknown tool "${name}"` }));
                    return;
                }
                try {
                    // No approval channel here by design: every allowlisted tool is
                    // read-only, so askApproval must never actually be consulted.
                    const r = await tool.run(input, {
                        cwd: o.cwd,
                        dataDir: o.dataDir,
                        askApproval: async () => false,
                    });
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: r.isError !== true, content: r.content }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // Push-to-talk (composer 🎤 button): one mic listen through the LOCAL
        // Windows dictation engine. Opening the microphone IS the consent — the
        // user clicked the mic button on their own machine — so this deliberately
        // bypasses /api/tool's read-only allowlist and the chat approval dialog.
        // Fully offline: audio never leaves the machine.
        if (req.method === 'POST' && route === '/api/listen') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 4096)
                    req.destroy();
            });
            req.on('end', async () => {
                let seconds;
                try {
                    const parsed = JSON.parse(body || '{}');
                    if (typeof parsed.seconds === 'number' && Number.isFinite(parsed.seconds)) {
                        seconds = parsed.seconds;
                    }
                }
                catch {
                    /* default window below */
                }
                try {
                    const r = await runListenMic({ cwd: o.cwd }, seconds);
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: r.ok, text: r.text, detail: r.detail }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, text: '', detail: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // In-app API key manager: view configured route statuses (never raw keys)
        if (req.method === 'GET' && route === '/api/keys') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, keys: listKeyStatuses(o.dataDir) }));
            return;
        }
        // In-app API key manager: update or clear an API key
        if (req.method === 'POST' && route === '/api/keys') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 8192)
                    req.destroy();
            });
            req.on('end', () => {
                let envVar = '';
                let keyVal = '';
                try {
                    const parsed = JSON.parse(body || '{}');
                    envVar = String(parsed.envVar ?? '').trim();
                    keyVal = String(parsed.value ?? '').trim();
                }
                catch {
                    /* reported as error below */
                }
                if (!envVar) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: 'envVar is required' }));
                    return;
                }
                try {
                    saveKey(o.dataDir, envVar, keyVal);
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, keys: listKeyStatuses(o.dataDir) }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // Multi-key rotation (B26): the roster for a provider. Masked previews
        // only, plus per-key health/cooldown — never a key value.
        if (req.method === 'GET' && route === '/api/keys/roster') {
            const provider = url.searchParams.get('provider') ?? '';
            const health = keyHealthSnapshot();
            const attach = (keys) => keys.map((k) => ({
                ...k,
                keys: k.previews.map((preview, index) => {
                    const h = health.find((x) => x.id.startsWith(`${k.envVar}#${index} `));
                    return { index, preview, state: h?.state ?? 'ok', cooldownMs: h?.cooldownMs ?? 0, usable: h?.usable ?? true };
                }),
            }));
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                ok: true,
                providers: attach(listProviderKeyStatuses(o.dataDir)).filter((p) => !provider || p.route === provider),
            }));
            return;
        }
        // Add / remove one key of a provider (multi-key rotation).
        // Provider registry (B27): add/remove an OpenAI-compatible gateway without
        // a code change. Base URLs are validated to http(s) and route names to a
        // safe charset before anything is written.
        if (req.method === 'GET' && route === '/api/providers') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                ok: true,
                presets: PROVIDER_PRESETS,
                providers: allProviderSpecs(o.dataDir),
            }));
            return;
        }
        if (req.method === 'POST' && route === '/api/providers') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 64 * 1024)
                    req.destroy();
            });
            req.on('end', () => {
                try {
                    const p = JSON.parse(body || '{}');
                    const entry = addProvider(o.dataDir, {
                        name: String(p.name ?? ''),
                        label: String(p.label ?? ''),
                        baseUrl: String(p.baseUrl ?? ''),
                        model: String(p.model ?? ''),
                        // default TRUE: sending no auth header to a gateway that wants one
                        // is a confusing failure, so "needs a key" is the safe assumption
                        needsKey: p.needsKey !== false,
                    });
                    const chain = readRouteChain(o.dataDir);
                    // Append to the end so the new route is a LAST resort: putting a
                    // brand-new gateway at the front would silently reroute every turn
                    // away from a chain that has been working.
                    let inChain = false;
                    let chainNote = '';
                    if (p.addToChain === true) {
                        if (chain.source === 'env') {
                            chainNote = ' BLACKROSE_ROUTES is set in this environment and takes precedence, so it was not added to the stored chain.';
                        }
                        else if (chain.routes.includes(entry.name)) {
                            inChain = true;
                        }
                        else {
                            // writeRouteChain publishes it for this process already.
                            writeRouteChain(o.dataDir, [...chain.routes, entry.name]);
                            inChain = true;
                        }
                    }
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: true,
                        added: entry,
                        providers: allProviderSpecs(o.dataDir),
                        inChain,
                        chainNote,
                    }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        if (req.method === 'DELETE' && route === '/api/providers') {
            const name = url.searchParams.get('name') ?? '';
            if (!name) {
                res.writeHead(400, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: false, error: 'name is required' }));
                return;
            }
            const removed = removeProvider(o.dataDir, name);
            res.writeHead(removed ? 200 : 404, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: removed, providers: allProviderSpecs(o.dataDir) }));
            return;
        }
        if (req.method === 'GET' && route === '/api/routes') {
            const chain = readRouteChain(o.dataDir);
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                ok: true,
                routes: chain.routes,
                // Reported so the UI can say WHY the chain is what it is. If the chain
                // comes from the environment, editing it here would silently do nothing,
                // and the user deserves to be told that rather than to watch clicks
                // appear to save.
                source: chain.source,
                editable: chain.source !== 'env',
            }));
            return;
        }
        if (req.method === 'POST' && route === '/api/routes') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 64 * 1024)
                    req.destroy();
            });
            req.on('end', () => {
                try {
                    const chain = readRouteChain(o.dataDir);
                    if (chain.source === 'env') {
                        res.writeHead(409, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({
                            ok: false,
                            error: 'BLACKROSE_ROUTES is set in this session\'s environment, which takes precedence. Change it there, or start BlackRose without it.',
                        }));
                        return;
                    }
                    const p = JSON.parse(body || '{}');
                    const routes = Array.isArray(p.routes) ? p.routes : [];
                    if (routes.length === 0) {
                        throw new Error('the fallback chain needs at least one route');
                    }
                    const saved = writeRouteChain(o.dataDir, routes.map(String));
                    // Published immediately so the running client picks up the new order
                    // on the next turn rather than needing a restart — the whole point of
                    // editing this from the UI.
                    process.env.BLACKROSE_ROUTES = saved.join(',');
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, routes: saved, source: 'vault' }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // Validate keys for one provider. Accepts EITHER the provider's stored keys
        // (envVar only) OR an unsaved bulk blob (envVar + text), so a user can check
        // a file BEFORE committing it to the vault. The response carries only
        // masked previews and verdicts — never a key, valid or not.
        if (req.method === 'POST' && route === '/api/keys/validate') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 2 * 1024 * 1024)
                    req.destroy();
            });
            req.on('end', async () => {
                let envVar = '';
                let text = '';
                try {
                    const parsed = JSON.parse(body || '{}');
                    envVar = String(parsed.envVar ?? '').trim();
                    text = typeof parsed.text === 'string' ? parsed.text : '';
                }
                catch {
                    /* reported below */
                }
                if (!envVar) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: 'envVar is required' }));
                    return;
                }
                const spec = allProviderSpecs(o.dataDir).find((s) => s.envVar === envVar);
                if (!spec) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: `Unknown provider "${envVar}"` }));
                    return;
                }
                const up = spec.route.toUpperCase();
                // A registered provider carries its own base URL; a built-in reads env.
                const baseUrl = spec.custom ? spec.baseUrl : (process.env[`BLACKROSE_${up}_BASE_URL`] ?? '');
                if (!baseUrl) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: false,
                        error: `${spec.route} has no BLACKROSE_${up}_BASE_URL set, so it cannot be probed`,
                    }));
                    return;
                }
                try {
                    // An unsaved blob validates exactly as it would after saving.
                    const keys = text.trim()
                        ? parseBulkKeys(text).keys
                        : readProviderKeys(o.dataDir, envVar);
                    if (keys.length === 0) {
                        res.writeHead(400, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({ ok: false, error: 'No keys to validate' }));
                        return;
                    }
                    const verdicts = await validateProviderKeys(envVar, baseUrl, keys);
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: true,
                        provider: spec.route,
                        label: spec.label,
                        summary: summarizeKeyValidation(verdicts),
                        verdicts,
                    }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        // Bulk import: add many keys for ONE provider from a pasted blob or an
        // uploaded file. Tolerant of the formats keys actually arrive in, and it
        // never echoes key content back — see parseBulkKeys.
        if (req.method === 'POST' && route === '/api/keys/bulk') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                // a few hundred keys is ~50KB; allow generous room but stay bounded
                if (body.length > 2 * 1024 * 1024)
                    req.destroy();
            });
            req.on('end', () => {
                let envVar = '';
                let text = '';
                try {
                    const parsed = JSON.parse(body || '{}');
                    envVar = String(parsed.envVar ?? '').trim();
                    text = typeof parsed.text === 'string' ? parsed.text : '';
                }
                catch {
                    /* reported below */
                }
                if (!envVar) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: 'envVar is required' }));
                    return;
                }
                try {
                    const parsedKeys = parseBulkKeys(text);
                    if (parsedKeys.keys.length === 0) {
                        res.writeHead(400, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({
                            ok: false,
                            error: 'No usable keys found in that input',
                            rejected: parsedKeys.rejected,
                            skipped: parsedKeys.skipped,
                        }));
                        return;
                    }
                    const before = readProviderKeys(o.dataDir, envVar).length;
                    const count = addProviderKeysBulk(o.dataDir, envVar, parsedKeys.keys);
                    resetKeyHealth();
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: true,
                        added: count - before,
                        count,
                        rejected: parsedKeys.rejected,
                        skipped: parsedKeys.skipped,
                        providers: listProviderKeyStatuses(o.dataDir),
                    }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        if (req.method === 'POST' && route === '/api/keys/rotate') {
            let body = '';
            req.on('data', (c) => {
                body += c.toString('utf8');
                if (body.length > 8192)
                    req.destroy();
            });
            req.on('end', () => {
                let envVar = '';
                let value = '';
                let index = -1;
                let op = 'add';
                try {
                    const parsed = JSON.parse(body || '{}');
                    envVar = String(parsed.envVar ?? '').trim();
                    value = String(parsed.value ?? '').trim();
                    index = Number(parsed.index ?? -1);
                    op = String(parsed.op ?? 'add').trim();
                }
                catch {
                    /* reported as error below */
                }
                if (!envVar) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: 'envVar is required' }));
                    return;
                }
                try {
                    // A removed key may have been parked; drop its health so a re-added
                    // key of the same shape starts clean.
                    if (op === 'remove') {
                        const removed = removeProviderKey(o.dataDir, envVar, index);
                        resetKeyHealth();
                        res.writeHead(200, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({ ok: true, count: removed, providers: listProviderKeyStatuses(o.dataDir) }));
                        return;
                    }
                    if (op === 'add') {
                        const count = addProviderKey(o.dataDir, envVar, value);
                        resetKeyHealth();
                        res.writeHead(200, { 'content-type': 'application/json' });
                        res.end(JSON.stringify({ ok: true, count, providers: listProviderKeyStatuses(o.dataDir) }));
                        return;
                    }
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: `Unsupported op "${op}"` }));
                }
                catch (e) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }));
                }
            });
            return;
        }
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
    });
    const connections = new Set();
    server.on('connection', (c) => {
        connections.add(c);
        c.on('close', () => connections.delete(c));
    });
    const host = o.host ?? '127.0.0.1';
    const wanted = o.port ?? 8788;
    /**
     * Listen on the first free port at or after `from`.
     *
     * EADDRINUSE used to be a completely silent failure: the process exited, the
     * browser kept showing whatever the PREVIOUS instance had served, and the
     * symptom was "the UI is broken, Cancel does nothing, the chat area is
     * invisible" — with no error on screen and none in the log, because the thing
     * that failed had already exited before anyone looked.
     *
     * The subtlety that makes this worth writing carefully: a try/catch around
     * server.listen() does NOT work here. listen() throws asynchronously as an
     * 'error' EVENT, so the catch block runs but the event is still unhandled and
     * still takes the process down. Verified on node 24. Each attempt therefore
     * needs its own one-shot error listener that decides its own fate.
     */
    const listenOn = (from) => new Promise((resolve, reject) => {
        const onError = (e) => {
            // Both branches reject: the caller decides whether EADDRINUSE is
            // recoverable. All this listener has to do is make sure the error is
            // HANDLED, because an unhandled 'error' event on a Server kills the
            // process outright.
            server.removeListener('listening', onListening);
            reject(e);
        };
        const onListening = () => {
            server.removeListener('error', onError);
            const addr = server.address();
            resolve(typeof addr === 'object' && addr ? addr.port : from);
        };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(from, host);
    });
    let port;
    try {
        port = await listenOn(wanted);
    }
    catch (e) {
        if (e.code !== 'EADDRINUSE')
            throw e;
        // A stale core from an earlier run is the NORMAL case on a desktop, so this
        // is a recovery path rather than an error. Fall through to the next port and
        // announce it: the alternative is a user staring at a page that nothing on
        // the machine is serving.
        port = -1;
        for (let p = wanted + 1; p < wanted + 20; p++) {
            try {
                port = await listenOn(p);
                console.log(`  ↪ port ${wanted} was already in use (another BlackRose is running) — using ${port} instead`);
                break;
            }
            catch {
                /* taken too — try the next */
            }
        }
        if (port < 0) {
            throw new Error(`Port ${wanted} is already in use (another BlackRose is probably running) ` +
                `and ports ${wanted + 1}-${wanted + 19} are taken too. Close the other instance, or pass --ui <port>.`);
        }
    }
    return {
        port,
        url: `http://localhost:${port}`,
        close: () => new Promise((resolve) => {
            for (const [id, p] of pendingApprovals) {
                pendingApprovals.delete(id);
                p.resolve(false);
            }
            for (const c of connections)
                c.destroy();
            server.close(() => resolve());
        }),
    };
}
return { countKnowledgeChunks,embedHealth,startWebUi };
}

__mod['ui/web/server.js'] = M69();

function M70() {
const { makeClient, routeProbeTarget } = __mod['llm/factory.js'];
const { resilientClient } = __mod['llm/resilient.js'];
const { buildSystemPrompt } = __mod['llm/prompt.js'];
const { buildTools } = __mod['tools/index.js'];
const { registerMcpTools } = __mod['mcp/client.js'];
const { loadSkills } = __mod['skills/skills.js'];
const { readProjectNotes } = __mod['tools/project.js'];
const { recordRouteProbe, routeEntriesFromClient } = __mod['llm/routeHealth.js'];
const { applyProviders } = __mod['core/providers.js'];
const { startWebUi } = __mod['ui/web/server.js'];
/**
 * Web UI entrypoint (Phase 7): `node src/index.ts --ui [port]` (or the built
 * BlackRose.exe) serves the professional interface in the default browser.
 * Tool approvals are interactive dialogs in the UI, driven by the human at
 * the screen — this is the opposite policy of the remote bridge (fail-closed).
 */
async function runWebUi(config, argv) {
    const i = argv.indexOf('--ui');
    const portArg = Number(argv[i + 1]);
    const port = Number.isFinite(portArg) && portArg > 0 ? portArg : 8788;
    // Providers added from the UI (B27) live in the vault, not in the process
    // environment, so they must be published BEFORE makeClient() - otherwise the
    // client is constructed against a stale environment that knows nothing about the
    // routes the user just added.
    //
    // ORDER BUG FIXED 2026-10-01: this used to sit 20 lines BELOW makeClient(),
    // directly under a comment asserting it ran first. It only appeared to work
    // because a later singleProvider() call re-read the vault; the startup path
    // itself resolved the router before any registry value reached the environment.
    applyProviders(config.dataDir);
    let client;
    try {
        client = resilientClient(makeClient(config), {
            onRetry: (attempt, delayMs, err) => console.log(`  ↻ transient LLM error (${err instanceof Error ? err.message.slice(0, 80) : String(err)}) — retry ${attempt} in ${delayMs}ms`),
        });
    }
    catch (e) {
        console.error(`${e instanceof Error ? e.message : String(e)}\n` +
            'Set ANTHROPIC_API_KEY, or BLACKROSE_PROVIDER=ollama for a fully local UI.');
        process.exit(1);
    }
    let tools = buildTools();
    const mcp = await registerMcpTools(config.dataDir, config.cwd);
    if (mcp.length > 0)
        tools = [...tools, ...mcp];
    /**
     * Build the system prompt FRESH, every time it is needed.
     *
     * This used to be computed once at boot and frozen for the process lifetime.
     * That is the "BlackRose has no memories" bug: memory_save and project_note
     * both write files DURING a session, and the prompt's memory-key list and
     * project notes never mentioned anything saved after launch. The tool
     * reported success and the file existed — it was simply invisible to the
     * model until the app was restarted. Rebuilding per request costs a directory
     * listing and two small file reads, which is nothing next to an LLM call.
     */
    const buildSystem = () => {
        const d = path.join(config.dataDir, 'memory');
        const keys = fs.existsSync(d) ? fs.readdirSync(d).filter((f) => f.endsWith('.md')) : [];
        return buildSystemPrompt(config.cwd, config.dataDir, keys, readProjectNotes(config.dataDir, config.cwd), loadSkills(config.dataDir).map((s) => ({ name: s.name, description: s.description })));
    };
    const system = buildSystem();
    // Route-status prober (2026-10-01).
    //
    // The "Connected routes" section is only useful if it shows real state, and
    // route health is otherwise learned ONLY from actual user traffic. On a fresh
    // launch — or for any route that has not been picked yet — every box read
    // "unknown", which is the same as telling the user nothing. This fills those
    // in: one cheap GET <base>/models per route, on a timer, off the request
    // path so it can never delay or fail a chat turn.
    //
    // Deliberately /models and NOT a chat completion: a probe must cost no tokens
    // and must not consume a provider's rate-limit budget. A gateway that hides
    // /models (OmniRoute, Cloudflare) answers 404/405, which proves nothing about
    // the route — classifyRouteProbe keeps that 'unknown', which is honest, and
    // the route's state becomes real the first time it actually answers.
    //
    // The route list comes from the composed client (the same name::model pairing
    // startWebUi registers) and the base URL/key come from factory.ts's own
    // resolver, so a probe can neither invent a second tray row nor skip a route
    // whose base URL is a built-in default instead of an env override.
    const probeRoutes = () => {
        for (const { name, model } of routeEntriesFromClient(client.name, client.model)) {
            const target = routeProbeTarget(name, config.dataDir);
            if (!target)
                continue;
            // Fail CLOSED: a keyed route with no key cannot answer, and the only
            // honest thing to show is that — never 'ok', and never a silent skip.
            if (target.needsKey && !target.apiKey) {
                recordRouteProbe(target.name, false, `missing API key — set ${target.keyEnvVar}`, model);
                continue;
            }
            const ac = new AbortController();
            const timer = setTimeout(() => ac.abort(), 4000);
            // Keyless gateways 401 on a placeholder bearer token, so send no header.
            const headers = target.apiKey ? { authorization: `Bearer ${target.apiKey}` } : undefined;
            void fetch(`${target.baseUrl}/models`, { headers, signal: ac.signal })
                .then(async (res) => {
                if (!res.ok) {
                    recordRouteProbe(target.name, false, `HTTP ${res.status}`, model);
                    return;
                }
                const j = (await res.json());
                const n = Array.isArray(j.data) ? j.data.length : 0;
                recordRouteProbe(target.name, true, n > 0 ? `reachable · ${n} model(s)` : 'reachable', model);
            })
                .catch((e) => {
                recordRouteProbe(target.name, false, e instanceof Error ? e.message : String(e), model);
            })
                .finally(() => clearTimeout(timer));
        }
    };
    probeRoutes();
    const probeTimer = setInterval(probeRoutes, 120_000);
    probeTimer.unref?.();
    // Token gate: auto-generate a single-use-per-launch token so the UI is safe
    // even when bound beyond loopback (BLACKROSE_UI_HOST). Override it with
    // BLACKROSE_UI_TOKEN; the browser page receives it via the #token= fragment,
    // which is never sent to the server in request URLs.
    const host = process.env.BLACKROSE_UI_HOST ?? '127.0.0.1';
    const token = process.env.BLACKROSE_UI_TOKEN || (host === '127.0.0.1' || host === 'localhost' ? '' : crypto.randomUUID());
    const h = await startWebUi({ client, system, buildSystem, tools, dataDir: config.dataDir, cwd: config.cwd, port, host, token });
    const url = token ? `${h.url}/#token=${token}` : h.url;
    console.log(`BlackRose UI: ${url}`);
    if (token) {
        console.log(`  token: ${token} (auth protects every route; set BLACKROSE_UI_TOKEN to fix it across restarts)`);
    }
    console.log(`  provider: ${client.name} · model: ${client.model}`);
    console.log('  approvals: shown as dialogs in the UI (Allow / Deny)');
    console.log('  Ctrl+C to stop.');
    try {
        // open the default browser (best-effort; non-fatal when headless)
        const { spawn } = await import('node:child_process');
        void spawn('cmd.exe', ['/c', 'start', '', url]);
    }
    catch {
        /* no browser available — user navigates manually */
    }
    const stop = () => {
        void h.close().then(() => process.exit(0));
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    setInterval(() => { }, 60_000); // keep the event loop alive
}
return { runWebUi };
}

__mod['ui/web/main.js'] = M70();

function M71() {
const { openStore } = __mod['memory/hybrid.js'];
const { embedBackendLabel, embedBaseUrl, embedModelName, embedStatus } = __mod['memory/embedder.js'];
const { sttConfig } = __mod['tools/stt.js'];
const { localSttAvailable } = __mod['tools/voice.js'];
const { keystoreStatus, keysFilePath } = __mod['core/keys.js'];
const { BUILTIN_FILE, loadSkills } = __mod['skills/skills.js'];
const { KEYLESS_ROUTES, KEYLESS_ROUTE_NAMES } = __mod['llm/factory.js'];
const { undoStats } = __mod['core/undo.js'];
/**
 * Zero-dependency diagnostics for BlackRose (`node src/index.ts --doctor`).
 *
 * Reports everything that commonly blocks a first run — provider/API-key
 * configuration, API route reachability, state-dir inventory, vector index
 * health — as plain informational lines. Never prints secrets, never
 * mutates state, works without any API key (that is the situation it is
 * most useful for).
 */










function countFiles(dir, suffix) {
    if (!fs.existsSync(dir))
        return 0;
    return fs.readdirSync(dir).filter((f) => (suffix ? f.endsWith(suffix) : fs.statSync(path.join(dir, f)).isFile())).length;
}
async function probeOpenAi(base, key, model) {
    // Gateways differ: some expose a public /models list, others (OmniRoute,
    // some proxies) only allow authenticated generation calls. Probe /models
    // first; if it is restricted/absent, fall back to a minimal chat ping so
    // the report reflects what actually matters: can we GENERATE with this key?
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 2000);
    try {
        const res = await fetch(`${base}/models`, { headers: { authorization: `Bearer ${key}` }, signal: ac.signal });
        clearTimeout(t);
        if (res.ok) {
            const data = (await res.json());
            const ids = (data.data ?? []).map((m) => m.id).filter(Boolean);
            const free = (data.data ?? [])
                .filter((m) => m.is_free || String(m.id).endsWith(':free'))
                .map((m) => m.id)
                .filter(Boolean);
            const freeTxt = free.length > 0 ? ` · free: ${free.slice(0, 4).join(', ')}${free.length > 4 ? '…' : ''}` : '';
            return { ok: true, detail: `${ids.length} model(s)${freeTxt}` };
        }
        if (res.status === 401 || res.status === 403 || res.status === 404 || res.status === 405) {
            // /models not usable — probe a minimal generation instead
            const ac2 = new AbortController();
            const t2 = setTimeout(() => ac2.abort(), 8000);
            const chat = await fetch(`${base}/chat/completions`, {
                method: 'POST',
                headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
                body: JSON.stringify({ model, messages: [{ role: 'user', content: 'Reply with exactly: OK' }], max_tokens: 6 }),
                signal: ac2.signal,
            });
            clearTimeout(t2);
            if (chat.ok) {
                const j = (await chat.json());
                return { ok: true, detail: `chat probe OK (model ${j.model ?? model}) — /models not exposed` };
            }
            const body = await chat.text().catch(() => '');
            return { ok: false, detail: `HTTP ${chat.status} on chat${body ? ` — ${body.replace(/\s+/g, ' ').slice(0, 100)}` : ''}` };
        }
        return { ok: false, detail: `HTTP ${res.status}` };
    }
    catch (e) {
        clearTimeout(t);
        return { ok: false, detail: e instanceof Error && e.name === 'AbortError' ? 'timeout (2s)' : 'not reachable' };
    }
}
async function runDoctor(cfg) {
    const out = [];
    out.push('BlackRose doctor');
    out.push(`  ✓ runtime — node ${process.version} · ${process.platform}`);
    const provider = process.env.BLACKROSE_PROVIDER ?? 'anthropic';
    if (provider === 'router') {
        out.push(`  ✓ provider router — routes: ${process.env.BLACKROSE_ROUTES ?? '(unset)'}`);
        const allNames = (process.env.BLACKROSE_ROUTES ?? '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
        const names = allNames.filter((s) => /^openai\d*$/.test(s));
        for (const name of names) {
            const up = name.toUpperCase();
            const base = (process.env[`BLACKROSE_${up}_BASE_URL`] ?? 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
            const key = name === 'openai'
                ? (process.env.BLACKROSE_OPENAI_API_KEY ?? process.env.OPENAI_API_KEY)
                : process.env[`BLACKROSE_${up}_API_KEY`];
            if (!key) {
                out.push(`  · route ${name} — BLACKROSE_${up}_API_KEY missing · ${base}`);
                continue;
            }
            const model = process.env[`BLACKROSE_${up}_MODEL`] ?? 'nvidia/nemotron-3-super-120b-a12b:free';
            const r = await probeOpenAi(base, key, model);
            out.push(r.ok
                ? `  ✓ route ${name} — ${base} · ${r.detail}`
                : `  · route ${name} — ${base} · ${r.detail}`);
        }
        // Keyless routes (kilo, ovh): no credential, so they are always "configured".
        // Probe with a real generation call — that is the only thing that proves a
        // free pool is actually serving right now.
        for (const keyless of KEYLESS_ROUTE_NAMES) {
            if (!allNames.includes(keyless))
                continue;
            const spec = KEYLESS_ROUTES[keyless];
            const base = (process.env[`BLACKROSE_${keyless.toUpperCase()}_BASE_URL`] ?? spec.baseUrl).replace(/\/+$/, '');
            const model = process.env[`BLACKROSE_${keyless.toUpperCase()}_MODEL`] ?? spec.model;
            const r = await probeOpenAi(base, '', model);
            out.push(r.ok
                ? `  ✓ route ${keyless} — ${base} · ${r.detail} (keyless)`
                : `  · route ${keyless} — ${base} · ${r.detail} (keyless; ${spec.note})`);
        }
        // 1min.ai: proprietary chat-with-ai endpoint (no /models list) — minimal chat probe
        if (allNames.includes('onemin') || allNames.includes('1min')) {
            const key = process.env.BLACKROSE_ONEMIN_API_KEY;
            const model = process.env.BLACKROSE_ONEMIN_MODEL ?? 'gpt-4o-mini';
            const base = (process.env.BLACKROSE_ONEMIN_BASE_URL ?? 'https://api.1min.ai').replace(/\/+$/, '');
            if (!key) {
                out.push(`  · route onemin — BLACKROSE_ONEMIN_API_KEY missing · ${base}`);
            }
            else {
                try {
                    const r = await fetch(`${base}/api/chat-with-ai`, {
                        method: 'POST',
                        headers: { 'content-type': 'application/json', 'API-KEY': key },
                        body: JSON.stringify({ type: 'UNIFY_CHAT_WITH_AI', model, promptObject: { prompt: 'Reply with exactly: OK' } }),
                    });
                    if (!r.ok) {
                        out.push(`  · route onemin — ${base} · HTTP ${r.status}`);
                    }
                    else {
                        const j = (await r.json());
                        out.push(`  ${j.aiRecord?.status === 'SUCCESS' ? '✓' : '·'} route onemin — ${base} · chat probe ${j.aiRecord?.status === 'SUCCESS' ? 'OK' : 'degraded'} (model ${model})`);
                    }
                }
                catch (e) {
                    out.push(`  · route onemin — ${base} · ${e instanceof Error ? e.message : 'probe failed'}`);
                }
            }
        }
    }
    else if (provider === 'openai' || /^openai\d+$/.test(provider)) {
        const up = provider.toUpperCase();
        const base = (process.env[`BLACKROSE_${up}_BASE_URL`] ?? 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
        const key = provider === 'openai'
            ? (process.env.BLACKROSE_OPENAI_API_KEY ?? process.env.OPENAI_API_KEY)
            : process.env[`BLACKROSE_${up}_API_KEY`];
        const model = process.env[`BLACKROSE_${up}_MODEL`] ?? 'nvidia/nemotron-3-super-120b-a12b:free';
        if (!key) {
            out.push(`  · provider ${provider} — BLACKROSE_${up}_API_KEY missing · ${base} · model ${model}`);
        }
        else {
            const r = await probeOpenAi(base, key, model);
            out.push(r.ok
                ? `  ✓ provider ${provider} — ${base} · model ${model} · ${r.detail}`
                : `  · provider ${provider} — ${base} · model ${model} · ${r.detail}`);
        }
    }
    else {
        const hasKey = Boolean(process.env.ANTHROPIC_API_KEY);
        out.push(hasKey
            ? '  ✓ provider anthropic — ANTHROPIC_API_KEY is set'
            : '  · provider anthropic — ANTHROPIC_API_KEY missing (set it, or BLACKROSE_PROVIDER=openai for a free gateway)');
    }
    const d = cfg.dataDir;
    out.push(fs.existsSync(d) ? `  ✓ data dir — ${d}` : `  · data dir — ${d} (created on first run)`);
    out.push(`  · memory files: ${countFiles(path.join(d, 'memory'), '.md')}`);
    out.push(`  · knowledge sources: ${countFiles(path.join(d, 'knowledge'), '.json')}`);
    out.push(`  · sessions: ${countFiles(path.join(d, 'sessions'), '.json')}`);
    out.push(`  · experience months: ${countFiles(path.join(d, 'experiences'), '.md')}`);
    // "skills" meant two different things on two surfaces: --doctor counted only
    // .md files on disk (0 here) while /api/health used loadSkills(), which merges
    // the BUILT-IN skills in as well (3). Both numbers were true and both were
    // labelled just "skills", so a user comparing them saw a contradiction and no
    // way to tell which was wrong. Name both explicitly instead.
    {
        const all = loadSkills(d);
        const shipped = all.filter((s) => s.file === BUILTIN_FILE);
        const custom = all.length - shipped.length;
        out.push(`  · skills: ${custom} saved by you` +
            (shipped.length > 0 ? ` + ${shipped.length} built-in (${shipped.map((s) => s.name).join(', ')})` : ''));
    }
    out.push(`  · schedules: ${countFiles(path.join(d, 'schedules'), '.json')}`);
    // B1 Secret Vault — is the key store actually sealed at rest? Values are never
    // printed; only the protection mode, a count and the path.
    const ks = keystoreStatus(d);
    const legacyPlain = fs.existsSync(keysFilePath(d));
    if (legacyPlain) {
        out.push(`  ✗ key store — PLAINTEXT ${keysFilePath(d)} still on disk (sealed and deleted on next key read)`);
    }
    else if (ks.encrypted) {
        out.push(`  ✓ key store — sealed ${ks.protection === 'dpapi' ? '(AES-256-GCM, DPAPI-wrapped key)' : `(AES-256-GCM, keyfile: ${ks.protection})`} · ${ks.entries} secret(s)`);
    }
    else {
        out.push(`  · key store — nothing sealed${ks.error ? ` · last error: ${ks.error}` : ''}`);
    }
    // B2 Undo — size of the rollback journal, so it cannot silently fill the disk.
    const uj = undoStats(d);
    out.push(`  · undo journal — ${uj.entries} entr${uj.entries === 1 ? 'y' : 'ies'} · ${(uj.blobBytes / 1048576).toFixed(1)} MB (keeps newest ${uj.keep})`);
    const store = openStore(d);
    const vecCount = Object.keys(store.file.entries).length;
    out.push(vecCount > 0
        ? `  ✓ vector index — ${vecCount} entr${vecCount === 1 ? 'y' : 'ies'} · model ${store.file.model} (${store.file.dim}d)`
        : '  · vector index — empty (populates automatically as you save/search)');
    if (embedBackendLabel() === 'gemini') {
        out.push(`  · embeddings — ${embedModelName()} via Gemini (${embedBaseUrl()}, dim 3072; fallback: hash embedder if unavailable)`);
    }
    else {
        out.push('  · embeddings — hash embedder (no API key configured, or BLACKROSE_EMBED=off) — retrieval is lexical, not semantic');
    }
    // Two states that used to be invisible: a spent daily quota, and a store
    // left in the hash space while the API is healthy again. Both mean "semantic
    // search is not actually happening", which is worth an explicit line rather
    // than being inferred by comparing the two lines above.
    {
        const es = embedStatus();
        if (es.quotaExhaustedAt > 0) {
            out.push(`  ! embedding quota — DAILY cap of ${es.dailyRequestQuota} requests/day observed exhausted; ` +
                'search is LEXICAL until Google resets it.');
            out.push('    re-index afterwards: node scripts/warm-embed.ts   (use --dry-run first)');
        }
        if (vecCount > 0 && store.file.model !== es.activeModel) {
            out.push(`  ! vector index is ${store.file.model} but the active backend would produce ${es.activeModel}; ` +
                `${vecCount} entr${vecCount === 1 ? 'y is' : 'ies are'} being re-embedded lazily on first search.`);
        }
    }
    out.push(process.platform === 'win32'
        ? '  · ocr — Windows OCR engine (ocr_read; learn_pdf falls back to OCR for scanned PDFs)'
        : '  · ocr — not available (Windows-only feature)');
    const stt = sttConfig();
    out.push(stt.apiKey
        ? `  · stt — ${stt.baseUrl} · model ${stt.model} (transcribe_audio; key configured)`
        : '  · stt — not configured (transcribe_audio needs BLACKROSE_STT_API_KEY or BLACKROSE_OPENAI1_API_KEY)');
    const localStt = await localSttAvailable();
    out.push(process.platform === 'win32'
        ? localStt
            ? `  · listen — local push-to-talk READY (Windows dictation engine; BLACKROSE_LISTEN_MS=${process.env.BLACKROSE_LISTEN_MS || '8000'})`
            : '  · listen — local push-to-talk UNAVAILABLE (no System.Speech recognizer installed; enable Speech Recognition in Windows settings)'
        : '  · listen — not available (Windows-only feature)');
    const blog = path.join(d, 'bridge.log');
    if (fs.existsSync(blog)) {
        const sz = fs.statSync(blog).size;
        out.push(`  ✓ bridge audit log — ${(sz / 1024).toFixed(1)} KB`);
    }
    out.push(`  · state password — ${process.env.BLACKROSE_STATE_PASSWORD ? 'set (sync/export ready)' : 'unset (/sync and /export need BLACKROSE_STATE_PASSWORD)'}`);
    out.push('  tip: "credit balance is too low" → add credits at console.anthropic.com, or switch providers: BLACKROSE_PROVIDER=openai (OpenAI-protocol; OpenRouter free models by default — set BLACKROSE_OPENAI_API_KEY) or BLACKROSE_PROVIDER=gemini.');
    return out;
}
return { runDoctor };
}

__mod['doctor.js'] = M71();

function M72() {
const { loadConfig } = __mod['config.js'];
const { makeClient } = __mod['llm/factory.js'];
const { buildSystemPrompt } = __mod['llm/prompt.js'];
const { runAgent } = __mod['core/agent.js'];
const { runGoal } = __mod['core/taskEngine.js'];
const { buildTools } = __mod['tools/index.js'];
const { memoryListTool, memorySaveTool } = __mod['tools/memory.js'];
const { saveSession, sessionFileId, loadLatestSession, compactHistory } = __mod['session/history.js'];
const { readProjectNotes } = __mod['tools/project.js'];
const { exportState, exportStateIncremental, importState } = __mod['state/aistate.js'];
const { loadSkills } = __mod['skills/skills.js'];
const { registerMcpTools } = __mod['mcp/client.js'];
const { startScheduler } = __mod['schedule/runner.js'];
const { Spinner, color } = __mod['ui/render.js'];
const { runBridge, runRemote } = __mod['bridge/main.js'];
const { runWebUi } = __mod['ui/web/main.js'];
const { bridgeHealth, bridgeSyncPull, bridgeSyncPush } = __mod['bridge/client.js'];
const { runDoctor } = __mod['doctor.js'];
const { resilientClient } = __mod['llm/resilient.js'];
const BANNER = `
  ┌──────────────────────────────────────────┐
  │  BlackRose — personal AI operating layer │
  └──────────────────────────────────────────┘
  /help for commands · /exit to quit
`;
const HELP = `Commands:
  /help            show this help
  /exit            quit
  /tools           list available tools
  /memory          list memory keys
  /knowledge       list learned sources
  /project         show this workspace's project memory
  /goal <text>     run the task engine: plan → execute → verify → remember
  /jobs            list background jobs
  /schedules       list scheduled tasks
  /say <text>      speak text aloud (offline TTS)
  /export <pass>   export AI state to an encrypted .aistate file
  /delta <pass>    export only what changed since the last export (v2)
  /import <f> <p>  restore an encrypted .aistate file
  /skills          list saved skills
  /bridge <u> <t>  connect to another BlackRose bridge (url + token)
  /sync push|pull  sync .aistate delta with the connected bridge
  /model <id>      switch model
  /new             start a fresh conversation
  /compact         fold older messages into a summary (frees context)
  One-shot mode:   node src/index.ts "task"  |  node src/index.ts --goal "goal"
  Resume:          node src/index.ts --resume   (continue the last session)
  Anything else is sent to the AI.`;
function makeClientOrExit(config) {
    try {
        return makeClient(config);
    }
    catch (e) {
        console.error(`${e instanceof Error ? e.message : String(e)}\n` +
            'Options:\n' +
            '  - set ANTHROPIC_API_KEY (cloud, default provider)\n' +
            '  - set BLACKROSE_PROVIDER=openai (OpenAI-protocol gateway — OpenRouter free models by default; needs BLACKROSE_OPENAI_API_KEY)\n' +
            '  - set BLACKROSE_PROVIDER=router + BLACKROSE_ROUTES="openai,gemini" (fallback chain)');
        process.exit(1);
    }
}
function listMemoryKeys(dataDir) {
    const dir = path.join(dataDir, 'memory');
    return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.md')) : [];
}
async function main() {
    const config = loadConfig();
    // Give the embedder its key pool before anything can call it. Without this the
    // pool stays empty and the embedder falls back to env-only, which is exactly
    // the pre-pool behaviour — so this is additive, never a new requirement.
    // Done here, at the one place dataDir is known for the CLI, the web UI and the
    // desktop shell alike.
    try {
        const { configureEmbedKeys } = await import("./memory/embedder.js");
        configureEmbedKeys(config.dataDir);
    }
    catch {
        /* diagnostics-only path; never block startup on it */
    }
    // SEAs consume the first user arg as argv[1]; shift so both modes are uniform
    let isSea = false;
    try {
        isSea = (await import('node:sea')).isSea();
    }
    catch {
        /* not a SEA build */
    }
    // Bridge dispatch (Phase 6): server mode and remote client mode never enter the REPL
    let cliArgs = process.argv.slice(isSea ? 1 : 2);
    if (cliArgs.includes('--bridge')) {
        await runBridge(config, cliArgs);
        return;
    }
    if (cliArgs.includes('--remote')) {
        await runRemote(cliArgs, config.dataDir);
        return;
    }
    // Web UI (Phase 7): professional browser interface with dialogs for approvals
    if (cliArgs.includes('--ui')) {
        await runWebUi(config, cliArgs);
        return;
    }
    // Diagnostics (Phase 6.2): works without any API key — that is its main use
    if (cliArgs.includes('--doctor')) {
        for (const line of await runDoctor(config))
            console.log(line);
        return;
    }
    // --resume is a mode flag, not a prompt: drop it before one-shot detection
    // turns it into a user message ("--resume" sent to the model).
    const resumed = cliArgs.includes('--resume');
    cliArgs = cliArgs.filter((a) => a !== '--resume');
    let tools = buildTools();
    // MCP servers (Phase 5): external tool providers from ~/.blackrose/mcp.json
    const mcp = await registerMcpTools(config.dataDir, config.cwd);
    if (mcp.length > 0)
        tools = [...tools, ...mcp];
    // Resilience (Phase 6.3): retry transient LLM failures with backoff;
    // auth/quota errors (401/400) still fail fast and visibly.
    const client = resilientClient(makeClientOrExit(config), {
        onRetry: (attempt, delayMs, err) => console.log(color.yellow(`  ↻ transient LLM error (${err instanceof Error ? err.message.slice(0, 90) : String(err)}) — retry ${attempt} in ${delayMs}ms`)),
    });
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q) => new Promise((res) => rl.question(q, res));
    // Fail closed when stdin is not a terminal (headless/piped runs): an
    // approval prompt could never be answered and the run would hang forever
    // (seen live 2026-09-15: a --goal run waited indefinitely on run_command
    // approval while stdin was nul). Interactive runs are unaffected.
    const interactive = process.stdin.isTTY === true;
    const baseCtx = {
        cwd: config.cwd,
        dataDir: config.dataDir,
        askApproval: async (toolName, reason) => {
            if (config.approve === 'all')
                return true;
            if (!interactive) {
                console.log(color.yellow(`  ⚠ non-interactive run: denied ${toolName} (${reason.slice(0, 120)}) — set BLACKROSE_APPROVE=all to allow unattended actions`));
                return false;
            }
            const answer = await ask(`\n  ⚠ approve ${toolName}?\n    ${reason}\n  [y/N] `);
            return answer.trim().toLowerCase() === 'y';
        },
        log: (line) => console.log(`  ${line}`),
    };
    // Multi-agent host (Phase 5): sub-agents get a fresh history and a ctx
    // WITHOUT runSubTask, so they cannot spawn further agents (depth-1).
    const ctx = {
        ...baseCtx,
        runSubTask: async (task, label) => {
            const subCtx = { ...baseCtx };
            console.log(color.cyan(`  ↳ sub-agent (${label ?? 'task'}) started`));
            const outcome = await runAgent({
                client,
                tools: tools.filter((t) => t.name !== 'spawn_agent' && t.name !== 'skill_run'),
                system,
                history: [{ role: 'user', content: task }],
                ctx: subCtx,
                maxTurns: 12,
                onToolCall: (name, input) => console.log(color.dim(`  ↳ ⚙ ${name} ${JSON.stringify(input).slice(0, 100)}`)),
            });
            console.log(color.cyan(`  ↳ sub-agent finished (${outcome.turns} turns)`));
            return { content: outcome.text || '(sub-agent returned no text)' };
        },
    };
    const memoryKeys = listMemoryKeys(config.dataDir);
    let system = buildSystemPrompt(config.cwd, config.dataDir, memoryKeys, readProjectNotes(config.dataDir, config.cwd), loadSkills(config.dataDir).map((s) => ({ name: s.name, description: s.description })));
    const rebuildSystem = () => {
        system = buildSystemPrompt(config.cwd, config.dataDir, listMemoryKeys(config.dataDir), readProjectNotes(config.dataDir, config.cwd), loadSkills(config.dataDir).map((s) => ({ name: s.name, description: s.description })));
    };
    let history = [];
    let sessionId = sessionFileId();
    // Session continuity (Phase 6.3): --resume picks up the most recent session
    if (resumed) {
        const prev = loadLatestSession(config.dataDir);
        if (prev) {
            history = prev.messages;
            sessionId = prev.id;
            console.log(color.cyan(`  resumed session ${prev.id} (${prev.messages.length} message(s))`));
        }
        else {
            console.log(color.yellow('  no previous session found — starting fresh'));
        }
    }
    const logExperience = (task, turns, outcome) => {
        const month = new Date().toISOString().slice(0, 7);
        const dir = path.join(config.dataDir, 'experiences');
        fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(path.join(dir, `${month}.md`), `- ${new Date().toISOString()} | turns:${turns} | task: ${task.replace(/\n/g, ' ').slice(0, 120)} | outcome: ${outcome.replace(/\n/g, ' ').slice(0, 220)}\n`, 'utf8');
    };
    const execute = async (userInput) => {
        history.push({ role: 'user', content: userInput });
        const spinner = new Spinner();
        spinner.start('working…');
        const outcome = await runAgent({
            client,
            tools,
            system,
            history,
            ctx,
            maxTurns: config.maxTurns,
            onToolCall: (name, input) => spinner.update(`⚙ ${name} ${JSON.stringify(input).slice(0, 70)}`),
            onText: (t) => {
                spinner.stop();
                console.log(`\n${t}\n`);
            },
        });
        spinner.stop();
        history = outcome.messages;
        const p = saveSession(config.dataDir, sessionId, history);
        logExperience(userInput, outcome.turns, outcome.text);
        if (outcome.turns >= config.maxTurns)
            console.log(color.yellow('  (stopped: turn budget exhausted)'));
        void p;
    };
    const runGoalCommand = async (goal) => {
        const spinner = new Spinner();
        try {
            const r = await runGoal({
                client,
                tools,
                system,
                ctx,
                goal,
                onEvent: (msg) => {
                    if (msg.startsWith('  ⚙')) {
                        spinner.stop();
                        console.log(color.dim(msg));
                        spinner.update('working…');
                    }
                    else {
                        spinner.update(msg.slice(0, 70));
                    }
                },
            });
            spinner.stop();
            console.log(`\n${r.report}\n`);
            const status = r.verified ? color.green('VERIFIED ✓') : color.red('NOT VERIFIED ✗');
            console.log(`  goal status: ${status} · plan: ${r.plan.length} step(s) · turns: ${r.turns}`);
            const key = goal.slice(0, 40).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
            await memorySaveTool.run({
                key: `goal/${key || 'goal'}`,
                content: `Goal: ${goal}\nVerified: ${r.verified}\nPlan: ${r.plan.join(' | ')}\nOutcome: ${r.report.slice(0, 800)}`,
            }, ctx);
            logExperience(`[GOAL] ${goal}`, r.turns, r.report);
            console.log(color.dim('  (lesson saved to memory)'));
        }
        catch (e) {
            spinner.stop();
            throw e;
        }
    };
    // Scheduler: fires due scheduled tasks while BlackRose runs (fail-closed)
    const scheduler = startScheduler({
        dataDir: config.dataDir,
        cwd: config.cwd,
        client,
        tools,
        system: () => system,
        onEvent: (msg) => console.log(color.cyan(`  ${msg}`)),
    });
    // Bridge connection (Phase 6): talk to another running BlackRose instance
    let bridgeUrl = null;
    let bridgeToken = null;
    const syncPassword = () => process.env.BLACKROSE_STATE_PASSWORD ?? '';
    // One-shot mode: node src/index.ts "do the thing" | node src/index.ts --goal "goal"
    const argv = cliArgs.slice(isSea ? 1 : 0);
    const goalFlag = argv[0] === '--goal';
    const oneShot = (goalFlag ? argv.slice(1) : argv).join(' ').trim();
    if (oneShot) {
        if (goalFlag)
            await runGoalCommand(oneShot);
        else
            await execute(oneShot);
        scheduler.stop();
        rl.close();
        return;
    }
    console.log(BANNER);
    console.log(`  model: ${client.model} · provider: ${client.name} · cwd: ${config.cwd}`);
    console.log(`  memory: ${memoryKeys.length} file(s) · approval: ${config.approve === 'all' ? 'AUTO (yolo)' : 'ask'}\n`);
    rl.setPrompt('you> ');
    rl.prompt();
    for await (const line of rl) {
        const t = line.trim();
        if (!t) {
            rl.prompt();
            continue;
        }
        if (t === '/exit' || t === '/quit')
            break;
        if (t === '/help')
            console.log(HELP);
        else if (t === '/tools')
            console.log(tools.map((x) => `  ${x.name}`).join('\n'));
        else if (t === '/memory')
            console.log((await memoryListTool.run({}, ctx)).content);
        else if (t === '/knowledge') {
            const k = tools.find((x) => x.name === 'knowledge_list');
            if (k)
                console.log((await k.run({}, ctx)).content);
        }
        else if (t === '/project') {
            const pr = tools.find((x) => x.name === 'project_read');
            if (pr)
                console.log((await pr.run({}, ctx)).content);
        }
        else if (t.startsWith('/goal ')) {
            const goal = t.slice(6).trim();
            if (goal)
                await runGoalCommand(goal);
            else
                console.log('  usage: /goal <what to achieve>');
        }
        else if (t === '/jobs') {
            const j = tools.find((x) => x.name === 'job_list');
            if (j)
                console.log((await j.run({}, ctx)).content);
        }
        else if (t === '/schedules') {
            const s = tools.find((x) => x.name === 'schedule_list');
            if (s)
                console.log((await s.run({}, ctx)).content);
        }
        else if (t === '/skills') {
            const s = tools.find((x) => x.name === 'skill_list');
            if (s)
                console.log((await s.run({}, ctx)).content);
        }
        else if (t.startsWith('/say ')) {
            const text = t.slice(5).trim();
            const s = tools.find((x) => x.name === 'say');
            if (!text)
                console.log('  usage: /say <text>');
            else if (s)
                console.log((await s.run({ text }, ctx)).content);
        }
        else if (t.startsWith('/export')) {
            const pass = t.slice(7).trim();
            if (!pass)
                console.log('  usage: /export <password>');
            else {
                try {
                    const r = exportState(config.dataDir, pass);
                    console.log(`  ✓ exported ${r.files} file(s) (${(r.bytes / 1024).toFixed(1)} KB) → ${r.path}`);
                }
                catch (e) {
                    console.error(`  export failed: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        }
        else if (t.startsWith('/delta ')) {
            const pass = t.slice(7).trim();
            if (!pass)
                console.log('  usage: /delta <password>');
            else {
                try {
                    const r = exportStateIncremental(config.dataDir, pass);
                    console.log(`  ✓ delta: ${r.files} changed file(s), ${r.skipped} unchanged (${(r.bytes / 1024).toFixed(1)} KB) → ${r.path}`);
                }
                catch (e) {
                    console.error(`  delta export failed: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        }
        else if (t.startsWith('/import ')) {
            const [file, pass] = t.slice(8).trim().split(/\s+/);
            if (!file || !pass)
                console.log('  usage: /import <file.aistate> <password>');
            else {
                try {
                    const r = importState(config.dataDir, file, pass);
                    rebuildSystem();
                    console.log(`  ✓ restored ${r.restored} file(s); memory/knowledge reloaded`);
                }
                catch (e) {
                    console.error(`  import failed: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        }
        else if (t.startsWith('/model ')) {
            config.model = t.slice(7).trim();
            console.log(`  model set to ${config.model} (takes effect next message via provider recreate)`);
        }
        else if (t.startsWith('/bridge ')) {
            const [u, tok] = t.slice(8).trim().split(/\s+/);
            if (!u || !tok)
                console.log('  usage: /bridge <url> <token>');
            else {
                bridgeUrl = u;
                bridgeToken = tok;
                try {
                    const h = await bridgeHealth(u);
                    console.log(`  ✓ bridge connected: ${h.name} v${h.version} · ${h.provider}/${h.model}`);
                }
                catch (e) {
                    console.error(`  saved, but health check failed: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        }
        else if (t.startsWith('/sync ')) {
            if (!bridgeUrl || !bridgeToken)
                console.log('  no bridge connected (use /bridge <url> <token> first)');
            else {
                const sub = t.slice(6).trim();
                try {
                    if (sub === 'push') {
                        const r = await bridgeSyncPush(bridgeUrl, bridgeToken, config.dataDir, syncPassword());
                        console.log(`  ✓ pushed ${r.files} changed file(s) → remote imported ${r.restored}`);
                    }
                    else if (sub === 'pull') {
                        const r = await bridgeSyncPull(bridgeUrl, bridgeToken, config.dataDir, syncPassword());
                        console.log(`  ✓ pulled and merged ${r.restored} file(s) from remote`);
                    }
                    else {
                        console.log('  usage: /sync push | /sync pull (set BLACKROSE_STATE_PASSWORD for the state encryption)');
                    }
                }
                catch (e) {
                    console.error(`  sync failed: ${e instanceof Error ? e.message : String(e)}`);
                }
            }
        }
        else if (t === '/new') {
            history = [];
            sessionId = sessionFileId();
            console.log('  fresh conversation started');
        }
        else if (t === '/compact') {
            const r = compactHistory(history, 8);
            history = r.messages;
            saveSession(config.dataDir, sessionId, history);
            console.log(r.removed > 0
                ? `  ✓ compacted: ${r.removed} older message(s) folded into a summary (${history.length} remain)`
                : '  nothing to compact (conversation is short)');
        }
        else {
            try {
                await execute(t);
            }
            catch (e) {
                console.error(`  error: ${e instanceof Error ? e.message : String(e)}`);
            }
        }
        rl.prompt();
    }
    scheduler.stop();
    rl.close();
}
main().catch((e) => {
    console.error(e);
    process.exit(1);
});
return {  };
}

__mod['index.js'] = M72();
