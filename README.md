<p align="center">
  <strong><code>🔐 vaultguard</code></strong><br/>
  <em>Your Obsidian vault, guarded for your AI agents.</em><br/><br/>
  <code>npx vaultguard init</code> · zero dependencies · pure Node · cross-platform
</p>

---

## The problem

Your AI agents are powerful. They ship code, run commands, and one day they will ask: *"give me the database URL."*

You hand it over. Now that value lives in every transcript, log, checkpoint, and backup of your conversations. Rotate it a month later — a year later — and the old one is still out there.

**The vault itself** — Obsidian — is encrypted only if you make it so, and your agent reading your notes means your agent reading your secrets.

## What vaultguard does

Secrets live in **your** Obsidian vault as AES-256-GCM ciphertext. Your agents get them **by name** over MCP — they run commands with the values injected into the environment and **never see them**, while every access is **audited**.

```
┌────────────────────────┐        ┌─────────────────────────────┐
│    Obsidian vault       │        │         your agent          │
│                        │        │   (opencode · Claude · …   │
│  Secrets.md            │        │   Cursor)                   │
│  │  ```secret-lock     │        │                             │
│  │    DB_URL           │  ◀─────│  list_secrets  → names only  │
│  │    AgH8qQc5…        │  MCP   │                             │
│  │  ```                │        │  run_with_secret            │
│  │                      │        │    → env: DB_URL=…          │
│  │  encrypted blocks    │        │    → output redacted        │
│  └──────────────────────┘        └─────────────────────────────┘
        ▲                                    ▲
        │  you: vaultguard add DB_URL        │  every call → audit.jsonl
        │       (or just click "Show"        │  + allowlist/approval gates
        │        in Obsidian!)               │
        └────────────────────────────────────┘
```

- **You own the data.** No cloud, no SaaS, no server. The encrypted blocks are plain markdown.
- **Readable in Obsidian.** Encrypted blocks look like notes; reveal them with one click.
- **Tell your agent to run things** using secrets — values never surface in transcripts.
- **Zero npm dependencies.** Pure Node ≥ 18. Windows / macOS / Linux.

---

## Quickstart

### 1 · Install

```bash
npm install -g vaultguard
```

### 2 · Point it at your vault

```bash
vaultguard init --vault "C:\Users\you\Documents\Obsidian Vault"
```

It asks for a **passphrase** — the key that encrypts and decrypts *every* block in this vault.
Then it:

- creates `Secrets.md` in your vault,
- installs the **Inline Secret Block** plugin into the vault automatically,
- writes `~/.vaultguard/config.json` (vault path, passphrase, security settings).

> Restart Obsidian and enable the plugin: **Settings → Community plugins → Inline Secret Block → Enable**.

### 3 · Add your first secret — the Obsidian way

In **Obsidian**, open `Secrets.md` and add a plaintext block:

````markdown
```secret DATABASE-URL
Mydatabaseurl@postgres
```
````

Click **Show** — the plugin instantly replaces it with an encrypted `secret-lock` block. Your raw value is gone; what remains:

````markdown
```secret-lock DATABASE-URL
Nx60U4Ph/+1CO+58Zr00HXhEW9GZ6voHlpS+bEXPpP69avbJaSfafZCC2dpPn6UgdMN+3PJUd+UPm39YAXhFTbHvLUpHDndzbODsL8fOm7IMWC16zjSQCW7CbRWklmUxOGl0lX2qpQ==
```
````

That's it. Same value, later, forever: click **Show** again.

> **No Obsidian? Use the CLI instead:**
> ```bash
> vaultguard add DB_URL     # hidden prompt
> vaultguard set DB_URL     # rotate in place
> ```

### 4 · Connect your agent

```bash
vaultguard mcp
```

prints ready-made config for your harness:

**opencode** — in `opencode.json` (or globally via the app):
```json
{
  "mcp": {
    "vaultguard": {
      "type": "local",
      "command": ["node", "C:/path/to/vaultguard/src/server.mjs"]
    }
  }
}
```

**Claude Code:**
```bash
claude mcp add vaultguard -- node C:/path/to/vaultguard/src/server.mjs
```

**Cursor:** add the same server to your project's `.cursor/mcp.json` (or the *MCP* settings tab).

### 5 · Use it

```text
you : "run a quick sanity check against DB_URL"
agent: run_with_secret(command: "psql $DB_URL -c 'SELECT 1'", secrets: ["DB_URL"])
you :  ✔ exit 0  ·  audit entry written  ·  no secret leaked
```

- `run_with_secret` — secrets injected into the command's environment only.
- Output is scrubbed — any accidental echo of a secret is replaced with `[REDACTED:NAME]`.
- `get_secret` — decrypts a value for tools that insist; use sparingly.

---

## Security model

| Layer | What stops it |
|---|---|
| **At rest** | AES-256-GCM, PBKDF2-SHA-256 (250,000 iterations, 16-byte salt, fresh 12-byte IV per value). Byte-compatible with the [Inline Secret Block](https://github.com/vnrtmnv/obsidian-inline-secret-block) plugin. |
| **Approval gate** | `run_with_secret` is **denied by default** unless an admin sets `requireApproval: false` (or `VAULTGUARD_REQUIRE_APPROVAL=0`). |
| **Host allowlist** | Only named clients (from MCP `clientInfo`) may call tools. Empty list = allow all. |
| **Command allowlist** | Only command prefixes you list may run (e.g. `["psql", "node", "git"]`). Empty = allow all. |
| **Audit log** | Every call — who (host), what, which secrets, outcome — appended to `~/.vaultguard/audit.jsonl`. View with `vaultguard audit`. |
| **Output scrubbing** | Secret values and their first 8 chars are redacted from command output. |

### Configuration

Edit `~/.vaultguard/config.json`:

```jsonc
{
  "vaultPath": "C:/Users/you/Documents/Obsidian Vault",
  "passphrase": "…",                 // fallback only — prefer the env var
  "allowlist": { "hosts": [], "commands": ["psql", "node"] },
  "requireApproval": false,          // true (default) = gate run_with_secret
  "audit": true
}
```

| Env var | Overrides |
|---|---|
| `VAULTGUARD_VAULT_PATH` / `VAULT_PATH` | vault path |
| `VAULTGUARD_PASSPHRASE` / `DOORMAN_PASSPHRASE` | passphrase |
| `VAULTGUARD_HOME` | config dir (default `~/.vaultguard`) |
| `VAULTGUARD_REQUIRE_APPROVAL=0` | auto-approve |
| `VAULTGUARD_AUDIT=0` | disable audit |

> **Passphrase hygiene:** you can keep it out of the config file entirely and export it in your shell / harness environment instead. Protect `~/.vaultguard` like you would an SSH key.

---

## CLI reference

| Command | What it does |
|---|---|
| `vaultguard init` | Configure vault + passphrase, create `Secrets.md`, install plugin |
| `vaultguard add <NAME>` | Encrypt + store a new secret (interactive or `--value`) |
| `vaultguard set <NAME>` | Rotate a secret in place |
| `vaultguard list` | List secret names (no values) |
| `vaultguard audit [--lines n]` | Tail the audit log |
| `vaultguard mcp` | Print harness-specific MCP config |
| `vaultguard info` | Show config + security posture |
| `vaultguard test` | Crypto self-test |

---

## FAQ

**Is my vault git-safe?** The encrypted blocks are plain markdown — safe to commit, sync, or put anywhere Obsidian works. Never commit `~/.vaultguard/config.json`.

**What if I forget the passphrase?** The blocks are AES-256-GCM. It cannot be recovered — that's the point.

**Which Obsidian plugin?** [Inline Secret Block](https://github.com/vnrtmnv/obsidian-inline-secret-block) — `vaultguard init` installs it for you.

**Do I need a server?** No. It's a local stdio MCP server (`node src/server.mjs`). Nothing listens on a port.

---

## License

MIT © vaultguard contributors.

The bundle installs the [Inline Secret Block](https://github.com/vnrtmnv/obsidian-inline-secret-block) plugin (also MIT), downloaded at `init` time from the plugin's official releases — it is **not** vendored into this package. This project uses Node.js built-ins only (`crypto`), so there are no dependency licenses to track.

---

*Guard your vault. Let your agents work.*