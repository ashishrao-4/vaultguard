# Vaultguard

> Your Obsidian vault, guarded for your AI agents.

Agents (opencode, Claude Code, Cursor) get secrets **by name** through [MCP](https://modelcontextprotocol.io) — they never see the values. You keep ownership of your secrets inside the vault you already think in.

```
vaultguard add DB_URL            →  rotate it once a quarter, agents pick it up automatically
   │
   ▼
 ┌────────────────────┐   encrypted in Obsidian    ┌────────────────────┐
 │   Obsidian vault   │  ⇄  AES-256-GCM blocks     │   your agent       │
 │   Secrets.md        │  list/add via vaultguard  │   (opencode /      │
 └────────────────────┘                            │    Claude / Cursor)│
                     ▲                             │                    │
                     └─────────  MCP tools ────────┤  only sees names   │
                              list_secrets         │  and runs commands  │
                              get_secret           │  with values from    │
                              run_with_secret      │  the environment     │
                                                   └────────────────────┘
```

- Works in the Obsidian app itself — reveal a secret with one click.
- Zero npm dependencies. Pure Node. Cross-platform (Windows / macOS / Linux).
- Secrets are encrypted with **AES-256-GCM**, keyed from your passphrase via **PBKDF2-SHA-256 (250k iterations)** — byte-for-byte compatible with the [Inline Secret Block](https://github.com/vnrtmnv/obsidian-inline-secret-block) plugin.

---

## Quickstart (5 minutes)

### 1. Install

```bash
npm install -g vaultguard
```

### 2. Point it at your vault

```bash
vaultguard init --vault "C:\Users\you\Documents\Obsidian Vault"
```

It will:
- ask for a **passphrase** (this encrypts/decrypts *every* secret in the vault),
- create `Secrets.md` in your vault,
- install the **Inline Secret Block** Obsidian plugin automatically (restart Obsidian and enable it under Settings → Community plugins),
- save `~/.vaultguard/config.json` with your vault path and passphrase.

> **Security note:** the passphrase is stored in plaintext at `~/.vaultguard/config.json` by default. For stronger setups, leave it out and export it instead:
> ```bash
> export VAULTGUARD_PASSPHRASE="your passphrase"
> ```

### 3. Add your first secret

```bash
vaultguard add DB_URL
# opens a hidden prompt → paste the value
```

Now open `Secrets.md` in Obsidian — you'll see only an encrypted block with the name `DB_URL`. Click **Show** to reveal it. Edit the value whenever you want; agents always read the latest.

### 4. Connect your agent

Run `vaultguard mcp` and it prints ready-made config for your harness:

**opencode** — add to `opencode.json` / `.opencode/opencode.json`:

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

**Cursor:** add the same entry under `"mcpServers"` in `.cursor/mcp.json`.

### 5. Use it

Ask your agent to "use the `DB_URL` secret". It calls `run_with_secret`, which runs the command with the value injected into the environment:

```
agent: run_with_secret(command: "psql $DB_URL -c 'SELECT 1'", secrets: ["DB_URL"])
you:   ✔ exit 0
```

- Secret **values never appear** in the agent's output (they're redacted).
- `get_secret` exists for tools that insist on a value — use it sparingly.

---

## Commands

| Command | What it does |
|---|---|
| `vaultguard init` | Configure vault path + passphrase, create `Secrets.md`, install plugin |
| `vaultguard add <NAME>` | Encrypt + store a new secret, interactively |
| `vaultguard set <NAME>` | Rotate a secret in place |
| `vaultguard list` | List secret names (no values) |
| `vaultguard mcp` | Print MCP config snippets for your harness |
| `vaultguard info` | Show current config state |
| `vaultguard test` | Run a crypto self-test |

## Environment variables

| Variable | Purpose |
|---|---|
| `VAULTGUARD_VAULT_PATH` / `VAULT_PATH` | Vault folder (overrides config) |
| `VAULTGUARD_PASSPHRASE` / `DOORMAN_PASSPHRASE` | Passphrase (overrides config) |
| `VAULTGUARD_HOME` | Config dir, defaults to `~/.vaultguard` |
| `VAULTGUARD_NO_APPROVAL=1` | Server auto-approves `run_with_secret` (not recommended) |

---

## Security model

- **At rest:** secrets live in your Obsidian vault as AES-256-GCM ciphertext. Nothing is readable without the passphrase (PBKDF2-SHA-256, 250k iterations, random salt + IV per secret).
- **In transit to agents:** secrets are injected into the child process *environment* only; MCP responses are redacted.
- **You own everything:** no cloud, no server, no SaaS. The `Secrets.md` file is *your* file — back it up, sync it, put it anywhere Obsidian works.
- **Known limits (roadmap):** `run_with_secret` currently trusts the requesting agent; there is no per-host allowlist, audit log, or expiration yet. Any process running on your machine with MCP access to the server can execute commands with secret env vars. See below.

## Roadmap / hardening

- [ ] Output scrubbing hardened (admin-provided allowlists)
- [ ] Host allowlist (only approved agent processes may call tools)
- [ ] Audit log (`Audit.md` in the vault / `audit.jsonl`)
- [ ] `npx vaultguard init` one-liner for non-global installs
- [ ] Approval gates for `run_with_secret` by default
- [ ] Secret rotation reminders / expiry hints

---

## How the encryption works

`vaultguard` speaks the exact wire format of the **Inline Secret Block** Obsidian plugin, so encrypted blocks are interchangeable:

```
payload  = base64( salt ‖ iv ‖ ciphertext ‖ authTag )
salt     = 16 bytes, fresh per secret
iv       = 12 bytes (AES-GCM nonce), fresh per secret
key      = PBKDF2-SHA-256(passphrase, salt, 250_000, 32)
```

---

## License

MIT © vaultguard contributors