# Running Inquisitor 24/7

A laptop is not a deployment. Task Scheduler starts the agent at logon, so a
closed lid is a stopped gate — and an unreliable home connection means dropped
API calls even while it is open.

This puts the agent on a small server. Roughly €4–7/month.

## What goes where, and why

| | Runs on | Tier | Keys |
|---|---|---|---|
| The agent — scans, reads verdicts, answers Telegram | **VPS** | T0 | none |
| The publisher — writes verdicts to Solana | **your machine** | T1 | issuer keypair |

This split is deliberate. The agent never needs a key, so it does not get one,
and the issuer keypair never travels to a rented box. Publishing stays an
operator action taken from a machine you control.

It also means **the server needs no inbound ports**. Telegram is polled, Solana
is polled, and nothing dials in. Deny all inbound except SSH.

## 1. The server

Hetzner Cloud, Ubuntu 24.04:

| Type | vCPU | RAM | Price | Notes |
|---|---|---|---|---|
| CX22 | 2 | 4 GB | ~€3.79/mo | Builds, but needs swap and takes ~an hour |
| **CX32** | 4 | 8 GB | ~€6.80/mo | **Recommended** — builds comfortably |

Add your SSH public key during creation. Do not enable a password login.

The build is the only demanding part; steady-state usage is negligible.

## 2. Harden before anything else

```bash
ssh root@<ip>

adduser --disabled-password --gecos "" inquisitor
usermod -aG sudo inquisitor
rsync --archive --chown=inquisitor:inquisitor ~/.ssh /home/inquisitor

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw enable

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

apt update && apt upgrade -y
apt install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades
```

Reconnect as `inquisitor` and confirm root login is refused before continuing.

## 3. Toolchain

```bash
sudo apt install -y build-essential pkg-config libssl-dev git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install 1.97.1
rustup target add wasm32-wasip2 --toolchain 1.97.1
```

ZeroClaw needs **rustc ≥ 1.96.1**; the stock apt Rust is older.

On a 4 GB box, add swap first or the linker will be killed mid-build:

```bash
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## 4. Build

```bash
git clone --depth 1 https://github.com/zeroclaw-labs/zeroclaw.git ~/zeroclaw
cd ~/zeroclaw
cargo +1.97.1 build --release --features plugins-wasm-cranelift
sudo install -m 0755 target/release/zeroclaw /usr/local/bin/zeroclaw
```

Expect 30–70 minutes depending on the box. Run it under `tmux` so an SSH drop
does not kill it.

```bash
git clone https://github.com/Techkeyy/inquisitor.git ~/inquisitor
cd ~/inquisitor
cargo +1.97.1 build --release --target wasm32-wasip2
mkdir -p dist/inquisitor
cp manifest.toml dist/inquisitor/
cp target/wasm32-wasip2/release/inquisitor.wasm dist/inquisitor/
```

## 5. Configure

Run quickstart and answer the prompts. **Do not copy `config.toml` from your
laptop** — secrets are encrypted against a local key, and moving the ciphertext
without the key gives you an agent that cannot decrypt its own credentials.

```bash
zeroclaw quickstart
```

Then wire everything up:

```bash
zeroclaw config set plugins.enabled true
zeroclaw plugin install ~/inquisitor/dist/inquisitor/

zeroclaw skills bundle add security
zeroclaw skills install ~/inquisitor/skills/inquisitor --bundle security
zeroclaw config set agents.<alias>.skill_bundles '["security"]'

# Read the public registry. No key required — this is the T0 path.
zeroclaw config set plugins.entries.inquisitor.config.rpc_url https://api.mainnet-beta.solana.com
zeroclaw config set plugins.entries.inquisitor.config.credential FqToqovT1TStTb6Fi4Jn1JV5V4cCr1nJ22z2vdBAW8J9

# Scanning is a pure read-only transform; auto-approving it does not weaken
# the profile.
zeroclaw config set risk_profiles.<profile>.auto_approve '["inquisitor_check"]'
```

Telegram, if you want the channel:

```bash
zeroclaw config set channels.telegram.home.bot_token   # masked prompt
zeroclaw config set channels.telegram.home.enabled true
zeroclaw config set agents.<alias>.channels '["telegram.home"]'
zeroclaw channel bind-telegram <your-telegram-id> --alias home
```

**One bot token, one running agent.** Two pollers on the same token fight over
updates and messages vanish, so stop the local daemon before starting the
server one — or register a second bot for the VPS.

## 6. Run it as a service

ZeroClaw installs a systemd user unit:

```bash
zeroclaw service install
zeroclaw service start
zeroclaw service status
```

Survive reboots without a login session:

```bash
sudo loginctl enable-linger inquisitor
```

Restart after **any** config change — the daemon reads config once at startup:

```bash
zeroclaw service restart
```

Logs:

```bash
zeroclaw service logs
journalctl --user -u zeroclaw -f
```

## 7. Verify

```bash
zeroclaw plugin list          # inquisitor present
zeroclaw skills list          # inquisitor in the security bundle
zeroclaw channel doctor       # healthy
zeroclaw service status       # running
```

Then message the bot a poisoned skill. A correct response quotes the verdict
and names the concealment instruction.

## 8. Keep the daily audit

```bash
zeroclaw cron add --agent <alias> --prompt --allowed-tool inquisitor_check \
  "0 9 * * *" \
  "Vet every skill installed on this machine. For each SKILL.md under the skills
   directories, read it and call inquisitor_check on its contents. Report any
   verdict that is not CLEAN, quoting it verbatim. If everything is clean, reply
   with just the count checked."
```

## Publishing, still from your machine

Nothing about the VPS changes this, and that is the point:

```powershell
cd C:\Users\HomePC\Desktop\inquisitor
$env:INQUISITOR_KEYPAIR=".issuer.json"
$env:INQUISITOR_RPC="https://api.mainnet-beta.solana.com"
cargo run --release --manifest-path publisher/Cargo.toml -- publish path\to\SKILL.md
```

Always through `cargo run`. A stale binary attests with stale rules — that
mistake reached mainnet twice.

## Updating

```bash
cd ~/inquisitor && git pull
cargo +1.97.1 build --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/inquisitor.wasm dist/inquisitor/
zeroclaw plugin install ./dist/inquisitor/
zeroclaw service restart
```

## What this costs, honestly

€4–7/month, plus an evening. In return the gate is up when you are asleep, the
network is a datacentre link rather than a home one, and "have you been running
it?" has an answer that does not depend on your laptop being open.
