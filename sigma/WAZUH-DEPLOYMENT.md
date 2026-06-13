# Using AuthGraph Sigma Rules with Wazuh

Your detection logic lives in **`sigma/*.yml`** only. Wazuh does **not** run Sigma YAML natively today — dropping `.yml` files into `/var/ossec/ruleset/rules/` will not work.

## What you maintain

```
sigma/
├── kerberoasting.yml          ← you edit these
├── password-spraying.yml
├── brute-force.yml
├── asreproasting.yml
├── golden-ticket.yml
└── */                         ← rule suites
```

**Single source of truth:** Sigma YAML in this repo. No separate Wazuh rule set to maintain.

## What Wazuh needs (under the hood)

Wazuh’s analysis engine only understands **its own XML rule format**. To use your Sigma rules, something must **convert YAML → Wazuh XML on the manager** at deploy time. That conversion is automatic; you still only edit Sigma in Git.

## Automatic conversion (recommended)

Use the included Python script — **only maintain Sigma YAML in Git**:

```bash
cd sigma/scripts
pip install -r requirements.txt
python convert_sigma_to_wazuh.py
sudo cp ../wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

See [`scripts/README.md`](./scripts/README.md) for full details.

## Manual workflow (alternative)

### 1. Prerequisites (unchanged)

- Wazuh agents on **Domain Controllers**
- Security log via `eventchannel`
- Audit policies enabled (4625, 4768, 4769, 4771, 4662, 4740) — see each suite README

### 2. Convert Sigma → Wazuh on the manager (one-time setup)

On the **Wazuh manager**, clone your repo and use a converter:

```bash
# Option A: sigma_to_wazuh (community)
git clone https://github.com/theflakes/sigma_to_wazuh
git clone https://github.com/hackatonteam96-eng/Autograph

cd sigma_to_wazuh
# Edit config.ini → point "directory" at Autograph/sigma/
python3 sigma_to_wazuh.py

# Output lands in configured output dir → copy to Wazuh
sudo cp output/*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

```bash
# Option B: SigmaForge CLI (Wazuh backend built-in)
pip install sigmaforge   # if available in your environment
sigmaforge convert /path/to/Autograph/sigma/kerberoasting.yml --backend wazuh --rule-id 100100
```

**Limitation:** Converters handle **simple** rules well. **Correlation** rules (`timeframe`, `count_distinct()`, `count() by`) often fail or need manual Wazuh `frequency` rules — track those in suite READMEs.

### 3. Re-deploy when Sigma changes

After you update YAML in Git:

```bash
git pull
python3 sigma_to_wazuh.py    # re-convert
sudo systemctl restart wazuh-manager
```

Your repo stays Sigma-only; XML exists only on the server as generated output.

## Rules that need manual correlation on Wazuh

These Sigma rules use aggregation — converters usually **cannot** auto-convert them:

| Sigma rule | Logic |
|------------|--------|
| `password-spraying.yml` | 5+ distinct users, same IP |
| `brute-force/01–05` | N failures, same user (+ IP) |
| `kerberoasting/02, 03, 04, 11, 13` | distinct SPN / burst |
| `asreproasting/02` | 3+ no-preauth accounts, same IP |
| `golden-ticket/02` | 10+ distinct SPNs, same user |

For these, either:

- Implement Wazuh `frequency` + `same_field` / `different_field` on the manager (one-time, from Sigma logic in README), or  
- Run detection in **AuthGraph backend** (`backend/detection/`) which can consume Wazuh events + apply Sigma logic in Node.js

## Alternative: detect outside Wazuh rules engine

If you want **zero XML on the manager**:

1. Wazuh collects and stores events (indexer)
2. Run **Sigma** against indexed logs with [Chainsaw](https://github.com/WithSecure/chainsaw) or pySigma CLI on a schedule
3. Send matches back as alerts (integrator / custom script)

This keeps Sigma as the only rule format but is **not** real-time Wazuh rule alerting.

## AuthGraph backend path (Sigma in code)

Your project already has detection logic aligned with Sigma:

```bash
node backend/detection/cli.js explain
```

Wazuh → export alerts → `data/wazuh-alert-real.json` → `POST /api/reload`  
Sigma semantics can be applied in **`backend/detection/`** without Wazuh XML at all.

## Summary

| Goal | Approach |
|------|----------|
| Only maintain Sigma in Git | ✅ Keep `sigma/*.yml` |
| Wazuh alerts from Sigma | Convert YAML→XML on manager at deploy (converter script) |
| No XML in your repo | ✅ Do not commit XML; generate on server |
| Wazuh reads YAML directly | ❌ Not supported (Wazuh 4.x) |
| Correlation rules | Manual Wazuh frequency or AuthGraph backend |

Native Sigma in Wazuh is tracked as a [future enhancement](https://github.com/wazuh/wazuh/issues/15451) — not available yet.
