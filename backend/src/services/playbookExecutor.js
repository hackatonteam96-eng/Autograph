const { execFile } = require("child_process");
const { promisify } = require("util");
const { appendEvent } = require("./eventLog");

const execFileAsync = promisify(execFile);

const LAB_ENABLED = process.env.LAB_AD_ENABLED === "true";
const LAB_HOST = process.env.LAB_AD_HOST || "";
const LAB_USER = process.env.LAB_AD_USER || "";

/** Map natural-language actions to concrete playbook steps */
const PLAYBOOK_PATTERNS = [
  {
    test: /disable.*user|source user disabled|disable.*account/i,
    id: "disable_source_user",
    command: (ctx) =>
      `Disable-ADAccount -Identity '${ctx.user}'`,
    description: "Disable compromised source user in Active Directory",
  },
  {
    test: /password|rotate|reset.*service|credential/i,
    id: "rotate_service_password",
    command: (ctx) =>
      `Set-ADAccountPassword -Identity '${ctx.target}' -Reset -PassThru | Set-ADUser -ChangePasswordAtLogon $true`,
    description: "Force password rotation on targeted service account",
  },
  {
    test: /rc4|encryption|kerberos hardening/i,
    id: "rc4_hardening",
    command: () =>
      "Set-ADDomain -Replace @{'msDS-SupportedEncryptionTypes'='24'} # AES only — lab GPO equivalent",
    description: "Recommend/disable RC4 Kerberos encryption domain-wide",
  },
  {
    test: /spn|service principal/i,
    id: "review_spn",
    command: (ctx) =>
      `Set-ADUser -Identity '${ctx.target}' -ServicePrincipalNames @{} # Review before apply`,
    description: "Review and remove exposed SPN from service account",
  },
  {
    test: /session|revoke|sign.?out|investigate.*session/i,
    id: "revoke_sessions",
    command: (ctx) =>
      `Get-ADUser '${ctx.user}' | Revoke-ADUserAllCertificates; # + force logoff via SOAR`,
    description: "Revoke active sessions for source user",
  },
  {
    test: /ticket|soc|incident|ITDR/i,
    id: "soc_ticket",
    command: (ctx) =>
      `# SOAR: create ticket — Kerberoasting ${ctx.user} → ${ctx.target} risk ${ctx.risk}`,
    description: "Create SOC incident ticket with ITDR context",
  },
  {
    test: /contain|isolate|block/i,
    id: "generic_contain",
    command: (ctx) =>
      `# Containment playbook — ${ctx.attack} on ${ctx.host}`,
    description: "Generic containment step",
  },
];

function matchPlaybook(action, context) {
  for (const pattern of PLAYBOOK_PATTERNS) {
    if (pattern.test.test(action)) {
      return {
        id: pattern.id,
        action,
        description: pattern.description,
        command: pattern.command(context),
      };
    }
  }
  return {
    id: "custom_action",
    action,
    description: "Custom approved response action",
    command: `# ${action}`,
  };
}

async function runPowerShell(command) {
  if (!LAB_HOST || !LAB_USER) {
    throw new Error("LAB_AD_HOST and LAB_AD_USER required for live execution");
  }
  const script = `$ErrorActionPreference='Stop'; ${command}`;
  const { stdout, stderr } = await execFileAsync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { timeout: 30000, windowsHide: true },
  );
  return { stdout: stdout?.trim(), stderr: stderr?.trim() };
}

/**
 * Execute approved containment actions — live when LAB_AD_ENABLED=true, else audited dry-run.
 */
async function executePlaybook(actions, context, incidentId) {
  const results = [];

  for (const action of actions) {
    const step = matchPlaybook(action, context);
    const base = {
      action,
      playbook_id: step.id,
      description: step.description,
      command: step.command,
    };

    if (!LAB_ENABLED) {
      const result = {
        ...base,
        status: "simulated",
        message: "Dry-run — set LAB_AD_ENABLED=true in backend/.env for live AD execution",
      };
      results.push(result);
      appendEvent("action", `Playbook dry-run: ${action}`, {
        incident_id: incidentId,
        playbook_id: step.id,
        command: step.command,
        status: "simulated",
      });
      continue;
    }

    try {
      const out = await runPowerShell(step.command);
      const result = {
        ...base,
        status: "executed",
        message: "Command completed on lab domain controller",
        output: out.stdout || out.stderr || "OK",
      };
      results.push(result);
      appendEvent("action", `Playbook executed: ${action}`, {
        incident_id: incidentId,
        playbook_id: step.id,
        command: step.command,
        status: "executed",
      });
    } catch (err) {
      const result = {
        ...base,
        status: "failed",
        message: err.message,
      };
      results.push(result);
      appendEvent("warn", `Playbook failed: ${action}`, {
        incident_id: incidentId,
        playbook_id: step.id,
        error: err.message,
      });
    }
  }

  return results;
}

module.exports = { executePlaybook, matchPlaybook, LAB_ENABLED };
