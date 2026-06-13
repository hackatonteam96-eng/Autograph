const { execFile } = require("child_process");
const { promisify } = require("util");
const { appendEvent } = require("./eventLog");

const execFileAsync = promisify(execFile);

const LAB_ENABLED = process.env.LAB_AD_ENABLED === "true";
const LAB_HOST = process.env.LAB_AD_HOST || "";
const LAB_USER = process.env.LAB_AD_USER || "";

function adSamAccount(upnOrSam) {
  const s = String(upnOrSam || "").trim();
  if (!s) return "UNKNOWN";
  return s.includes("@") ? s.split("@")[0] : s;
}

function buildPlaybookContext(alert = {}) {
  const userSam = adSamAccount(alert.user);
  const targetSam = adSamAccount(alert.target);
  const server = LAB_HOST || alert.host || "DC01";
  return {
    user: userSam,
    userUpn: alert.user || `${userSam}@lab.local`,
    target: targetSam,
    targetSpn: alert.target || targetSam,
    host: alert.host || server,
    server,
    attack: alert.attack || "Kerberoasting",
    risk: alert.risk ?? 0,
    eventId: alert.event_id ?? 4769,
  };
}

function psServerFlag(ctx) {
  return ctx.server ? ` -Server '${ctx.server}'` : "";
}

/** Map natural-language actions to concrete playbook steps */
const PLAYBOOK_PATTERNS = [
  {
    test: /pre-auth|preauth|as-rep|asrep|do not require/i,
    id: "disable_preauth",
    command: (ctx) =>
      `# 1) Audit — Kerberos pre-auth setting\nGet-ADUser -Identity '${ctx.target}' -Properties DoesNotRequirePreAuth,ServicePrincipalName,PasswordLastSet${psServerFlag(ctx)} | Format-List Name,SamAccountName,DoesNotRequirePreAuth,ServicePrincipalName,PasswordLastSet\n\n# 2) Contain — require Kerberos pre-authentication\nSet-ADAccountControl -Identity '${ctx.target}' -DoesNotRequirePreAuth $false${psServerFlag(ctx)}\n\n# 3) Verify\nGet-ADUser -Identity '${ctx.target}' -Properties DoesNotRequirePreAuth${psServerFlag(ctx)} | Select-Object Name,SamAccountName,DoesNotRequirePreAuth`,
    description: "Audit, disable Do not require Kerberos preauthentication, and verify",
  },
  {
    test: /disable.*user|source user|Disable-ADAccount/i,
    id: "disable_source_user",
    command: (ctx) =>
      `Disable-ADAccount -Identity '${ctx.user}'${psServerFlag(ctx)}`,
    description: "Disable compromised source user in Active Directory",
  },
  {
    test: /password|rotate|reset.*service|credential/i,
    id: "rotate_service_password",
    command: (ctx) =>
      `$newPwd = ConvertTo-SecureString -AsPlainText (([guid]::NewGuid().ToString('N') + 'Aa1!').Substring(0,16)) -Force\nSet-ADAccountPassword -Identity '${ctx.target}' -Reset -NewPassword $newPwd${psServerFlag(ctx)}\nSet-ADUser -Identity '${ctx.target}' -ChangePasswordAtLogon $true${psServerFlag(ctx)}`,
    description: "Force password rotation on targeted service account",
  },
  {
    test: /rc4|encryption|kerberos hardening/i,
    id: "rc4_hardening",
    command: (ctx) =>
      `Set-ADDomain -Identity '${ctx.host.split(".")[0] || "lab"}' -Replace @{'msDS-SupportedEncryptionTypes'='24'}${psServerFlag(ctx)}`,
    description: "Disable RC4 Kerberos encryption domain-wide (AES128+256 only)",
  },
  {
    test: /spn|service principal/i,
    id: "review_spn",
    command: (ctx) =>
      `Get-ADUser -Identity '${ctx.target}' -Properties ServicePrincipalName${psServerFlag(ctx)} | Select-Object Name,SamAccountName,ServicePrincipalName\n# Remove exposed SPN after review:\n# Set-ADUser -Identity '${ctx.target}' -ServicePrincipalNames @{}${psServerFlag(ctx)}`,
    description: "Review and remove exposed SPN from service account",
  },
  {
    test: /session|revoke|sign.?out|investigate.*session/i,
    id: "revoke_sessions",
    command: (ctx) =>
      `Get-ADUser -Identity '${ctx.user}' -Properties LastLogonDate,LockedOut${psServerFlag(ctx)} | Format-List\n# Force logoff via SOAR / Reset-ComputerMachinePassword if needed`,
    description: "Investigate and revoke active sessions for source user",
  },
  {
    test: /ticket|soc|incident|ITDR/i,
    id: "soc_ticket",
    command: (ctx) =>
      `# SOAR ticket — ${ctx.attack}: ${ctx.userUpn} → ${ctx.targetSpn} (risk ${ctx.risk}/100, event ${ctx.eventId})`,
    description: "Create SOC incident ticket with ITDR context",
  },
  {
    test: /contain|isolate|block/i,
    id: "generic_contain",
    command: (ctx) =>
      `Disable-ADAccount -Identity '${ctx.user}'${psServerFlag(ctx)}\nSet-ADAccountPassword -Identity '${ctx.target}' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid.Substring(0,16) -Force)${psServerFlag(ctx)}`,
    description: "Generic containment — disable source + rotate target credential",
  },
];

function matchPlaybook(action, context) {
  const ctx = context?.user ? context : buildPlaybookContext(context);
  const actionText = typeof action === "string" ? action : action?.action || String(action ?? "");
  for (const pattern of PLAYBOOK_PATTERNS) {
    if (!pattern.test || !pattern.test.test(actionText)) continue;
    return {
      id: pattern.id,
      action: actionText,
      description: pattern.description,
      command: pattern.command(ctx),
    };
  }
  return {
    id: "custom_action",
    action: actionText,
    description: "Custom approved response action",
    command: `# ${action}`,
  };
}

function previewPlaybookActions(actions, alert) {
  const ctx = buildPlaybookContext(alert);
  return (actions || []).map((action) => matchPlaybook(action, ctx));
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
  const ctx = buildPlaybookContext(context);
  const results = [];

  for (const action of actions) {
    const step = matchPlaybook(action, ctx);
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
        message: "Copy-run — paste in lab AD PowerShell (not executed automatically)",
      };
      results.push(result);
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

module.exports = {
  executePlaybook,
  matchPlaybook,
  previewPlaybookActions,
  buildPlaybookContext,
  LAB_ENABLED,
};
