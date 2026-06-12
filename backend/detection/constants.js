/**
 * AuthGraph ITDR — Detection constants
 * Kerberoasting scoring weights and Windows Event 4769 field mappings.
 */

const MITRE = {
  KERBEROASTING: "T1558.003",
  ACCOUNT_DISCOVERY: "T1087",
  GROUP_DISCOVERY: "T1069",
  VALID_ACCOUNTS: "T1078",
};

/** Risk scoring weights — sum capped at 100 */
const RISK_WEIGHTS = {
  KERBEROASTING: 35,
  RC4_ENCRYPTION: 20,
  MULTIPLE_TGS: 15,
  SERVICE_ACCOUNT_SPN: 15,
  PRIVILEGED_PATH_FULL: 20,
  PRIVILEGED_ASSET_LINK: 2,
};

const SEVERITY_THRESHOLDS = {
  critical: 80,
  high: 60,
  medium: 35,
  low: 0,
};

/** Windows Event 4769 TicketEncryptionType values indicating RC4 (crackable) */
const RC4_ENCRYPTION_TYPES = new Set([
  "0x17",
  "0x1",
  "0x23",
  "0x3",
  23,
  1,
  3,
  "23",
  "1",
  "3",
  "RC4-HMAC",
  "rc4-hmac",
]);

const KERBEROS_EVENT_ID = 4769;

const MULTIPLE_TGS_THRESHOLD = 3;

const SERVICE_ACCOUNT_TYPES = new Set([
  "service_account",
  "service",
  "svc",
  "spn",
]);

const PRIVILEGED_GROUP_PATTERNS = [
  /admin/i,
  /domain admins/i,
  /enterprise admins/i,
  /sql admins/i,
  /backup operators/i,
  /account operators/i,
];

const EVIDENCE_MESSAGES = {
  kerberoasting: "Kerberoasting pattern detected (TGS request for SPN-backed account)",
  rc4: "RC4 encrypted service ticket requested",
  multiple_tgs: "Multiple Kerberos TGS requests from one user",
  spn: "Target account has SPN configured",
  privileged_link: "Service account is linked to privileged SQL server",
  privileged_path: "Service account has path to domain sensitive assets",
};

module.exports = {
  MITRE,
  RISK_WEIGHTS,
  SEVERITY_THRESHOLDS,
  RC4_ENCRYPTION_TYPES,
  KERBEROS_EVENT_ID,
  MULTIPLE_TGS_THRESHOLD,
  SERVICE_ACCOUNT_TYPES,
  PRIVILEGED_GROUP_PATTERNS,
  EVIDENCE_MESSAGES,
};
