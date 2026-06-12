const path = require("path");
const fs = require("fs");

function loadEnvFile() {
  const envPath = path.resolve(__dirname, "../.env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!process.env[key]) process.env[key] = value;
  }
}

loadEnvFile();

const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.cwd(), process.env.DATA_DIR)
  : path.resolve(__dirname, "../../data");
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_CHAT_MODEL = process.env.OPENROUTER_CHAT_MODEL || "deepseek/deepseek-v4-flash";
const OPENROUTER_REASONING_MODEL = process.env.OPENROUTER_REASONING_MODEL || process.env.OPENROUTER_MODEL || "deepseek/deepseek-v4-pro";
const SIGMA_DIR = path.resolve(__dirname, "../../sigma");

module.exports = {
  PORT,
  HOST,
  DATA_DIR,
  CORS_ORIGIN,
  OPENROUTER_API_KEY,
  OPENROUTER_CHAT_MODEL,
  OPENROUTER_REASONING_MODEL,
  SIGMA_DIR,
};
