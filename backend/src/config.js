const path = require("path");

const PORT = Number(process.env.PORT) || 8000;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.cwd(), process.env.DATA_DIR)
  : path.resolve(__dirname, "../../data");
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

module.exports = { PORT, HOST, DATA_DIR, CORS_ORIGIN };
