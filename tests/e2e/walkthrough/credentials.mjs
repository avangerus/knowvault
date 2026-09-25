// Card U-2: read a stand login from a credentials file that lives outside the
// repository.
//
// The file is read at run time and kept in memory for the length of one run.
// Only the file path travels through the environment; the password never does.
// redactSecrets is the second line of defence: every string the walkthrough
// records (report fields, console errors, page excerpts, answer texts) passes
// through it, so a secret that slipped into a screen or an error message still
// cannot reach the report.

import { readFile } from "node:fs/promises";

const USERNAME_KEYS = ["username", "user", "login"];
const PASSWORD_KEYS = ["password", "pass", "secret"];
const REDACTED = "[REDACTED]";

function firstString(object, keys) {
  for (const key of keys) {
    const value = object[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return "";
}

// parseCredentials accepts the shapes an operator realistically keeps next to a
// stand:
//   - one bare value: the password (a file that holds nothing else);
//   - `key = value` lines with username/password (unknown keys are ignored);
//   - a JSON object with username/password.
// The username may be absent; the caller then takes it from the environment.
export function parseCredentials(text) {
  const body = String(text ?? "").replace(/^\uFEFF/, "");
  const trimmed = body.trim();
  if (trimmed === "") {
    throw new Error("credentials file is empty");
  }
  if (trimmed.startsWith("{")) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`credentials file is not valid JSON: ${error.message}`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("credentials file JSON must be an object");
    }
    const password = firstString(parsed, PASSWORD_KEYS);
    if (password === "") {
      throw new Error("credentials file has no password");
    }
    return { username: firstString(parsed, USERNAME_KEYS), password };
  }

  let username = "";
  let password = "";
  const bare = [];
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator === -1) {
      bare.push(line);
      continue;
    }
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (USERNAME_KEYS.includes(key)) username = value;
    else if (PASSWORD_KEYS.includes(key)) password = value;
  }
  if (password === "" && bare.length === 1) password = bare[0];
  if (password === "" && bare.length > 1) {
    throw new Error("credentials file has several bare values and no password key");
  }
  if (password === "") {
    throw new Error("credentials file has no password");
  }
  return { username, password };
}

// readCredentials reads and parses the file. The path is included in the error
// message so a misconfiguration is actionable; the contents never are.
export async function readCredentials(filePath, options = {}) {
  const readFileImpl = options.readFile ?? readFile;
  if (typeof filePath !== "string" || filePath.trim() === "") {
    throw new Error("credentials file path is empty");
  }
  let body;
  try {
    body = await readFileImpl(filePath, "utf8");
  } catch (error) {
    const reason = error !== null && typeof error === "object" && "code" in error ? error.code : error.message;
    throw new Error(`cannot read credentials file ${filePath}: ${reason}`);
  }
  return parseCredentials(body);
}

// redactSecrets replaces every occurrence of a secret, and of its URL-encoded
// forms, with a fixed marker. Secrets shorter than four characters are skipped
// because replacing them would mangle unrelated text; a stand password is
// never that short.
export function redactSecrets(text, secrets) {
  let result = String(text ?? "");
  for (const secret of secrets) {
    if (typeof secret !== "string" || secret.length < 4) continue;
    const variants = [secret, encodeURIComponent(secret), encodeURI(secret)];
    for (const variant of new Set(variants)) {
      if (variant === "") continue;
      result = result.split(variant).join(REDACTED);
    }
  }
  return result;
}
