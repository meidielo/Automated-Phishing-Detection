#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

const TOOL_NAME = "analyze_payment_email";
const PROTOCOL_VERSION = "2025-06-18";
const DEFAULT_TOOL_TIMEOUT_MS = 60000;
const DEFAULT_MAX_TOOL_OUTPUT_BYTES = 2 * 1024 * 1024;

const INPUT_SCHEMA = {
  type: "object",
  properties: {
    email_path: {
      type: "string",
      description: "Local path to a .eml file to inspect."
    },
    include_email_metadata: {
      type: "boolean",
      description: "Include sender, recipient, subject, date, and attachment names.",
      default: true
    }
  },
  required: ["email_path"],
  additionalProperties: false
};

const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    tool: { type: "string" },
    schema_version: { type: "string" },
    decision: { type: "string", enum: ["SAFE", "VERIFY", "DO_NOT_PAY"] },
    risk_score: { type: "number" },
    confidence: { type: "number" },
    summary: { type: "string" },
    agent_next_action: { type: "string" },
    signals: { type: "array" },
    verification_steps: { type: "array", items: { type: "string" } },
    safety: { type: "object" }
  }
};

function writeResponse(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function result(id, payload) {
  return { jsonrpc: "2.0", id, result: payload };
}

function error(id, code, message, data) {
  const payload = { jsonrpc: "2.0", id, error: { code, message } };
  if (data !== undefined) {
    payload.error.data = data;
  }
  return payload;
}

function toolDefinition() {
  return {
    name: TOOL_NAME,
    title: "Payment Email Scam Analyzer",
    description:
      "Analyze a local .eml invoice or payment email and return a SAFE, VERIFY, or DO_NOT_PAY decision with evidence and verification steps.",
    inputSchema: INPUT_SCHEMA,
    outputSchema: OUTPUT_SCHEMA
  };
}

function projectRoot() {
  return process.env.PAYMENT_FIREWALL_PROJECT_ROOT || process.cwd();
}

function pythonExecutable() {
  return process.env.PAYMENT_FIREWALL_PYTHON || "python";
}

function positiveIntegerFromEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function resolveToolScript() {
  return path.join(projectRoot(), "scripts", "agent_payment_tool.py");
}

function runPythonTool(args) {
  return new Promise((resolve) => {
    const script = resolveToolScript();
    if (!fs.existsSync(script)) {
      resolve({
        ok: false,
        message: `agent_payment_tool.py not found at ${script}`
      });
      return;
    }

    const timeoutMs = positiveIntegerFromEnv(
      "PAYMENT_FIREWALL_TOOL_TIMEOUT_MS",
      DEFAULT_TOOL_TIMEOUT_MS
    );
    const maxOutputBytes = positiveIntegerFromEnv(
      "PAYMENT_FIREWALL_MAX_TOOL_OUTPUT_BYTES",
      DEFAULT_MAX_TOOL_OUTPUT_BYTES
    );
    let settled = false;
    let timeout = null;
    const finish = (payload) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timeout) {
        clearTimeout(timeout);
      }
      resolve(payload);
    };

    const child = spawn(
      pythonExecutable(),
      [
        script,
        args.email_path,
        ...(args.include_email_metadata === false ? ["--no-metadata"] : [])
      ],
      {
        cwd: projectRoot(),
        windowsHide: true
      }
    );

    let stdout = "";
    let stderr = "";
    timeout = setTimeout(() => {
      child.kill();
      finish({
        ok: false,
        message: `Python tool timed out after ${timeoutMs}ms`
      });
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      if (Buffer.byteLength(stdout, "utf8") > maxOutputBytes) {
        child.kill();
        finish({
          ok: false,
          message: `Python tool output exceeded ${maxOutputBytes} bytes`
        });
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
      if (Buffer.byteLength(stderr, "utf8") > maxOutputBytes) {
        child.kill();
        finish({
          ok: false,
          message: `Python tool error output exceeded ${maxOutputBytes} bytes`
        });
      }
    });
    child.on("error", (err) => {
      finish({ ok: false, message: err.message });
    });
    child.on("close", (code) => {
      if (code !== 0) {
        finish({ ok: false, message: stderr.trim() || `Python tool exited with ${code}` });
        return;
      }
      try {
        finish({ ok: true, payload: JSON.parse(stdout) });
      } catch (err) {
        finish({ ok: false, message: `Could not parse Python tool JSON: ${err.message}` });
      }
    });
  });
}

async function callTool(params) {
  if (params.name !== TOOL_NAME) {
    throw new Error(`Unknown tool: ${params.name}`);
  }
  const args = params.arguments || {};
  if (typeof args.email_path !== "string" || args.email_path.length === 0) {
    throw new Error("email_path is required");
  }
  if (path.extname(args.email_path).toLowerCase() !== ".eml") {
    throw new Error("Only .eml files are supported");
  }
  if (
    Object.prototype.hasOwnProperty.call(args, "include_email_metadata") &&
    typeof args.include_email_metadata !== "boolean"
  ) {
    throw new Error("include_email_metadata must be a boolean");
  }

  const analysis = await runPythonTool(args);
  if (!analysis.ok) {
    return {
      content: [{ type: "text", text: analysis.message }],
      isError: true
    };
  }
  return {
    content: [{ type: "text", text: JSON.stringify(analysis.payload) }],
    structuredContent: analysis.payload,
    isError: false
  };
}

async function handleMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return error(null, -32600, "Invalid Request");
  }
  if (!Object.prototype.hasOwnProperty.call(message, "id")) {
    return null;
  }

  const id = message.id;
  const params = message.params || {};
  switch (message.method) {
    case "initialize":
      return result(id, {
        protocolVersion: params.protocolVersion || PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: "payment-scam-firewall",
          title: "Payment Scam Firewall",
          version: "0.1.0"
        },
        instructions:
          "Use analyze_payment_email for local .eml payment or invoice emails. Treat VERIFY and DO_NOT_PAY as human-review payment holds."
      });
    case "ping":
      return result(id, {});
    case "tools/list":
      return result(id, { tools: [toolDefinition()] });
    case "tools/call":
      try {
        return result(id, await callTool(params));
      } catch (err) {
        return error(id, -32602, err.message);
      }
    default:
      return error(id, -32601, `Method not found: ${message.method}`);
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity
});

rl.on("line", async (line) => {
  if (!line.trim()) {
    return;
  }
  try {
    const response = await handleMessage(JSON.parse(line));
    if (response) {
      writeResponse(response);
    }
  } catch (err) {
    writeResponse(error(null, -32700, err.message));
  }
});
