import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

const scriptsDirectory = fileURLToPath(new URL(
  "../../../plugins/azure-support/skills/azure-support/scripts/",
  import.meta.url,
));
const testsDirectory = fileURLToPath(new URL("../../", import.meta.url));

const bashExecutable = process.platform === "win32"
  ? path.join(process.env.ProgramFiles ?? "C:\\Program Files", "Git", "bin", "bash.exe")
  : "bash";
const powershellExecutable = process.platform === "win32" ? "powershell" : "pwsh";
const toBashPath = (value: string) => process.platform === "win32"
  ? value.replace(/^([A-Za-z]):/, (_, drive: string) => `/${drive.toLowerCase()}`).replaceAll("\\", "/")
  : value;

let scratchRoot = "";
let caseCounter = 0;

function newCaseDirectory(): string {
  const directory = path.join(scratchRoot, `case-${++caseCounter}`);
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

// Keep scratch files out of the system temp directory and stop git discovery above the
// scratch root so append-record does not see this repository as the record's work tree.
function scriptEnv(): NodeJS.ProcessEnv {
  return { ...process.env, GIT_CEILING_DIRECTORIES: scratchRoot };
}

type Shell = "bash" | "powershell";

function run(shell: Shell, name: string, bashArgs: string[], powershellArgs: string[]) {
  const result = shell === "bash"
    ? spawnSync(bashExecutable, [toBashPath(path.join(scriptsDirectory, `${name}.sh`)), ...bashArgs], {
      encoding: "utf8",
      env: scriptEnv(),
    })
    : spawnSync(powershellExecutable, [
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(scriptsDirectory, `${name}.ps1`), ...powershellArgs,
    ], { encoding: "utf8", env: scriptEnv() });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

function scan(shell: Shell, file: string, scopes: string[] = []) {
  return run(
    shell,
    "scan-ticket",
    ["--file", toBashPath(file), ...scopes.flatMap(scope => ["--scope", scope])],
    ["-File", file, ...(scopes.length ? ["-Scope", scopes.join(",")] : [])],
  );
}

interface RecordAction {
  entry?: string;
  close?: boolean;
  verify?: boolean;
  allowWorkspace?: boolean;
}

function record(shell: Shell, recordPath: string, action: RecordAction) {
  const bashArgs = ["--record", toBashPath(recordPath)];
  const powershellArgs = ["-Record", recordPath];
  if (action.entry) {
    bashArgs.push("--entry-file", toBashPath(action.entry));
    powershellArgs.push("-EntryFile", action.entry);
  }
  if (action.close) {
    bashArgs.push("--close");
    powershellArgs.push("-Close");
  }
  if (action.verify) {
    bashArgs.push("--verify");
    powershellArgs.push("-Verify");
  }
  if (action.allowWorkspace) {
    bashArgs.push("--allow-workspace");
    powershellArgs.push("-AllowWorkspace");
  }
  return run(shell, "append-record", bashArgs, powershellArgs);
}

const scopeId = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-support";
const fakeKey = "ZmFrZS1rZXktZm9yLWV2YWwtb25seQ";
const highEntropyToken = "Xq7pL2mZ9vR4tK8wN3bH6yJ1cF5dG0sA_eU-";
const shells: Shell[] = ["bash", "powershell"];

beforeAll(() => {
  scratchRoot = fs.mkdtempSync(path.join(testsDirectory, ".azure-support-scratch-"));
});

afterAll(() => {
  fs.rmSync(scratchRoot, { recursive: true, force: true });
});

describe("azure-support scripts ship as Bash and PowerShell pairs", () => {
  test.each(["scan-ticket", "append-record"])("%s", (name) => {
    const bash = fs.readFileSync(path.join(scriptsDirectory, `${name}.sh`), "utf8");
    const powershell = fs.readFileSync(path.join(scriptsDirectory, `${name}.ps1`), "utf8");
    expect(bash).toMatch(/^#!\/usr\/bin\/env bash/);
    expect(bash).toMatch(/set -[a-z]*uo pipefail/);
    expect(bash).not.toMatch(/\beval\s/);
    expect(powershell).not.toContain("[Parameter(Mandatory");
  });
});

describe.each(shells)("scan-ticket (%s)", (shell) => {
  test("passes a clean ticket with in-scope IDs, plain words, and hashes", () => {
    const file = path.join(newCaseDirectory(), "ticket.md");
    fs.writeFileSync(file, [
      "Title: VM scale set AllocationFailed in westus3",
      `Resource: ${scopeId}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-web`,
      "Word: supercalifragilisticexpialidociousness",
      "Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "Docs: https://learn.microsoft.com/azure/azure-portal/supportability/how-to-create-azure-support-request",
      "",
    ].join("\n"));
    const result = scan(shell, file, [scopeId]);
    expect(result.output).toContain("CLEAN");
    expect(result.status).toBe(0);
  });

  test("flags an unpadded high-entropy token and masks it", () => {
    const file = path.join(newCaseDirectory(), "ticket.md");
    fs.writeFileSync(file, `Log: request failed with token ${highEntropyToken}\n`);
    const result = scan(shell, file, [scopeId]);
    expect(result.status).toBe(1);
    expect(result.output).toMatch(/\[high-entropy\] Xq7p\*\*\*\*/);
    expect(result.output).not.toContain(highEntropyToken);
  });

  test("flags keys, passwords, and out-of-scope subscriptions", () => {
    const file = path.join(newCaseDirectory(), "ticket.md");
    fs.writeFileSync(file, [
      `conn: AccountKey=${fakeKey}==`,
      "password: not-a-real-password",
      "Other: /subscriptions/99999999-2222-3333-4444-555555555555/resourceGroups/other",
      "",
    ].join("\n"));
    const result = scan(shell, file, [scopeId]);
    expect(result.status).toBe(1);
    expect(result.output).toContain("[connection-string]");
    expect(result.output).toContain("[password-or-secret]");
    expect(result.output).toContain("[out-of-scope-resource]");
    expect(result.output).not.toContain(fakeKey);
  });
});

describe.each(shells)("append-record (%s)", (shell) => {
  test("redacts at write time, closes, and verifies the whole record", () => {
    const directory = newCaseDirectory();
    const recordPath = path.join(directory, "session.md");
    const entry = path.join(directory, "entry.md");
    fs.writeFileSync(entry, `conn: AccountKey=${fakeKey}==\nAuthorization: Bearer abc.def\n`);

    expect(record(shell, recordPath, { entry }).status).toBe(0);
    expect(record(shell, recordPath, { entry }).status).toBe(0);
    const written = fs.readFileSync(recordPath, "utf8");
    expect(written).not.toContain(fakeKey);
    expect(written).toContain("AccountKey=<redacted>");
    expect(written).toContain("Bearer <redacted>");

    const open = record(shell, recordPath, { verify: true });
    expect(open.status).toBe(0);
    expect(open.output).toContain("record still open");

    expect(record(shell, recordPath, { close: true }).status).toBe(0);
    const closed = record(shell, recordPath, { verify: true });
    expect(closed.status).toBe(0);
    expect(closed.output).toContain("record closed");

    expect(record(shell, recordPath, { entry }).status).toBe(1);
  });

  test("detects an edit to the final entry after closing", () => {
    const directory = newCaseDirectory();
    const recordPath = path.join(directory, "session.md");
    const entry = path.join(directory, "entry.md");
    fs.writeFileSync(entry, "Outcome: inconclusive\n");
    record(shell, recordPath, { entry });
    record(shell, recordPath, { close: true });
    fs.writeFileSync(recordPath, fs.readFileSync(recordPath, "utf8").replace("inconclusive", "escalated"));

    const result = record(shell, recordPath, { verify: true });
    expect(result.status).toBe(1);
    expect(result.output).toContain("BROKEN closing line");
  });

  test("refuses a record inside a git work tree unless allowed, then ignores it", () => {
    const repo = newCaseDirectory();
    spawnSync("git", ["init", "-q", repo], { env: scriptEnv() });
    const recordPath = path.join(repo, ".azure-support", "session.md");
    const entry = path.join(repo, "entry.md");
    fs.writeFileSync(entry, "Scope: test\n");

    expect(record(shell, recordPath, { entry }).status).toBe(1);
    expect(record(shell, recordPath, { entry, allowWorkspace: true }).status).toBe(0);
    expect(fs.readFileSync(path.join(repo, ".gitignore"), "utf8").split("\n")).toContain(".azure-support/");
  });
});

test("records written by one implementation verify with the other", () => {
  const directory = newCaseDirectory();
  const recordPath = path.join(directory, "session.md");
  const entry = path.join(directory, "entry.md");
  fs.writeFileSync(entry, "Check: Resource Health Unknown\n");
  record("bash", recordPath, { entry });
  record("powershell", recordPath, { entry });
  record("bash", recordPath, { close: true });

  expect(record("powershell", recordPath, { verify: true }).status).toBe(0);
  expect(record("bash", recordPath, { verify: true }).status).toBe(0);
});
