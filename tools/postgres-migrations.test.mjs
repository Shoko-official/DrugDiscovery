import assert from "node:assert/strict";
import test from "node:test";

import {
  POSTGRES_IMAGE,
  createContainerName,
  discoverMigrations,
  redactBoundedOutput,
  runPostgresMigrations,
} from "./postgres-migrations.mjs";

const EXPECTED_IMAGE =
  "postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296";
const NONCE = "0123456789abcdef01234567";
const CONTAINER_NAME = `bioworld-postgres-migrations-${NONCE}`;
const POSTGRES_PASSWORD = "0123456789abcdef".repeat(4);
const SECRET = "postgresql://admin:do-not-expose@example.invalid/database";
const FIXTURE_SQL = [
  "INSERT INTO scientific_event (event_id)",
  "VALUES ('00000000-0000-4000-8000-000000000001');",
].join("\n");
const VERIFICATION_SQL = [
  "SELECT CASE",
  "  WHEN to_regclass('public.scientific_event') IS NOT NULL",
  "  THEN 'bioworld_migrations_ready'",
  "  ELSE 'bioworld_migrations_missing'",
  "END;",
].join("\n");

const migrations = [
  {
    name: "0002_decision_event_contract.sql",
    isFile: true,
    sql: "ALTER TABLE scientific_event ADD COLUMN verified boolean;",
  },
  {
    name: "0001_scientific_event.sql",
    isFile: true,
    sql: "CREATE TABLE scientific_event (event_id uuid PRIMARY KEY);",
  },
];

function result(status = 0, stdout = "", stderr = "") {
  return { status, stdout, stderr };
}

function clock() {
  let current = 0;
  return {
    now: () => current,
    sleep: async (milliseconds) => {
      current += milliseconds;
    },
  };
}

async function captureError(promise) {
  let caught;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof Error, "expected operation to reject with an Error");
  return caught;
}

function commandKind(args, options = {}) {
  if (args[0] === "run") {
    return "start";
  }
  if (args[0] === "logs") {
    return "logs";
  }
  if (args[0] === "rm") {
    return "cleanup";
  }
  if (args.includes("pg_isready")) {
    return "health";
  }
  if (!args.includes("psql")) {
    throw new Error(`Unexpected test command: ${args.join(" ")}`);
  }

  const input = String(options.input ?? "");
  if (input.trim() === "SELECT 1;") {
    return "readiness";
  }
  if (input.includes(migrations[1].sql)) {
    return "migration-0001";
  }
  if (input.includes(FIXTURE_SQL)) {
    return "fixture";
  }
  if (input.includes(migrations[0].sql)) {
    return "migration-0002";
  }
  if (input.includes("bioworld_migrations_ready")) {
    return "verify";
  }
  throw new Error("Unexpected psql input in test command.");
}

function operationResult(kind) {
  if (kind === "readiness") {
    return result(0, "1\n");
  }
  if (kind === "verify") {
    return result(0, "bioworld_migrations_ready\n");
  }
  return result(0);
}

function runOptions(runCommand, time = clock(), overrides = {}) {
  return {
    migrations,
    fixtureSql: FIXTURE_SQL,
    verificationSql: VERIFICATION_SQL,
    nonce: NONCE,
    postgresPassword: POSTGRES_PASSWORD,
    runCommand,
    now: time.now,
    sleep: time.sleep,
    ...overrides,
  };
}

test("pins the exact PostgreSQL 18.4 Bookworm image digest", () => {
  assert.equal(POSTGRES_IMAGE, EXPECTED_IMAGE);
});

test("discovers regular migration files in strict contiguous version order", () => {
  assert.deepEqual(discoverMigrations(migrations), [
    migrations[1],
    migrations[0],
  ]);
});

test("rejects an empty or ambiguous migration set", () => {
  const invalidSets = [
    [],
    [{ name: "0002_second.sql", isFile: true, sql: "SELECT 2;" }],
    [
      { name: "0001_first.sql", isFile: true, sql: "SELECT 1;" },
      { name: "0003_third.sql", isFile: true, sql: "SELECT 3;" },
    ],
    [
      { name: "0001_first.sql", isFile: true, sql: "SELECT 1;" },
      { name: "0001_duplicate.sql", isFile: true, sql: "SELECT 2;" },
    ],
    [{ name: "1_short.sql", isFile: true, sql: "SELECT 1;" }],
    [{ name: "0001_Uppercase.sql", isFile: true, sql: "SELECT 1;" }],
    [{ name: "README.md", isFile: true, sql: "documentation" }],
    [{ name: "0001_first.sql", isFile: false, sql: "SELECT 1;" }],
    [{ name: "0001_first.sql", isFile: true, sql: "   " }],
    [{ name: "0001_first.sql", isFile: true, sql: "SELECT '\0';" }],
  ];

  for (const entries of invalidSets) {
    assert.throws(() => discoverMigrations(entries));
  }
});

test("builds a fixed-prefix container name only from lowercase hexadecimal entropy", () => {
  assert.equal(createContainerName(NONCE), CONTAINER_NAME);

  for (const unsafe of [
    "",
    "ABCDEF0123456789ABCDEF01",
    "../../docker.sock",
    "0123456789abcdef;docker-rm",
    "01234567 89abcdef",
    "a".repeat(65),
  ]) {
    assert.throws(() => createContainerName(unsafe));
  }
});

test("requires an independent high-entropy PostgreSQL password", async () => {
  assert.notEqual(POSTGRES_PASSWORD, NONCE);
  assert.match(POSTGRES_PASSWORD, /^[0-9a-f]{64}$/);

  for (const postgresPassword of ["", "postgres", NONCE]) {
    let called = false;
    await assert.rejects(
      runPostgresMigrations(
        runOptions(async () => {
          called = true;
          return result(0);
        }, undefined, { postgresPassword }),
      ),
    );
    assert.equal(called, false);
  }
});

test("uses distinct bounded psql sessions in migration lifecycle order", async () => {
  const calls = [];
  const time = clock();
  let healthAttempts = 0;
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    const kind = commandKind(args, options);
    if (kind === "health") {
      healthAttempts += 1;
      return healthAttempts < 3 ? result(1) : result(0);
    }
    return operationResult(kind);
  };

  await runPostgresMigrations(
    runOptions(runCommand, time, {
      healthTimeoutMs: 5_000,
      healthPollIntervalMs: 100,
    }),
  );

  assert.deepEqual(
    calls.map(({ args, options }) => commandKind(args, options)),
    [
      "start",
      "health",
      "health",
      "health",
      "readiness",
      "migration-0001",
      "fixture",
      "migration-0002",
      "verify",
      "cleanup",
    ],
  );

  assert.deepEqual(calls[0].args, [
    "run",
    "--detach",
    "--rm",
    "--pull=always",
    "--name",
    CONTAINER_NAME,
    "--network",
    "none",
    "--env",
    "POSTGRES_PASSWORD",
    "--env",
    "POSTGRES_DB=bioworld_migrations",
    EXPECTED_IMAGE,
  ]);
  assert.equal(calls[0].options.env.POSTGRES_PASSWORD, POSTGRES_PASSWORD);
  assert.ok(!calls[0].args.includes("--publish"));
  assert.ok(!calls[0].args.includes("-p"));
  assert.ok(
    !calls[0].args.some((argument) =>
      argument.includes("POSTGRES_HOST_AUTH_METHOD"),
    ),
  );
  assert.equal(calls[0].options.env.POSTGRES_HOST_AUTH_METHOD, undefined);

  const healthCalls = calls.filter(
    ({ args, options }) => commandKind(args, options) === "health",
  );
  for (const call of healthCalls) {
    assert.deepEqual(call.args, [
      "exec",
      CONTAINER_NAME,
      "pg_isready",
      "--username",
      "postgres",
      "--dbname",
      "bioworld_migrations",
      "--quiet",
    ]);
  }

  const readinessCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "readiness",
  );
  assert.deepEqual(readinessCall.args, [
    "exec",
    "--interactive",
    CONTAINER_NAME,
    "psql",
    "--username",
    "postgres",
    "--dbname",
    "bioworld_migrations",
    "--no-password",
    "--no-psqlrc",
    "--set",
    "ON_ERROR_STOP=1",
    "--tuples-only",
    "--no-align",
    "--file",
    "-",
  ]);
  assert.equal(readinessCall.options.input, "SELECT 1;\n");

  const transactionKinds = ["migration-0001", "fixture", "migration-0002"];
  const transactionCalls = transactionKinds.map((expectedKind) =>
    calls.find(
      ({ args, options }) => commandKind(args, options) === expectedKind,
    ),
  );
  assert.equal(new Set(transactionCalls).size, transactionCalls.length);
  for (const call of transactionCalls) {
    assert.deepEqual(call.args, [
      "exec",
      "--interactive",
      CONTAINER_NAME,
      "psql",
      "--username",
      "postgres",
      "--dbname",
      "bioworld_migrations",
      "--no-password",
      "--no-psqlrc",
      "--set",
      "ON_ERROR_STOP=1",
      "--quiet",
      "--single-transaction",
      "--file",
      "-",
    ]);
  }
  assert.match(transactionCalls[0].options.input, /0001_scientific_event\.sql/);
  assert.match(transactionCalls[1].options.input, /after-0001\.sql/);
  assert.match(
    transactionCalls[2].options.input,
    /0002_decision_event_contract\.sql/,
  );

  const verificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "verify",
  );
  assert.deepEqual(verificationCall.args, [
    "exec",
    "--interactive",
    CONTAINER_NAME,
    "psql",
    "--username",
    "postgres",
    "--dbname",
    "bioworld_migrations",
    "--no-password",
    "--no-psqlrc",
    "--set",
    "ON_ERROR_STOP=1",
    "--quiet",
    "--tuples-only",
    "--no-align",
    "--file",
    "-",
  ]);
  assert.equal(verificationCall.options.input, VERIFICATION_SQL);
  assert.ok(!verificationCall.args.includes("--command"));
  assert.ok(!verificationCall.args.includes("--single-transaction"));

  assert.deepEqual(calls.at(-1).args, [
    "rm",
    "--force",
    "--volumes",
    CONTAINER_NAME,
  ]);

  for (const [index, { command, args, options }] of calls.entries()) {
    assert.equal(command, "docker");
    assert.notEqual(options.shell, true);
    assert.equal(options.encoding, "utf8");
    assert.equal(options.windowsHide, true);
    assert.ok(Number.isSafeInteger(options.timeout));
    assert.ok(options.timeout > 0 && options.timeout <= 120_000);
    assert.ok(Number.isSafeInteger(options.maxBuffer));
    assert.ok(options.maxBuffer > 0 && options.maxBuffer <= 64 * 1024);
    assert.ok(!args.join(" ").includes(POSTGRES_PASSWORD));
    assert.ok(!args.join(" ").includes(SECRET));
    assert.ok(!String(options.input ?? "").includes(POSTGRES_PASSWORD));
    assert.ok(!String(options.input ?? "").includes(SECRET));
    if (index > 0) {
      assert.equal(options.env?.POSTGRES_PASSWORD, undefined);
      assert.equal(options.env?.POSTGRES_HOST_AUTH_METHOD, undefined);
    }
  }
});

test("readiness timeout captures bounded logs before cleanup", async () => {
  const calls = [];
  const time = clock();
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    const kind = commandKind(args, options);
    if (kind === "health") {
      return result(1);
    }
    return operationResult(kind);
  };

  await assert.rejects(
    runPostgresMigrations(
      runOptions(runCommand, time, {
        healthTimeoutMs: 500,
        healthPollIntervalMs: 100,
      }),
    ),
    { message: "PostgreSQL migration container did not become ready." },
  );

  const kinds = calls.map(({ args, options }) => commandKind(args, options));
  assert.ok(kinds.filter((kind) => kind === "health").length <= 6);
  assert.deepEqual(kinds.slice(-2), ["logs", "cleanup"]);
  assert.ok(!kinds.includes("readiness"));
  assert.ok(!kinds.includes("migration-0001"));
  const logsCall = calls.at(-2);
  assert.deepEqual(logsCall.args, ["logs", "--tail", "200", CONTAINER_NAME]);
  assert.ok(logsCall.options.maxBuffer <= 64 * 1024);
});

test("failed final readiness probe captures logs and never starts migrations", async () => {
  const calls = [];
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    const kind = commandKind(args, options);
    if (kind === "readiness") {
      return result(1, SECRET, SECRET);
    }
    return operationResult(kind);
  };

  const error = await captureError(
    runPostgresMigrations(runOptions(runCommand)),
  );

  assert.equal(error.message, "PostgreSQL migration container did not become ready.");
  assert.ok(!error.message.includes(SECRET));
  const kinds = calls.map(({ args, options }) => commandKind(args, options));
  assert.deepEqual(kinds.slice(-3), ["readiness", "logs", "cleanup"]);
  assert.ok(kinds.filter((kind) => kind === "readiness").length > 1);
  assert.ok(!kinds.includes("migration-0001"));
});

test("startup diagnostics are bounded and redact passwords and URL credentials", async () => {
  const diagnostics = [];
  const hugeOutput = `${SECRET}\n${POSTGRES_PASSWORD}\n${"x".repeat(128 * 1024)}`;
  const runCommand = async (_command, args, options = {}) => {
    const kind = commandKind(args, options);
    if (kind === "start" || kind === "logs") {
      return result(1, hugeOutput, hugeOutput);
    }
    return operationResult(kind);
  };

  await assert.rejects(
    runPostgresMigrations(
      runOptions(runCommand, undefined, {
        reportDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
      }),
    ),
    { message: "PostgreSQL migration container could not start." },
  );

  assert.equal(diagnostics.length, 2);
  for (const diagnostic of diagnostics) {
    assert.ok(Buffer.byteLength(diagnostic, "utf8") <= 64 * 1024);
    assert.ok(!diagnostic.includes(POSTGRES_PASSWORD));
    assert.ok(!diagnostic.includes("admin:do-not-expose"));
  }
});

test("redacts a secret crossing the retained output boundary", () => {
  const maximumBytes = 64 * 1024;
  const output = Buffer.from(
    `${"x".repeat(maximumBytes)}${POSTGRES_PASSWORD}tail`,
    "utf8",
  );
  const redacted = redactBoundedOutput(output, maximumBytes, [
    POSTGRES_PASSWORD,
  ]);

  assert.ok(Buffer.byteLength(redacted, "utf8") <= maximumBytes);
  assert.ok(!redacted.includes(POSTGRES_PASSWORD));
  assert.ok(!redacted.includes(POSTGRES_PASSWORD.slice(-32)));
  assert.match(redacted, /\[redacted\]tail$/);
});

test("command failures remain secret-safe and always clean up", async (t) => {
  const scenarios = [
    ["start", "PostgreSQL migration container could not start."],
    ["migration-0001", "PostgreSQL migrations failed."],
    ["fixture", "PostgreSQL migration fixture failed."],
    ["migration-0002", "PostgreSQL migrations failed."],
    ["verify", "PostgreSQL migration verification failed."],
  ];

  for (const [failedKind, expectedMessage] of scenarios) {
    await t.test(failedKind, async () => {
      const calls = [];
      const hugeSecretOutput = `${SECRET}${POSTGRES_PASSWORD}${"x".repeat(1024 * 1024)}`;
      const runCommand = async (command, args, options = {}) => {
        calls.push({ command, args, options });
        const kind = commandKind(args, options);
        if (kind === failedKind) {
          return result(9, hugeSecretOutput, hugeSecretOutput);
        }
        if (kind === "cleanup" && failedKind === "migration-0001") {
          return result(9, hugeSecretOutput, hugeSecretOutput);
        }
        return operationResult(kind);
      };

      const error = await captureError(
        runPostgresMigrations(runOptions(runCommand)),
      );

      assert.equal(error.message, expectedMessage);
      assert.ok(error.message.length < 128);
      assert.ok(!error.message.includes(SECRET));
      assert.ok(!error.message.includes(POSTGRES_PASSWORD));
      assert.equal(
        commandKind(calls.at(-1).args, calls.at(-1).options),
        "cleanup",
      );
    });
  }
});

test("unexpected verification output fails closed without exposing output", async () => {
  const calls = [];
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    const kind = commandKind(args, options);
    if (kind === "verify") {
      return result(0, `${SECRET}${POSTGRES_PASSWORD}\n`);
    }
    return operationResult(kind);
  };

  const error = await captureError(
    runPostgresMigrations(runOptions(runCommand)),
  );

  assert.equal(
    error.message,
    "PostgreSQL migration verification returned an unexpected result.",
  );
  assert.ok(!error.message.includes(SECRET));
  assert.ok(!error.message.includes(POSTGRES_PASSWORD));
  assert.equal(
    commandKind(calls.at(-1).args, calls.at(-1).options),
    "cleanup",
  );
});

test("cleanup failure is reported only when no earlier failure exists", async () => {
  const runCommand = async (_command, args, options = {}) => {
    const kind = commandKind(args, options);
    if (kind === "cleanup") {
      return result(1, SECRET, POSTGRES_PASSWORD);
    }
    return operationResult(kind);
  };

  const error = await captureError(
    runPostgresMigrations(runOptions(runCommand)),
  );

  assert.equal(
    error.message,
    "PostgreSQL migration container cleanup failed.",
  );
  assert.ok(!error.message.includes(SECRET));
  assert.ok(!error.message.includes(POSTGRES_PASSWORD));
});
