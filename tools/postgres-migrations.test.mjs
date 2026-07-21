import assert from "node:assert/strict";
import test from "node:test";

import {
  POSTGRES_IMAGE,
  RUST_INTEGRATION_IMAGE,
  createContainerName,
  discoverMigrations,
  redactBoundedOutput,
  runPostgresMigrations,
} from "./postgres-migrations.mjs";

const EXPECTED_IMAGE =
  "postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296";
const EXPECTED_RUST_IMAGE =
  "rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1";
const NONCE = "0123456789abcdef01234567";
const CONTAINER_NAME = `bioworld-postgres-migrations-${NONCE}`;
const WRITER_SOURCE_CONTAINER = `bioworld-postgres-writer-source-${NONCE}`;
const WRITER_FETCH_CONTAINER = `bioworld-postgres-writer-fetch-${NONCE}`;
const WRITER_BUILD_CONTAINER = `bioworld-postgres-writer-build-${NONCE}`;
const WRITER_TEST_CONTAINER = `bioworld-postgres-writer-test-${NONCE}`;
const WRITER_CARGO_VOLUME = `bioworld-postgres-writer-cargo-${NONCE}`;
const WRITER_TARGET_VOLUME = `bioworld-postgres-writer-target-${NONCE}`;
const WRITER_SOURCE_VOLUME = `bioworld-postgres-writer-source-${NONCE}`;
const POSTGRES_PASSWORD = "0123456789abcdef".repeat(4);
const MIGRATOR_PASSWORD = "123456789abcdef0".repeat(4);
const WRITER_PASSWORD = "23456789abcdef01".repeat(4);
const READER_PASSWORD = "3456789abcdef012".repeat(4);
const SECRET = "postgresql://admin:do-not-expose@example.invalid/database";
const ROLE_BOOTSTRAP_SQL = [
  "CREATE ROLE bioworld_owner NOLOGIN;",
  "CREATE ROLE bioworld_migrator LOGIN;",
  "CREATE ROLE bioworld_writer LOGIN;",
  "ALTER TABLE public.scientific_event OWNER TO bioworld_owner;",
].join("\n");
const WRITER_ACCESS_SQL = [
  "GRANT USAGE ON SCHEMA public TO bioworld_writer;",
  "GRANT SELECT, INSERT ON public.scientific_event TO bioworld_writer;",
].join("\n");
const READER_ACCESS_SQL = [
  "GRANT USAGE ON SCHEMA public TO bioworld_reader;",
  "GRANT SELECT ON public.scientific_event TO bioworld_reader;",
].join("\n");
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
const TENANT_VERIFICATION_SQL =
  "SELECT 'bioworld_tenant_access_ready';";
const READER_VERIFICATION_SQL =
  "SELECT 'bioworld_reader_access_ready';";
const OWNER_VERIFICATION_SQL =
  "SELECT 'bioworld_owner_boundary_ready';";

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
  {
    name: "0003_postgres_tenant_boundary.sql",
    isFile: true,
    sql: "ALTER TABLE public.scientific_event ENABLE ROW LEVEL SECURITY;",
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
  if (args[0] === "pull") {
    return "writer-image-pull";
  }
  if (args[0] === "volume" && args[1] === "create") {
    if (args.includes(WRITER_CARGO_VOLUME)) {
      return "writer-cargo-volume-create";
    }
    return args.includes(WRITER_TARGET_VOLUME)
      ? "writer-target-volume-create"
      : "writer-source-volume-create";
  }
  if (args[0] === "volume" && args[1] === "rm") {
    if (args.includes(WRITER_CARGO_VOLUME)) {
      return "writer-cargo-volume-cleanup";
    }
    return args.includes(WRITER_TARGET_VOLUME)
      ? "writer-target-volume-cleanup"
      : "writer-source-volume-cleanup";
  }
  if (args[0] === "run") {
    if (args.includes(EXPECTED_RUST_IMAGE)) {
      if (args.includes(`container:${CONTAINER_NAME}`)) {
        return "writer-test";
      }
      if (args.includes(WRITER_SOURCE_CONTAINER)) {
        return "writer-source-stage";
      }
      return args.includes(WRITER_FETCH_CONTAINER)
        ? "writer-fetch"
        : "writer-build";
    }
    return "start";
  }
  if (args[0] === "logs") {
    return "logs";
  }
  if (args[0] === "rm") {
    if (args.includes(WRITER_SOURCE_CONTAINER)) {
      return "writer-source-stage-cleanup";
    }
    if (args.includes(WRITER_FETCH_CONTAINER)) {
      return "writer-fetch-cleanup";
    }
    if (args.includes(WRITER_BUILD_CONTAINER)) {
      return "writer-build-cleanup";
    }
    if (args.includes(WRITER_TEST_CONTAINER)) {
      return "writer-test-cleanup";
    }
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
  if (input.includes(ROLE_BOOTSTRAP_SQL)) {
    return "bootstrap";
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
  if (input.includes(migrations[2].sql)) {
    return "migration-0003";
  }
  if (input.includes(WRITER_ACCESS_SQL)) {
    return "writer-access";
  }
  if (input.includes(READER_ACCESS_SQL)) {
    return "reader-access";
  }
  if (input.includes("bioworld_tenant_access_ready")) {
    return "tenant-verify";
  }
  if (input.includes("bioworld_owner_boundary_ready")) {
    return "owner-verify";
  }
  if (input.includes("bioworld_reader_access_ready")) {
    return "reader-verify";
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
  if (kind === "tenant-verify") {
    return result(0, "bioworld_tenant_access_ready\n");
  }
  if (kind === "reader-verify") {
    return result(0, "bioworld_reader_access_ready\n");
  }
  if (kind === "owner-verify") {
    return result(0, "bioworld_owner_boundary_ready\n");
  }
  return result(0);
}

function assertRunsAllPostgresIntegrationTests(args) {
  const cargoIndex = args.lastIndexOf("cargo");
  assert.notEqual(cargoIndex, -1);
  const cargoArgs = args.slice(cargoIndex + 1);
  assert.equal(cargoArgs[0], "test");
  const packages = [];
  for (let index = 0; index < cargoArgs.length; index += 1) {
    if (["-p", "--package"].includes(cargoArgs[index])) {
      packages.push(cargoArgs[index + 1]);
    }
  }
  assert.deepEqual(
    new Set(packages),
    new Set([
      "bioworld-event-store-postgres",
      "bioworld-decision-grpc-postgres",
    ]),
  );

  const runsAllPackageTargets =
    !cargoArgs.includes("--test") &&
    !cargoArgs.some((argument) =>
      ["--lib", "--bins", "--examples", "--doc"].includes(argument),
    );
  const runsAllIntegrationTargets = cargoArgs.includes("--tests");

  assert.ok(
    runsAllPackageTargets || runsAllIntegrationTargets,
    "cargo test command must cover every PostgreSQL integration target",
  );
}

function runOptions(runCommand, time = clock(), overrides = {}) {
  return {
    migrations,
    fixtureSql: FIXTURE_SQL,
    verificationSql: VERIFICATION_SQL,
    roleBootstrapSql: ROLE_BOOTSTRAP_SQL,
    writerAccessSql: WRITER_ACCESS_SQL,
    readerAccessSql: READER_ACCESS_SQL,
    tenantVerificationSql: TENANT_VERIFICATION_SQL,
    readerVerificationSql: READER_VERIFICATION_SQL,
    ownerVerificationSql: OWNER_VERIFICATION_SQL,
    nonce: NONCE,
    postgresPassword: POSTGRES_PASSWORD,
    migratorPassword: MIGRATOR_PASSWORD,
    writerPassword: WRITER_PASSWORD,
    readerPassword: READER_PASSWORD,
    runCommand,
    now: time.now,
    sleep: time.sleep,
    ...overrides,
  };
}

test("pins the exact PostgreSQL 18.4 Bookworm image digest", () => {
  assert.equal(POSTGRES_IMAGE, EXPECTED_IMAGE);
});

test("pins the exact Rust 1.95 Bookworm integration image digest", () => {
  assert.equal(RUST_INTEGRATION_IMAGE, EXPECTED_RUST_IMAGE);
});

test("requires both PostgreSQL integration packages", () => {
  assert.throws(() =>
    assertRunsAllPostgresIntegrationTests([
      "cargo",
      "test",
      "--package",
      "bioworld-event-store-postgres",
      "--tests",
    ]),
  );
  assert.throws(() =>
    assertRunsAllPostgresIntegrationTests([
      "cargo",
      "test",
      "--package",
      "bioworld-event-store-postgres",
      "--package",
      "bioworld-decision-grpc-postgres",
      "--test",
      "postgres_writer",
      "--test",
      "postgres_reader",
    ]),
  );
  assert.doesNotThrow(() =>
    assertRunsAllPostgresIntegrationTests([
      "cargo",
      "test",
      "--package",
      "bioworld-event-store-postgres",
      "--package",
      "bioworld-decision-grpc-postgres",
      "--tests",
    ]),
  );
});

test("builds PostgreSQL integration tests without credentials and runs them only beside PostgreSQL", async () => {
  const calls = [];
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    return operationResult(commandKind(args, options));
  };

  await runPostgresMigrations(
    runOptions(runCommand, undefined, { writerIntegration: true }),
  );

  assert.deepEqual(
    calls.map(({ args, options }) => commandKind(args, options)),
    [
      "writer-image-pull",
      "writer-cargo-volume-create",
      "writer-target-volume-create",
      "writer-source-volume-create",
      "writer-source-stage",
      "writer-fetch",
      "writer-build",
      "start",
      "health",
      "readiness",
      "bootstrap",
      "migration-0001",
      "fixture",
      "migration-0002",
      "migration-0003",
      "writer-access",
      "reader-access",
      "verify",
      "tenant-verify",
      "reader-verify",
      "owner-verify",
      "writer-test",
      "writer-test-cleanup",
      "writer-build-cleanup",
      "writer-fetch-cleanup",
      "writer-source-stage-cleanup",
      "cleanup",
      "writer-source-volume-cleanup",
      "writer-target-volume-cleanup",
      "writer-cargo-volume-cleanup",
    ],
  );

  const imagePull = calls.find(
    ({ args, options }) => commandKind(args, options) === "writer-image-pull",
  );
  assert.deepEqual(imagePull.args, ["pull", EXPECTED_RUST_IMAGE]);

  const sourceStage = calls.find(
    ({ args, options }) => commandKind(args, options) === "writer-source-stage",
  );
  assert.ok(sourceStage.args.includes("none"));
  assert.ok(
    sourceStage.args.some((value) => value.endsWith("target=/workspace,readonly")),
  );
  assert.ok(
    sourceStage.args.some((value) =>
      value.includes(`source=${WRITER_SOURCE_VOLUME},target=/sanitized`),
    ),
  );
  const sourceCommand = sourceStage.args.at(-1);
  assert.match(sourceCommand, /git .*ls-files/);
  assert.match(sourceCommand, /Cargo\.toml Cargo\.lock rust-toolchain\.toml/);
  assert.match(sourceCommand, /apps\/desktop\/src-tauri crates proto/);
  assert.match(sourceCommand, /tar --extract --no-same-owner/);
  assert.match(
    sourceCommand,
    /crates\/event-store-postgres\/tests\/postgres_writer\.rs/,
  );
  assert.match(
    sourceCommand,
    /crates\/event-store-postgres\/tests\/postgres_reader\.rs/,
  );
  assert.match(
    sourceCommand,
    /crates\/decision-grpc-postgres\/src\/pool\.rs/,
  );
  assert.match(
    sourceCommand,
    /crates\/decision-grpc-postgres\/tests\/reader_pool\.rs/,
  );
  assert.match(sourceCommand, /crates\/decision-grpc\/src\/service\.rs/);
  assert.match(
    sourceCommand,
    /crates\/decision-grpc\/tests\/decision_service\.rs/,
  );

  const fetch = calls.find(
    ({ args, options }) => commandKind(args, options) === "writer-fetch",
  );
  assert.ok(fetch.args.includes("bridge"));
  assert.ok(
    fetch.args.some((value) =>
      value.includes(`source=${WRITER_SOURCE_VOLUME},target=/workspace,readonly`),
    ),
  );
  assert.ok(!fetch.args.some((value) => value.includes("type=bind")));
  assert.deepEqual(fetch.args.slice(-3), ["cargo", "fetch", "--locked"]);

  const build = calls.find(
    ({ args, options }) => commandKind(args, options) === "writer-build",
  );
  assert.ok(build);
  assert.ok(build.args.includes("none"));
  assert.ok(!build.args.some((value) => value.includes("type=bind")));
  assert.ok(
    build.args.some((value) =>
      value.includes(`source=${WRITER_SOURCE_VOLUME},target=/workspace,readonly`),
    ),
  );
  assert.ok(build.args.includes("CARGO_HOME=/cargo"));
  assert.ok(build.args.includes("CARGO_TARGET_DIR=/target"));
  assert.ok(build.args.includes("CARGO_NET_OFFLINE=true"));
  assert.ok(build.args.includes("RUSTUP_TOOLCHAIN=1.95.0"));
  assert.ok(build.args.includes("--offline"));
  assert.ok(build.args.includes("--no-run"));
  assertRunsAllPostgresIntegrationTests(build.args);
  assert.equal(build.options.env.BIOWORLD_POSTGRES_WRITER_PASSWORD, undefined);
  assert.equal(build.options.env.BIOWORLD_POSTGRES_READER_PASSWORD, undefined);
  assert.equal(build.options.env.POSTGRES_PASSWORD, undefined);
  assert.equal(build.options.env.PGPASSWORD, undefined);

  const runtime = calls.find(
    ({ args, options }) => commandKind(args, options) === "writer-test",
  );
  assert.ok(runtime);
  assert.ok(runtime.args.includes(`container:${CONTAINER_NAME}`));
  assert.ok(!runtime.args.some((value) => value.includes("type=bind")));
  assert.ok(
    runtime.args.some((value) =>
      value.includes(`source=${WRITER_SOURCE_VOLUME},target=/workspace,readonly`),
    ),
  );
  assert.ok(runtime.args.includes("BIOWORLD_POSTGRES_WRITER_PASSWORD"));
  assert.ok(runtime.args.includes("BIOWORLD_POSTGRES_READER_PASSWORD"));
  assert.ok(runtime.args.includes("BIOWORLD_POSTGRES_INTEGRATION_REQUIRED=1"));
  assert.ok(runtime.args.includes("CARGO_NET_OFFLINE=true"));
  assert.ok(runtime.args.includes("RUSTUP_TOOLCHAIN=1.95.0"));
  assert.ok(runtime.args.includes("--offline"));
  assert.ok(!runtime.args.includes("--publish"));
  assert.ok(!runtime.args.includes("-p"));
  assertRunsAllPostgresIntegrationTests(runtime.args);
  assert.equal(
    runtime.options.env.BIOWORLD_POSTGRES_WRITER_PASSWORD,
    WRITER_PASSWORD,
  );
  assert.equal(
    runtime.options.env.BIOWORLD_POSTGRES_READER_PASSWORD,
    READER_PASSWORD,
  );

  for (const integrationCall of [sourceStage, fetch, build]) {
    assert.equal(
      integrationCall.options.env.BIOWORLD_POSTGRES_WRITER_PASSWORD,
      undefined,
    );
    assert.equal(
      integrationCall.options.env.BIOWORLD_POSTGRES_READER_PASSWORD,
      undefined,
    );
  }

  const serializedArguments = calls
    .flatMap(({ args }) => args)
    .join(" ");
  for (const secret of [
    POSTGRES_PASSWORD,
    MIGRATOR_PASSWORD,
    WRITER_PASSWORD,
    READER_PASSWORD,
  ]) {
    assert.ok(!serializedArguments.includes(secret));
  }
});

test("writer integration build failure cleans isolated containers and volumes", async () => {
  const kinds = [];
  const runCommand = async (_command, args, options = {}) => {
    const kind = commandKind(args, options);
    kinds.push(kind);
    return kind === "writer-build" ? result(1, "", "build failed") : operationResult(kind);
  };

  await assert.rejects(
    runPostgresMigrations(
      runOptions(runCommand, undefined, { writerIntegration: true }),
    ),
    { message: "PostgreSQL writer integration build failed." },
  );
  assert.deepEqual(kinds, [
    "writer-image-pull",
    "writer-cargo-volume-create",
    "writer-target-volume-create",
    "writer-source-volume-create",
    "writer-source-stage",
    "writer-fetch",
    "writer-build",
    "writer-build-cleanup",
    "writer-fetch-cleanup",
    "writer-source-stage-cleanup",
    "cleanup",
    "writer-source-volume-cleanup",
    "writer-target-volume-cleanup",
    "writer-cargo-volume-cleanup",
  ]);
});

test("writer integration runtime failure is redacted and fully cleaned", async () => {
  const calls = [];
  const diagnostics = [];
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    const kind = commandKind(args, options);
    return kind === "writer-test"
      ? result(
          1,
          `${POSTGRES_PASSWORD}${READER_PASSWORD}`,
          `${WRITER_PASSWORD}${SECRET}`,
        )
      : operationResult(kind);
  };

  await assert.rejects(
    runPostgresMigrations(
      runOptions(runCommand, undefined, {
        writerIntegration: true,
        reportDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
      }),
    ),
    { message: "PostgreSQL writer integration verification failed." },
  );
  assert.deepEqual(
    calls
      .slice(-8)
      .map(({ args, options }) => commandKind(args, options)),
    [
      "writer-test-cleanup",
      "writer-build-cleanup",
      "writer-fetch-cleanup",
      "writer-source-stage-cleanup",
      "cleanup",
      "writer-source-volume-cleanup",
      "writer-target-volume-cleanup",
      "writer-cargo-volume-cleanup",
    ],
  );
  assert.equal(diagnostics.length, 1);
  for (const secret of [
    POSTGRES_PASSWORD,
    WRITER_PASSWORD,
    READER_PASSWORD,
    "admin:do-not-expose",
  ]) {
    assert.ok(!diagnostics[0].includes(secret));
  }
});

test("interrupts writer build and runtime with unsignaled full cleanup", async (t) => {
  for (const scenario of [
    {
      kind: "writer-source-stage",
      cleanup: [
        "writer-source-stage-cleanup",
        "cleanup",
        "writer-source-volume-cleanup",
        "writer-target-volume-cleanup",
        "writer-cargo-volume-cleanup",
      ],
    },
    {
      kind: "writer-fetch",
      cleanup: [
        "writer-fetch-cleanup",
        "writer-source-stage-cleanup",
        "cleanup",
        "writer-source-volume-cleanup",
        "writer-target-volume-cleanup",
        "writer-cargo-volume-cleanup",
      ],
    },
    {
      kind: "writer-build",
      cleanup: [
        "writer-build-cleanup",
        "writer-fetch-cleanup",
        "writer-source-stage-cleanup",
        "cleanup",
        "writer-source-volume-cleanup",
        "writer-target-volume-cleanup",
        "writer-cargo-volume-cleanup",
      ],
    },
    {
      kind: "writer-test",
      cleanup: [
        "writer-test-cleanup",
        "writer-build-cleanup",
        "writer-fetch-cleanup",
        "writer-source-stage-cleanup",
        "cleanup",
        "writer-source-volume-cleanup",
        "writer-target-volume-cleanup",
        "writer-cargo-volume-cleanup",
      ],
    },
  ]) {
    await t.test(scenario.kind, async () => {
      const originalExitCode = process.exitCode;
      const calls = [];
      let interrupt;
      let interrupted = false;
      let unregistered = false;
      process.exitCode = undefined;

      try {
        const runCommand = async (command, args, options = {}) => {
          calls.push({ command, args, options });
          const kind = commandKind(args, options);
          if (kind === scenario.kind && !interrupted) {
            interrupted = true;
            interrupt();
            return result(1, POSTGRES_PASSWORD, WRITER_PASSWORD);
          }
          return operationResult(kind);
        };

        const error = await captureError(
          runPostgresMigrations(
            runOptions(runCommand, undefined, {
              writerIntegration: true,
              signalRegistrar: (abortController, setExitCode) => {
                interrupt = () => {
                  setExitCode(130);
                  abortController.abort();
                };
                return () => {
                  unregistered = true;
                };
              },
            }),
          ),
        );
        assert.equal(
          error.message,
          "PostgreSQL migration verification interrupted.",
        );
        assert.equal(process.exitCode, 130);
        assert.equal(unregistered, true);

        const kinds = calls.map(({ args, options }) =>
          commandKind(args, options),
        );
        const interruptedIndex = kinds.indexOf(scenario.kind);
        assert.deepEqual(kinds.slice(interruptedIndex + 1), scenario.cleanup);
        assert.equal(calls[interruptedIndex].options.signal.aborted, true);
        for (const call of calls.slice(interruptedIndex + 1)) {
          assert.equal(call.options.signal, undefined);
        }
      } finally {
        process.exitCode = originalExitCode;
      }
    });
  }
});

test("interrupts writer volume creation and removes every deterministic volume", async (t) => {
  for (const interruptedKind of [
    "writer-cargo-volume-create",
    "writer-target-volume-create",
    "writer-source-volume-create",
  ]) {
    await t.test(interruptedKind, async () => {
      const originalExitCode = process.exitCode;
      const calls = [];
      let interrupt;
      process.exitCode = undefined;

      try {
        const runCommand = async (command, args, options = {}) => {
          calls.push({ command, args, options });
          const kind = commandKind(args, options);
          if (kind === interruptedKind) {
            interrupt();
            return result(1);
          }
          return operationResult(kind);
        };

        const error = await captureError(
          runPostgresMigrations(
            runOptions(runCommand, undefined, {
              writerIntegration: true,
              signalRegistrar: (abortController, setExitCode) => {
                interrupt = () => {
                  setExitCode(130);
                  abortController.abort();
                };
                return () => {};
              },
            }),
          ),
        );

        assert.equal(
          error.message,
          "PostgreSQL migration verification interrupted.",
        );
        const kinds = calls.map(({ args, options }) =>
          commandKind(args, options),
        );
        const interruptedIndex = kinds.indexOf(interruptedKind);
        assert.deepEqual(kinds.slice(interruptedIndex + 1), [
          "cleanup",
          "writer-source-volume-cleanup",
          "writer-target-volume-cleanup",
          "writer-cargo-volume-cleanup",
        ]);
        for (const call of calls.slice(interruptedIndex + 1)) {
          assert.equal(call.options.signal, undefined);
        }
      } finally {
        process.exitCode = originalExitCode;
      }
    });
  }
});

test("discovers regular migration files in strict contiguous version order", () => {
  assert.deepEqual(discoverMigrations(migrations), [
    migrations[1],
    migrations[0],
    migrations[2],
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

test("requires four distinct high-entropy role passwords", async () => {
  const invalidCredentials = [
    { migratorPassword: "" },
    { writerPassword: "writer" },
    { readerPassword: "reader" },
    { migratorPassword: POSTGRES_PASSWORD },
    { writerPassword: POSTGRES_PASSWORD },
    { readerPassword: POSTGRES_PASSWORD },
    { writerPassword: MIGRATOR_PASSWORD },
    { readerPassword: MIGRATOR_PASSWORD },
    { readerPassword: WRITER_PASSWORD },
  ];

  for (const credentials of invalidCredentials) {
    let called = false;
    await assert.rejects(
      runPostgresMigrations(
        runOptions(async () => {
          called = true;
          return result(0);
        }, undefined, credentials),
      ),
    );
    assert.equal(called, false);
  }
});

test("provisions and verifies a distinct reader credential", async () => {
  const calls = [];
  await runPostgresMigrations(
    runOptions(async (command, args, options = {}) => {
      calls.push({ command, args, options });
      return operationResult(commandKind(args, options));
    }),
  );

  const bootstrapCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "bootstrap",
  );
  assert.ok(bootstrapCall.args.includes("BIOWORLD_READER_PASSWORD"));
  assert.equal(
    bootstrapCall.options.env.BIOWORLD_READER_PASSWORD,
    READER_PASSWORD,
  );

  const readerAccessCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "reader-access",
  );
  assert.ok(readerAccessCall);
  assert.equal(readerAccessCall.options.env.PGPASSWORD, MIGRATOR_PASSWORD);

  const readerVerificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "reader-verify",
  );
  assert.ok(readerVerificationCall);
  assert.equal(
    readerVerificationCall.args[
      readerVerificationCall.args.indexOf("--username") + 1
    ],
    "bioworld_reader",
  );
  assert.equal(readerVerificationCall.options.env.PGPASSWORD, READER_PASSWORD);
});

test("requires every role-boundary SQL input before Docker", async () => {
  for (const input of [
    "roleBootstrapSql",
    "writerAccessSql",
    "readerAccessSql",
    "tenantVerificationSql",
    "readerVerificationSql",
    "ownerVerificationSql",
  ]) {
    let called = false;
    await assert.rejects(
      runPostgresMigrations(
        runOptions(
          async () => {
            called = true;
            return result(0);
          },
          undefined,
          { [input]: " " },
        ),
      ),
    );
    assert.equal(called, false);
  }
});

test("rejects an invalid legacy upgrade boundary before Docker", async () => {
  for (const legacyUpgradeFromVersion of [-1, 1.5, migrations.length, 99]) {
    let called = false;
    await assert.rejects(
      runPostgresMigrations(
        runOptions(
          async () => {
            called = true;
            return result(0);
          },
          undefined,
          { legacyUpgradeFromVersion },
        ),
      ),
    );
    assert.equal(called, false);
  }

  let called = false;
  await assert.rejects(
    runPostgresMigrations(
      runOptions(
        async () => {
          called = true;
          return result(0);
        },
        undefined,
        { legacyUpgradeFromVersion: 2, writerIntegration: true },
      ),
    ),
  );
  assert.equal(called, false);
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
      "bootstrap",
      "migration-0001",
      "fixture",
      "migration-0002",
      "migration-0003",
      "writer-access",
      "reader-access",
      "verify",
      "tenant-verify",
      "reader-verify",
      "owner-verify",
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
  assert.equal(calls[0].options.env.PGPASSWORD, undefined);
  assert.equal(calls[0].options.env.BIOWORLD_MIGRATOR_PASSWORD, undefined);
  assert.equal(calls[0].options.env.BIOWORLD_WRITER_PASSWORD, undefined);
  assert.equal(calls[0].options.env.BIOWORLD_READER_PASSWORD, undefined);
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
      "--host",
      "127.0.0.1",
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
    "--env",
    "PGPASSWORD",
    CONTAINER_NAME,
    "psql",
    "--host",
    "127.0.0.1",
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
  assert.equal(readinessCall.options.env.PGPASSWORD, POSTGRES_PASSWORD);

  const bootstrapCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "bootstrap",
  );
  assert.deepEqual(bootstrapCall.args, [
    "exec",
    "--interactive",
    "--env",
    "PGPASSWORD",
    "--env",
    "BIOWORLD_MIGRATOR_PASSWORD",
    "--env",
    "BIOWORLD_WRITER_PASSWORD",
    "--env",
    "BIOWORLD_READER_PASSWORD",
    CONTAINER_NAME,
    "psql",
    "--host",
    "127.0.0.1",
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
  assert.equal(bootstrapCall.options.env.PGPASSWORD, POSTGRES_PASSWORD);
  assert.equal(
    bootstrapCall.options.env.BIOWORLD_MIGRATOR_PASSWORD,
    MIGRATOR_PASSWORD,
  );
  assert.equal(
    bootstrapCall.options.env.BIOWORLD_WRITER_PASSWORD,
    WRITER_PASSWORD,
  );
  assert.equal(
    bootstrapCall.options.env.BIOWORLD_READER_PASSWORD,
    READER_PASSWORD,
  );
  assert.equal(bootstrapCall.options.env.POSTGRES_PASSWORD, undefined);

  const transactionKinds = [
    "migration-0001",
    "fixture",
    "migration-0002",
    "migration-0003",
    "writer-access",
    "reader-access",
  ];
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
      "--env",
      "PGPASSWORD",
      CONTAINER_NAME,
      "psql",
      "--host",
      "127.0.0.1",
      "--username",
      "bioworld_migrator",
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
    assert.equal(call.options.env.PGPASSWORD, MIGRATOR_PASSWORD);
    assert.equal(call.options.env.POSTGRES_PASSWORD, undefined);
    assert.equal(call.options.env.BIOWORLD_MIGRATOR_PASSWORD, undefined);
    assert.equal(call.options.env.BIOWORLD_WRITER_PASSWORD, undefined);
    assert.equal(call.options.env.BIOWORLD_READER_PASSWORD, undefined);
    assert.match(call.options.input, /SET LOCAL ROLE bioworld_owner;/);
    assert.match(
      call.options.input,
      /SET LOCAL search_path = public, pg_catalog;/,
    );
  }
  assert.match(transactionCalls[0].options.input, /0001_scientific_event\.sql/);
  assert.match(transactionCalls[1].options.input, /after-0001\.sql/);
  assert.match(
    transactionCalls[2].options.input,
    /0002_decision_event_contract\.sql/,
  );
  assert.match(
    transactionCalls[3].options.input,
    /0003_postgres_tenant_boundary\.sql/,
  );
  assert.match(
    transactionCalls[4].options.input,
    /grant-writer-access\.sql/,
  );
  assert.match(
    transactionCalls[5].options.input,
    /grant-reader-access\.sql/,
  );

  const verificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "verify",
  );
  assert.deepEqual(verificationCall.args, [
    "exec",
    "--interactive",
    "--env",
    "PGPASSWORD",
    CONTAINER_NAME,
    "psql",
    "--host",
    "127.0.0.1",
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
  assert.equal(verificationCall.options.env.PGPASSWORD, POSTGRES_PASSWORD);

  const tenantVerificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "tenant-verify",
  );
  assert.equal(
    tenantVerificationCall.args[
      tenantVerificationCall.args.indexOf("--username") + 1
    ],
    "bioworld_writer",
  );
  assert.equal(tenantVerificationCall.options.env.PGPASSWORD, WRITER_PASSWORD);
  assert.equal(
    tenantVerificationCall.options.env.BIOWORLD_MIGRATOR_PASSWORD,
    undefined,
  );
  assert.equal(
    tenantVerificationCall.options.env.BIOWORLD_WRITER_PASSWORD,
    undefined,
  );
  assert.equal(
    tenantVerificationCall.options.input,
    TENANT_VERIFICATION_SQL,
  );

  const readerVerificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "reader-verify",
  );
  assert.equal(
    readerVerificationCall.args[
      readerVerificationCall.args.indexOf("--username") + 1
    ],
    "bioworld_reader",
  );
  assert.equal(readerVerificationCall.options.env.PGPASSWORD, READER_PASSWORD);
  assert.equal(
    readerVerificationCall.options.env.BIOWORLD_MIGRATOR_PASSWORD,
    undefined,
  );
  assert.equal(
    readerVerificationCall.options.env.BIOWORLD_WRITER_PASSWORD,
    undefined,
  );
  assert.equal(
    readerVerificationCall.options.env.BIOWORLD_READER_PASSWORD,
    undefined,
  );
  assert.equal(
    readerVerificationCall.options.input,
    READER_VERIFICATION_SQL,
  );

  const ownerVerificationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "owner-verify",
  );
  assert.equal(
    ownerVerificationCall.args[
      ownerVerificationCall.args.indexOf("--username") + 1
    ],
    "bioworld_migrator",
  );
  assert.equal(ownerVerificationCall.options.env.PGPASSWORD, MIGRATOR_PASSWORD);
  assert.equal(ownerVerificationCall.options.input, OWNER_VERIFICATION_SQL);

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
    assert.ok(!args.join(" ").includes(MIGRATOR_PASSWORD));
    assert.ok(!args.join(" ").includes(WRITER_PASSWORD));
    assert.ok(!args.join(" ").includes(READER_PASSWORD));
    assert.ok(!args.join(" ").includes(SECRET));
    assert.ok(!String(options.input ?? "").includes(POSTGRES_PASSWORD));
    assert.ok(!String(options.input ?? "").includes(MIGRATOR_PASSWORD));
    assert.ok(!String(options.input ?? "").includes(WRITER_PASSWORD));
    assert.ok(!String(options.input ?? "").includes(READER_PASSWORD));
    assert.ok(!String(options.input ?? "").includes(SECRET));
    if (index > 0) {
      assert.equal(options.env?.POSTGRES_PASSWORD, undefined);
      assert.equal(options.env?.POSTGRES_HOST_AUTH_METHOD, undefined);
    }
  }
});

test("reassigns legacy-owned objects before applying the tenant migration", async () => {
  const calls = [];
  const runCommand = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    return operationResult(commandKind(args, options));
  };

  await runPostgresMigrations(
    runOptions(runCommand, undefined, { legacyUpgradeFromVersion: 2 }),
  );

  const kinds = calls.map(({ args, options }) => commandKind(args, options));
  assert.deepEqual(kinds, [
    "start",
    "health",
    "readiness",
    "migration-0001",
    "fixture",
    "migration-0002",
    "bootstrap",
    "migration-0003",
    "writer-access",
    "reader-access",
    "verify",
    "tenant-verify",
    "reader-verify",
    "owner-verify",
    "cleanup",
  ]);

  for (const kind of ["migration-0001", "fixture", "migration-0002"]) {
    const call = calls.find(
      ({ args, options }) => commandKind(args, options) === kind,
    );
    assert.equal(call.args[call.args.indexOf("--username") + 1], "postgres");
    assert.equal(call.options.env.PGPASSWORD, POSTGRES_PASSWORD);
    assert.doesNotMatch(call.options.input, /SET LOCAL ROLE bioworld_owner;/);
  }

  const bootstrapCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "bootstrap",
  );
  assert.match(
    bootstrapCall.options.input,
    /ALTER TABLE public\.scientific_event OWNER TO bioworld_owner;/,
  );

  const tenantMigrationCall = calls.find(
    ({ args, options }) => commandKind(args, options) === "migration-0003",
  );
  assert.equal(
    tenantMigrationCall.args[
      tenantMigrationCall.args.indexOf("--username") + 1
    ],
    "bioworld_migrator",
  );
  assert.equal(tenantMigrationCall.options.env.PGPASSWORD, MIGRATOR_PASSWORD);
  assert.match(
    tenantMigrationCall.options.input,
    /SET LOCAL ROLE bioworld_owner;/,
  );
});

test("interrupts every privileged phase and performs unsignaled cleanup", async (t) => {
  for (const scenario of [
    { name: "bootstrap", kind: "bootstrap" },
    { name: "migration-0003", kind: "migration-0003" },
    { name: "writer-access", kind: "writer-access" },
    { name: "reader-access", kind: "reader-access" },
    { name: "verify", kind: "verify" },
    { name: "tenant-verify", kind: "tenant-verify" },
    { name: "reader-verify", kind: "reader-verify" },
    { name: "owner-verify", kind: "owner-verify" },
    {
      name: "legacy-migration-0001",
      kind: "migration-0001",
      legacyUpgradeFromVersion: 2,
    },
    {
      name: "legacy-fixture",
      kind: "fixture",
      legacyUpgradeFromVersion: 2,
    },
    {
      name: "legacy-migration-0002",
      kind: "migration-0002",
      legacyUpgradeFromVersion: 2,
    },
  ]) {
    await t.test(scenario.name, async () => {
      const originalExitCode = process.exitCode;
      const calls = [];
      const diagnostics = [];
      let interrupt;
      let interrupted = false;
      let unregistered = false;
      process.exitCode = undefined;

      try {
        const runCommand = async (command, args, options = {}) => {
          calls.push({ command, args, options });
          const kind = commandKind(args, options);
          if (kind === scenario.kind && !interrupted) {
            interrupted = true;
            interrupt();
            return result(
              1,
              `${POSTGRES_PASSWORD}${MIGRATOR_PASSWORD}`,
              `${WRITER_PASSWORD}${READER_PASSWORD}${SECRET}`,
            );
          }
          return operationResult(kind);
        };

        const error = await captureError(
          runPostgresMigrations(
            runOptions(runCommand, undefined, {
              reportDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
              ...(scenario.legacyUpgradeFromVersion === undefined
                ? {}
                : {
                    legacyUpgradeFromVersion:
                      scenario.legacyUpgradeFromVersion,
                  }),
              signalRegistrar: (abortController, setExitCode) => {
                interrupt = () => {
                  setExitCode(130);
                  abortController.abort();
                };
                return () => {
                  unregistered = true;
                };
              },
            }),
          ),
        );

        assert.equal(
          error.message,
          "PostgreSQL migration verification interrupted.",
        );
        assert.equal(process.exitCode, 130);
        assert.equal(unregistered, true);

        const kinds = calls.map(({ args, options }) =>
          commandKind(args, options),
        );
        const interruptedIndex = kinds.indexOf(scenario.kind);
        assert.deepEqual(kinds.slice(interruptedIndex + 1), ["cleanup"]);

        const interruptedCall = calls[interruptedIndex];
        assert.equal(interruptedCall.options.signal.aborted, true);
        const cleanupCall = calls.at(-1);
        assert.equal(cleanupCall.options.signal, undefined);

        assert.equal(diagnostics.length, 1);
        assert.ok(!diagnostics[0].includes(POSTGRES_PASSWORD));
        assert.ok(!diagnostics[0].includes(MIGRATOR_PASSWORD));
        assert.ok(!diagnostics[0].includes(WRITER_PASSWORD));
        assert.ok(!diagnostics[0].includes(READER_PASSWORD));
        assert.ok(!diagnostics[0].includes("admin:do-not-expose"));
      } finally {
        process.exitCode = originalExitCode;
      }
    });
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
  const hugeOutput = [
    SECRET,
    POSTGRES_PASSWORD,
    MIGRATOR_PASSWORD,
    WRITER_PASSWORD,
    READER_PASSWORD,
    "x".repeat(128 * 1024),
  ].join("\n");
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
    assert.ok(!diagnostic.includes(MIGRATOR_PASSWORD));
    assert.ok(!diagnostic.includes(WRITER_PASSWORD));
    assert.ok(!diagnostic.includes(READER_PASSWORD));
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
    ["bootstrap", "PostgreSQL role bootstrap failed."],
    ["migration-0001", "PostgreSQL migrations failed."],
    ["fixture", "PostgreSQL migration fixture failed."],
    ["migration-0002", "PostgreSQL migrations failed."],
    ["migration-0003", "PostgreSQL migrations failed."],
    ["writer-access", "PostgreSQL writer access provisioning failed."],
    ["reader-access", "PostgreSQL reader access provisioning failed."],
    ["verify", "PostgreSQL migration verification failed."],
    ["tenant-verify", "PostgreSQL tenant access verification failed."],
    ["reader-verify", "PostgreSQL reader access verification failed."],
    ["owner-verify", "PostgreSQL owner boundary verification failed."],
  ];

  for (const [failedKind, expectedMessage] of scenarios) {
    await t.test(failedKind, async () => {
      const calls = [];
      const hugeSecretOutput = `${SECRET}${POSTGRES_PASSWORD}${MIGRATOR_PASSWORD}${WRITER_PASSWORD}${READER_PASSWORD}${"x".repeat(1024 * 1024)}`;
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
      assert.ok(!error.message.includes(MIGRATOR_PASSWORD));
      assert.ok(!error.message.includes(WRITER_PASSWORD));
      assert.ok(!error.message.includes(READER_PASSWORD));
      assert.equal(
        commandKind(calls.at(-1).args, calls.at(-1).options),
        "cleanup",
      );
    });
  }
});

test("unexpected verification output fails closed without exposing output", async (t) => {
  const scenarios = [
    [
      "verify",
      "PostgreSQL migration verification returned an unexpected result.",
    ],
    [
      "tenant-verify",
      "PostgreSQL tenant access verification returned an unexpected result.",
    ],
    [
      "owner-verify",
      "PostgreSQL owner boundary verification returned an unexpected result.",
    ],
    [
      "reader-verify",
      "PostgreSQL reader access verification returned an unexpected result.",
    ],
  ];

  for (const [failedKind, expectedMessage] of scenarios) {
    await t.test(failedKind, async () => {
      const calls = [];
      const runCommand = async (command, args, options = {}) => {
        calls.push({ command, args, options });
        const kind = commandKind(args, options);
        if (kind === failedKind) {
          return result(
            0,
            `${SECRET}${POSTGRES_PASSWORD}${MIGRATOR_PASSWORD}${WRITER_PASSWORD}${READER_PASSWORD}\n`,
          );
        }
        return operationResult(kind);
      };

      const error = await captureError(
        runPostgresMigrations(runOptions(runCommand)),
      );

      assert.equal(error.message, expectedMessage);
      assert.ok(!error.message.includes(SECRET));
      assert.ok(!error.message.includes(POSTGRES_PASSWORD));
      assert.ok(!error.message.includes(MIGRATOR_PASSWORD));
      assert.ok(!error.message.includes(WRITER_PASSWORD));
      assert.ok(!error.message.includes(READER_PASSWORD));
      assert.equal(
        commandKind(calls.at(-1).args, calls.at(-1).options),
        "cleanup",
      );
    });
  }
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
