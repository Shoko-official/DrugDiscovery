import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const POSTGRES_IMAGE =
  "postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296";

const DATABASE_NAME = "bioworld_migrations";
const SUCCESS_MARKER = "bioworld_migrations_ready";
const TENANT_SUCCESS_MARKER = "bioworld_tenant_access_ready";
const OWNER_SUCCESS_MARKER = "bioworld_owner_boundary_ready";
const POSTGRES_USER = "postgres";
const OWNER_ROLE = "bioworld_owner";
const MIGRATOR_ROLE = "bioworld_migrator";
const WRITER_ROLE = "bioworld_writer";
const MAX_BUFFER = 64 * 1024;
const MAX_MIGRATION_BYTES = 1024 * 1024;
const MAX_TOTAL_MIGRATION_BYTES = 8 * 1024 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES = 16 * 1024;
const COMMAND_TIMEOUT_MS = 120_000;
const CLEANUP_TIMEOUT_MS = 30_000;
const DOCKER_ENVIRONMENT_KEYS = new Set([
  "APPDATA",
  "ALL_PROXY",
  "COMSPEC",
  "DOCKER_CERT_PATH",
  "DOCKER_CONFIG",
  "DOCKER_CONTEXT",
  "DOCKER_HOST",
  "DOCKER_TLS_VERIFY",
  "HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LOCALAPPDATA",
  "NO_PROXY",
  "PATH",
  "PATHEXT",
  "PROGRAMDATA",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "WINDIR",
  "XDG_CONFIG_HOME",
  "XDG_RUNTIME_DIR",
]);
const SESSION_LIMITS = [
  "SET statement_timeout = '60s';",
  "SET lock_timeout = '10s';",
  "SET idle_in_transaction_session_timeout = '60s';",
].join("\n");
const TRANSACTION_LIMITS = [
  "SET LOCAL statement_timeout = '60s';",
  "SET LOCAL lock_timeout = '10s';",
  "SET LOCAL idle_in_transaction_session_timeout = '60s';",
].join("\n");

function appendBounded(current, chunk, maximumBytes) {
  const next = Buffer.concat([current, Buffer.from(chunk)]);
  return next.length <= maximumBytes
    ? next
    : next.subarray(next.length - maximumBytes);
}

function redactText(value, redactions) {
  let redacted = value;
  for (const secret of redactions) {
    redacted = redacted.replaceAll(secret, "[redacted]");
  }
  return redacted.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/giu,
    "$1[redacted]@",
  );
}

export function redactBoundedOutput(buffer, maximumBytes, redactions = []) {
  const values = Array.isArray(redactions) ? redactions : [];
  const secrets = [...new Set(values)].filter(
    (value) =>
      typeof value === "string" &&
      value !== "" &&
      Buffer.byteLength(value, "utf8") <= MAX_ENVIRONMENT_VALUE_BYTES,
  );
  const maximumSecretBytes = secrets.reduce(
    (maximum, value) => Math.max(maximum, Buffer.byteLength(value, "utf8")),
    0,
  );
  const captureBytes = maximumBytes + Math.max(0, maximumSecretBytes - 1);
  const captured =
    buffer.length <= captureBytes
      ? buffer
      : buffer.subarray(buffer.length - captureBytes);
  const sanitized = Buffer.from(redactText(captured.toString("utf8"), secrets));
  return sanitized.length <= maximumBytes
    ? sanitized.toString("utf8")
    : sanitized.subarray(sanitized.length - maximumBytes).toString("utf8");
}

async function defaultRunCommand(
  command,
  args,
  {
    input = "",
    encoding = "utf8",
    windowsHide = true,
    timeout = COMMAND_TIMEOUT_MS,
    maxBuffer = MAX_BUFFER,
    env = process.env,
    redactions = [],
    signal,
  } = {},
) {
  return new Promise((resolveResult) => {
    let settled = false;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let timedOut = false;
    let timer;
    const child = spawn(command, args, {
      env,
      shell: false,
      signal,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide,
    });

    const finish = (status) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolveResult({
        status,
        stdout:
          encoding === "utf8"
            ? redactBoundedOutput(stdout, maxBuffer, redactions)
            : stdout.toString(encoding),
        stderr:
          encoding === "utf8"
            ? redactBoundedOutput(stderr, maxBuffer, redactions)
            : stderr.toString(encoding),
        timedOut,
      });
    };

    const overlapBytes = redactions.reduce(
      (maximum, value) =>
        typeof value === "string"
          ? Math.max(maximum, Buffer.byteLength(value, "utf8"))
          : maximum,
      0,
    );
    const captureBytes = maxBuffer + Math.max(0, overlapBytes - 1);
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk, captureBytes);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk, captureBytes);
    });
    child.on("error", () => finish(null));
    child.on("close", (status) => finish(status));

    timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeout);

    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

function buildDockerEnvironment(environment, injected = {}) {
  const child = {};
  for (const [key, value] of Object.entries(environment)) {
    if (
      DOCKER_ENVIRONMENT_KEYS.has(key.toUpperCase()) &&
      typeof value === "string" &&
      Buffer.byteLength(value, "utf8") <= MAX_ENVIRONMENT_VALUE_BYTES
    ) {
      child[key] = value;
    }
  }
  for (const [key, value] of Object.entries(injected)) {
    if (
      typeof value !== "string" ||
      value === "" ||
      Buffer.byteLength(value, "utf8") > MAX_ENVIRONMENT_VALUE_BYTES
    ) {
      throw new Error("PostgreSQL command environment is invalid.");
    }
    child[key] = value;
  }
  return child;
}

function commandOptions(environment, overrides = {}) {
  return {
    encoding: "utf8",
    windowsHide: true,
    timeout: COMMAND_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
    env: environment,
    ...overrides,
  };
}

async function invoke(runCommand, args, options) {
  try {
    return await runCommand("docker", args, options);
  } catch {
    return { status: null, stdout: "", stderr: "" };
  }
}

function validateSql(value, label) {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    value.includes("\0") ||
    Buffer.byteLength(value, "utf8") > MAX_MIGRATION_BYTES
  ) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

export function createContainerName(nonce) {
  if (typeof nonce !== "string" || !/^[0-9a-f]{24}$/.test(nonce)) {
    throw new Error("PostgreSQL migration container nonce is invalid.");
  }
  return `bioworld-postgres-migrations-${nonce}`;
}

export function discoverMigrations(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("PostgreSQL migrations are missing.");
  }

  let totalBytes = 0;
  const migrations = entries.map((entry) => {
    const match =
      typeof entry?.name === "string"
        ? /^(\d{4})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/.exec(entry.name)
        : null;
    if (!match || entry.isFile !== true) {
      throw new Error("PostgreSQL migration entry is invalid.");
    }
    const sql = validateSql(entry.sql, "PostgreSQL migration");
    totalBytes += Buffer.byteLength(sql, "utf8");
    if (totalBytes > MAX_TOTAL_MIGRATION_BYTES) {
      throw new Error("PostgreSQL migrations exceed the size limit.");
    }
    return { ...entry, version: Number.parseInt(match[1], 10), sql };
  });

  migrations.sort((left, right) => left.version - right.version);
  for (const [index, migration] of migrations.entries()) {
    if (migration.version !== index + 1) {
      throw new Error("PostgreSQL migration versions must be contiguous.");
    }
  }
  return migrations.map(({ version: _version, ...migration }) => migration);
}

function psqlArgs(
  containerName,
  {
    username = POSTGRES_USER,
    environmentKeys = [],
    quiet = true,
    singleTransaction = false,
    tuplesOnly = false,
    unaligned = false,
  } = {},
) {
  const args = [
    "exec",
    "--interactive",
  ];
  for (const key of environmentKeys) {
    args.push("--env", key);
  }
  args.push(
    containerName,
    "psql",
    "--host",
    "127.0.0.1",
    "--username",
    username,
    "--dbname",
    DATABASE_NAME,
    "--no-password",
    "--no-psqlrc",
    "--set",
    "ON_ERROR_STOP=1",
  );
  if (quiet) {
    args.push("--quiet");
  }
  if (tuplesOnly) {
    args.push("--tuples-only");
  }
  if (unaligned) {
    args.push("--no-align");
  }
  if (singleTransaction) {
    args.push("--single-transaction");
  }
  args.push("--file", "-");
  return args;
}

function transactionInput(name, sql) {
  return `-- ${name}\n${SESSION_LIMITS}\n${sql}`;
}

function ownerTransactionInput(name, sql) {
  return [
    `-- ${name}`,
    `SET LOCAL ROLE ${OWNER_ROLE};`,
    "SET LOCAL search_path = public, pg_catalog;",
    TRANSACTION_LIMITS,
    sql,
  ].join("\n");
}

function registerSignalCancellation(abortController, setExitCode) {
  const createHandler = (exitCode) => () => {
    setExitCode(exitCode);
    abortController.abort();
  };
  const onInterrupt = createHandler(130);
  const onTermination = createHandler(143);
  process.once("SIGINT", onInterrupt);
  process.once("SIGTERM", onTermination);
  return () => {
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTermination);
  };
}

function sanitizeDiagnostic(result, secrets) {
  const combined = redactText(
    `${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    secrets,
  ).trim();
  if (combined === "") {
    return "";
  }
  const bytes = Buffer.from(combined, "utf8");
  return (bytes.length <= MAX_BUFFER
    ? bytes
    : bytes.subarray(bytes.length - MAX_BUFFER)
  ).toString("utf8");
}

export async function runPostgresMigrations({
  migrations: migrationEntries,
  fixtureSql,
  verificationSql,
  roleBootstrapSql,
  writerAccessSql,
  tenantVerificationSql,
  ownerVerificationSql,
  nonce,
  postgresPassword,
  migratorPassword,
  writerPassword,
  legacyUpgradeFromVersion,
  runCommand = defaultRunCommand,
  now = Date.now,
  sleep = (milliseconds) =>
    new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds)),
  healthTimeoutMs = 60_000,
  healthPollIntervalMs = 1_000,
  environment = process.env,
  reportDiagnostic,
  signalRegistrar,
} = {}) {
  const migrations = discoverMigrations(migrationEntries);
  const fixture = validateSql(fixtureSql, "PostgreSQL migration fixture");
  const verification = validateSql(
    verificationSql,
    "PostgreSQL migration verification",
  );
  const roleBootstrap = validateSql(
    roleBootstrapSql,
    "PostgreSQL role bootstrap",
  );
  const writerAccess = validateSql(
    writerAccessSql,
    "PostgreSQL writer access provisioning",
  );
  const tenantVerification = validateSql(
    tenantVerificationSql,
    "PostgreSQL tenant verification",
  );
  const ownerVerification = validateSql(
    ownerVerificationSql,
    "PostgreSQL owner verification",
  );
  const containerName = createContainerName(nonce);
  const legacyMigrationCount =
    legacyUpgradeFromVersion === undefined ? 0 : legacyUpgradeFromVersion;
  const passwords = [postgresPassword, migratorPassword, writerPassword];
  if (
    passwords.some(
      (password) =>
        typeof password !== "string" ||
        !/^[0-9a-f]{64}$/.test(password) ||
        password === nonce,
    ) ||
    new Set(passwords).size !== passwords.length
  ) {
    throw new Error("PostgreSQL role passwords are invalid.");
  }
  if (
    !Number.isSafeInteger(healthTimeoutMs) ||
    healthTimeoutMs <= 0 ||
    !Number.isSafeInteger(healthPollIntervalMs) ||
    healthPollIntervalMs <= 0 ||
    healthPollIntervalMs > healthTimeoutMs ||
    typeof now !== "function" ||
    typeof sleep !== "function" ||
    typeof runCommand !== "function" ||
    (signalRegistrar !== undefined && typeof signalRegistrar !== "function") ||
    !Number.isSafeInteger(legacyMigrationCount) ||
    legacyMigrationCount < 0 ||
    legacyMigrationCount >= migrations.length
  ) {
    throw new Error("PostgreSQL migration runner configuration is invalid.");
  }

  const dockerEnvironment = buildDockerEnvironment(environment);
  const startEnvironment = buildDockerEnvironment(
    environment,
    { POSTGRES_PASSWORD: postgresPassword },
  );
  const postgresEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: postgresPassword,
  });
  const bootstrapEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: postgresPassword,
    BIOWORLD_MIGRATOR_PASSWORD: migratorPassword,
    BIOWORLD_WRITER_PASSWORD: writerPassword,
  });
  const migratorEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: migratorPassword,
  });
  const writerEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: writerPassword,
  });
  const diagnosticSecrets = [
    postgresPassword,
    migratorPassword,
    writerPassword,
    ...Object.entries(startEnvironment)
      .filter(
        ([key, value]) =>
          key.toUpperCase().includes("PROXY") ||
          (typeof value === "string" && /:\/\/[^\s/@]+@/u.test(value)),
      )
      .map(([, value]) => value),
  ];
  const abortController =
    runCommand === defaultRunCommand || signalRegistrar !== undefined
      ? new AbortController()
      : undefined;
  let signalExitCode;
  const diagnosticReporter =
    typeof reportDiagnostic === "function"
      ? reportDiagnostic
      : runCommand === defaultRunCommand
        ? (diagnostic) => console.error(diagnostic)
        : () => {};
  const activeOptions = (childEnvironment, overrides = {}) =>
    commandOptions(childEnvironment, {
      redactions: diagnosticSecrets,
      ...overrides,
      ...(abortController ? { signal: abortController.signal } : {}),
    });
  const reportResult = (result) => {
    const diagnostic = sanitizeDiagnostic(result, diagnosticSecrets);
    if (diagnostic !== "") {
      try {
        diagnosticReporter(diagnostic);
      } catch {}
    }
  };
  const collectContainerLogs = async () => {
    const logs = await invoke(
      runCommand,
      ["logs", "--tail", "200", containerName],
      activeOptions(dockerEnvironment, { timeout: 30_000 }),
    );
    reportResult(logs);
  };
  const cleanup = () =>
    invoke(
      runCommand,
      ["rm", "--force", "--volumes", containerName],
      commandOptions(dockerEnvironment, {
        redactions: diagnosticSecrets,
        timeout: CLEANUP_TIMEOUT_MS,
      }),
    );
  const unregisterSignals = abortController
    ? (signalRegistrar ?? registerSignalCancellation)(
        abortController,
        (exitCode) => {
          signalExitCode ??= exitCode;
        },
      )
    : () => {};
  const bootstrapRoles = async () => {
    const bootstrapped = await invoke(
      runCommand,
      psqlArgs(containerName, {
        environmentKeys: [
          "PGPASSWORD",
          "BIOWORLD_MIGRATOR_PASSWORD",
          "BIOWORLD_WRITER_PASSWORD",
        ],
        singleTransaction: true,
      }),
      activeOptions(bootstrapEnvironment, {
        input: transactionInput("bootstrap-roles.sql", roleBootstrap),
      }),
    );
    if (bootstrapped.status !== 0) {
      reportResult(bootstrapped);
      throw new Error("PostgreSQL role bootstrap failed.");
    }
  };
  let primaryError;

  try {
    const started = await invoke(
      runCommand,
      [
        "run",
        "--detach",
        "--rm",
        "--pull=always",
        "--name",
        containerName,
        "--network",
        "none",
        "--env",
        "POSTGRES_PASSWORD",
        "--env",
        `POSTGRES_DB=${DATABASE_NAME}`,
        POSTGRES_IMAGE,
      ],
      activeOptions(startEnvironment),
    );
    if (started.status !== 0) {
      reportResult(started);
      await collectContainerLogs();
      throw new Error("PostgreSQL migration container could not start.");
    }

    const deadline = now() + healthTimeoutMs;
    let responsive = false;
    while (now() < deadline) {
      const health = await invoke(
        runCommand,
        [
          "exec",
          containerName,
          "pg_isready",
          "--host",
          "127.0.0.1",
          "--username",
          POSTGRES_USER,
          "--dbname",
          DATABASE_NAME,
          "--quiet",
        ],
        activeOptions(dockerEnvironment, { timeout: 10_000 }),
      );
      if (health.status === 0) {
        const readiness = await invoke(
          runCommand,
          psqlArgs(containerName, {
            environmentKeys: ["PGPASSWORD"],
            quiet: false,
            tuplesOnly: true,
            unaligned: true,
          }),
          activeOptions(postgresEnvironment, {
            input: "SELECT 1;\n",
            timeout: 10_000,
          }),
        );
        responsive = readiness.status === 0 && readiness.stdout.trim() === "1";
        if (responsive) {
          break;
        }
      }
      await sleep(healthPollIntervalMs);
    }

    if (!responsive) {
      await collectContainerLogs();
      throw new Error("PostgreSQL migration container did not become ready.");
    }

    let rolesBootstrapped = false;
    if (legacyMigrationCount === 0) {
      await bootstrapRoles();
      rolesBootstrapped = true;
    }

    for (const [index, migration] of migrations.entries()) {
      if (!rolesBootstrapped && index === legacyMigrationCount) {
        await bootstrapRoles();
        rolesBootstrapped = true;
      }
      const legacyOwned = index < legacyMigrationCount;
      const migrated = await invoke(
        runCommand,
        psqlArgs(containerName, {
          username: legacyOwned ? POSTGRES_USER : MIGRATOR_ROLE,
          environmentKeys: ["PGPASSWORD"],
          singleTransaction: true,
        }),
        activeOptions(legacyOwned ? postgresEnvironment : migratorEnvironment, {
          input: legacyOwned
            ? transactionInput(migration.name, migration.sql)
            : ownerTransactionInput(migration.name, migration.sql),
        }),
      );
      if (migrated.status !== 0) {
        reportResult(migrated);
        throw new Error("PostgreSQL migrations failed.");
      }
      if (migration.name.startsWith("0001_")) {
        const seeded = await invoke(
          runCommand,
          psqlArgs(containerName, {
            username: legacyOwned ? POSTGRES_USER : MIGRATOR_ROLE,
            environmentKeys: ["PGPASSWORD"],
            singleTransaction: true,
          }),
          activeOptions(
            legacyOwned ? postgresEnvironment : migratorEnvironment,
            {
              input: legacyOwned
                ? transactionInput("after-0001.sql", fixture)
                : ownerTransactionInput("after-0001.sql", fixture),
            },
          ),
        );
        if (seeded.status !== 0) {
          reportResult(seeded);
          throw new Error("PostgreSQL migration fixture failed.");
        }
      }
    }
    if (!rolesBootstrapped) {
      throw new Error("PostgreSQL role bootstrap did not run.");
    }

    const writerProvisioned = await invoke(
      runCommand,
      psqlArgs(containerName, {
        username: MIGRATOR_ROLE,
        environmentKeys: ["PGPASSWORD"],
        singleTransaction: true,
      }),
      activeOptions(migratorEnvironment, {
        input: ownerTransactionInput("grant-writer-access.sql", writerAccess),
      }),
    );
    if (writerProvisioned.status !== 0) {
      reportResult(writerProvisioned);
      throw new Error("PostgreSQL writer access provisioning failed.");
    }

    const verified = await invoke(
      runCommand,
      psqlArgs(containerName, {
        environmentKeys: ["PGPASSWORD"],
        tuplesOnly: true,
        unaligned: true,
      }),
      activeOptions(postgresEnvironment, { input: verification }),
    );
    if (verified.status !== 0) {
      reportResult(verified);
      throw new Error("PostgreSQL migration verification failed.");
    }
    if (verified.stdout.trim() !== SUCCESS_MARKER) {
      throw new Error(
        "PostgreSQL migration verification returned an unexpected result.",
      );
    }

    const tenantVerified = await invoke(
      runCommand,
      psqlArgs(containerName, {
        username: WRITER_ROLE,
        environmentKeys: ["PGPASSWORD"],
        tuplesOnly: true,
        unaligned: true,
      }),
      activeOptions(writerEnvironment, { input: tenantVerification }),
    );
    if (tenantVerified.status !== 0) {
      reportResult(tenantVerified);
      throw new Error("PostgreSQL tenant access verification failed.");
    }
    if (tenantVerified.stdout.trim() !== TENANT_SUCCESS_MARKER) {
      throw new Error(
        "PostgreSQL tenant access verification returned an unexpected result.",
      );
    }

    const ownerVerified = await invoke(
      runCommand,
      psqlArgs(containerName, {
        username: MIGRATOR_ROLE,
        environmentKeys: ["PGPASSWORD"],
        tuplesOnly: true,
        unaligned: true,
      }),
      activeOptions(migratorEnvironment, { input: ownerVerification }),
    );
    if (ownerVerified.status !== 0) {
      reportResult(ownerVerified);
      throw new Error("PostgreSQL owner boundary verification failed.");
    }
    if (ownerVerified.stdout.trim() !== OWNER_SUCCESS_MARKER) {
      throw new Error(
        "PostgreSQL owner boundary verification returned an unexpected result.",
      );
    }
  } catch (error) {
    primaryError =
      error instanceof Error
        ? error
        : new Error("PostgreSQL migration verification failed.");
  } finally {
    const removed = await cleanup();
    unregisterSignals();
    if (signalExitCode !== undefined) {
      process.exitCode = signalExitCode;
      primaryError = new Error("PostgreSQL migration verification interrupted.");
    } else if (removed.status !== 0 && primaryError === undefined) {
      primaryError = new Error(
        "PostgreSQL migration container cleanup failed.",
      );
    }
  }

  if (primaryError !== undefined) {
    throw primaryError;
  }
}

function readBoundedFile(path) {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0 ||
    metadata.size > MAX_MIGRATION_BYTES
  ) {
    throw new Error("PostgreSQL migration input is invalid.");
  }
  return readFileSync(path, "utf8");
}

function resolveOwnedDirectory(repositoryRoot, ...segments) {
  const root = realpathSync(repositoryRoot);
  const candidate = resolve(root, ...segments);
  const metadata = lstatSync(candidate);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("PostgreSQL migration directory is invalid.");
  }
  const directory = realpathSync(candidate);
  const directoryFromRoot = relative(root, directory);
  if (
    directoryFromRoot === "" ||
    directoryFromRoot.startsWith("..") ||
    isAbsolute(directoryFromRoot)
  ) {
    throw new Error("PostgreSQL migration directory is invalid.");
  }
  return directory;
}

function loadInputs(repositoryRoot) {
  const migrationsRoot = resolveOwnedDirectory(repositoryRoot, "migrations");
  const entries = readdirSync(migrationsRoot, { withFileTypes: true }).map(
    (entry) => {
      const path = resolve(migrationsRoot, entry.name);
      const pathFromRoot = relative(migrationsRoot, path);
      if (
        pathFromRoot === "" ||
        pathFromRoot.startsWith("..") ||
        isAbsolute(pathFromRoot)
      ) {
        throw new Error("PostgreSQL migration entry is invalid.");
      }
      const metadata = lstatSync(path);
      if (metadata.size > MAX_MIGRATION_BYTES) {
        throw new Error("PostgreSQL migration entry is invalid.");
      }
      return {
        name: entry.name,
        isFile:
          entry.isFile() && metadata.isFile() && !metadata.isSymbolicLink(),
        sql: metadata.isFile() ? readFileSync(path, "utf8") : "",
      };
    },
  );
  const toolsRoot = resolveOwnedDirectory(repositoryRoot, "tools", "postgres");
  return {
    migrations: entries,
    fixtureSql: readBoundedFile(resolve(toolsRoot, "after-0001.sql")),
    roleBootstrapSql: readBoundedFile(
      resolve(toolsRoot, "bootstrap-roles.sql"),
    ),
    writerAccessSql: readBoundedFile(
      resolve(toolsRoot, "grant-writer-access.sql"),
    ),
    verificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-migrations.sql"),
    ),
    tenantVerificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-tenant-access.sql"),
    ),
    ownerVerificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-owner-boundary.sql"),
    ),
  };
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]).toLowerCase() ===
    fileURLToPath(import.meta.url).toLowerCase();

if (isMain) {
  try {
    const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
    const inputs = loadInputs(repositoryRoot);
    await runPostgresMigrations({
      ...inputs,
      nonce: randomBytes(12).toString("hex"),
      postgresPassword: randomBytes(32).toString("hex"),
      migratorPassword: randomBytes(32).toString("hex"),
      writerPassword: randomBytes(32).toString("hex"),
    });
    await runPostgresMigrations({
      ...inputs,
      nonce: randomBytes(12).toString("hex"),
      postgresPassword: randomBytes(32).toString("hex"),
      migratorPassword: randomBytes(32).toString("hex"),
      writerPassword: randomBytes(32).toString("hex"),
      legacyUpgradeFromVersion: 2,
    });
    console.log("PostgreSQL fresh install and legacy upgrade verified.");
  } catch (error) {
    console.error(
      error instanceof Error
        ? error.message
        : "PostgreSQL migration verification failed.",
    );
    process.exitCode ??= 1;
  }
}
