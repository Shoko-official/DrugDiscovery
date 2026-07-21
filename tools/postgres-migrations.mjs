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
export const RUST_INTEGRATION_IMAGE =
  "rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1";

const REPOSITORY_ROOT = realpathSync(
  resolve(dirname(fileURLToPath(import.meta.url)), ".."),
);
const DATABASE_NAME = "bioworld_migrations";
const SUCCESS_MARKER = "bioworld_migrations_ready";
const TENANT_SUCCESS_MARKER = "bioworld_tenant_access_ready";
const READER_SUCCESS_MARKER = "bioworld_reader_access_ready";
const OWNER_SUCCESS_MARKER = "bioworld_owner_boundary_ready";
const POSTGRES_USER = "postgres";
const OWNER_ROLE = "bioworld_owner";
const MIGRATOR_ROLE = "bioworld_migrator";
const WRITER_ROLE = "bioworld_writer";
const READER_ROLE = "bioworld_reader";
const MAX_BUFFER = 64 * 1024;
const MAX_MIGRATION_BYTES = 1024 * 1024;
const MAX_TOTAL_MIGRATION_BYTES = 8 * 1024 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES = 16 * 1024;
const COMMAND_TIMEOUT_MS = 120_000;
const CLEANUP_TIMEOUT_MS = 30_000;
const WRITER_BUILD_TIMEOUT_MS = 10 * 60_000;
const WRITER_TEST_TIMEOUT_MS = 5 * 60_000;
const POSTGRES_TLS_CA_FILE = "/postgres-tls/ca.crt";
const POSTGRES_TLS_SETUP_SCRIPT = [
  "umask 077",
  "mkdir -p /postgres-tls",
  "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj /CN=bioworld-postgres-test-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout /postgres-tls/ca.key -out /postgres-tls/ca.crt",
  "openssl req -newkey rsa:2048 -nodes -sha256 -subj /CN=127.0.0.1 -keyout /postgres-tls/server.key -out /postgres-tls/server.csr",
  "printf '%s\\n' 'subjectAltName=IP:127.0.0.1' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' > /postgres-tls/server.ext",
  "openssl x509 -req -in /postgres-tls/server.csr -CA /postgres-tls/ca.crt -CAkey /postgres-tls/ca.key -CAcreateserial -days 1 -sha256 -extfile /postgres-tls/server.ext -out /postgres-tls/server.crt",
  "rm -f /postgres-tls/ca.key /postgres-tls/ca.srl /postgres-tls/server.csr /postgres-tls/server.ext",
  "chmod 600 /postgres-tls/server.key",
  "chmod 644 /postgres-tls/server.crt /postgres-tls/ca.crt",
  "chown postgres:postgres /postgres-tls/server.key /postgres-tls/server.crt",
].join("\n");
const WRITER_TEST_SOURCE_STAGE_SCRIPT = [
  "cp -R /source/apps/decision-server/. /workspace/apps/decision-server/",
  'exec "$@"',
].join("\n");
const WRITER_SOURCE_STAGE_SCRIPT = [
  "umask 077",
  "cd /workspace",
  "git -c safe.directory=/workspace ls-files -z -- Cargo.toml Cargo.lock rust-toolchain.toml apps/desktop/src-tauri apps/decision-server crates proto | tar --null --files-from=- --create | tar --extract --no-same-owner --directory=/sanitized",
  "for source_path in apps/decision-server/Cargo.toml apps/decision-server/src/config.rs apps/decision-server/src/lib.rs apps/decision-server/src/main.rs apps/decision-server/src/runtime.rs apps/decision-server/src/secure_file.rs apps/decision-server/src/windows_acl.rs apps/decision-server/tests/process.rs apps/decision-server/tests/runtime_config.rs apps/decision-server/tests/runtime_integration.rs crates/event-store-postgres/Cargo.toml crates/event-store-postgres/src/lib.rs crates/event-store-postgres/src/reader.rs crates/event-store-postgres/tests/postgres_writer.rs crates/event-store-postgres/tests/postgres_reader.rs crates/decision-grpc/src/service.rs crates/decision-grpc/tests/decision_service.rs crates/decision-grpc-jwt/Cargo.toml crates/decision-grpc-jwt/src/lib.rs crates/decision-grpc-jwt/tests/jwt_authenticator.rs crates/decision-grpc-postgres/Cargo.toml crates/decision-grpc-postgres/src/pool.rs crates/decision-grpc-postgres/tests/postgres_executor.rs crates/decision-grpc-postgres/tests/reader_pool.rs crates/decision-grpc-server/Cargo.toml crates/decision-grpc-server/src/lib.rs crates/decision-grpc-server/src/config.rs crates/decision-grpc-server/src/server.rs crates/decision-grpc-server/tests/server_config.rs crates/decision-grpc-server/tests/server_startup.rs crates/decision-grpc-server/tests/server_transport.rs; do",
  '  test -f "$source_path"',
  '  test ! -L "$source_path"',
  '  mkdir -p "/sanitized/$(dirname "$source_path")"',
  '  cp "$source_path" "/sanitized/$source_path"',
  "done",
].join("\n");
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

function createWriterIntegrationResources(nonce) {
  createContainerName(nonce);
  return {
    sourceContainer: `bioworld-postgres-writer-source-${nonce}`,
    fetchContainer: `bioworld-postgres-writer-fetch-${nonce}`,
    buildContainer: `bioworld-postgres-writer-build-${nonce}`,
    testContainer: `bioworld-postgres-writer-test-${nonce}`,
    cargoVolume: `bioworld-postgres-writer-cargo-${nonce}`,
    targetVolume: `bioworld-postgres-writer-target-${nonce}`,
    sourceVolume: `bioworld-postgres-writer-source-${nonce}`,
  };
}

function createPostgresTlsResources(nonce) {
  createContainerName(nonce);
  return {
    setupContainer: `bioworld-postgres-tls-setup-${nonce}`,
    volume: `bioworld-postgres-tls-${nonce}`,
  };
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
  readerAccessSql,
  tenantVerificationSql,
  readerVerificationSql,
  ownerVerificationSql,
  nonce,
  postgresPassword,
  migratorPassword,
  writerPassword,
  readerPassword,
  legacyUpgradeFromVersion,
  writerIntegration = false,
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
  const readerAccess = validateSql(
    readerAccessSql,
    "PostgreSQL reader access provisioning",
  );
  const tenantVerification = validateSql(
    tenantVerificationSql,
    "PostgreSQL tenant verification",
  );
  const readerVerification = validateSql(
    readerVerificationSql,
    "PostgreSQL reader verification",
  );
  const ownerVerification = validateSql(
    ownerVerificationSql,
    "PostgreSQL owner verification",
  );
  const containerName = createContainerName(nonce);
  const legacyMigrationCount =
    legacyUpgradeFromVersion === undefined ? 0 : legacyUpgradeFromVersion;
  const passwords = [
    postgresPassword,
    migratorPassword,
    writerPassword,
    readerPassword,
  ];
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
    typeof writerIntegration !== "boolean" ||
    !Number.isSafeInteger(legacyMigrationCount) ||
    legacyMigrationCount < 0 ||
    legacyMigrationCount >= migrations.length ||
    (writerIntegration && legacyMigrationCount !== 0)
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
    BIOWORLD_READER_PASSWORD: readerPassword,
  });
  const migratorEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: migratorPassword,
  });
  const writerEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: writerPassword,
  });
  const readerEnvironment = buildDockerEnvironment(environment, {
    PGPASSWORD: readerPassword,
  });
  const writerIntegrationEnvironment = writerIntegration
    ? buildDockerEnvironment(environment, {
        BIOWORLD_POSTGRES_WRITER_PASSWORD: writerPassword,
        BIOWORLD_POSTGRES_READER_PASSWORD: readerPassword,
      })
    : undefined;
  const writerResources = writerIntegration
    ? createWriterIntegrationResources(nonce)
    : undefined;
  const postgresTlsResources = createPostgresTlsResources(nonce);
  const diagnosticSecrets = [
    postgresPassword,
    migratorPassword,
    writerPassword,
    readerPassword,
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
  const cleanupDatabase = () =>
    invoke(
      runCommand,
      ["rm", "--force", "--volumes", containerName],
      commandOptions(dockerEnvironment, {
        redactions: diagnosticSecrets,
        timeout: CLEANUP_TIMEOUT_MS,
      }),
    );
  const cleanupContainer = (name) =>
    invoke(
      runCommand,
      ["rm", "--force", "--volumes", name],
      commandOptions(dockerEnvironment, {
        redactions: diagnosticSecrets,
        timeout: CLEANUP_TIMEOUT_MS,
      }),
    );
  const cleanupVolume = (name) =>
    invoke(
      runCommand,
      ["volume", "rm", "--force", name],
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
          "BIOWORLD_READER_PASSWORD",
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
  let sourceContainerAttempted = false;
  let fetchContainerAttempted = false;
  let buildContainerAttempted = false;
  let testContainerAttempted = false;
  let tlsSetupContainerAttempted = false;
  let primaryError;

  try {
    const tlsVolume = await invoke(
      runCommand,
      ["volume", "create", "--name", postgresTlsResources.volume],
      activeOptions(dockerEnvironment, { timeout: CLEANUP_TIMEOUT_MS }),
    );
    if (tlsVolume.status !== 0) {
      reportResult(tlsVolume);
      throw new Error("PostgreSQL TLS storage failed.");
    }

    tlsSetupContainerAttempted = true;
    const tlsIdentityGenerated = await invoke(
      runCommand,
      [
        "run",
        "--name",
        postgresTlsResources.setupContainer,
        "--pull=always",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--security-opt",
        "no-new-privileges:true",
        "--mount",
        `type=volume,source=${postgresTlsResources.volume},target=/postgres-tls`,
        POSTGRES_IMAGE,
        "sh",
        "-ceu",
        POSTGRES_TLS_SETUP_SCRIPT,
      ],
      activeOptions(dockerEnvironment),
    );
    if (tlsIdentityGenerated.status !== 0) {
      reportResult(tlsIdentityGenerated);
      throw new Error("PostgreSQL TLS identity generation failed.");
    }

    if (writerResources !== undefined) {
      const rustImagePulled = await invoke(
        runCommand,
        ["pull", RUST_INTEGRATION_IMAGE],
        activeOptions(dockerEnvironment, { timeout: WRITER_BUILD_TIMEOUT_MS }),
      );
      if (rustImagePulled.status !== 0) {
        reportResult(rustImagePulled);
        throw new Error("PostgreSQL writer integration image pull failed.");
      }

      const cargoVolume = await invoke(
        runCommand,
        ["volume", "create", "--name", writerResources.cargoVolume],
        activeOptions(dockerEnvironment, { timeout: CLEANUP_TIMEOUT_MS }),
      );
      if (cargoVolume.status !== 0) {
        reportResult(cargoVolume);
        throw new Error("PostgreSQL writer integration storage failed.");
      }
      const targetVolume = await invoke(
        runCommand,
        ["volume", "create", "--name", writerResources.targetVolume],
        activeOptions(dockerEnvironment, { timeout: CLEANUP_TIMEOUT_MS }),
      );
      if (targetVolume.status !== 0) {
        reportResult(targetVolume);
        throw new Error("PostgreSQL writer integration storage failed.");
      }
      const sourceVolume = await invoke(
        runCommand,
        ["volume", "create", "--name", writerResources.sourceVolume],
        activeOptions(dockerEnvironment, { timeout: CLEANUP_TIMEOUT_MS }),
      );
      if (sourceVolume.status !== 0) {
        reportResult(sourceVolume);
        throw new Error("PostgreSQL writer integration storage failed.");
      }

      sourceContainerAttempted = true;
      const sourceStaged = await invoke(
        runCommand,
        [
          "run",
          "--name",
          writerResources.sourceContainer,
          "--pull=never",
          "--network",
          "none",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--mount",
          `type=bind,source=${REPOSITORY_ROOT},target=/workspace,readonly`,
          "--mount",
          `type=volume,source=${writerResources.sourceVolume},target=/sanitized`,
          "--workdir",
          "/workspace",
          RUST_INTEGRATION_IMAGE,
          "sh",
          "-ceu",
          WRITER_SOURCE_STAGE_SCRIPT,
        ],
        activeOptions(dockerEnvironment, { timeout: COMMAND_TIMEOUT_MS }),
      );
      if (sourceStaged.status !== 0) {
        reportResult(sourceStaged);
        throw new Error("PostgreSQL writer integration source staging failed.");
      }

      fetchContainerAttempted = true;
      const dependenciesFetched = await invoke(
        runCommand,
        [
          "run",
          "--name",
          writerResources.fetchContainer,
          "--pull=never",
          "--network",
          "bridge",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--mount",
          `type=volume,source=${writerResources.sourceVolume},target=/workspace,readonly`,
          "--mount",
          `type=volume,source=${writerResources.cargoVolume},target=/cargo`,
          "--env",
          "CARGO_HOME=/cargo",
          "--env",
          "RUSTUP_TOOLCHAIN=1.95.0",
          "--workdir",
          "/workspace",
          RUST_INTEGRATION_IMAGE,
          "cargo",
          "fetch",
          "--locked",
        ],
        activeOptions(dockerEnvironment, { timeout: WRITER_BUILD_TIMEOUT_MS }),
      );
      if (dependenciesFetched.status !== 0) {
        reportResult(dependenciesFetched);
        throw new Error("PostgreSQL writer integration dependency fetch failed.");
      }

      buildContainerAttempted = true;
      const writerBuilt = await invoke(
        runCommand,
        [
          "run",
          "--name",
          writerResources.buildContainer,
          "--pull=never",
          "--network",
          "none",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--mount",
          `type=volume,source=${writerResources.sourceVolume},target=/workspace,readonly`,
          "--mount",
          `type=volume,source=${writerResources.cargoVolume},target=/cargo`,
          "--mount",
          `type=volume,source=${writerResources.targetVolume},target=/target`,
          "--env",
          "CARGO_HOME=/cargo",
          "--env",
          "CARGO_TARGET_DIR=/target",
          "--env",
          "CARGO_NET_OFFLINE=true",
          "--env",
          "RUSTUP_TOOLCHAIN=1.95.0",
          "--workdir",
          "/workspace",
          RUST_INTEGRATION_IMAGE,
          "cargo",
          "test",
          "-p",
          "bioworld-event-store-postgres",
          "-p",
          "bioworld-decision-grpc-postgres",
          "-p",
          "bioworld-decision-server",
          "--tests",
          "--locked",
          "--offline",
          "--no-run",
        ],
        activeOptions(dockerEnvironment, { timeout: WRITER_BUILD_TIMEOUT_MS }),
      );
      if (writerBuilt.status !== 0) {
        reportResult(writerBuilt);
        throw new Error("PostgreSQL writer integration build failed.");
      }
    }

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
        "--env",
        "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
        "--mount",
        `type=volume,source=${postgresTlsResources.volume},target=/postgres-tls,readonly`,
        POSTGRES_IMAGE,
        "postgres",
        "-c",
        "ssl=on",
        "-c",
        "ssl_cert_file=/postgres-tls/server.crt",
        "-c",
        "ssl_key_file=/postgres-tls/server.key",
        "-c",
        "ssl_min_protocol_version=TLSv1.2",
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

    const readerProvisioned = await invoke(
      runCommand,
      psqlArgs(containerName, {
        username: MIGRATOR_ROLE,
        environmentKeys: ["PGPASSWORD"],
        singleTransaction: true,
      }),
      activeOptions(migratorEnvironment, {
        input: ownerTransactionInput("grant-reader-access.sql", readerAccess),
      }),
    );
    if (readerProvisioned.status !== 0) {
      reportResult(readerProvisioned);
      throw new Error("PostgreSQL reader access provisioning failed.");
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

    const readerVerified = await invoke(
      runCommand,
      psqlArgs(containerName, {
        username: READER_ROLE,
        environmentKeys: ["PGPASSWORD"],
        tuplesOnly: true,
        unaligned: true,
      }),
      activeOptions(readerEnvironment, { input: readerVerification }),
    );
    if (readerVerified.status !== 0) {
      reportResult(readerVerified);
      throw new Error("PostgreSQL reader access verification failed.");
    }
    if (readerVerified.stdout.trim() !== READER_SUCCESS_MARKER) {
      throw new Error(
        "PostgreSQL reader access verification returned an unexpected result.",
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

    if (writerResources !== undefined) {
      testContainerAttempted = true;
      const writerTested = await invoke(
        runCommand,
        [
          "run",
          "--name",
          writerResources.testContainer,
          "--pull=never",
          "--network",
          `container:${containerName}`,
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--mount",
          `type=volume,source=${writerResources.sourceVolume},target=/workspace,readonly`,
          "--mount",
          `type=volume,source=${writerResources.sourceVolume},target=/source,readonly`,
          "--mount",
          `type=volume,source=${writerResources.cargoVolume},target=/cargo`,
          "--mount",
          `type=volume,source=${writerResources.targetVolume},target=/target`,
          "--mount",
          `type=volume,source=${postgresTlsResources.volume},target=/postgres-tls,readonly`,
          "--tmpfs",
          "/workspace/apps/decision-server:rw,noexec,nosuid,nodev,size=1048576",
          "--env",
          "BIOWORLD_POSTGRES_WRITER_PASSWORD",
          "--env",
          "BIOWORLD_POSTGRES_READER_PASSWORD",
          "--env",
          `BIOWORLD_POSTGRES_TLS_CA_FILE=${POSTGRES_TLS_CA_FILE}`,
          "--env",
          "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED=1",
          "--env",
          "CARGO_HOME=/cargo",
          "--env",
          "CARGO_TARGET_DIR=/target",
          "--env",
          "CARGO_NET_OFFLINE=true",
          "--env",
          "RUSTUP_TOOLCHAIN=1.95.0",
          "--workdir",
          "/workspace",
          RUST_INTEGRATION_IMAGE,
          "sh",
          "-ceu",
          WRITER_TEST_SOURCE_STAGE_SCRIPT,
          "sh",
          "cargo",
          "test",
          "--manifest-path",
          "/workspace/Cargo.toml",
          "--package",
          "bioworld-event-store-postgres",
          "--package",
          "bioworld-decision-grpc-postgres",
          "--package",
          "bioworld-decision-server",
          "--tests",
          "--locked",
          "--offline",
        ],
        activeOptions(writerIntegrationEnvironment, {
          timeout: WRITER_TEST_TIMEOUT_MS,
        }),
      );
      if (writerTested.status !== 0) {
        reportResult(writerTested);
        throw new Error("PostgreSQL writer integration verification failed.");
      }
    }
  } catch (error) {
    primaryError =
      error instanceof Error
        ? error
        : new Error("PostgreSQL migration verification failed.");
  } finally {
    let cleanupFailed = false;
    if (testContainerAttempted && writerResources !== undefined) {
      const removed = await cleanupContainer(writerResources.testContainer);
      cleanupFailed ||= removed.status !== 0;
    }
    if (buildContainerAttempted && writerResources !== undefined) {
      const removed = await cleanupContainer(writerResources.buildContainer);
      cleanupFailed ||= removed.status !== 0;
    }
    if (fetchContainerAttempted && writerResources !== undefined) {
      const removed = await cleanupContainer(writerResources.fetchContainer);
      cleanupFailed ||= removed.status !== 0;
    }
    if (sourceContainerAttempted && writerResources !== undefined) {
      const removed = await cleanupContainer(writerResources.sourceContainer);
      cleanupFailed ||= removed.status !== 0;
    }
    const removed = await cleanupDatabase();
    cleanupFailed ||= removed.status !== 0;
    if (tlsSetupContainerAttempted) {
      const removedTlsSetup = await cleanupContainer(
        postgresTlsResources.setupContainer,
      );
      cleanupFailed ||= removedTlsSetup.status !== 0;
    }
    const removedTlsVolume = await cleanupVolume(postgresTlsResources.volume);
    cleanupFailed ||= removedTlsVolume.status !== 0;
    if (writerResources !== undefined) {
      const removedVolume = await cleanupVolume(writerResources.sourceVolume);
      cleanupFailed ||= removedVolume.status !== 0;
    }
    if (writerResources !== undefined) {
      const removedVolume = await cleanupVolume(writerResources.targetVolume);
      cleanupFailed ||= removedVolume.status !== 0;
    }
    if (writerResources !== undefined) {
      const removedVolume = await cleanupVolume(writerResources.cargoVolume);
      cleanupFailed ||= removedVolume.status !== 0;
    }
    unregisterSignals();
    if (signalExitCode !== undefined) {
      process.exitCode = signalExitCode;
      primaryError = new Error("PostgreSQL migration verification interrupted.");
    } else if (cleanupFailed && primaryError === undefined) {
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
    readerAccessSql: readBoundedFile(
      resolve(toolsRoot, "grant-reader-access.sql"),
    ),
    verificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-migrations.sql"),
    ),
    tenantVerificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-tenant-access.sql"),
    ),
    readerVerificationSql: readBoundedFile(
      resolve(toolsRoot, "verify-reader-access.sql"),
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
    const inputs = loadInputs(REPOSITORY_ROOT);
    await runPostgresMigrations({
      ...inputs,
      nonce: randomBytes(12).toString("hex"),
      postgresPassword: randomBytes(32).toString("hex"),
      migratorPassword: randomBytes(32).toString("hex"),
      writerPassword: randomBytes(32).toString("hex"),
      readerPassword: randomBytes(32).toString("hex"),
      writerIntegration: true,
    });
    await runPostgresMigrations({
      ...inputs,
      nonce: randomBytes(12).toString("hex"),
      postgresPassword: randomBytes(32).toString("hex"),
      migratorPassword: randomBytes(32).toString("hex"),
      writerPassword: randomBytes(32).toString("hex"),
      readerPassword: randomBytes(32).toString("hex"),
      legacyUpgradeFromVersion: 2,
    });
    await runPostgresMigrations({
      ...inputs,
      nonce: randomBytes(12).toString("hex"),
      postgresPassword: randomBytes(32).toString("hex"),
      migratorPassword: randomBytes(32).toString("hex"),
      writerPassword: randomBytes(32).toString("hex"),
      readerPassword: randomBytes(32).toString("hex"),
      legacyUpgradeFromVersion: 3,
    });
    console.log(
      "PostgreSQL fresh install and version 2 and 3 upgrades verified.",
    );
  } catch (error) {
    console.error(
      error instanceof Error
        ? error.message
        : "PostgreSQL migration verification failed.",
    );
    process.exitCode ??= 1;
  }
}
