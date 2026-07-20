import { existsSync, readdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE = "Usage: node tools/native-desktop.mjs <preflight|check|build>";
const TEMPORARY_KEYS = new Set(["BIOWORLD_VSDEVCMD", "BIOWORLD_ENV_MARKER"]);
const EXACT_CHILD_KEYS = new Set(
  [
    "ALLUSERSPROFILE",
    "APPDATA",
    "CARGO_BUILD_TARGET",
    "CARGO_HOME",
    "CARGO_HTTP_CHECK_REVOKE",
    "CARGO_HTTP_MULTIPLEXING",
    "CARGO_HTTP_TIMEOUT",
    "CARGO_INCREMENTAL",
    "CARGO_NET_GIT_FETCH_WITH_CLI",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "CI",
    "COMSPEC",
    "COREPACK_DEFAULT_TO_LATEST",
    "COREPACK_ENABLE_DOWNLOAD_PROMPT",
    "COREPACK_HOME",
    "COREPACK_INTEGRITY_KEYS",
    "DEVENVDIR",
    "EXTENSIONSDKDIR",
    "FORCE_COLOR",
    "FRAMEWORK40VERSION",
    "FRAMEWORKDIR",
    "FRAMEWORKDIR32",
    "FRAMEWORKDIR64",
    "FRAMEWORKVERSION",
    "FRAMEWORKVERSION32",
    "FRAMEWORKVERSION64",
    "HOMEDRIVE",
    "HOMEPATH",
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "NO_COLOR",
    "NETFXSDKDIR",
    "OS",
    "PATH",
    "PATHEXT",
    "PNPM_HOME",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SOURCE_DATE_EPOCH",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "UCRTVERSION",
    "UNIVERSALCRTSDKDIR",
    "VCIDEINSTALLDIR",
    "VCINSTALLDIR",
    "VCTOOLSINSTALLDIR",
    "VCTOOLSREDISTDIR",
    "VCTOOLSVERSION",
    "VISUALSTUDIOVERSION",
    "VSCMD_ARG_APP_PLAT",
    "VSCMD_ARG_HOST_ARCH",
    "VSCMD_ARG_TGT_ARCH",
    "VSCMD_VER",
    "VSCMD_DEBUG",
    "VSCMD_START_DIR",
    "VSCMD_PREINIT_PATH",
    "VSINSTALLDIR",
    "WINDIR",
    "WINDOWSLIBPATH",
    "WINDOWSSDKBINPATH",
    "WINDOWSSDKDIR",
    "WINDOWSSDKLIBVERSION",
    "WINDOWSSDKVERSION",
    "__VSCMD_PREINIT_PATH",
  ].map((name) => name.toUpperCase()),
);
const CHILD_KEY_PREFIXES = ["TAURI_ENV_", "VITE_"];
const REQUIREMENT_LABELS = {
  "target-architecture": "x64 target environment",
  "msvc-compiler": "MSVC compiler",
  "msvc-linker": "MSVC linker",
  "windows-resource-compiler": "Windows resource compiler",
  "windows-sdk-headers": "Windows SDK headers",
  "windows-sdk-libraries": "Windows SDK libraries",
};

export function getEnvironmentValue(environment, name) {
  const normalized = name.toUpperCase();
  for (const [key, value] of Object.entries(environment)) {
    if (key.toUpperCase() === normalized) {
      return value;
    }
  }
  return undefined;
}

export function splitWindowsPathList(value) {
  return (value ?? "")
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function findFileInPathList(filename, value, isFile) {
  for (const directory of splitWindowsPathList(value)) {
    const candidate = win32.join(directory, filename);
    if (isFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

export function validateNativeEnvironment(environment, isFile = existsSync) {
  const vcTools = getEnvironmentValue(environment, "VCToolsInstallDir");
  const sdkRoot = getEnvironmentValue(environment, "WindowsSdkDir");
  const sdkVersion = (
    getEnvironmentValue(environment, "WindowsSDKVersion") ??
    getEnvironmentValue(environment, "WindowsSDKLibVersion") ??
    ""
  ).replace(/[\\/]+$/, "");
  const targetArchitecture = getEnvironmentValue(environment, "VSCMD_ARG_TGT_ARCH");
  const missing = [];

  if (targetArchitecture?.toLowerCase() !== "x64") {
    missing.push("target-architecture");
  }
  if (
    !vcTools ||
    !isFile(win32.join(vcTools, "bin", "Hostx64", "x64", "cl.exe"))
  ) {
    missing.push("msvc-compiler");
  }
  if (
    !vcTools ||
    !isFile(win32.join(vcTools, "bin", "Hostx64", "x64", "link.exe"))
  ) {
    missing.push("msvc-linker");
  }
  if (
    !sdkRoot ||
    !sdkVersion ||
    !isFile(win32.join(sdkRoot, "bin", sdkVersion, "x64", "rc.exe"))
  ) {
    missing.push("windows-resource-compiler");
  }
  if (
    !sdkRoot ||
    !sdkVersion ||
    !isFile(win32.join(sdkRoot, "Include", sdkVersion, "um", "windows.h"))
  ) {
    missing.push("windows-sdk-headers");
  }
  if (
    !sdkRoot ||
    !sdkVersion ||
    !isFile(win32.join(sdkRoot, "Lib", sdkVersion, "um", "x64", "kernel32.lib"))
  ) {
    missing.push("windows-sdk-libraries");
  }

  return missing;
}

export function findVswhere(environment, isFile = existsSync) {
  const candidates = [];
  for (const key of ["ProgramFiles(x86)", "ProgramFiles"]) {
    const root = getEnvironmentValue(environment, key);
    if (root) {
      candidates.push(
        win32.join(root, "Microsoft Visual Studio", "Installer", "vswhere.exe"),
      );
    }
  }
  const fromPath = findFileInPathList(
    "vswhere.exe",
    getEnvironmentValue(environment, "PATH"),
    isFile,
  );
  if (fromPath) {
    candidates.push(fromPath);
  }
  return candidates.find((candidate) => isFile(candidate));
}

function listDirectoryNames(path) {
  try {
    return readdirSync(path, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return [];
  }
}

export function findVsDevCmdCandidates(
  environment,
  isFile = existsSync,
  listDirectories = listDirectoryNames,
) {
  const candidates = [];
  const configuredRoot = getEnvironmentValue(environment, "VSINSTALLDIR");
  if (configuredRoot) {
    const configured = win32.join(configuredRoot, "Common7", "Tools", "VsDevCmd.bat");
    if (isFile(configured)) {
      candidates.push(configured);
    }
  }

  for (const key of ["ProgramFiles", "ProgramFiles(x86)"]) {
    const programFiles = getEnvironmentValue(environment, key);
    if (!programFiles) {
      continue;
    }
    const visualStudioRoot = win32.join(programFiles, "Microsoft Visual Studio");
    const versions = listDirectories(visualStudioRoot).sort((left, right) =>
      right.localeCompare(left, undefined, { numeric: true, sensitivity: "base" }),
    );
    for (const version of versions) {
      const versionRoot = win32.join(visualStudioRoot, version);
      const editions = listDirectories(versionRoot).sort((left, right) =>
        left.localeCompare(right, undefined, { sensitivity: "base" }),
      );
      for (const edition of editions) {
        const candidate = win32.join(
          versionRoot,
          edition,
          "Common7",
          "Tools",
          "VsDevCmd.bat",
        );
        if (isFile(candidate)) {
          candidates.push(candidate);
        }
      }
    }
  }
  const seen = new Set();
  return candidates.filter((candidate) => {
    const normalized = candidate.toLowerCase();
    if (seen.has(normalized)) {
      return false;
    }
    seen.add(normalized);
    return true;
  });
}

export function findVsDevCmd(
  environment,
  isFile = existsSync,
  listDirectories = listDirectoryNames,
) {
  return findVsDevCmdCandidates(environment, isFile, listDirectories)[0];
}

export function parseEnvironmentDump(output, marker) {
  const lines = output.split(/\r?\n/).map((line) => line.replace(/^\ufeff/, ""));
  const markerIndex = lines.findIndex((line) => line === marker);
  if (markerIndex === -1) {
    throw new Error("Developer environment capture failed.");
  }

  const environment = {};
  for (const line of lines.slice(markerIndex + 1)) {
    const separator = line.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const key = line.slice(0, separator);
    if (TEMPORARY_KEYS.has(key.toUpperCase())) {
      continue;
    }
    environment[key] = line.slice(separator + 1);
  }
  return environment;
}

export function parseMode(arguments_) {
  const mode = arguments_[0] ?? "preflight";
  if (arguments_.length > 1 || !["preflight", "check", "build"].includes(mode)) {
    throw new Error(USAGE);
  }
  return mode;
}

export function buildChildEnvironment(environment) {
  const child = {};
  for (const [key, value] of Object.entries(environment)) {
    const normalized = key.toUpperCase();
    const allowed =
      EXACT_CHILD_KEYS.has(normalized) ||
      CHILD_KEY_PREFIXES.some((prefix) => normalized.startsWith(prefix));
    if (allowed && !TEMPORARY_KEYS.has(normalized)) {
      child[key] = value;
    }
  }
  return child;
}

export function commandForMode(mode, repositoryRoot) {
  if (mode === "preflight") {
    return null;
  }
  if (mode === "check") {
    return {
      command: "cargo",
      args: ["check", "-p", "bioworld-desktop", "--locked"],
      cwd: repositoryRoot,
    };
  }
  if (mode === "build") {
    const desktopRoot = win32.join(repositoryRoot, "apps", "desktop");
    return {
      command: process.execPath,
      args: [
        win32.join(
          desktopRoot,
          "node_modules",
          "@tauri-apps",
          "cli",
          "tauri.js",
        ),
        "build",
        "--no-bundle",
      ],
      cwd: desktopRoot,
    };
  }
  throw new Error(USAGE);
}

function describeMissingRequirements(missing) {
  return missing.map((code) => REQUIREMENT_LABELS[code]).join(", ");
}

export function initializeNativeEnvironment({
  environment = process.env,
  platform = process.platform,
  isFile = existsSync,
  listDirectories = listDirectoryNames,
  spawn = spawnSync,
  uuid = randomUUID,
} = {}) {
  if (platform !== "win32") {
    throw new Error("Native desktop verification supports Windows only.");
  }

  if (validateNativeEnvironment(environment, isFile).length === 0) {
    return environment;
  }

  const candidates = [];
  const vswhere = findVswhere(environment, isFile);
  if (vswhere) {
    const discovery = spawn(
      vswhere,
      [
        "-all",
        "-products",
        "*",
        "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "-property",
        "installationPath",
        "-utf8",
      ],
      { encoding: "utf8", windowsHide: true },
    );
    const installationPaths =
      discovery.status === 0
        ? (discovery.stdout ?? "")
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
        : [];
    for (const installationPath of installationPaths) {
      const discovered = win32.join(
        installationPath,
        "Common7",
        "Tools",
        "VsDevCmd.bat",
      );
      if (isFile(discovered)) {
        candidates.push(discovered);
      }
    }
  }
  candidates.push(
    ...findVsDevCmdCandidates(environment, isFile, listDirectories),
  );
  const seen = new Set();
  const uniqueCandidates = candidates.filter((candidate) => {
    const normalized = candidate.toLowerCase();
    if (seen.has(normalized)) {
      return false;
    }
    seen.add(normalized);
    return true;
  });
  if (uniqueCandidates.length === 0) {
    throw new Error(
      "A compatible Visual Studio C++ installation was not detected.",
    );
  }

  const command =
    'call "%BIOWORLD_VSDEVCMD%" -no_logo -arch=x64 -host_arch=x64 >nul && echo %BIOWORLD_ENV_MARKER%&& set';
  let lastMissing = [];
  for (const vsDevCmd of uniqueCandidates) {
    const marker = uuid();
    const capture = spawn(
      getEnvironmentValue(environment, "ComSpec") ?? "cmd.exe",
      ["/d", "/u", "/s", "/c", command],
      {
        env: {
          ...buildChildEnvironment(environment),
          BIOWORLD_VSDEVCMD: vsDevCmd,
          BIOWORLD_ENV_MARKER: marker,
        },
        encoding: "utf16le",
        windowsHide: true,
        windowsVerbatimArguments: true,
      },
    );
    if (capture.status !== 0 || typeof capture.stdout !== "string") {
      continue;
    }
    let initialized;
    try {
      initialized = parseEnvironmentDump(capture.stdout, marker);
    } catch {
      continue;
    }
    lastMissing = validateNativeEnvironment(initialized, isFile);
    if (lastMissing.length === 0) {
      return initialized;
    }
  }
  if (lastMissing.length > 0) {
    throw new Error(
      `Native desktop toolchain is incomplete: ${describeMissingRequirements(lastMissing)}.`,
    );
  }
  throw new Error("Visual Studio developer environment initialization failed.");
}

export function runNativeDesktop(
  mode,
  {
    repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), ".."),
    spawn = spawnSync,
    initialize = initializeNativeEnvironment,
  } = {},
) {
  const environment = initialize();
  const command = commandForMode(mode, repositoryRoot);
  if (!command) {
    console.log("Native desktop toolchain ready.");
    return 0;
  }

  const result = spawn(command.command, command.args, {
    cwd: command.cwd,
    env: buildChildEnvironment(environment),
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error || typeof result.status !== "number") {
    throw new Error("Native desktop command could not start.");
  }
  return result.status;
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();

if (isMain) {
  try {
    process.exitCode = runNativeDesktop(parseMode(process.argv.slice(2)));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Native desktop verification failed.");
    process.exitCode = 2;
  }
}
