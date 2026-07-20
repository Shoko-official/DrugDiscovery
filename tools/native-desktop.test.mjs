import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { win32 } from "node:path";

import {
  buildChildEnvironment,
  commandForMode,
  findVsDevCmd,
  findVswhere,
  getEnvironmentValue,
  initializeNativeEnvironment,
  parseEnvironmentDump,
  parseMode,
  runNativeDesktop,
  splitWindowsPathList,
  validateNativeEnvironment,
} from "./native-desktop.mjs";

const normalize = (value) => value.toLowerCase();

function fileProbe(files) {
  const known = new Set(files.map(normalize));
  return (path) => known.has(normalize(path));
}

function nativeEnvironment() {
  return {
    PATH: "C:\\VC\\bin;C:\\SDK\\bin",
    INCLUDE: "C:\\VC\\include;C:\\SDK\\include",
    LIB: "C:\\VC\\lib;C:\\SDK\\lib",
    VCToolsInstallDir: "C:\\VC",
    WindowsSdkDir: "C:\\SDK",
    WindowsSDKVersion: "10.0.26100.0\\",
    VSCMD_ARG_TGT_ARCH: "x64",
  };
}

function nativeFiles(environment = nativeEnvironment()) {
  return [
    win32.join(environment.VCToolsInstallDir, "bin", "Hostx64", "x64", "cl.exe"),
    win32.join(environment.VCToolsInstallDir, "bin", "Hostx64", "x64", "link.exe"),
    win32.join(environment.WindowsSdkDir, "bin", "10.0.26100.0", "x64", "rc.exe"),
    win32.join(environment.WindowsSdkDir, "Include", "10.0.26100.0", "um", "windows.h"),
    win32.join(environment.WindowsSdkDir, "Lib", "10.0.26100.0", "um", "x64", "kernel32.lib"),
  ];
}

test("reads Windows environment keys without case sensitivity", () => {
  const environment = { Path: "C:\\Tools;D:\\More", windowsSdkDir: "C:\\SDK" };

  assert.equal(getEnvironmentValue(environment, "PATH"), "C:\\Tools;D:\\More");
  assert.equal(getEnvironmentValue(environment, "WINDOWSSDKDIR"), "C:\\SDK");
  assert.equal(getEnvironmentValue(environment, "MISSING"), undefined);
  assert.deepEqual(splitWindowsPathList(" C:\\Tools ; ;D:\\More "), [
    "C:\\Tools",
    "D:\\More",
  ]);
});

test("parses the developer environment after the marker", () => {
  const dump = [
    "ignored output",
    "READY-123",
    "Path=C:\\Outils;C:\\Rust",
    "UNICODE=C:\\Utilisateurs\\René",
    "VALUE=left=right",
    "=C:=C:\\workspace",
    "BIOWORLD_VSDEVCMD=C:\\private",
    "BIOWORLD_ENV_MARKER=READY-123",
  ].join("\r\n");

  assert.deepEqual(parseEnvironmentDump(dump, "READY-123"), {
    Path: "C:\\Outils;C:\\Rust",
    UNICODE: "C:\\Utilisateurs\\René",
    VALUE: "left=right",
  });
});

test("rejects an environment dump without its marker", () => {
  assert.throws(
    () => parseEnvironmentDump("SECRET_VALUE=hidden", "READY-123"),
    { message: "Developer environment capture failed." },
  );
});

test("validates the compiler, linker, resource compiler, headers, and libraries", () => {
  const environment = nativeEnvironment();
  const files = fileProbe(nativeFiles(environment));

  assert.deepEqual(validateNativeEnvironment(environment, files), []);
  assert.deepEqual(validateNativeEnvironment({}, files), [
    "target-architecture",
    "msvc-compiler",
    "msvc-linker",
    "windows-resource-compiler",
    "windows-sdk-headers",
    "windows-sdk-libraries",
  ]);
  assert.deepEqual(
    validateNativeEnvironment(
      { ...environment, VSCMD_ARG_TGT_ARCH: "x86" },
      files,
    ),
    ["target-architecture"],
  );
});

test("finds vswhere from standard locations before PATH", () => {
  const environment = {
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    ProgramFiles: "C:\\Program Files",
    PATH: "C:\\Fallback",
  };
  const expected = win32.join(
    environment["ProgramFiles(x86)"],
    "Microsoft Visual Studio",
    "Installer",
    "vswhere.exe",
  );

  assert.equal(findVswhere(environment, fileProbe([expected])), expected);
  assert.equal(
    findVswhere({ PATH: "C:\\Fallback" }, fileProbe(["C:\\Fallback\\vswhere.exe"])),
    "C:\\Fallback\\vswhere.exe",
  );
});

test("finds the newest Visual Studio developer command without vswhere", () => {
  const environment = { ProgramFiles: "C:\\Program Files" };
  const visualStudioRoot = win32.join(
    environment.ProgramFiles,
    "Microsoft Visual Studio",
  );
  const expected = win32.join(
    visualStudioRoot,
    "18",
    "Community",
    "Common7",
    "Tools",
    "VsDevCmd.bat",
  );
  const directories = new Map([
    [normalize(visualStudioRoot), ["17", "18"]],
    [normalize(win32.join(visualStudioRoot, "17")), ["BuildTools"]],
    [normalize(win32.join(visualStudioRoot, "18")), ["Community"]],
  ]);

  assert.equal(
    findVsDevCmd(
      environment,
      fileProbe([expected]),
      (path) => directories.get(normalize(path)) ?? [],
    ),
    expected,
  );
});

test("parses supported modes and returns deterministic child commands", () => {
  assert.equal(parseMode([]), "preflight");
  assert.equal(parseMode(["check"]), "check");
  assert.equal(parseMode(["build"]), "build");
  assert.throws(() => parseMode(["release"]), {
    message:
      "Usage: node tools/native-desktop.mjs <preflight|check|test|clippy|build>",
  });

  assert.deepEqual(commandForMode("check", "C:\\repo"), {
    command: "cargo",
    args: ["check", "-p", "bioworld-desktop", "--locked"],
    cwd: "C:\\repo",
  });
  assert.deepEqual(commandForMode("build", "C:\\repo"), {
    command: process.execPath,
    args: [
      win32.join(
        "C:\\repo",
        "apps",
        "desktop",
        "node_modules",
        "@tauri-apps",
        "cli",
        "tauri.js",
      ),
      "build",
      "--no-bundle",
    ],
    cwd: win32.join("C:\\repo", "apps", "desktop"),
  });
  assert.equal(commandForMode("preflight", "C:\\repo"), null);
});

test("maps native test mode to the locked desktop crate tests", () => {
  assert.equal(parseMode(["test"]), "test");
  assert.deepEqual(commandForMode("test", "C:\\repo"), {
    command: "cargo",
    args: ["test", "-p", "bioworld-desktop", "--locked"],
    cwd: "C:\\repo",
  });
});

test("exposes the native desktop test mode through the root package", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );

  assert.equal(
    packageJson.scripts["desktop:native:test"],
    "node tools/native-desktop.mjs test",
  );
});

test("maps native clippy mode to warning-denied checks for all desktop targets", () => {
  assert.equal(parseMode(["clippy"]), "clippy");
  assert.deepEqual(commandForMode("clippy", "C:\\repo"), {
    command: "cargo",
    args: [
      "clippy",
      "-p",
      "bioworld-desktop",
      "--all-targets",
      "--locked",
      "--",
      "-D",
      "warnings",
    ],
    cwd: "C:\\repo",
  });
});

test("exposes the native desktop clippy mode through the root package", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );

  assert.equal(
    packageJson.scripts["desktop:native:clippy"],
    "node tools/native-desktop.mjs clippy",
  );
});

test("builds a restricted child environment without application secrets", () => {
  const environment = {
    Path: "C:\\Tools",
    INCLUDE: "C:\\SDK\\include",
    LIB: "C:\\SDK\\lib",
    VCINSTALLDIR: "C:\\VC",
    WindowsSdkDir: "C:\\SDK",
    CARGO_HOME: "C:\\Cargo",
    RUSTUP_HOME: "C:\\Rustup",
    VITE_PUBLIC_API: "https://example.invalid",
    TAURI_ENV_TARGET_TRIPLE: "x86_64-pc-windows-msvc",
    API_TOKEN: "must-not-pass",
    NPM_TOKEN: "must-not-pass",
    CARGO_REGISTRIES_PRIVATE_TOKEN: "must-not-pass",
    NODE_OPTIONS: "--require=must-not-pass",
    BIOWORLD_VSDEVCMD: "must-not-pass",
    BIOWORLD_ENV_MARKER: "must-not-pass",
  };

  assert.deepEqual(buildChildEnvironment(environment), {
    Path: "C:\\Tools",
    INCLUDE: "C:\\SDK\\include",
    LIB: "C:\\SDK\\lib",
    VCINSTALLDIR: "C:\\VC",
    WindowsSdkDir: "C:\\SDK",
    CARGO_HOME: "C:\\Cargo",
    RUSTUP_HOME: "C:\\Rustup",
    VITE_PUBLIC_API: "https://example.invalid",
    TAURI_ENV_TARGET_TRIPLE: "x86_64-pc-windows-msvc",
  });
});

test("initializes a sanitized x64 developer environment", () => {
  const programFiles = "C:\\Program Files";
  const vsDevCmd = win32.join(
    programFiles,
    "Microsoft Visual Studio",
    "18",
    "Community",
    "Common7",
    "Tools",
    "VsDevCmd.bat",
  );
  const initialized = nativeEnvironment();
  const directories = new Map([
    [normalize(win32.join(programFiles, "Microsoft Visual Studio")), ["18"]],
    [
      normalize(win32.join(programFiles, "Microsoft Visual Studio", "18")),
      ["Community"],
    ],
  ]);
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    const lines = ["READY-123", ...Object.entries(initialized).map(([key, value]) => `${key}=${value}`)];
    return { status: 0, stdout: `${lines.join("\r\n")}\r\n` };
  };

  const result = initializeNativeEnvironment({
    environment: {
      ProgramFiles: programFiles,
      ComSpec: "C:\\Windows\\System32\\cmd.exe",
      NPM_TOKEN: "must-not-pass",
    },
    platform: "win32",
    isFile: fileProbe([vsDevCmd, ...nativeFiles(initialized)]),
    listDirectories: (path) => directories.get(normalize(path)) ?? [],
    spawn,
    uuid: () => "READY-123",
  });

  assert.deepEqual(result, initialized);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args.slice(0, 4), ["/d", "/u", "/s", "/c"]);
  assert.equal(calls[0].options.windowsVerbatimArguments, true);
  assert.equal(calls[0].options.env.NPM_TOKEN, undefined);
  assert.equal(calls[0].options.env.BIOWORLD_VSDEVCMD, vsDevCmd);
});

test("asks vswhere for every compatible installation", () => {
  const programFilesX86 = "C:\\Program Files (x86)";
  const vswhere = win32.join(
    programFilesX86,
    "Microsoft Visual Studio",
    "Installer",
    "vswhere.exe",
  );
  const installation = "C:\\Visual Studio\\Community";
  const vsDevCmd = win32.join(
    installation,
    "Common7",
    "Tools",
    "VsDevCmd.bat",
  );
  const ready = nativeEnvironment();
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args });
    if (command === vswhere) {
      return { status: 0, stdout: `${installation}\r\n` };
    }
    const lines = [
      options.env.BIOWORLD_ENV_MARKER,
      ...Object.entries(ready).map(([key, value]) => `${key}=${value}`),
    ];
    return { status: 0, stdout: `${lines.join("\r\n")}\r\n` };
  };

  assert.deepEqual(
    initializeNativeEnvironment({
      environment: { "ProgramFiles(x86)": programFilesX86 },
      platform: "win32",
      isFile: fileProbe([vswhere, vsDevCmd, ...nativeFiles(ready)]),
      listDirectories: () => [],
      spawn,
      uuid: () => "READY-123",
    }),
    ready,
  );
  assert.equal(calls[0].command, vswhere);
  assert.ok(calls[0].args.includes("-all"));
  assert.ok(!calls[0].args.includes("-latest"));
});

test("tries another Visual Studio installation when the first one is incomplete", () => {
  const programFiles = "C:\\Program Files";
  const visualStudioRoot = win32.join(programFiles, "Microsoft Visual Studio");
  const buildTools = win32.join(
    visualStudioRoot,
    "18",
    "BuildTools",
    "Common7",
    "Tools",
    "VsDevCmd.bat",
  );
  const community = win32.join(
    visualStudioRoot,
    "18",
    "Community",
    "Common7",
    "Tools",
    "VsDevCmd.bat",
  );
  const ready = nativeEnvironment();
  const directories = new Map([
    [normalize(visualStudioRoot), ["18"]],
    [normalize(win32.join(visualStudioRoot, "18")), ["BuildTools", "Community"]],
  ]);
  const calls = [];
  const spawn = (_command, _args, options) => {
    calls.push(options.env.BIOWORLD_VSDEVCMD);
    const values =
      options.env.BIOWORLD_VSDEVCMD === buildTools
        ? { ...ready, VSCMD_ARG_TGT_ARCH: "x86" }
        : ready;
    const lines = [
      options.env.BIOWORLD_ENV_MARKER,
      ...Object.entries(values).map(([key, value]) => `${key}=${value}`),
    ];
    return { status: 0, stdout: `${lines.join("\r\n")}\r\n` };
  };

  const result = initializeNativeEnvironment({
    environment: { ProgramFiles: programFiles },
    platform: "win32",
    isFile: fileProbe([buildTools, community, ...nativeFiles(ready)]),
    listDirectories: (path) => directories.get(normalize(path)) ?? [],
    spawn,
    uuid: () => "READY-123",
  });

  assert.equal(result.VSCMD_ARG_TGT_ARCH, "x64");
  assert.deepEqual(calls, [buildTools, community]);
});

test("propagates native command status without exposing the full environment", () => {
  const calls = [];
  const status = runNativeDesktop("check", {
    repositoryRoot: "C:\\repo",
    initialize: () => ({ ...nativeEnvironment(), API_TOKEN: "must-not-pass" }),
    spawn: (command, args, options) => {
      calls.push({ command, args, options });
      return { status: 7 };
    },
  });

  assert.equal(status, 7);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "cargo");
  assert.deepEqual(calls[0].args, ["check", "-p", "bioworld-desktop", "--locked"]);
  assert.equal(calls[0].options.env.API_TOKEN, undefined);
});
