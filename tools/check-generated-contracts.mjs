import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generatedPath = join("packages", "contracts", "src", "gen");
const committedRoot = join(repositoryRoot, generatedPath);
const temporaryRoot = await mkdtemp(join(tmpdir(), "bioworld-contracts-"));

async function listFiles(directory, root = directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(path, root)));
    } else if (entry.isFile()) {
      files.push(relative(root, path).replaceAll("\\", "/"));
    }
  }

  return files;
}

try {
  const executable = join(
    repositoryRoot,
    "node_modules",
    "@bufbuild",
    "buf",
    "bin",
    "buf",
  );
  const generation = spawnSync(
    process.execPath,
    [executable, "generate", "-o", temporaryRoot],
    {
      cwd: repositoryRoot,
      stdio: "inherit",
    },
  );

  if (generation.error) {
    throw generation.error;
  }
  if (generation.status !== 0) {
    throw new Error(`buf generate exited with status ${generation.status}`);
  }

  const generatedRoot = join(temporaryRoot, generatedPath);
  const committedFiles = await listFiles(committedRoot);
  const generatedFiles = await listFiles(generatedRoot);
  const paths = [...new Set([...committedFiles, ...generatedFiles])].sort();
  const differences = [];

  for (const path of paths) {
    if (!committedFiles.includes(path) || !generatedFiles.includes(path)) {
      differences.push(path);
      continue;
    }

    const [committed, generated] = await Promise.all([
      readFile(join(committedRoot, path)),
      readFile(join(generatedRoot, path)),
    ]);
    if (!committed.equals(generated)) {
      differences.push(path);
    }
  }

  if (differences.length > 0) {
    console.error("Generated contracts are stale:");
    for (const path of differences) {
      console.error(`- ${path}`);
    }
    process.exitCode = 1;
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
