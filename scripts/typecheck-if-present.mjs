import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const ignoredDirectories = new Set([".git", "build", "coverage", "dist", "node_modules", "target"]);
const roots = ["apps", "packages", "src"];

function hasTypeScriptSource(directory) {
  let entries;
  try {
    entries = readdirSync(directory);
  } catch (error) {
    if (error.code === "ENOENT") {
      return false;
    }
    throw error;
  }

  return entries.some((entry) => {
    const fullPath = join(directory, entry);
    const stats = statSync(fullPath);

    if (stats.isDirectory()) {
      return !ignoredDirectories.has(entry) && hasTypeScriptSource(fullPath);
    }

    return entry.endsWith(".ts") || entry.endsWith(".tsx");
  });
}

if (!roots.some(hasTypeScriptSource)) {
  console.log(
    "No TypeScript sources found; strict typecheck is pending until frontend code is added."
  );
  process.exit(0);
}

const result = spawnSync("tsc", ["--noEmit"], { shell: true, stdio: "inherit" });
process.exit(result.status ?? 1);
