// Adds shadcn/ui components from the official registry (non-interactive).
// Usage: node tools/add-registry.mjs card badge button ...
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const REGISTRY_BASES = [
  "https://ui.shadcn.com/r/styles/new-york-v4",
  "https://ui.shadcn.com/r",
];

const names = process.argv.slice(2);
if (!names.length) {
  console.error("no components given");
  process.exit(1);
}

const deps = new Set();

async function fetchEntry(name) {
  for (const base of REGISTRY_BASES) {
    try {
      const res = await fetch(`${base}/${name}.json`);
      if (res.ok) return await res.json();
    } catch {}
  }
  throw new Error(`registry entry not found: ${name}`);
}

async function writeItems(items) {
  for (const item of items) {
    const target = item.target || item.path; // e.g. "@/components/ui/card.tsx"
    const rel = target.replace("@/", "src/");
    const abs = join(ROOT, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, item.content, "utf8");
    console.log(`  + ${rel}`);
  }
}

for (const name of names) {
  const entry = await fetchEntry(name);
  console.log(`* ${entry.name}`);
  for (const d of entry.dependencies ?? []) deps.add(d);
  if (entry.registryDependencies?.length) {
    for (const rd of entry.registryDependencies) {
      if (rd.startsWith("http")) {
        const res = await fetch(rd);
        if (res.ok) await writeItems((await res.json()).files ?? []);
      } else if (!names.includes(rd) && !["utils"].includes(rd)) {
        // resolve simple registry deps one level (hooks, etc.)
        try {
          const depEntry = await fetchEntry(rd);
          for (const d2 of depEntry.dependencies ?? []) deps.add(d2);
          await writeItems(depEntry.files ?? []);
        } catch {
          console.log(`  (skip registry dep: ${rd})`);
        }
      }
    }
  }
  await writeItems(entry.files ?? []);
}

if (deps.size) {
  console.log(`\nnpm deps to install:\nnpm install ${[...deps].join(" ")}`);
}
