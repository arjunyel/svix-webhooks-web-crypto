// ex. scripts/build_npm.ts
import { build, emptyDir } from "https://deno.land/x/dnt@0.32.0/mod.ts";

await emptyDir("./npm");

await build({
  entryPoints: ["./src/main.ts"],
  outDir: "./npm",
  compilerOptions: {
    target: "Latest",
    lib: ["es2022", "dom"],
  },
  shims: {
    deno: {
      test: "dev",
    },
  },
  package: {
    // package.json properties
    name: "svix-webhooks-web-crypto",
    version: Deno.args[0],
    description:
      "Verify webhooks from Svix in Bun, Cloudflare Workers, Deno, and Node",
    repository: {
      type: "git",
      url: "git+https://github.com/arjunyel/svix-webhooks-web-crypto.git",
    },
    bugs: {
      url: "https://github.com/arjunyel/svix-webhooks-web-crypto/issues",
    },
    engines: {
      "node": ">=v16",
    },
  },
});

// post build steps
Deno.copyFileSync("README.md", "npm/README.md");
// Deno.copyFileSync("LICENSE", "npm/LICENSE");
