# 🤝 Contributing to Sugreev OS

Thank you for considering a contribution! Sugreev OS is a learning project, and every new command, detection rule or UI polish makes it better for the next student.

## 🚀 Getting started

```bash
git clone https://github.com/<your-username>/Sugreev-OS.git
cd Sugreev-OS
npm install
npm run dev          # http://localhost:5173  (password: sugreev)
```

## 🌿 Branching & commits

| Branch | Purpose |
|---|---|
| `main` | Always deployable — protected, merged via PR only |
| `feature/<name>` | New functionality |
| `fix/<name>` | Bug fixes |
| `docs/<name>` | Documentation only |

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(shell): add `lsof` command
fix(siem): keep paused log view stable
docs: describe alert playbooks
```

## ✅ Before you open a PR

```bash
npx tsc --noEmit
npm run build
mkdir -p .tmp
npx esbuild tests/shell.smoke.ts --bundle --platform=node --format=esm --outfile=.tmp/shell.smoke.mjs
node .tmp/shell.smoke.mjs
npx esbuild tests/ui.smoke.tsx --bundle --platform=node --format=esm --jsx=automatic --loader:.css=empty --external:jsdom --outfile=.tmp/ui.smoke.mjs
node .tmp/ui.smoke.mjs
```

## 🧩 Recipes

### Add a terminal command

1. Pick the file: `src/os/shell/sys.ts` (system / files) or `src/os/shell/sec.ts` (security).
2. Register it:

```ts
mycmd: {
  cat: "Security",                       // help category
  desc: "One-line description",
  usage: "mycmd [options] <target>",
  async run(args, c) {
    c.print("Hello from mycmd", "ok");   // kinds: out err ok warn info dim accent crit
    await c.sleep(300);                  // abortable with Ctrl+C
  },
},
```

3. Add a case to `tests/shell.smoke.ts`.
4. Re-generate `docs/COMMANDS.md` (see `docs/ARCHITECTURE.md`).

### Add a SIEM detection rule

Add a template to `TEMPLATES` in `src/os/kernel.ts` (message, severity, MITRE technique) and a row in `RULES` inside `src/apps/Siem.tsx`.

### Add a desktop app

1. Create `src/apps/MyApp.tsx` (default export a component).
2. Register it in `src/os/registry.tsx` and add its id to `AppId` in `src/os/context.tsx`.

## 🛡️ Golden rule — keep it simulated

Contributions **must not** perform real scanning, exploitation, credential attacks or any outbound probing. VAPT features stay deterministic simulations backed by public CVE data.

## 🎨 Style

- TypeScript `strict`, functional React components
- Tailwind utility classes; theme colours via CSS variables (`--accent`)
- Keep apps self-contained in `src/apps/`; shared logic in `src/os/`

## 📜 Code of Conduct

Be kind. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
