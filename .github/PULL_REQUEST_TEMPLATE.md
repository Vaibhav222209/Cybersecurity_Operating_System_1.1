## 📝 Summary

<!-- What does this PR change and why? Link issues with "Closes #123". -->

## 🔧 Type of change

- [ ] 🐛 Bug fix
- [ ] ✨ New feature (app, terminal command, SIEM rule …)
- [ ] 🎨 UI / UX improvement
- [ ] 📚 Documentation
- [ ] ♻️ Refactor / chore

## 🧪 How was it tested?

- [ ] `npx tsc --noEmit` passes
- [ ] `npm run build` passes
- [ ] Shell smoke tests pass (`tests/shell.smoke.ts`)
- [ ] Manually tested in the browser (describe below)

<!-- Screenshots / GIFs are very welcome for UI changes -->

## ✅ Checklist

- [ ] Follows the existing code style (TypeScript strict, Tailwind utility classes)
- [ ] New terminal commands are registered with `desc`, `usage` and `cat`
- [ ] Nothing performs **real** network scanning — everything stays simulated
- [ ] Docs updated (`README.md` / `docs/COMMANDS.md`) if behaviour changed
