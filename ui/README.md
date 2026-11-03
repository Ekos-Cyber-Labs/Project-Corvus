# UI

Read-only React and Vite single-page app served by FastAPI. The browser talks only to same-origin `/api`. Model and event text renders as plain text.

## Folder map

- `src/app/` holds `App.tsx`, `routes.tsx`, `AppShell.tsx` and `providers.tsx` for the shell, hash route table, sidebar frame and theme provider.
- `src/api/` holds `client.ts`, `types.ts`, `incidents.ts`, `rules.ts` and `health.ts` for the single same-origin GET fetch wrapper and domain calls.
- `src/components/layout/` holds `Sidebar`, `PageHeader` and `StatusPill`.
- `src/components/ui/` holds `Badge`, `Button`, `Card`, `Table`, `FilterChips`, `Pagination`, `EmptyState`, `ErrorState`, `Spinner` and `Skeleton`.
- `src/components/charts/` holds `SeverityBars`, `SeverityGauge`, `ActivityStrip`, `KillChain`, `BacktestBars` and `LifecycleStepper` plus severity helpers.
- `src/features/incidents/` holds incident pages, components, hooks and utils with tests in `Incidents.test.tsx`.
- `src/features/rules/` holds rule pages, components, hooks and utils with tests in `Rules.test.tsx`.
- `src/app/routes.test.tsx` covers the shell routes and sidebar active state.
- `src/lib/` holds `format.ts`, `attack.ts`, `attackMap.ts`, `theme.ts`, `hash.ts` and `a11y.ts`.
- `src/styles/` holds `tokens.css`, `base.css`, `utilities.css` and one CSS module per component or page.
- `src/test/` holds `setup.ts` and shared fixtures.
- `scripts/generate-attack-map.mjs` regenerates `src/lib/attackMap.ts` from the pinned ATT&CK dictionary.
- `public/favicon.svg` is the site icon.

## Dev

Run the API on port 8000, then:

```bash
npm run dev
```

Vite serves the app and proxies `/api` to `http://127.0.0.1:8000`. Existing hash URLs keep working: `#/`, `#/incidents`, `#/incidents/<id>`, `#/rules`, `#/rules/<id>` and `#/rules?status=shadow`.

## Build

```bash
npm run build
npm test
```

`npm run build` runs `tsc --noEmit` and writes the offline bundle to `ui/dist`. Fonts are self-hosted from the build, never a CDN.
