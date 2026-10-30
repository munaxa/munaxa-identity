# Dependency overrides

`pnpm audit --audit-level high` gates every pull request and every push to `main`. A finding is
fixed by upgrading the direct dependency that brings it in. An override in `package.json`
(`pnpm.overrides`) is used only when no release of that direct dependency takes the patched
version yet, and every override is listed here with the condition for removing it.

| Package        | Override | Advisory                                                  | Reaches us through                                 | Runtime image | Why an override                                                                                                                     | Remove when                                                                                             |
| -------------- | -------- | --------------------------------------------------------- | -------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `multer`       | `^2.5.0` | GHSA-q7qp-rjg7-q26m (high, `<2.5.0`), GHSA-3pph-fpjx-jg34 | `@nestjs/platform-express` (pins `multer` exactly) | yes           | `@nestjs/platform-express@11.2.8`, the last 11.x release, pins `multer@2.4.0`. NestJS 12 is a major upgrade of the whole framework. | A `@nestjs/platform-express` 11.x release pins `multer` 2.5.0 or later, or Identity moves to NestJS 12. |
| `deepmerge-ts` | `^8.0.0` | GHSA-ggr8-5vv4-36mx (high, `<8.0.0`)                      | `prisma` > `@prisma/config` (pins `deepmerge-ts`)  | no (CLI only) | `@prisma/config` still pins `deepmerge-ts@7.1.5`.                                                                                   | `@prisma/config` takes `deepmerge-ts` 8 or later.                                                       |

Identity never accepts a multipart body, so the `multer` code path is not reachable from a request
today; it is still in the runtime image, which is why it is patched rather than accepted.

## Not overrides

- `vite` is a root `devDependency` (`^7.3.7`). It is the peer dependency of `vitest`, which pnpm had
  installed automatically at the vulnerable 7.3.6 and would not move on its own. Declaring the
  peer is the supported way to choose its version. Remove it if `vitest` stops needing `vite`, or
  keep it in step with the `vitest` major.
- `proxy-addr` 2.0.8, `body-parser` 2.4.0, `qs` 6.17.1, `fast-uri` 3.1.9, `brace-expansion`
  1.1.21 and 5.0.12, and `source-map-js` 1.2.2 are inside the ranges their parents already declare.
  The lockfile was refreshed for them (`pnpm update --depth Infinity`), with no override.

## Accepted, with no fix available

- `deepmerge` 4.3.1, GHSA-gcqx-w48m-w2h4 (low), through `@nestjs/cli`, then
  `fork-ts-checker-webpack-plugin`. No patched release exists. It is Nest CLI build tooling and is
  not in the runtime image. Revisit when a fixed `deepmerge` is published.
