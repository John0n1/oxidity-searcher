# mitander.dev

Production frontend for `mitander.dev`.

## Commands

- `npm ci`
- `npm run dev`
- `npm run lint`
- `npm run build`

## Environment

- `VITE_API_BASE_URL`
- `VITE_PUBLIC_RPC_URL`
- `VITE_SUPPORT_EMAIL`

`npm run sync:public-assets` mirrors the canonical PGP key in `public/pgp.asc` to the public routes that need the same content.
