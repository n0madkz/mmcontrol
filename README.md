# MM Control

Web application for project, income, expense, company account, and contract tracking.

## Development

```bash
npm install
npx wrangler pages dev public
```

## Deployment

The application is configured for Cloudflare Pages, D1, and KV in `wrangler.jsonc`.

```bash
npx wrangler pages deploy public --project-name mm-control --branch main
```

The D1 schema is stored in `migrations/`.
