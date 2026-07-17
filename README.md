# MM Control

Web application for project, income, expense, company account, and contract tracking.

## PHP hosting (Plesk)

1. Create a MySQL database and user in Plesk.
2. Copy `public/api/config.example.php` to `public/api/config.php` and enter the MySQL credentials.
3. Upload the contents of `public/` to the website's `httpdocs/` folder.
4. Open the website over HTTPS and sign in. The tables are created automatically on the first request.

The PHP API is in `public/api/`. It provides password login, multi-device synchronization, data storage, and password changes without Node.js.

Face ID / passkeys are disabled in this PHP build until a PHP WebAuthn library is connected.

## Cloudflare development

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
