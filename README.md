# ZenithCart

ZenithCart is a Flask-based ecommerce app with a storefront, cart/checkout, admin dashboard, flash sales, and customer reviews.

## Features (everything in the app)
- Storefront pages: home, categories, product details
- Cart and checkout flows
- Orders + order items tracking
- Admin dashboard with metrics, order status updates, products management
- Flash sale management (select items, set duration)
- Product reviews + ratings
- Sign-in and sign-up email notifications
- Optional SMS notifications on sign-in
- Optional M-Pesa STK Push integration

## Tech stack
- Python + Flask
- MySQL (via PyMySQL)
- Bootstrap (templates)

## Requirements
- Python 3.10+ (recommended)
- A MySQL database (local or hosted)

## Quick start (Windows)
1) Create and activate a virtual environment
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

2) Install dependencies
```bash
pip install -r requirements.txt
```

3) Create a `.env` file
```bash
copy .env.example .env
```

4) Run the app
```bash
python app.py
```

Open:
- Storefront: http://127.0.0.1:5000/
- Admin: http://127.0.0.1:5000/admin

## Environment variables (complete list)
Create a `.env` file in the project root and add what you need. Values are grouped by feature.

### Core
- `FLASK_SECRET_KEY` (required)
- `WHATSAPP_NUMBER` (optional; displayed in templates)
- `ADMIN_USERS` (optional; comma-separated usernames that should be admin)
- `FLASK_SESSION_SECURE` (optional; set `1` in production/HTTPS)
- `PORT` (optional; used by Railway and other platforms)

### Database
Use **one** of these approaches:
- `DATABASE_URL` (preferred; e.g. `mysql://user:pass@host:3306/dbname`)
- `MYSQL_URL` or `DB_URL` (same format as `DATABASE_URL`)

Or provide all of:
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

Other DB options:
- `DB_SSL_DISABLED` (optional; set `1` to disable SSL)

### Email (sign-in / sign-up notifications)
- `EMAIL_ENABLED` (optional; `1` or `0`, default is enabled)
- `EMAIL_FROM`
- `EMAIL_FROM_NAME`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_USE_TLS` (optional; default `1`)
- `SMTP_USE_SSL` (optional; default `0`)
- `APP_BASE_URL` (optional; used for links in emails)

### SMS (optional sign-in notification via Africa's Talking)
- `AFRICASTALKING_USERNAME`
- `AFRICASTALKING_API_KEY`
- `DEFAULT_COUNTRY_CODE` (optional; example: `+254`)
- `AFRICASTALKING_SENDER_ID` (optional)

### M-Pesa (optional STK Push)
- `MPESA_BASE_URL` (optional; default: `https://sandbox.safaricom.co.ke`)
- `MPESA_CONSUMER_KEY`
- `MPESA_CONSUMER_SECRET`
- `MPESA_PASSKEY`
- `MPESA_SHORT_CODE` (optional; default: `174379`)
- `MPESA_CALLBACK_URL`

## Database notes
The app expects these tables to exist:
- `users`
- `products`
- `orders`
- `order_items`

These tables are created automatically if missing:
- `product_reviews`
- `flash_sale_settings`
- `flash_sale_items`

If you are starting from scratch, create the DB and core tables before running the app.

## Database setup (SQL)
This repo includes a full schema file:
```bash
mysql -u root -p your_database < scripts/schema.sql
```
Convenience scripts (uses `DB_*` env vars from your shell):
```bash
# Windows PowerShell
.\scripts\init_db.ps1

# macOS/Linux
bash scripts/init_db.sh
```

## Running in production
This repo includes production-ready entrypoints:
- `Procfile` (Gunicorn)
- `wsgi.py` (Gunicorn app loader)
- `runtime.txt` (Python version pin)
- `railway.json` + `nixpacks.toml` (Railway/Nixpacks config)
- `Dockerfile` (container deployments)

Run locally (production-like):
```bash
gunicorn wsgi:app --bind 0.0.0.0:8000
```

## Deploy to Railway (recommended)
1) Push this repo to GitHub.
2) Create a new Railway project and add your repo.
3) Add a MySQL plugin in Railway and copy its connection string.
4) Set env vars in Railway:
   - `DATABASE_URL` (or `MYSQL_URL`) to the Railway MySQL connection string
   - `FLASK_SECRET_KEY`
   - `FLASK_SESSION_SECURE=1`
   - Any optional email/SMS/M-Pesa variables you plan to use
5) Deploy. Railway will use `railway.json` / `nixpacks.toml` or the `Procfile` automatically.

Tip: If you see MySQL connection errors, make sure you used the **public** MySQL host/port or `DATABASE_URL`.

## Deploy to Vercel (alternative)
1) Push this repo to GitHub.
2) In Vercel, import the repo.
3) Add all required env vars in Vercel.
4) Deploy.

`vercel.json` is already included for Python deployments.

## Docker (optional)
Build and run:
```bash
docker build -t zenithcart .
docker run --env-file .env -p 8000:8000 zenithcart
```

## Common issues
- **Module not found**: run `pip install -r requirements.txt` in your venv.
- **Database connection failed**: verify `DATABASE_URL` or `DB_*` values.
- **SMS not sending**: check Africa's Talking keys.
- **Email not sending**: check SMTP settings and `EMAIL_ENABLED=1`.

## Security
- Never commit `.env` or any client secret files.
- Rotate any secrets that were exposed.
