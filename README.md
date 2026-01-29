# ZenithCart

A simple Flask-based ecommerce store with product listings, cart, checkout, admin dashboard, flash sales, and reviews.

## What you get
- Storefront pages (home, categories, product details)
- Cart + checkout
- Admin dashboard (orders, products, flash sales)
- Flash sales section
- Product reviews and ratings
- Email notifications (sign-in/sign-up)
- SMS notifications (sign-in)

## Tech stack
- Python + Flask
- MySQL (via PyMySQL)
- Bootstrap

## Quick start (Windows)
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file from `.env.example` and fill in real values.

Run the app:
```bash
python app.py
```

Visit:
- Storefront: http://127.0.0.1:5000/
- Admin: http://127.0.0.1:5000/admin

## Environment variables
Start with `.env.example`. Required values depend on the features you use.

Minimum:
- `FLASK_SECRET_KEY`
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `WHATSAPP_NUMBER`

Email (sign-in/sign-up):
- `EMAIL_ENABLED`
- `EMAIL_FROM`, `EMAIL_FROM_NAME`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_USE_TLS`, `SMTP_USE_SSL`

SMS (sign-in notification):
- `AFRICASTALKING_USERNAME`
- `AFRICASTALKING_API_KEY`
- `DEFAULT_COUNTRY_CODE`
- `AFRICASTALKING_SENDER_ID` (optional)

M-Pesa:
- `MPESA_BASE_URL`, `MPESA_CONSUMER_KEY`, `MPESA_CONSUMER_SECRET`
- `MPESA_PASSKEY`, `MPESA_SHORT_CODE`, `MPESA_CALLBACK_URL`

## Database notes
This app expects a MySQL database with the relevant tables (users, products, orders, order_items, etc.).
If you are starting from scratch, create the DB and tables before running the app.

## Deploy (GitHub + Vercel)
1. Push this repo to GitHub.
2. In Vercel, import the repo.
3. Add all required environment variables in Vercel (same keys as `.env`).
4. Deploy.

`vercel.json` is already included for Python deployments.

## Common issues
- **Module not found**: run `pip install -r requirements.txt` in your venv.
- **SMS not sending**: check Africa's Talking keys in `.env`.
- **Email not sending**: check SMTP settings and `EMAIL_ENABLED=1`.

## Security
- Never commit `.env` or any client secret files.
- Rotate any secrets that were exposed.
