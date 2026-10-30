# Arena backend (starter)
1. `createdb arena && psql $DATABASE_URL -f schema.sql`
2. Secrets: DATABASE_URL, GOOGLE_CLIENT_ID, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET,
   RAZORPAY_WEBHOOK_SECRET, SESSION_SECRET (long random), ADMIN_EMAIL (your Google email).
3. `npm install && npm start`
4. First admin: sign in with Google using ADMIN_EMAIL on a fresh DB. Only the first such login becomes admin.
5. Creator codes: as admin, POST /admin/codes {maxUses, expiresAt}. The plaintext code is returned once.
6. Razorpay: Dashboard > Webhooks > URL `https://<host>/webhooks/razorpay`, event `payment.captured`.
Not yet built: results routes, edit/cancel, dashboards, user suspension, a job to release stale `payment_pending` slots, the frontend.
