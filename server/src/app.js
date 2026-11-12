import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'node:crypto';
import { doubleCsrf } from 'csrf-csrf';
import { requireAuth } from './middleware/auth.js';
import authRoutes from './routes/auth.js';
import bookingRoutes from './routes/bookings.js';
import userRoutes from './routes/users.js';
import maintenanceRoutes from './routes/maintenance.js';

const app = express();
const fallbackCsrfSecret = randomBytes(32).toString('hex');
const production = process.env.NODE_ENV === 'production';
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || fallbackCsrfSecret,
  // Bind the signature to the entire authenticated session, not just the user ID.
  getSessionIdentifier: (req) => req.cookies.token,
  cookieName: production ? '__Host-csrf-token' : 'csrf-token',
  cookieOptions: { httpOnly: true, secure: production, sameSite: 'lax', path: '/' },
  getCsrfTokenFromRequest: (req) => req.get('x-csrf-token')
});

app.use(morgan('dev'));
// CORS is locked to the client origin with credentials enabled so the browser
// may send the auth cookie on cross-origin XHR. (CORS alone does NOT stop CSRF.)
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse urlencoded bodies so a bare HTML <form> POST (the classic CSRF vector,
// which needs no JavaScript and triggers no CORS preflight) is understood.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/csrf-token', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

app.use('/api', (req, res, next) => {
  // Login and registration establish a session and cannot require its token yet.
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
      (req.method === 'POST' && /^\/auth\/(login|register)\/?$/i.test(req.path))) {
    return next();
  }
  requireAuth(req, res, (err) => {
    if (err) return next(err);
    doubleCsrfProtection(req, res, next);
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/users', userRoutes);
app.use('/api/maintenance', maintenanceRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
