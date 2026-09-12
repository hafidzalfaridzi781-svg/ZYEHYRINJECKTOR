import express from 'express';
import crypto from 'crypto';
import { query } from '../db.js';
import { verifyPassword } from '../utils/password.js';
import { loginLimiter } from '../middleware/rateLimit.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();
const JWT_EXPIRES_IN = parseInt(process.env.JWT_EXPIRES_IN || '3600', 10);

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password, device_id, device_info } = req.body || {};
    if (!username || !password || !device_id)
      return res.status(400).json({ ok: false, code: 'INVALID_CREDENTIALS' });

    const userRes = await query(
      `SELECT id, username, password_hash, is_active FROM users WHERE username = $1 LIMIT 1`,
      [username]
    );
    const user = userRes.rows[0] || null;
    const valid = user
      ? await verifyPassword(user.password_hash, password)
      : await verifyPassword(
          '$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          password
        );
    if (!user || !valid || !user.is_active)
      return res.status(401).json({ ok: false, code: 'INVALID_CREDENTIALS' });

    const devRes = await query(`SELECT device_id FROM user_devices WHERE user_id = $1`, [user.id]);
    if (devRes.rows.length === 0) {
      await query(
        `INSERT INTO user_devices (user_id, device_id, first_ip, last_ip, device_label)
         VALUES ($1, $2, $3, $3, $4)`,
        [user.id, device_id, req.ip, (device_info || '').substring(0, 200)]
      );
    } else {
      if (devRes.rows[0].device_id !== device_id)
        return res.status(403).json({ ok: false, code: 'DEVICE_MISMATCH' });
      await query(
        `UPDATE user_devices SET last_ip = $1, last_seen_at = NOW() WHERE user_id = $2`,
        [req.ip, user.id]
      );
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + JWT_EXPIRES_IN * 1000);

    await query(
      `INSERT INTO sessions (token_hash, user_id, device_id, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [tokenHash, user.id, device_id, req.ip,
       (req.headers['user-agent'] || '').substring(0, 500), expiresAt]
    );

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('hyr_token', rawToken, {
      httpOnly: true, secure: isProd, sameSite: 'strict',
      maxAge: JWT_EXPIRES_IN * 1000, path: '/'
    });

    res.json({
      ok: true, token: rawToken, expires_in: JWT_EXPIRES_IN,
      user: { username: user.username }
    });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  try {
    let token = null;
    if (req.cookies && req.cookies.hyr_token) token = req.cookies.hyr_token;
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer '))
      token = req.headers.authorization.slice(7);

    if (token) {
      const th = crypto.createHash('sha256').update(token).digest('hex');
      await query(`UPDATE sessions SET revoked = TRUE WHERE token_hash = $1`, [th]);
    }
    res.clearCookie('hyr_token', { path: '/' });
    res.json({ ok: true });
  } catch (e) {
    console.error('logout error:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR' });
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: { username: req.user.username } });
});

export default router;