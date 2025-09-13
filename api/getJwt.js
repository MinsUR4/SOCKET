import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'replace-me-in-production';
const ALLOWED_ORIGINS = new Set([
  'https://teach-teach-teach-1-15324649.codehs.me'
]);

const usedJtiStore = new Map();

// cleanup expired jtis every 60s
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of usedJtiStore.entries()) {
    if (v.expires <= now) usedJtiStore.delete(k);
  }
}, 60_000);

export default async function handler(req, res) {
  const ALLOWED_ORIGINS = new Set([
    'https://teach-teach-teach-1-15324649.codehs.me'
  ]);
  const origin = req.headers.origin || '';

  // --- Handle preflight OPTIONS request ---
  if (req.method === 'OPTIONS') {
    if (!ALLOWED_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      return res.status(403).end();
    }

    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    return res.status(204).end();
  }

  // --- Only allow allowed origins ---
  if (!ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  // --- Set CORS headers for actual POST ---
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // --- Your JWT logic here ---
  const body = await new Promise((resolve, reject) => {
    let s = '';
    req.on('data', chunk => s += chunk);
    req.on('end', () => resolve(JSON.parse(s || '{}')));
    req.on('error', reject);
  });

  const fp = body.fingerprint;
  if (!fp) return res.status(400).json({ error: 'Missing fingerprint' });

  // create short-lived JWT
  const crypto = require('crypto');
  const jwt = require('jsonwebtoken');
  const jti = crypto.randomBytes(16).toString('hex');
  const token = jwt.sign({ fp, jti }, process.env.JWT_SECRET || 'replace-me', { algorithm: 'HS256', expiresIn: '30s', jwtid: jti });

  return res.status(200).json({ token });
}
