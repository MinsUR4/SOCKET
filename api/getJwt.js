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
  const origin = req.headers.origin || '';

  // --- Always set some CORS headers ---
  res.setHeader('Vary', 'Origin');

  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'null');
  }

  // --- Handle OPTIONS preflight ---
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(ALLOWED_ORIGINS.has(origin) ? 204 : 403).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Block forbidden origins
  if (!ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  // --- Parse body safely ---
  let body = {};
  try {
    body = await new Promise((resolve, reject) => {
      let s = '';
      req.on('data', chunk => s += chunk);
      req.on('end', () => resolve(JSON.parse(s || '{}')));
      req.on('error', reject);
    });
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const fp = body.fingerprint;
  if (!fp) return res.status(400).json({ error: 'Missing fingerprint' });

  // create short-lived JWT
  const jti = crypto.randomBytes(16).toString('hex');
  const token = jwt.sign(
    { fp, jti },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '30s', jwtid: jti }
  );

  return res.status(200).json({ token });
}
