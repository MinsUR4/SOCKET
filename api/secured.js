// /api/secured.js
// npm dependency: jsonwebtoken
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'replace-me-in-production';
const ALLOWED_ORIGINS = new Set([
  'https://teach-teach-teach-1-15324649.codehs.me'
]);

// Demo in-memory jti store. Must be the same store as getJwt or shared Redis
const usedJtiStore = new Map();

// --- SECRET PAYLOAD (the code string returned to the client) ---
// Replace iframe.src with your real secret URL if needed
const PAYLOAD = {
  code: `;(function(){ 
    // Secret injection: open about:blank in a new window and insert an iframe.
    try {
      // Try to open a new tab/window (may be blocked unless user-initiated)
      const w = window.open('about:blank', '_blank');

      const injectIntoWindow = (win) => {
        // build minimal HTML then insert iframe
        win.document.open();
        win.document.write('<!doctype html><html><head><meta charset="utf-8"><title>frame</title></head><body style="margin:0;padding:0;height:100vh;">');
        win.document.write('</body></html>');
        win.document.close();

        const iframe = win.document.createElement('iframe');
        iframe.src = 'https://example.com/secret'; // <-- change this to your secret URL
        iframe.style.border = 'none';
        iframe.style.width = '100%';
        iframe.style.height = '100vh';
        win.document.body.appendChild(iframe);
      };

      if (w) {
        // If the popup opened, inject into it
        try { injectIntoWindow(w); } catch(e){ console.error('inject failed', e); }
      } else {
        // Popup blocked - as fallback, try to replace this window's location with about:blank then inject.
        try {
          // NOTE: navigation will stop current scripts, so we open a small intermediate window via data URL
          const w2 = window.open('about:blank', '_self');
          // with _self we get a same-origin about:blank so we can inject
          injectIntoWindow(window);
        } catch (e) {
          console.error('fallback failed', e);
        }
      }

      // Try to close the original tab/window (works only if this was opened by script)
      try { window.close(); } catch (e) { /* ignored */ }

      // If close() failed, try to nudge user: replace body with message (non-ideal)
      setTimeout(() => {
        try {
          if (!window.closed) {
            document.body.innerHTML = '<div style="font-family:system-ui, sans-serif;font-size:14px;padding:20px">If a new window did not open, <a id="openLink" href="#" style="color:blue">click here</a> to open it.</div>';
            document.getElementById('openLink').addEventListener('click', function(ev){ ev.preventDefault(); const nw=window.open('about:blank','_blank'); try { const iframe = nw.document.createElement('iframe'); iframe.src = "https://example.com/secret"; iframe.style.border="none"; iframe.style.width="100%"; iframe.style.height="100vh"; nw.document.body.appendChild(iframe);} catch(e){console.error(e);} });
          }
        } catch(e){}
      }, 500);
    } catch (err) {
      console.error('secret code error', err);
    }
  })();`
};

export default async function handler(req, res) {
  const origin = req.headers.origin || '';

  // Handle OPTIONS preflight
  if (req.method === 'OPTIONS') {
    if (!ALLOWED_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      return res.status(403).end();
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-Fingerprint');
    res.setHeader('Access-Control-Max-Age', '60');
    return res.status(204).end();
  }

  if (!ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-Fingerprint');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Read Authorization header: "Bearer <token>"
  const auth = (req.headers.authorization || '');
  const m = auth.match(/^Bearer\\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing Authorization' });

  const token = m[1];

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // token contains `fp` and `jti`
  const fpFromToken = payload.fp;
  const jti = payload.jti || payload.jti || payload.jti; // jwtid stored as jti normally

  // require client to send computed fingerprint header for extra binding
  const fpHeader = req.headers['x-fingerprint'] || '';
  if (!fpHeader || fpHeader !== fpFromToken) {
    return res.status(403).json({ error: 'Fingerprint mismatch' });
  }

  // check jti unused (demo store): Must use shared Redis in production
  const entry = usedJtiStore.get(jti);
  if (!entry) {
    return res.status(403).json({ error: 'token jti missing/expired' });
  }
  if (entry.used) {
    return res.status(403).json({ error: 'token already used' });
  }
  // mark used
  entry.used = true;
  usedJtiStore.set(jti, entry);

  // ok — return the secret payload
  return res.status(200).json(PAYLOAD);
}
