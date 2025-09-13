// /api/secured.js (Vercel serverless / Next-style handler)
const ALLOWED_ORIGINS = new Set([
  'https://ti-84-plus-ce-calculator-15409344.codehs.me',
  'http://ti-84-plus-ce-calculator-15409344.codehs.me',
  'https://teach-teach-teach-1-15324649.codehs.me' // add your CodeHS origin
]);

const PAYLOAD = {
  code: `;(function(){
    // secret injection
    const el = document.createElement('div');
    el.id = 'secret-area';
    el.style = 'position:fixed;right:10px;bottom:10px;background:#fff;padding:8px;border-radius:6px;z-index:99999';
    el.innerHTML = '<button id="x">secret</button>';
    document.documentElement.appendChild(el);
    document.getElementById('x').addEventListener('click', ()=>alert("clicked"));
  })();`
};

export default async function handler(req, res) {
  const origin = req.headers.origin || '';

  // determine if origin is allowed
  const allowed = ALLOWED_ORIGINS.has(origin);

  // If you want to allow requests from same-origin (no origin header), handle that:
  // if (!origin) { /* treat as same-origin or reject depending on your use-case */ }

  // Always respond to OPTIONS preflight with the same CORS headers
  if (req.method === 'OPTIONS') {
    if (!allowed) {
      // rejected preflight — send 403 or minimal headers
      res.setHeader('Access-Control-Allow-Origin', 'null');
      return res.status(403).end();
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Client-Key');
    // allow credentials if client will send them
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    // cache preflight for 60 seconds (optional)
    res.setHeader('Access-Control-Max-Age', '60');
    return res.status(204).end();
  }

  // For non-OPTIONS requests:
  if (!allowed) {
    res.setHeader('Access-Control-Allow-Origin', 'null'); // explicit reject
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  // Allowed origin — set correct CORS headers
  res.setHeader('Access-Control-Allow-Origin', origin); // echo allowed origin
  res.setHeader('Access-Control-Allow-Credentials', 'true'); // required if you use credentials
  res.setHeader('Vary', 'Origin'); // helps caches handle different origins

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // your secure logic here (token checks, rate-limit, fingerprinting, etc.)
  return res.status(200).json(PAYLOAD);
}
