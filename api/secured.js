// /api/secured.js (Vercel serverless)
const ALLOWED_ORIGINS = [
  'https://teach-teach-teach-1-15324649.codehs.me/',
  'http://teach-teach-teach-1-15324649.codehs.me/'
];

const PAYLOAD = {
  // server can choose to deliver code or an opaque string
  code: `;(function(){ 
    // secret injection — will create a hidden UI
    const el = document.createElement('div');
    el.id = 'secret-area';
    el.style = 'position:fixed;right:10px;bottom:10px;background:#fff;padding:8px;border-radius:6px;z-index:99999';
    el.innerHTML = '<button id="x">secret</button>';
    document.documentElement.appendChild(el);
    document.getElementById('x').addEventListener('click', ()=>alert("clicked"));
  })();`
};

export default async function handler(req,res){
  const origin = req.headers.origin || '';
  if(!ALLOWED_ORIGINS.includes(origin)){
    res.setHeader('Access-Control-Allow-Origin', 'null');
    return res.status(403).json({error:'forbidden'});
  }
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='GET') return res.status(405).json({error:'method not allowed'});
  // optionally you can do more checks: tokens, rate-limit, fingerprint, etc
  return res.status(200).json(PAYLOAD);
}
