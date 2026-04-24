// ═══════════════════════════════════════════════════════════════
// ChainMind — OKX OnchainOS API Proxy (Vercel Serverless Function)
// ═══════════════════════════════════════════════════════════════
// This proxy keeps your OKX Secret Key safe on the server side.
// Frontend calls YOUR backend → backend signs & forwards to OKX API.
//
// Deploy to Vercel:
//   1. npm i -g vercel
//   2. cd chainmind-backend && vercel
//   3. Set environment variables in Vercel dashboard:
//      OKX_API_KEY, OKX_SECRET_KEY, OKX_PASSPHRASE, OKX_PROJECT_ID
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── Generate OKX API signature ──
function createSignature(timestamp, method, requestPath, secretKey) {
  const preHash = timestamp + method + requestPath;
  const hmac = crypto.createHmac('sha256', secretKey);
  hmac.update(preHash);
  return hmac.digest('base64');
}

// ── Build OKX auth headers ──
function getOKXHeaders(method, requestPath) {
  const apiKey = process.env.OKX_API_KEY;
  const secretKey = process.env.OKX_SECRET_KEY;
  const passphrase = process.env.OKX_PASSPHRASE;
  const projectId = process.env.OKX_PROJECT_ID || '';

  if (!apiKey || !secretKey || !passphrase) {
    throw new Error('Missing OKX API credentials in environment variables');
  }

  const timestamp = new Date().toISOString();
  const sign = createSignature(timestamp, method, requestPath, secretKey);

  const headers = {
    'Content-Type': 'application/json',
    'OK-ACCESS-KEY': apiKey,
    'OK-ACCESS-SIGN': sign,
    'OK-ACCESS-TIMESTAMP': timestamp,
    'OK-ACCESS-PASSPHRASE': passphrase,
  };

  if (projectId) {
    headers['OK-ACCESS-PROJECT'] = projectId;
  }

  return headers;
}

// ── Allowed API endpoints (whitelist for security) ──
const ALLOWED_PATHS = [
  '/api/v6/dex/aggregator/quote',
  '/api/v6/dex/aggregator/swap',
  '/api/v6/dex/aggregator/supported/chain',
  '/api/v6/dex/aggregator/supported/liquidity-source',
  '/api/v6/dex/aggregator/get-liquidity',
  '/api/v6/dex/aggregator/get-tokens',
  '/api/v6/dex/aggregator/all-tokens',
  '/api/v6/dex/aggregator/approve-transaction',
  '/api/v5/wallet/token/current-price',
  '/api/v5/wallet/token/token-detail',
  '/api/v6/dex/market/price-info',
];

module.exports = async (req, res) => {
  // ── CORS headers ──
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Get the target OKX API path from query parameter
    const { path: apiPath, ...queryParams } = req.query;

    if (!apiPath) {
      return res.status(400).json({ error: 'Missing "path" query parameter' });
    }

    // Security: only allow whitelisted API paths
    const basePath = apiPath.split('?')[0];
    if (!ALLOWED_PATHS.includes(basePath)) {
      return res.status(403).json({ error: 'API path not allowed' });
    }

    // Build the full request path with query parameters
    const params = new URLSearchParams(queryParams);
    const fullPath = params.toString() ? `${apiPath}?${params.toString()}` : apiPath;

    // Generate signed headers
    const method = req.method === 'POST' ? 'POST' : 'GET';
    const headers = getOKXHeaders(method, fullPath);

    // Forward request to OKX
    const okxUrl = `https://web3.okx.com${fullPath}`;
    
    const fetchOptions = {
      method,
      headers,
    };

    if (method === 'POST' && req.body) {
      fetchOptions.body = JSON.stringify(req.body);
    }

    const response = await fetch(okxUrl);
    const data = await response.json();

    return res.status(200).json(data);

  } catch (error) {
    console.error('OKX Proxy Error:', error.message);
    return res.status(500).json({ 
      error: 'Proxy error', 
      message: error.message 
    });
  }
};
