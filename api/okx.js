import crypto from 'crypto';

export default async function handler(req, res) {
  const { path, ...queryParams } = req.query;

  if (!path) {
    return res.status(400).json({ error: 'Missing path parameter' });
  }

  // 检查环境变量
  const apiKey = process.env.OKX_API_KEY;
  const secretKey = process.env.OKX_SECRET_KEY;
  const passphrase = process.env.OKX_PASSPHRASE;
  const projectId = process.env.OKX_PROJECT_ID;

  if (!apiKey || !secretKey || !passphrase) {
    return res.status(401).json({
      error: 'Missing OKX API credentials',
      message: 'Please add OKX_API_KEY, OKX_SECRET_KEY, and OKX_PASSPHRASE to Vercel environment variables'
    });
  }

  // 构建 OKX API URL
  let okxUrl = `https://www.okx.com${path}`;
  let queryString = '';

  // 构建查询参数字符串
  if (Object.keys(queryParams).length > 0) {
    const params = new URLSearchParams(queryParams).toString();
    queryString = `?${params}`;
    okxUrl += queryString;
  }

  // 生成签名
  const timestamp = new Date().toISOString();
  const method = 'GET';

  // 签名字符串：timestamp + method + requestPath + queryString
  const signString = timestamp + method + path + queryString;
  const sign = crypto
    .createHmac('sha256', secretKey)
    .update(signString)
    .digest('base64');

  try {
    const response = await fetch(okxUrl, {
      method: 'GET',
      headers: {
        'OK-ACCESS-KEY': apiKey,
        'OK-ACCESS-SIGN': sign,
        'OK-ACCESS-TIMESTAMP': timestamp,
        'OK-ACCESS-PASSPHRASE': passphrase,
        'OK-ACCESS-PROJECT': projectId || '',
        'Content-Type': 'application/json'
      }
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Proxy request failed', message: error.message });
  }
}
