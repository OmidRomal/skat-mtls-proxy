/**
 * mTLS Proxy for SKAT Sterling File Gateway
 * Handles OCES3 certificate authentication for eIndkomst
 */

const https = require('https');
const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const SKAT_HOST = 'ei-indberetning.skat.dk';
const SKAT_PORT = 444;

// Load certificate from environment (base64 encoded PFX)
const CERT_BASE64 = process.env.OCES3_CERTIFICATE_BASE64;
const CERT_PASSWORD = process.env.OCES3_CERTIFICATE_PASSWORD;

// Allowed API key for securing the proxy
const API_KEY = process.env.PROXY_API_KEY;

const server = http.createServer(async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  // Health check endpoint
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      hasCertificate: !!CERT_BASE64 
    }));
  }

  // Validate API key
  const apiKey = req.headers['x-api-key'];
  if (API_KEY && apiKey !== API_KEY) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized - Invalid API key' }));
  }

  // Only allow POST to /proxy
  if (req.method !== 'POST' || !req.url.startsWith('/proxy')) {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Method not allowed' }));
  }

  // Check certificate configuration
  if (!CERT_BASE64 || !CERT_PASSWORD) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ 
      error: 'Certificate not configured',
      details: 'OCES3_CERTIFICATE_BASE64 and OCES3_CERTIFICATE_PASSWORD must be set'
    }));
  }

  // Collect request body
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try {
      // Decode certificate from base64
      const pfxBuffer = Buffer.from(CERT_BASE64, 'base64');

      // Determine SOAP path from request
      const urlParams = new URL(req.url, `http://${req.headers.host}`);
      const skatPath = urlParams.searchParams.get('path') || '/B2B/EIndkomst/EIndkomstServiceFunctionBinding';

      console.log(`[PROXY] Forwarding to SKAT: ${SKAT_HOST}:${SKAT_PORT}${skatPath}`);
      console.log(`[PROXY] Request size: ${body.length} bytes`);

      const options = {
        hostname: SKAT_HOST,
        port: SKAT_PORT,
        path: skatPath,
        method: 'POST',
        pfx: pfxBuffer,
        passphrase: CERT_PASSWORD,
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          'Content-Length': Buffer.byteLength(body, 'utf8'),
          'SOAPAction': req.headers['soapaction'] || ''
        },
        // Important for mTLS
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      };

      const proxyReq = https.request(options, proxyRes => {
        console.log(`[PROXY] SKAT response status: ${proxyRes.statusCode}`);
        
        let responseBody = '';
        proxyRes.on('data', chunk => responseBody += chunk);
        proxyRes.on('end', () => {
          console.log(`[PROXY] Response size: ${responseBody.length} bytes`);
          
          res.writeHead(proxyRes.statusCode, {
            'Content-Type': proxyRes.headers['content-type'] || 'text/xml',
            'Access-Control-Allow-Origin': '*'
          });
          res.end(responseBody);
        });
      });

      proxyReq.on('error', (e) => {
        console.error(`[PROXY] Error connecting to SKAT:`, e.message);
        console.error(`[PROXY] Error code:`, e.code);
        
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          error: 'Failed to connect to SKAT',
          details: e.message,
          code: e.code
        }));
      });

      proxyReq.write(body);
      proxyReq.end();

    } catch (error) {
      console.error(`[PROXY] Internal error:`, error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        error: 'Internal proxy error',
        details: error.message
      }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`[PROXY] mTLS Proxy for SKAT running on port ${PORT}`);
  console.log(`[PROXY] Certificate configured: ${!!CERT_BASE64}`);
  console.log(`[PROXY] API key required: ${!!API_KEY}`);
});
