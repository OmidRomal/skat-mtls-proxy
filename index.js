/**
 * mTLS Proxy for SKAT Sterling File Gateway
 * Handles OCES3 certificate authentication for eIndkomst
 */

const https = require('https');
const http = require('http');

const PORT = process.env.PORT || 3000;
const SKAT_HOST = 'ei-indberetning.skat.dk';
const SKAT_PORT = 444;

// Load certificate from environment (base64 encoded PFX)
const CERT_BASE64 = process.env.OCES3_CERTIFICATE_BASE64;
const CERT_PASSWORD = process.env.OCES3_CERTIFICATE_PASSWORD;

// Allowed API key for securing the proxy
const API_KEY = process.env.PROXY_API_KEY;

// Validate certificate on startup
let pfxBuffer = null;
let certError = null;

if (CERT_BASE64) {
  try {
    pfxBuffer = Buffer.from(CERT_BASE64, 'base64');
    console.log(`[PROXY] Certificate loaded, size: ${pfxBuffer.length} bytes`);
  } catch (e) {
    certError = `Failed to decode certificate: ${e.message}`;
    console.error(`[PROXY] ${certError}`);
  }
} else {
  certError = 'OCES3_CERTIFICATE_BASE64 not set';
  console.error(`[PROXY] ${certError}`);
}

if (!CERT_PASSWORD) {
  certError = certError || 'OCES3_CERTIFICATE_PASSWORD not set';
  console.error(`[PROXY] OCES3_CERTIFICATE_PASSWORD not set`);
}

const server = http.createServer((req, res) => {
  // CORS headers for all responses
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, SOAPAction',
  };

  // Helper to send JSON response
  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, { ...corsHeaders, 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  };

  try {
    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(200, corsHeaders);
      return res.end();
    }

    // Health check endpoint
    if (req.url === '/health' && req.method === 'GET') {
      return sendJson(200, {
        status: certError ? 'degraded' : 'ok',
        timestamp: new Date().toISOString(),
        hasCertificate: !!pfxBuffer,
        hasPassword: !!CERT_PASSWORD,
        certSize: pfxBuffer ? pfxBuffer.length : 0,
        error: certError || undefined
      });
    }

    // Debug endpoint to test proxy without calling SKAT
    if (req.url === '/debug' && req.method === 'GET') {
      return sendJson(200, {
        status: 'ok',
        timestamp: new Date().toISOString(),
        hasCertificate: !!pfxBuffer,
        hasPassword: !!CERT_PASSWORD,
        hasApiKey: !!API_KEY,
        certSize: pfxBuffer ? pfxBuffer.length : 0,
        skatHost: SKAT_HOST,
        skatPort: SKAT_PORT,
        nodeVersion: process.version,
        error: certError || undefined
      });
    }

    // Validate API key for /proxy endpoint
    const apiKey = req.headers['x-api-key'];
    if (API_KEY && apiKey !== API_KEY) {
      console.log(`[PROXY] Invalid API key`);
      return sendJson(401, { error: 'Unauthorized - Invalid API key' });
    }

    // Only allow POST to /proxy
    if (req.method !== 'POST' || !req.url.startsWith('/proxy')) {
      console.log(`[PROXY] Method not allowed: ${req.method} ${req.url}`);
      return sendJson(405, { error: 'Method not allowed', method: req.method, url: req.url });
    }

    // Check certificate is ready
    if (!pfxBuffer || !CERT_PASSWORD) {
      console.log(`[PROXY] Certificate not configured`);
      return sendJson(500, {
        error: 'Certificate not configured',
        details: certError || 'Missing certificate or password'
      });
    }

    // Collect request body
    let body = '';
    req.on('data', chunk => body += chunk);
    
    req.on('error', (err) => {
      console.error(`[PROXY] Request stream error:`, err.message);
      sendJson(400, { error: 'Request error', details: err.message });
    });

    req.on('end', () => {
      try {
        // Parse URL and get SKAT path
        const urlParams = new URL(req.url, `http://${req.headers.host}`);
        const skatPath = urlParams.searchParams.get('path') || '/B2B/EIndkomst/EIndkomstServiceFunctionBinding';
        const soapAction = req.headers['soapaction'] || '';

        console.log(`[PROXY] === New Request ===`);
        console.log(`[PROXY] Target: ${SKAT_HOST}:${SKAT_PORT}${skatPath}`);
        console.log(`[PROXY] SOAPAction: ${soapAction || '(none)'}`);
        console.log(`[PROXY] Body size: ${body.length} bytes`);
        console.log(`[PROXY] Content-Type: ${req.headers['content-type']}`);

        const options = {
          hostname: SKAT_HOST,
          port: SKAT_PORT,
          path: skatPath,
          method: 'POST',
          pfx: pfxBuffer,
          passphrase: CERT_PASSWORD,
          headers: {
            'Content-Type': req.headers['content-type'] || 'text/xml; charset=utf-8',
            'Content-Length': Buffer.byteLength(body, 'utf8'),
            'SOAPAction': soapAction
          },
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2'
        };

        const proxyReq = https.request(options, proxyRes => {
          console.log(`[PROXY] SKAT response status: ${proxyRes.statusCode}`);

          let responseBody = '';
          proxyRes.on('data', chunk => responseBody += chunk);
          
          proxyRes.on('end', () => {
            console.log(`[PROXY] Response size: ${responseBody.length} bytes`);
            console.log(`[PROXY] Response preview: ${responseBody.substring(0, 300)}`);

            res.writeHead(proxyRes.statusCode, {
              ...corsHeaders,
              'Content-Type': proxyRes.headers['content-type'] || 'text/xml'
            });
            res.end(responseBody);
          });
        });

        proxyReq.on('error', (e) => {
          console.error(`[PROXY] HTTPS request error: ${e.message}`);
          console.error(`[PROXY] Error code: ${e.code}`);
          
          // Provide specific error messages for common issues
          let errorMessage = e.message;
          if (e.code === 'ERR_OSSL_PKCS12_MAC_VERIFY_FAILURE') {
            errorMessage = 'Certificate password is incorrect';
          } else if (e.code === 'ERR_OSSL_PKCS12_PKCS12_PFX_PDU_PARSING_ERROR') {
            errorMessage = 'Certificate file is corrupted or invalid';
          } else if (e.code === 'ECONNREFUSED') {
            errorMessage = 'Connection refused by SKAT server';
          } else if (e.code === 'ETIMEDOUT') {
            errorMessage = 'Connection to SKAT timed out';
          }

          sendJson(502, {
            error: 'Failed to connect to SKAT',
            details: errorMessage,
            code: e.code
          });
        });

        proxyReq.write(body);
        proxyReq.end();

      } catch (error) {
        console.error(`[PROXY] Request processing error:`, error.message);
        console.error(`[PROXY] Stack:`, error.stack);
        sendJson(500, {
          error: 'Internal proxy error',
          details: error.message
        });
      }
    });

  } catch (error) {
    console.error(`[PROXY] Unhandled error:`, error.message);
    console.error(`[PROXY] Stack:`, error.stack);
    sendJson(500, {
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Handle uncaught exceptions to prevent crashes
process.on('uncaughtException', (error) => {
  console.error(`[PROXY] Uncaught exception:`, error.message);
  console.error(`[PROXY] Stack:`, error.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error(`[PROXY] Unhandled rejection:`, reason);
});

server.listen(PORT, () => {
  console.log(`[PROXY] ========================================`);
  console.log(`[PROXY] mTLS Proxy for SKAT running on port ${PORT}`);
  console.log(`[PROXY] Certificate loaded: ${!!pfxBuffer} (${pfxBuffer ? pfxBuffer.length : 0} bytes)`);
  console.log(`[PROXY] Password configured: ${!!CERT_PASSWORD}`);
  console.log(`[PROXY] API key required: ${!!API_KEY}`);
  console.log(`[PROXY] Target: ${SKAT_HOST}:${SKAT_PORT}`);
  if (certError) {
    console.log(`[PROXY] WARNING: ${certError}`);
  }
  console.log(`[PROXY] ========================================`);
});
