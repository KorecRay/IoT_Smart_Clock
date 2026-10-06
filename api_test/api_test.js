/**
 * HMAC-SHA256 signature generation function (Compatible with modern browsers & Node.js 16+ Web Crypto API)
 * @param {string} secretKey 35-character secret key (e.g., AUTH_SECRET_KEY)
 * @param {string|number} timestamp Timestamp (in milliseconds or seconds)
 * @returns {Promise<string>} 64-character Hex signature string
 */
export async function generateHmacSignature(secretKey, timestamp) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(String(timestamp))
    );

    return Array.from(new Uint8Array(signatureBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Send a request with HMAC authentication headers to Cloudflare Worker
 * @param {string} workerUrl Worker URL (local test usually http://127.0.0.1:8787)
 * @param {string} secretKey AUTH_SECRET_KEY
 * @param {RequestInit} [options] Additional fetch options
 * @returns {Promise<Response>}
 */
export async function sendAuthenticatedRequest(workerUrl, secretKey, options = {}) {
    const timestamp = Date.now().toString();
    const signature = await generateHmacSignature(secretKey, timestamp);

    const headers = new Headers(options.headers || {});
    headers.set('X-Timestamp', timestamp);
    headers.set('X-Signature', signature);

    return fetch(workerUrl, {
        ...options,
        method: options.method || 'GET',
        headers
    });
}

// Local test demonstration function
export async function runTest(url = 'http://127.0.0.1:8787', secret = 'sdwt2-asdj2-23jfs-213js-hluk7-slkgj') {
    console.log(`[TEST] Sending test request to: ${url}`);
    try {
        const res = await sendAuthenticatedRequest(url, secret);
        const data = await res.json();
        console.log(`[TEST] HTTP Status Code: ${res.status}`);
        console.log('[TEST] Response Content:', data);
        return { status: res.status, data };
    } catch (err) {
        console.error('[TEST] Request failed:', err);
        throw err;
    }
}

// If executed directly via CLI in Node.js (node api_test/api_test.js)
if (typeof process !== 'undefined' && process.argv && process.argv[1]?.endsWith('api_test.js')) {
    runTest();
}