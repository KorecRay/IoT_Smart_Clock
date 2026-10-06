const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Timestamp, X-Signature, X-Api-Key'
};

const MAX_TIMESTAMP_AGE_MS = 1 * 60 * 1000;

/**
 * convert 64 char hex string to Uint8Array
 * @param {string} hex
 * @returns {Uint8Array|null}
 */
function hexToUint8Array(hex) {
    if (
        typeof hex !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(hex)
    ) {
        return null;
    }

    const array = new Uint8Array(32);

    for (let i = 0; i < 32; i++) {
        array[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return array;
}

export default {
    async fetch(request, env, ctx) {
        // process CORS Preflight request
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: CORS });
        }

        const timestamp = request.headers.get('X-Timestamp');
        const signatureHex = request.headers.get('X-Signature');

        if (!timestamp || !signatureHex) {
            return new Response(JSON.stringify({ error: 'Missing X-Timestamp or X-Signature header' }), {
                status: 401,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        if (!env.AUTH_SECRET_KEY) {
            return new Response(JSON.stringify({ error: 'Server authentication key is not configured' }), {
                status: 500,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        // verify timestamp is a valid number and within the allowed time window
        const tsNum = Number(timestamp);
        if (!Number.isFinite(tsNum)) {
            return new Response(JSON.stringify({ error: 'Invalid X-Timestamp value' }), {
                status: 401,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        const tsMs = tsNum < 1e11 ? tsNum * 1000 : tsNum;
        if (Math.abs(Date.now() - tsMs) > MAX_TIMESTAMP_AGE_MS) {
            return new Response(JSON.stringify({ error: 'Request timestamp expired or out of allowed window' }), {
                status: 401,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        // verify Hex signature format
        const signatureBytes = hexToUint8Array(signatureHex);
        if (!signatureBytes) {
            return new Response(JSON.stringify({ error: 'Invalid X-Signature format (must be 64-char hex string)' }), {
                status: 401,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        // import the secret key and use the Web Crypto API to verify the signature
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(env.AUTH_SECRET_KEY),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );

        const isValid = await crypto.subtle.verify(
            'HMAC',
            key,
            signatureBytes,
            encoder.encode(timestamp)
        );

        if (!isValid) {
            return new Response(JSON.stringify({ error: 'Invalid HMAC signature' }), {
                status: 401,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            });
        }

        // return a success res if the request is authsuccessfully
        return new Response(
            JSON.stringify({
                success: true,
                message: 'Authenticated successfully',
                timestamp: Date.now()
            }),
            {
                status: 200,
                headers: { ...CORS, 'Content-Type': 'application/json' }
            }
        );
    }
};