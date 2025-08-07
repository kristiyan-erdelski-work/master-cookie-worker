/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

// src/index.js

export default {
    async fetch(request, env, ctx) {
        return await setMasterCookie(request);
    },
};

/**
 * Handles incoming requests to set a master cookie based on user consent.
 * This Worker acts as a proxy, fetching the original content and then modifying its headers.
 * @param {Request} request The incoming HTTP request.
 * @returns {Response} The modified HTTP response with the master cookie set if consent is given.
 */
async function setMasterCookie(request) {
  const CONSENT_COOKIE_NAME = 'CookieConsent';
  const MASTER_COOKIE_NAME = 'whg_mid';
  let cookies;

  const cookieHeader = request.headers.get('Cookie');

  let hasConsent = false;
  let consentValue = null;

  // Parse existing cookies from the request header
  if (cookieHeader) {
    cookies = cookieHeader.split('; ').reduce((acc, cookie) => {
      const parts = cookie.split('=');
      const name = decodeURIComponent(parts[0]);
      const value = decodeURIComponent(parts.slice(1).join('='));
      acc[name] = value;
      return acc;
    }, {});

    // Check if the consent cookie exists and indicates consent for statistics or marketing
    if (cookies[CONSENT_COOKIE_NAME]) {
      consentValue = cookies[CONSENT_COOKIE_NAME];
      if (consentValue.includes('statistics:true') || consentValue.includes('marketing:true')) {
        hasConsent = true;
      }
    }
  }

  // Determine the root domain for setting the cookie
  const url = new URL(request.url);
  let domain = url.hostname;
  const two_part_tlds = ['com.co', 'co.uk', 'co.nz', 'com.au'];

  const parts = domain.split('.');
  if (parts.length > 2 && !two_part_tlds.includes(parts.slice(-2).join('.'))) {
    domain = parts.slice(-2).join('.');
  } else if (parts.length > 2 && two_part_tlds.includes(parts.slice(-2).join('.'))) {
    domain = parts.slice(-3).join('.');
  }
  const rootDomain = `.${domain}`;

  // Fetch the original request. When deployed, this will proxy to your origin server.
  // During local development (wrangler dev), this will fetch from localhost:8787.
  // Ensure your local dev setup (e.g., a web server running on another port)
  // handles requests if you need to test against specific content.
  let originalResponse = await fetch(request);

  // Create a new Response object to ensure its headers are mutable.
  // Copy the body and headers from the original response.
  let response = new Response(originalResponse.body, {
      status: originalResponse.status,
      statusText: originalResponse.statusText,
      headers: new Headers(originalResponse.headers)
  });

  // If consent is given, append the master cookie to the response headers
  if (hasConsent) {
    // Reuse existing master cookie value or generate a new UUID
    const COOKIE_VALUE = cookies[MASTER_COOKIE_NAME] || crypto.randomUUID();
    const EXPIRY_SECONDS = 60 * 60 * 24 * 730; // 2 years

    response.headers.append(
      'Set-Cookie',
      `${MASTER_COOKIE_NAME}=${COOKIE_VALUE}; Path=/; Max-Age=${EXPIRY_SECONDS}; Domain=${rootDomain}; Secure; SameSite=Lax`
    );
  }

  return response;
}