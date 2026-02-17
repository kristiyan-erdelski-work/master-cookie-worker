/**
* Cloudflare Worker — First-Party Cookie Manager
*
* Sets and maintains first-party cookies on document navigations only.
* Static assets, XHR, and other subrequests pass through with zero overhead.
*
* Cookies set (all on root domain, shared across subdomains):
*   - whg_mid    : Persistent user identity for Stape Custom Loader / Cookie Keeper.
*                  Generated once (UUID), expiry refreshed on each visit. (400 days)
*   - _attr_ft   : First-touch attribution. Set once on first visit, never overwritten. (400 days)
*   - _attr_st   : Second-touch attribution. Set once when a distinct source appears. (400 days)
*   - _attr_lt   : Last-touch attribution. Merged on each new external touch. (90 days)
*
* Attribution signals captured: UTM params, ad platform click IDs (gclid, fbclid, etc.),
* external referrer, landing URL, and CF-IPCountry.
*/

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  },
};

async function handleRequest(request) {
  // Fast path — bail immediately for non-document requests
  if (request.method !== 'GET') return fetch(request);

  const secDest = request.headers.get('Sec-Fetch-Dest');
  const secMode = request.headers.get('Sec-Fetch-Mode');
  const accept = request.headers.get('Accept') || '';

  // Use Sec-Fetch headers when available (reliable), fall back to Accept heuristic
  const isNavigation = secDest
    ? (secDest === 'document')
    : (secMode === 'navigate' || accept.includes('text/html'));

  if (!isNavigation) return fetch(request);

  const url = new URL(request.url);
  const path = url.pathname.toLowerCase();
  if (STATIC_EXTS.some(ext => path.endsWith(ext))) return fetch(request);

  // Document request — full processing
  const origin = await fetch(request);

  // Skip non-HTML responses (JSON API, etc. that passed Accept check)
  const contentType = (origin.headers.get('Content-Type') || '').toLowerCase();
  if (!contentType.includes('text/html')) return origin;

  const cookieHeader = request.headers.get('Cookie');
  const cookies = parseCookiesFromHeader(cookieHeader);
  const rootDomain = '.' + extractRootDomain(url.hostname);

  const response = new Response(origin.body, origin);

  // Master identity cookie — set once, extend expiry on subsequent visits
  const COOKIE_NAME = 'whg_mid';
  const EXPIRY = 60 * 60 * 24 * 400; // 400 days (browser max)
  const cookieValue = cookies[COOKIE_NAME] || crypto.randomUUID();
  response.headers.append(
    'Set-Cookie',
    `${COOKIE_NAME}=${cookieValue}; Path=/; Max-Age=${EXPIRY}; Domain=${rootDomain}; Secure; SameSite=Lax`
  );

  // Attribution cookies (first-touch, second-touch, last-touch)
  setAttributionCookies(request, response, url, rootDomain, cookies);

  return response;
}


// --- Configuration ---

const ATTR_FT_COOKIE = '_attr_ft'; // First touch — set once, never overwritten
const ATTR_ST_COOKIE = '_attr_st'; // Second touch — set once when source differs from FT
const ATTR_LT_COOKIE = '_attr_lt'; // Last touch — merged on each new external touch

const ATTR_FT_EXPIRY = 60 * 60 * 24 * 400; // 400 days
const ATTR_ST_EXPIRY = 60 * 60 * 24 * 400; // 400 days
const ATTR_LT_EXPIRY = 60 * 60 * 24 * 90;  // 90 days

const MAX_URL_LENGTH = 500;
const MAX_PARAM_LENGTH = 150;  // Cap individual param values to prevent cookie bloat
const MAX_COOKIE_SIZE = 3800;  // Stay under 4KB browser limit after encoding overhead

const STATIC_EXTS = [
  '.js', '.mjs', '.cjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
  '.woff', '.woff2', '.ttf', '.eot', '.map', '.json', '.xml',
  '.webp', '.avif', '.mp4', '.webm', '.pdf', '.zip', '.gz', '.br'
];

// Domains that should never be treated as external referrers (payment, auth, etc.)
// Only specific subdomains — root domains like google.com, facebook.com are real referrers
const IGNORED_REFERRER_DOMAINS = [
  'paypal.com', 'www.paypal.com', 'checkout.paypal.com',
  'stripe.com', 'checkout.stripe.com',
  'adyen.com', 'checkoutshopper-live.adyen.com',
  'klarna.com', 'pay.klarna.com',
  'afterpay.com', 'portal.afterpay.com',
  'braintreegateway.com', 'braintree-api.com',
  'worldpay.com', 'access.worldpay.com',
  'mollie.com', 'checkout.mollie.com',
  'gocardless.com', 'pay.gocardless.com',
  'appleid.apple.com',         // Sign in with Apple
  'accounts.google.com',       // Google OAuth
  'pay.google.com',            // Google Pay
];

const TRACKED_PARAMS = [
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
  'gclid', 'wbraid', 'gbraid', 'dclid',
  'fbclid', 'msclkid', 'ttclid', 'twclid', 'li_fat_id', 'rdt_cid',
  'aid', 'pid', 'affiliate_id', 'ref', 'upm_aff'
];


// --- Helpers ---

function extractRootDomain(hostname) {
  const twoPartTlds = ['com.co', 'co.uk', 'co.nz', 'com.au', 'co.in', 'com.br', 'co.jp', 'org.uk', 'com.sg', 'co.za'];
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;

  const lastTwo = parts.slice(-2).join('.');
  return twoPartTlds.includes(lastTwo)
    ? parts.slice(-3).join('.')
    : parts.slice(-2).join('.');
}

function parseCookiesFromHeader(header) {
  if (!header) return {};
  return header.split(';').reduce((acc, pair) => {
    const trimmed = pair.trim();
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) return acc;
    const name = trimmed.slice(0, eqIdx);
    const value = trimmed.slice(eqIdx + 1);
    try { acc[name] = decodeURIComponent(value); }
    catch { acc[name] = value; }
    return acc;
  }, {});
}

// UTF-8 safe base64 encode/decode (handles international referrer URLs)
function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64) {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0)));
}

function decodeAttrCookie(encoded) {
  if (!encoded) return null;
  try { return JSON.parse(fromBase64(encoded)); }
  catch { return null; }
}

function encodeAttrCookie(data) {
  try { return toBase64(JSON.stringify(data)); }
  catch { return null; }
}

function extractTrackingParams(url) {
  const params = {};
  let hasParams = false;
  for (const key of TRACKED_PARAMS) {
    const value = url.searchParams.get(key);
    if (value !== null && value !== '') {
      params[key] = value.length > MAX_PARAM_LENGTH ? value.substring(0, MAX_PARAM_LENGTH) : value;
      hasParams = true;
    }
  }
  return { params, hasParams };
}

function parseReferrer(request, rootDomain) {
  const referer = request.headers.get('Referer') || request.headers.get('Referrer');
  if (!referer) return { url: null, domain: null, isExternal: false };

  try {
    const refUrl = new URL(referer);
    const refDomain = refUrl.hostname.toLowerCase();
    const currentDomain = rootDomain.replace(/^\./, '').toLowerCase();

    // Internal navigation or ignored domain (payment, auth, etc.)
    if (
      refDomain === currentDomain ||
      refDomain.endsWith('.' + currentDomain) ||
      IGNORED_REFERRER_DOMAINS.some(d => refDomain === d || refDomain.endsWith('.' + d))
    ) {
      return { url: referer, domain: refDomain, isExternal: false };
    }

    return {
      url: referer.length > MAX_URL_LENGTH ? referer.substring(0, MAX_URL_LENGTH) : referer,
      domain: refDomain,
      isExternal: true
    };
  } catch {
    return { url: null, domain: null, isExternal: false };
  }
}

function isDistinctSource(newData, existingData) {
  if (!existingData) return true;
  if (newData.utm_source && existingData.utm_source && newData.utm_source !== existingData.utm_source) return true;
  if (newData._ref_domain && existingData._ref_domain && newData._ref_domain !== existingData._ref_domain) return true;
  if (newData.utm_source && !existingData.utm_source) return true;
  if (newData._ref_domain && !existingData._ref_domain) return true;

  const clickIdKeys = ['gclid', 'wbraid', 'gbraid', 'dclid', 'fbclid', 'msclkid', 'ttclid', 'twclid', 'li_fat_id', 'rdt_cid'];
  for (const key of clickIdKeys) {
    if (newData[key] && !existingData[key]) return true;
  }
  return false;
}

function appendAttrCookie(response, name, data, maxAge, domain) {
  const encoded = encodeAttrCookie(data);
  if (!encoded) return;

  // Check post-encoded size (encodeURIComponent expands +/=/  in base64)
  const finalValue = encodeURIComponent(encoded);
  if (finalValue.length > MAX_COOKIE_SIZE) return;

  response.headers.append(
    'Set-Cookie',
    `${name}=${finalValue}; Path=/; Max-Age=${maxAge}; Domain=${domain}; Secure; SameSite=Lax`
  );
}


// --- Attribution Handler ---

function setAttributionCookies(request, response, url, rootDomain, cookies) {
  const now = Date.now();

  const { params: urlParams, hasParams } = extractTrackingParams(url);
  const refInfo = parseReferrer(request, rootDomain);
  const rawCountry = request.headers.get('CF-IPCountry');
  const country = (rawCountry && rawCountry !== 'XX') ? rawCountry : null;
  const hasNewTouch = hasParams || refInfo.isExternal;

  // Build incoming signal from URL params, referrer, and CF headers
  const incoming = { ...urlParams };

  if (refInfo.isExternal) {
    incoming._referrer = refInfo.url;
    incoming._ref_domain = refInfo.domain;
  }

  const landingUrl = url.href;
  incoming._landing_url = landingUrl.length > MAX_URL_LENGTH ? landingUrl.substring(0, MAX_URL_LENGTH) : landingUrl;
  incoming._landing_path = url.pathname;
  if (country) incoming._country = country;
  incoming._ts = now;

  const existingFt = decodeAttrCookie(cookies[ATTR_FT_COOKIE]);
  const existingSt = decodeAttrCookie(cookies[ATTR_ST_COOKIE]);
  const existingLt = decodeAttrCookie(cookies[ATTR_LT_COOKIE]);

  // First Touch — set once on first visit, never overwritten
  if (!existingFt) {
    const ftData = { ...incoming, _created: now, _updated: now };
    appendAttrCookie(response, ATTR_FT_COOKIE, ftData, ATTR_FT_EXPIRY, rootDomain);
    appendAttrCookie(response, ATTR_LT_COOKIE, { ...ftData }, ATTR_LT_EXPIRY, rootDomain);
    return; // First visit — FT and LT initialised, ST not applicable yet
  }

  // Second Touch — set once when a distinct source appears after FT
  if (!existingSt && hasNewTouch) {
    const stCandidate = { ...incoming, _created: now, _updated: now };
    if (isDistinctSource(stCandidate, existingFt)) {
      appendAttrCookie(response, ATTR_ST_COOKIE, stCandidate, ATTR_ST_EXPIRY, rootDomain);
    }
  }

  // Last Touch — merge new signals into existing LT on each external touch
  if (hasNewTouch) {
    const merged = { ...(existingLt || {}), ...incoming };
    merged._created = (existingLt && existingLt._created) ? existingLt._created : now;
    merged._updated = now;
    appendAttrCookie(response, ATTR_LT_COOKIE, merged, ATTR_LT_EXPIRY, rootDomain);
  }
}
 