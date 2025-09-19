export function cookieAttrs({ maxAge, sameSite = "Lax", secure = true, httpOnly = true, path = "/", domain } = {}) {
    const parts = [`Path=${path}`];
    if (httpOnly) parts.push("HttpOnly");
    if (secure) parts.push("Secure");
    if (sameSite) parts.push(`SameSite=${sameSite}`);
    if (typeof maxAge === "number") parts.push(`Max-Age=${maxAge}`);
    if (domain) parts.push(`Domain=${domain}`);
    return parts.join("; ");
}

export function setCookie(name, value, opts) {
    return `${name}=${encodeURIComponent(value)}; ${cookieAttrs(opts)}`;
}

export function clearCookie(name, opts) {
    return `${name}=; ${cookieAttrs({ ...opts, maxAge: 0 })}`;
}

export function parseCookies(headers = {}) {
    const all = headers.cookie || headers.Cookie || "";
    const out = {};
    all.split(";").map(s => s.trim()).filter(Boolean).forEach(kv => {
        const i = kv.indexOf("=");
        const k = kv.slice(0, i);
        const v = kv.slice(i + 1);
        out[k] = decodeURIComponent(v || "");
    });
    return out;
}