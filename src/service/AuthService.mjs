import {makePkcePair, randomState} from "../utils/crypto.mjs";
import {setCookie, clearCookie, parseCookies} from "../utils/cookies.mjs";
import {Tokens} from "../model/Tokens.mjs";

const {
    COGNITO_DOMAIN,
    CLIENT_ID,
    FRONT_REDIRECT_PATH,
    COOKIE_DOMAIN,
    CLIENT_SECRET,
    ENVIRONMENT
} = process.env;

const COMMON_COOKIE = {sameSite: "None", secure: true, httpOnly: true, domain: COOKIE_DOMAIN};

const UI_ORIGIN_BY_ENV = {
    localhost: "http://localhost:5173",
    preprod:   "https://shoplist-ui-preprod.cyrilmarchive.com",
    prod:      "https://shoplist.cyrilmarchive.com",
};

const REDIRECT_URI_BY_ENV = {
    localhost: "https://shoplist-auth-preprod.cyrilmarchive.com/auth/callback",
    preprod:   "https://shoplist-auth-preprod.cyrilmarchive.com/auth/callback",
    prod:      "https://shoplist-auth.cyrilmarchive.com/auth/callback",
}

function resolveUiOrigin() {
    const env = (ENVIRONMENT || "").toLowerCase();
    return UI_ORIGIN_BY_ENV[env] || UI_ORIGIN_BY_ENV.localhost;
}

function resolveRedirectUri() {
    const env = (ENVIRONMENT || "").toLowerCase();
    return REDIRECT_URI_BY_ENV[env] || REDIRECT_URI_BY_ENV.localhost;
}

function resolveFrontUrl() {
    return `${resolveUiOrigin()}/${FRONT_REDIRECT_PATH}`;
}

function resolveLogoutUrl() {
    return `${resolveUiOrigin()}/`;
}

export class AuthService {
    static buildAuthorizeRedirect() {
        const {codeVerifier, codeChallenge} = makePkcePair();
        const state = randomState();

        const tmpCookie = setCookie(
            "auth_tmp",
            JSON.stringify({state, codeVerifier}),
            {...COMMON_COOKIE, maxAge: 300}
        );

        const url = new URL(`${COGNITO_DOMAIN}/oauth2/authorize`);
        url.searchParams.set("client_id", CLIENT_ID);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("redirect_uri", resolveRedirectUri());
        url.searchParams.set("scope", "openid email profile");
        url.searchParams.set("state", state);
        url.searchParams.set("code_challenge_method", "S256");
        url.searchParams.set("code_challenge", codeChallenge);

        return {authorizeUrl: url.toString(), tmpCookie};
    }

    /** @param {any} event */
    static async exchangeCodeForTokens(event) {
        const qs = event.queryStringParameters || {};
        const {code, state} = qs;

        let cookieHeader = event.headers?.cookie || event.headers?.Cookie || "";
        if (!cookieHeader && Array.isArray(event.cookies) && event.cookies.length) {
            cookieHeader = event.cookies.join("; ");
        }
        const cookies = parseCookies({cookie: cookieHeader});
        const tmpRaw = cookies.auth_tmp;
        if (!code || !state || !tmpRaw) {
            return {error: "Invalid callback", status: 400};
        }

        let tmp;
        try {
            tmp = JSON.parse(tmpRaw);
        } catch {
            try {
                tmp = JSON.parse(decodeURIComponent(tmpRaw));
            } catch {
            }
        }

        if (!tmp || tmp.state !== state || !tmp.codeVerifier) {
            return {error: "State mismatch or missing code_verifier", status: 400};
        }

        const form = new URLSearchParams();
        form.set("grant_type", "authorization_code");
        form.set("client_id", CLIENT_ID);
        form.set("redirect_uri", resolveRedirectUri());
        form.set("code", code);
        form.set("code_verifier", tmp.codeVerifier);

        const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
        const res = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": `Basic ${basic}`
            },
            body: form
        });

        if (!res.ok) {
            return {error: "Token exchange failed", details: await res.text(), status: 502};
        }

        const raw = await res.json();
        const tokens = new Tokens(raw);

        const cookiesOut = [
            setCookie("access_token", tokens.accessToken, {...COMMON_COOKIE, maxAge: tokens.expiresIn}),
            setCookie("id_token", tokens.idToken, {...COMMON_COOKIE, maxAge: tokens.expiresIn}),
            clearCookie("auth_tmp", COMMON_COOKIE)
        ];
        if (tokens.refreshToken) {
            cookiesOut.push(setCookie("refresh_token", tokens.refreshToken, {
                ...COMMON_COOKIE,
                maxAge: 60 * 60 * 24 * 30
            }));
        }

        return {tokens, cookiesOut, redirectTo: resolveFrontUrl(), status: 302};
    }

    /** @param {any} event */
    static async refresh(event) {
        let cookieHeader = event.headers?.cookie || event.headers?.Cookie || "";
        if (!cookieHeader && Array.isArray(event.cookies) && event.cookies.length) {
            cookieHeader = event.cookies.join("; ");
        }
        const cookies = parseCookies({cookie: cookieHeader});
        const refresh = cookies.refresh_token;
        if (!refresh) return {error: "Missing refresh token", status: 401};

        const form = new URLSearchParams();
        form.set("grant_type", "refresh_token");
        form.set("client_id", CLIENT_ID);
        form.set("refresh_token", refresh);

        const res = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: form
        });

        if (!res.ok) {
            return {error: "Refresh failed", details: await res.text(), status: 401};
        }

        const raw = await res.json();
        const tokens = new Tokens(raw);

        const cookiesOut = [
            setCookie("access_token", tokens.accessToken, {...COMMON_COOKIE, maxAge: tokens.expiresIn})
        ];
        if (tokens.idToken) {
            cookiesOut.push(setCookie("id_token", tokens.idToken, {...COMMON_COOKIE, maxAge: tokens.expiresIn}));
        }

        return {ok: true, cookiesOut, status: 200};
    }

    static buildLogoutRedirect() {
        const url = new URL(`${COGNITO_DOMAIN}/logout`);
        url.searchParams.set("client_id", CLIENT_ID);
        url.searchParams.set("logout_uri", resolveLogoutUrl());

        const cookies = [
            clearCookie("access_token", COMMON_COOKIE),
            clearCookie("id_token", COMMON_COOKIE),
            clearCookie("refresh_token", COMMON_COOKIE),
            clearCookie("auth_tmp", COMMON_COOKIE)
        ];

        return {logoutUrl: url.toString(), cookies};
    }
}