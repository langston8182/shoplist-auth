import {makePkcePair, randomState} from "../utils/crypto.mjs";
import {clearCookie, parseCookies, setCookie} from "../utils/cookies.mjs";
import {Tokens} from "../model/Tokens.mjs";
import {getConfigValue} from "../utils/config.appconfig.mjs";

let cachedCognitoCfg = null;
let cachedCognitoCfgPromise = null;

let cachedAuthCfg = null;
let cachedAuthCfgPromise = null;

const ENV = process.env.ENVIRONMENT || "preprod";

/**
 * Charge la config auth depuis AppConfig (profil adossé à Secrets Manager)
 * Attendu (extrait):
 * {
 *   "preprod": { "CLIENT_ID":"...", "CLIENT_SECRET":"...", "COGNITO_DOMAIN":"...", "COOKIE_DOMAIN":"...", "FRONT_REDIRECT_PATH":"..." },
 *   "prod":    { ... }
 * }
 */
async function getCognitoConfig() {
    if (cachedCognitoCfg) return cachedCognitoCfg;
    if (!cachedCognitoCfgPromise) {
        cachedCognitoCfgPromise = (async () => {
            const profileName = "cognito";
            const envCfg = await getConfigValue(profileName, ENV, {});

            // fallback process.env utile en local/tests
            const merged = {
                ENVIRONMENT: ENV,
                COGNITO_DOMAIN: envCfg.COGNITO_DOMAIN || process.env.COGNITO_DOMAIN,
                CLIENT_ID: envCfg.CLIENT_ID || process.env.CLIENT_ID,
                CLIENT_SECRET: envCfg.CLIENT_SECRET || process.env.CLIENT_SECRET,
                COOKIE_DOMAIN: envCfg.COOKIE_DOMAIN || process.env.COOKIE_DOMAIN,
                CALLBACK_URL: envCfg.CALLBACK_URL || process.env.CALLBACK_URL,
                FRONT_REDIRECT_PATH:
                    envCfg.FRONT_REDIRECT_PATH || process.env.FRONT_REDIRECT_PATH || "",
            };

            ["COGNITO_DOMAIN", "CLIENT_ID"].forEach((k) => {
                if (!merged[k]) {
                    throw new Error(
                        `Missing ${k} in AppConfig profile '${profileName}' for env '${env}'`
                    );
                }
            });
            return merged;
        })();
    }
    cachedCognitoCfg = await cachedCognitoCfgPromise;
    return cachedCognitoCfg;
}

async function getAuthConfig() {
    if (cachedAuthCfg) return cachedAuthCfg;
    if (!cachedAuthCfgPromise) {
        cachedAuthCfgPromise = (async () => {
            const profileName = "auth";
            const envCfg = await getConfigValue(profileName, "", {});

            // fallback process.env utile en local/tests
            return {
                ENVIRONMENT: ENV,
                FRONT_URL: envCfg.FRONT_URL || process.env.FRONT_URL,
                FRONT_REDIRECT_PATH:
                    envCfg.FRONT_REDIRECT_PATH || process.env.FRONT_REDIRECT_PATH || "",
                APP_NAME: envCfg.APP_NAME || process.env.APP_NAME || "app",
            };
        })();
    }
    cachedAuthCfg = await cachedAuthCfgPromise;
    return cachedAuthCfg;
}

/**
 * Retourne le nom du cookie préfixé par l'application
 * Ex: shoplist_access_token, sport_access_token
 */
async function getCookieName(baseName) {
    const { APP_NAME } = await getAuthConfig();
    return `${APP_NAME}_${baseName}`;
}

async function commonCookie() {
    const { COOKIE_DOMAIN } = await getCognitoConfig();
    return { sameSite: "None", secure: true, httpOnly: true, domain: COOKIE_DOMAIN };
}

export class AuthService {
    static async buildAuthorizeRedirect() {
        const { codeVerifier, codeChallenge } = makePkcePair();
        const state = randomState();
        const cfgCognito = await getCognitoConfig();
        const cfgAuth = await getAuthConfig();

        const tmpCookie = setCookie(
            await getCookieName("auth_tmp"),
            JSON.stringify({ state, codeVerifier }),
            { ...(await commonCookie()), maxAge: 300 }
        );

        const url = new URL(`${cfgCognito.COGNITO_DOMAIN}/oauth2/authorize`);
        url.searchParams.set("client_id", cfgCognito.CLIENT_ID);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("redirect_uri", cfgCognito.CALLBACK_URL);
        url.searchParams.set("scope", "openid email profile");
        url.searchParams.set("state", state);
        url.searchParams.set("code_challenge_method", "S256");
        url.searchParams.set("code_challenge", codeChallenge);

        return { authorizeUrl: url.toString(), tmpCookie };
    }

    /** @param {any} event */
    static async exchangeCodeForTokens(event) {
        const cfgCognito = await getCognitoConfig();
        const cfgAuth = await getAuthConfig();

        const qs = event.queryStringParameters || {};
        const { code, state } = qs;

        let cookieHeader = event.headers?.cookie || event.headers?.Cookie || "";
        if (!cookieHeader && Array.isArray(event.cookies) && event.cookies.length) {
            cookieHeader = event.cookies.join("; ");
        }
        const cookies = parseCookies({ cookie: cookieHeader });
        const tmpRaw = cookies[await getCookieName("auth_tmp")];
        if (!code || !state || !tmpRaw) {
            return { error: "Invalid callback", status: 400 };
        }

        let tmp;
        try {
            tmp = JSON.parse(tmpRaw);
        } catch {
            try {
                tmp = JSON.parse(decodeURIComponent(tmpRaw));
            } catch {}
        }

        if (!tmp || tmp.state !== state || !tmp.codeVerifier) {
            return { error: "State mismatch or missing code_verifier", status: 400 };
        }

        const form = new URLSearchParams();
        form.set("grant_type", "authorization_code");
        form.set("client_id", cfgCognito.CLIENT_ID);
        form.set("redirect_uri", cfgCognito.CALLBACK_URL);
        form.set("code", code);
        form.set("code_verifier", tmp.codeVerifier);

        const basic = Buffer.from(`${cfgCognito.CLIENT_ID}:${cfgCognito.CLIENT_SECRET}`).toString("base64");
        const res = await fetch(`${cfgCognito.COGNITO_DOMAIN}/oauth2/token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Authorization: `Basic ${basic}`,
            },
            body: form,
        });

        if (!res.ok) {
            return { error: "Token exchange failed", details: await res.text(), status: 502 };
        }

        const raw = await res.json();
        const tokens = new Tokens(raw);

        const cookiesOut = [
            setCookie(await getCookieName("access_token"), tokens.accessToken, { ...(await commonCookie()), maxAge: tokens.expiresIn }),
            setCookie(await getCookieName("id_token"), tokens.idToken, { ...(await commonCookie()), maxAge: tokens.expiresIn }),
            clearCookie(await getCookieName("auth_tmp"), await commonCookie()),
        ];
        if (tokens.refreshToken) {
            cookiesOut.push(
                setCookie(await getCookieName("refresh_token"), tokens.refreshToken, {
                    ...(await commonCookie()),
                    maxAge: 60 * 60 * 24 * 30,
                })
            );
        }

        return { tokens, cookiesOut, redirectTo: cfgAuth.FRONT_URL, status: 302 };
    }

    /** @param {any} event */
    static async refresh(event) {
        const cfgCognito = await getCognitoConfig();

        let cookieHeader = event.headers?.cookie || event.headers?.Cookie || "";
        if (!cookieHeader && Array.isArray(event.cookies) && event.cookies.length) {
            cookieHeader = event.cookies.join("; ");
        }
        const cookies = parseCookies({ cookie: cookieHeader });
        const refresh = cookies[await getCookieName("refresh_token")];
        if (!refresh) return { error: "Missing refresh token", status: 401 };

        const form = new URLSearchParams();
        form.set("grant_type", "refresh_token");
        form.set("client_id", (await getCognitoConfig()).CLIENT_ID);
        form.set("refresh_token", refresh);

        const basic = Buffer.from(`${cfgCognito.CLIENT_ID}:${cfgCognito.CLIENT_SECRET}`).toString('base64');
        const res = await fetch(`${(await getCognitoConfig()).COGNITO_DOMAIN}/oauth2/token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": `Basic ${basic}`
            },
            body: form,
        });

        if (!res.ok) {
            return { error: "Refresh failed", details: await res.text(), status: 401 };
        }

        const raw = await res.json();
        const tokens = new Tokens(raw);

        const cookiesOut = [
            setCookie(await getCookieName("access_token"), tokens.accessToken, { ...(await commonCookie()), maxAge: tokens.expiresIn }),
        ];
        if (tokens.idToken) {
            cookiesOut.push(setCookie(await getCookieName("id_token"), tokens.idToken, { ...(await commonCookie()), maxAge: tokens.expiresIn }));
        }

        return { ok: true, cookiesOut, status: 200 };
    }

    static async buildLogoutRedirect() {
        const cfgCognito = await getCognitoConfig();
        const cfgAuth = await getAuthConfig();
        const url = new URL(`${cfgCognito.COGNITO_DOMAIN}/logout`);
        url.searchParams.set("client_id", cfgCognito.CLIENT_ID);
        url.searchParams.set("logout_uri", `${cfgAuth.FRONT_URL}/`);

        const cookies = [
            clearCookie(await getCookieName("access_token"), await commonCookie()),
            clearCookie(await getCookieName("id_token"), await commonCookie()),
            clearCookie(await getCookieName("refresh_token"), await commonCookie()),
            clearCookie(await getCookieName("auth_tmp"), await commonCookie()),
        ];

        return { logoutUrl: url.toString(), cookies };
    }
}