import * as jose from "jose";
import {parseCookies} from "../utils/cookies.mjs";
import {getConfigValue} from "../utils/config.appconfig.mjs";

let cachedCognitoCfg = null;
let cachedCognitoCfgPromise = null;

let cachedAuthCfg = null;
let cachedAuthCfgPromise = null;

const ENV = process.env.ENVIRONMENT || "preprod";

async function getCognitoConfig() {
    if (cachedCognitoCfg) return cachedCognitoCfg;
    if (!cachedCognitoCfgPromise) {
        cachedCognitoCfgPromise = (async () => {
            const profileName = "cognito";
            const envCfg = await getConfigValue(profileName, ENV, {});

            // fallback process.env utile en local/tests
            return {
                ENVIRONMENT: ENV,
                REGION: envCfg.REGION || process.env.REGION,
                USER_POOL_ID: envCfg.USER_POOL_ID || process.env.USER_POOL_ID,
            };
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
                APP_NAME: envCfg.APP_NAME || process.env.APP_NAME || "app",
            };
        })();
    }
    cachedAuthCfg = await cachedAuthCfgPromise;
    return cachedAuthCfg;
}

/**
 * Retourne le nom du cookie préfixé par l'application
 */
async function getCookieName(baseName) {
    const { APP_NAME } = await getAuthConfig();
    return `${APP_NAME}_${baseName}`;
}

function getCookieHeader(event) {
    if (Array.isArray(event.cookies) && event.cookies.length) return event.cookies.join("; ");
    return event.headers?.cookie || event.headers?.Cookie || "";
}

export class UserService {
    /**
     * Lit les cookies, vérifie le JWT, et renvoie un profil minimal.
     * @throws Error si token manquant/invalid
     */
    static async meFromCookies(event) {
        const cfgCognito = await getCognitoConfig();
        const issuer = `https://cognito-idp.${cfgCognito.REGION}.amazonaws.com/${cfgCognito.USER_POOL_ID}`;
        const jwks = jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
        const cookieHeader = getCookieHeader(event);
        const cookies = parseCookies({ cookie: cookieHeader });
        // Supporte plusieurs noms si besoin
        const token = cookies[await getCookieName("id_token")] || null;
        if (!token) throw new Error("missing_token");

        // Vérifie la signature + issuer
        const { payload } = await jose.jwtVerify(token, jwks, { issuer: issuer });

        // Optionnel : s’assurer de l’usage access
        if (payload.token_use && payload.token_use !== "id") {
            throw new Error("not_access_token");
        }

        // Construis un profil minimal
        return {
            sub: payload.sub,
            email: payload.email || null,
            given_name: payload.given_name || null,
            family_name: payload.family_name || "",
        };
    }
}