import { parseCookies } from "../utils/cookies.mjs";
import { verifyJwt } from "../utils/jwt.mjs";
import { Profile } from "../model/Profile.mjs";
import { getConfigValue } from "../utils/config.appconfig.mjs";

const { JWT_ISS, JWT_AUD } = process.env;

let cachedAuthCfg = null;
let cachedAuthCfgPromise = null;

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

export class SessionService {
    /** @param {any} event */
    static async getProfileFromCookies(event) {
        const cookies = parseCookies(event.headers);
        const token = cookies[await getCookieName("id_token")] || cookies[await getCookieName("access_token")];
        if (!token) return null;
        try {
            const claims = await verifyJwt(token, { iss: JWT_ISS, aud: JWT_AUD });
            return new Profile(claims);
        } catch {
            return null;
        }
    }

    /** @param {any} event */
    static async requireAccessTokenClaims(event) {
        const cookies = parseCookies(event.headers);
        const token = cookies[await getCookieName("access_token")];
        if (!token) throw new Error("Unauthorized");
        return verifyJwt(token, { iss: JWT_ISS, aud: JWT_AUD });
    }
}