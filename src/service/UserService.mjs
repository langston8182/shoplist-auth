import * as jose from "jose";
import { parseCookies } from "../utils/cookies.mjs";

const REGION = process.env.REGION;
const USER_POOL_ID = process.env.USER_POOL_ID;
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

// JWKS résolu une seule fois (cache interne de jose)
const JWKS = jose.createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));

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
        const cookieHeader = getCookieHeader(event);
        const cookies = parseCookies({ cookie: cookieHeader });
        // Supporte plusieurs noms si besoin
        const token = cookies.id_token || null;
        if (!token) throw new Error("missing_token");

        // Vérifie la signature + issuer
        const { payload } = await jose.jwtVerify(token, JWKS, { issuer: ISSUER });

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