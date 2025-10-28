import { parseCookies } from "../utils/cookies.mjs";
import { verifyJwt } from "../utils/jwt.mjs";
import { Profile } from "../model/Profile.mjs";

const { JWT_ISS, JWT_AUD } = process.env;

export class SessionService {
    /** @param {any} event */
    static async getProfileFromCookies(event) {
        const cookies = parseCookies(event.headers);
        const token = cookies.id_token || cookies.access_token;
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
        const token = cookies.access_token;
        if (!token) throw new Error("Unauthorized");
        return verifyJwt(token, { iss: JWT_ISS, aud: JWT_AUD });
    }
}