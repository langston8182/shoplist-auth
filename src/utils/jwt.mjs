import * as jose from "jose";

let jwksCache = null;

/** @param {string} issuer */
async function getJWKS(issuer) {
    if (!jwksCache || jwksCache.iss !== issuer) {
        jwksCache = {
            iss: issuer,
            jwks: jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`))
        };
    }
    return jwksCache.jwks;
}

/** @param {string} token @param {{iss:string,aud:string}} opts */
export async function verifyJwt(token, { iss, aud }) {
    const jwks = await getJWKS(iss);
    const { payload } = await jose.jwtVerify(token, jwks, { issuer: iss, audience: aud });
    return payload;
}