import crypto from "crypto";

export function base64url(buf) {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomState() {
    return base64url(crypto.randomBytes(32));
}

export function makePkcePair() {
    const codeVerifier = base64url(crypto.randomBytes(64));
    const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
    return { codeVerifier, codeChallenge };
}