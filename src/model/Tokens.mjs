export class Tokens {
    constructor(raw) {
        this.accessToken = raw.access_token;
        this.idToken = raw.id_token;
        this.refreshToken = raw.refresh_token;
        this.expiresIn = raw.expires_in;
        this.tokenType = raw.token_type;
    }
}