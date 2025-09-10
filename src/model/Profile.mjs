export class Profile {
    constructor(claims) {
        this.sub = claims.sub;
        this.email = claims.email || null;
        this.name = claims.name || claims["cognito:username"] || null;
        this.groups = claims["cognito:groups"] || [];
    }
}