// Helpers pour API Gateway HTTP API v2 (support "cookies" dans la réponse)
export function redirect(location, cookies = []) {
    return { statusCode: 302, headers: { Location: location }, cookies, body: "" };
}

export function json(status, body, cookies = [], extraHeaders = {}) {
    return {
        statusCode: status,
        headers: { "Content-Type": "application/json", ...extraHeaders },
        cookies,
        body: JSON.stringify(body)
    };
}