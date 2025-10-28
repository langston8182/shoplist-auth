// index.mjs
import { AuthController } from "./controller/AuthController.mjs";

function json(status, body) {
    return {
        statusCode: status,
        headers: { "Content-Type": "application/json", ...corsBase },
        body: JSON.stringify(body),
    };
}

export const handler = async (event) => {
    const method =
        (event.requestContext?.http?.method || event.httpMethod || "GET").toUpperCase();
    const rawPath =
        event.requestContext?.http?.path || event.rawPath || event.path || "/";
    const path = rawPath.replace(/^\/+|\/+$/g, ""); // retire les / de début/fin

    // === Routes AUTH ===
    if (path.startsWith("auth/")) {
        const sub = path.slice(5); // après "auth/"

        if (method === "GET" && sub === "login") {
            return AuthController.login();
        }
        if (method === "GET" && sub === "callback") {
            return AuthController.callback(event);
        }
        if (method === "POST" && sub === "refresh") {
            return AuthController.refresh(event);
        }
        if (method === "GET" && (sub === "logout" || sub === "signout")) {
            return AuthController.logout();
        }

        if (method === "GET" && sub === "me") {
            return AuthController.me(event);
        }

        return json(404, { error: "Not Found", route: path, method });
    }

    return json(404, { error: "Not Found", route: path, method });
};