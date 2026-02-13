const crypto = require("crypto");

function generateFingerprint(req) {
    const raw = [
        req.headers["user-agent"],
        req.headers["accept-language"],
        req.headers["accept-encoding"],
        req.headers["sec-ch-ua"],
        req.headers["sec-ch-ua-platform"],
        req.headers["sec-fetch-site"],
        req.headers["sec-fetch-mode"],
        req.headers["sec-fetch-dest"],
        req.ip,
    ]
        .filter(Boolean)
        .join("|");

    return crypto.createHash("sha256").update(raw).digest("hex");
}

module.exports = generateFingerprint;
