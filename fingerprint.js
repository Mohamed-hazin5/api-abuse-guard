const crypto = require("crypto");

function generateFingerprint(req) {
    const raw = [
        req.headers["user-agent"],
        req.headers["accept-language"],
        req.headers["accept-encoding"],
        req.ip,
    ].join("|");

    return crypto.createHash("sha256").update(raw).digest("hex");
}

module.exports = generateFingerprint;
