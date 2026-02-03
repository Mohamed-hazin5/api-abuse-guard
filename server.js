const express = require("express");
const redis = require("./redisClient");
const generateFingerprint = require("./fingerprint");

const app = express();
const PORT = 3000;

app.set("trust proxy", true);

app.use(async (req, res, next) => {
    const fingerprint = generateFingerprint(req);
    const key = `fp:${fingerprint}`;

    try {
        const hits = await redis.incr(key);

        if (hits === 1) {
            await redis.expire(key, 300);
        }

        const clientIp = req.headers["x-forwarded-for"] || req.ip;

        console.log(
            JSON.stringify({
                time: new Date().toISOString(),
                ip: clientIp,
                fingerprint,
                hits,
                path: req.originalUrl,
            })
        );

        if (hits > 20) {
            console.log(
                JSON.stringify({
                    ALERT: "BOT DETECTED",
                    ip: clientIp,
                    fingerprint,
                    hits,
                })
            );

            return res.status(429).json({
                message: "Too Many Requests — Bot behavior detected",
            });
        }

        next();
    } catch (err) {
        console.error(err);
        next();
    }
});
// Health check (for ops / monitoring)
app.get("/health", async (req, res) => {
    try {
        await redis.ping();
        res.json({ status: "ok", redis: "connected" });
    } catch {
        res.status(500).json({ status: "error", redis: "down" });
    }
});

// Simple metrics (how many fingerprints active right now)
app.get("/metrics", async (req, res) => {
    const keys = await redis.keys("fp:*");
    res.json({
        activeFingerprints: keys.length,
    });
});



app.get("/", (req, res) => {
    res.send("API Abuse Guard running 🚀");
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
