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
            await redis.expire(key, 300); // 5 min window
        }

        if (hits > 20) {
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

app.get("/", (req, res) => {
    res.send("API Abuse Guard running 🚀");
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
