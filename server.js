const express = require("express");
const redis = require("./redisClient");
const generateFingerprint = require("./fingerprint");

const {
    PutItemCommand
} = require("@aws-sdk/client-dynamodb");

const dynamo = require("./services/dynamoService");
const dashboardRoutes = require("./routes/dashboardRoutes");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);

/* ======================================================
   MAIN INSPECTION + RISK ENGINE
====================================================== */
app.use(async (req, res, next) => {
    try {
        const clientIp =
            (req.headers["x-forwarded-for"] || req.ip || "")
                .split(",")[0]
                .trim();

        const fingerprint = generateFingerprint(req);
        const redisKey = `fp:${fingerprint}`;
        const banKey = `ban:${clientIp}`;

        // 1️⃣ Check Ban
        const isBanned = await redis.get(banKey);
        if (isBanned) {
            return res.status(403).json({
                message: "IP banned due to suspicious activity"
            });
        }

        // 2️⃣ Track fingerprint
        const hits = await redis.incr(redisKey);
        if (hits === 1) {
            await redis.expire(redisKey, 300);
        }

        // 3️⃣ Risk Engine
        let riskScore = 0;

        if (hits > 10) riskScore += 30;
        if (hits > 20) riskScore += 40;

        const userAgent = req.headers["user-agent"] || "";

        if (userAgent.toLowerCase().includes("curl"))
            riskScore += 40;

        if (!req.headers["accept"])
            riskScore += 20;

        if (req.originalUrl.toLowerCase().includes("admin"))
            riskScore += 30;

        // 4️⃣ Save to DynamoDB (FIXED key name)
        try {
            await dynamo.send(new PutItemCommand({
                TableName: "api-request-logs",
                Item: {
                    ipAddress: { S: clientIp },  // ✅ FIXED
                    timestamp: { S: new Date().toISOString() },
                    fingerprint: { S: fingerprint },
                    hits: { N: hits.toString() },
                    riskScore: { N: riskScore.toString() },
                    path: { S: req.originalUrl },
                    userAgent: { S: userAgent || "unknown" }
                }
            }));
        } catch (err) {
            console.error("DynamoDB write failed:", err.message);
        }

        // 5️⃣ Decision
        if (riskScore >= 70) {
            await redis.set(banKey, "1", "EX", 600);

            return res.status(429).json({
                message: "Blocked — High risk behavior",
                riskScore
            });
        }

        next();

    } catch (err) {
        console.error("Middleware error:", err);
        next();
    }
});

/* ======================================================
   HEALTH
====================================================== */
app.get("/health", async (req, res) => {
    try {
        await redis.ping();
        res.json({ status: "ok", redis: "connected" });
    } catch {
        res.status(500).json({ status: "error", redis: "down" });
    }
});

/* ======================================================
   DASHBOARD ROUTES
====================================================== */
app.use("/api/dashboard", dashboardRoutes);

/* ======================================================
   ROOT
====================================================== */
app.get("/", (req, res) => {
    res.send("API Abuse Guard running 🚀");
});

/* ======================================================
   START
====================================================== */
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
