const express = require("express");
const cors = require("cors");
const redis = require("./redisClient");
const generateFingerprint = require("./fingerprint");

const { PutItemCommand } = require("@aws-sdk/client-dynamodb");
const dynamo = require("./services/dynamoService");
const dashboardRoutes = require("./routes/dashboardRoutes");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);

/* ======================================================
   CORS CONFIG
====================================================== */
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

/* ======================================================
   MAIN INSPECTION + ADVANCED RISK ENGINE
====================================================== */
app.use(async (req, res, next) => {
    try {

        /* ------------------------------------------------
           🚫 Skip system routes (dashboard + health)
        ------------------------------------------------ */
        const skipPaths = ["/health", "/api/dashboard"];

        if (skipPaths.some(path => req.originalUrl.startsWith(path))) {
            return next();
        }

        /* ------------------------------------------------
           Extract real client IP
        ------------------------------------------------ */
        const clientIp =
            (req.headers["x-forwarded-for"] || req.ip || "")
                .split(",")[0]
                .trim();

        const fingerprint = generateFingerprint(req);

        const fpKey = `fp:${fingerprint}`;
        const fpBanKey = `ban:fp:${fingerprint}`;
        const ipBanKey = `ban:ip:${clientIp}`;
        const ipRiskKey = `ip:risk:${clientIp}`;

        /* ------------------------------------------------
           1️⃣ Check Full IP Ban
        ------------------------------------------------ */
        const ipBanned = await redis.get(ipBanKey);
        if (ipBanned) {
            return res.status(403).json({
                message: "Network temporarily blocked due to repeated abuse"
            });
        }

        /* ------------------------------------------------
           2️⃣ Check Fingerprint Ban
        ------------------------------------------------ */
        const fpBanned = await redis.get(fpBanKey);
        if (fpBanned) {
            return res.status(403).json({
                message: "Device temporarily blocked"
            });
        }

        /* ------------------------------------------------
           3️⃣ Track Fingerprint Activity
        ------------------------------------------------ */
        const hits = await redis.incr(fpKey);

        if (hits === 1) {
            await redis.expire(fpKey, 300); // 5-minute window
        }

        /* ------------------------------------------------
           4️⃣ Risk Scoring Engine
        ------------------------------------------------ */
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

        /* ------------------------------------------------
           5️⃣ Save Log to DynamoDB
        ------------------------------------------------ */
        try {
            await dynamo.send(new PutItemCommand({
                TableName: "api-request-logs",
                Item: {
                    ipAddress: { S: clientIp },
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

        /* ------------------------------------------------
           6️⃣ Advanced Decision Engine
        ------------------------------------------------ */
        if (riskScore >= 70) {

            // 🔴 Ban fingerprint first
            await redis.set(fpBanKey, "1", "EX", 600); // 10 min

            // 🔴 Increase IP abuse counter
            const ipRiskCount = await redis.incr(ipRiskKey);
            await redis.expire(ipRiskKey, 900); // 15 min tracking window

            // 🚨 Escalation: multiple devices attacking from same IP
            if (ipRiskCount >= 3) {
                await redis.set(ipBanKey, "1", "EX", 1800); // 30 min full IP ban
                console.log("🚨 NETWORK ESCALATION BAN:", clientIp);
            }

            return res.status(429).json({
                message: "Device blocked due to suspicious activity",
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
   HEALTH ROUTE
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
   ROOT ROUTE
====================================================== */
app.get("/", (req, res) => {
    res.send("API Abuse Guard running 🚀");
});

/* ======================================================
   START SERVER
====================================================== */
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
