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
   CORS CONFIGURATION (VERY IMPORTANT)
====================================================== */
app.use(cors({
    origin: "*", // You can restrict later if needed
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

/* ======================================================
   MAIN INSPECTION + RISK ENGINE
====================================================== */
app.use(async (req, res, next) => {
    try {

        /* ------------------------------------------------
           🚫 Skip inspection for system routes
        ------------------------------------------------ */
        const skipPaths = [
            "/health",
            "/api/dashboard"
        ];

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
        const redisKey = `fp:${fingerprint}`;
        const banKey = `ban:${clientIp}`;

        /* ------------------------------------------------
           1️⃣ Check Ban List
        ------------------------------------------------ */
        const isBanned = await redis.get(banKey);
        if (isBanned) {
            return res.status(403).json({
                message: "IP banned due to suspicious activity"
            });
        }

        /* ------------------------------------------------
           2️⃣ Track Fingerprint Activity
        ------------------------------------------------ */
        const hits = await redis.incr(redisKey);

        if (hits === 1) {
            await redis.expire(redisKey, 300); // 5-minute window
        }

        /* ------------------------------------------------
           3️⃣ Risk Scoring Engine
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
           4️⃣ Save to DynamoDB
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
           5️⃣ Decision Engine
        ------------------------------------------------ */
        if (riskScore >= 70) {
            await redis.set(banKey, "1", "EX", 600); // 10 min ban

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
