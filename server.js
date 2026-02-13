const express = require("express");
const redis = require("./redisClient");
const generateFingerprint = require("./fingerprint");

const {
    DynamoDBClient,
    PutItemCommand,
    ScanCommand
} = require("@aws-sdk/client-dynamodb");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);

const dynamo = new DynamoDBClient({
    region: "ap-south-1"
});

/* ======================================================
   MAIN INSPECTION + RISK ENGINE
====================================================== */
app.use(async (req, res, next) => {
    try {
        // Extract real client IP
        const clientIp =
            (req.headers["x-forwarded-for"] || req.ip || "")
                .split(",")[0]
                .trim();

        const fingerprint = generateFingerprint(req);
        const redisKey = `fp:${fingerprint}`;
        const banKey = `ban:${clientIp}`;

        /* -------------------------
           1️⃣ CHECK BAN LIST
        -------------------------- */
        const isBanned = await redis.get(banKey);
        if (isBanned) {
            return res.status(403).json({
                message: "IP banned due to suspicious activity"
            });
        }

        /* -------------------------
           2️⃣ TRACK FINGERPRINT
        -------------------------- */
        const hits = await redis.incr(redisKey);
        if (hits === 1) {
            await redis.expire(redisKey, 300); // 5-minute window
        }

        /* -------------------------
           3️⃣ RISK SCORING ENGINE
        -------------------------- */
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

        /* -------------------------
           4️⃣ SAVE LOG TO DYNAMODB
        -------------------------- */
        try {
            await dynamo.send(new PutItemCommand({
                TableName: "api-request-logs",
                Item: {
                    ip: { S: clientIp },
                    fingerprint: { S: fingerprint },
                    timestamp: { S: new Date().toISOString() },
                    hits: { N: hits.toString() },
                    riskScore: { N: riskScore.toString() },
                    path: { S: req.originalUrl },
                    userAgent: { S: userAgent || "unknown" }
                }
            }));
        } catch (dbErr) {
            console.error("DynamoDB write failed:", dbErr.message);
        }

        console.log(JSON.stringify({
            time: new Date().toISOString(),
            ip: clientIp,
            fingerprint,
            hits,
            riskScore,
            path: req.originalUrl
        }));

        /* -------------------------
           5️⃣ DECISION ENGINE
        -------------------------- */
        if (riskScore >= 70) {
            await redis.set(banKey, "1", "EX", 600); // 10 min ban

            console.log("🚨 AUTO BAN:", clientIp);

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
   HEALTH CHECK
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
   REDIS LIVE METRICS
====================================================== */
app.get("/metrics", async (req, res) => {
    const keys = await redis.keys("fp:*");
    res.json({
        activeFingerprints: keys.length
    });
});

/* ======================================================
   DASHBOARD: OVERVIEW
====================================================== */
app.get("/api/dashboard/overview", async (req, res) => {
    try {
        const data = await dynamo.send(new ScanCommand({
            TableName: "api-request-logs"
        }));

        const items = data.Items || [];

        const totalRequests = items.length;

        const highRiskRequests = items.filter(
            item => parseInt(item.riskScore.N) >= 70
        ).length;

        const uniqueIPs = new Set(
            items.map(item => item.ip.S)
        ).size;

        const recentActivity = items
            .sort((a, b) =>
                new Date(b.timestamp.S) - new Date(a.timestamp.S)
            )
            .slice(0, 20);

        res.json({
            totalRequests,
            highRiskRequests,
            uniqueIPs,
            recentActivity
        });

    } catch (err) {
        console.error("Dashboard overview error:", err);
        res.status(500).json({ error: "Dashboard failed" });
    }
});

/* ======================================================
   DASHBOARD: TOP ATTACKERS
====================================================== */
app.get("/api/dashboard/top-ips", async (req, res) => {
    try {
        const data = await dynamo.send(new ScanCommand({
            TableName: "api-request-logs"
        }));

        const items = data.Items || [];
        const counter = {};

        items.forEach(item => {
            const ip = item.ip.S;
            counter[ip] = (counter[ip] || 0) + 1;
        });

        const sorted = Object.entries(counter)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        res.json(sorted);

    } catch (err) {
        console.error("Top IP error:", err);
        res.status(500).json({ error: "Failed" });
    }
});

/* ======================================================
   ROOT
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
