const { ScanCommand } = require("@aws-sdk/client-dynamodb");
const dynamo = require("../services/dynamoService");
const redis = require("../redisClient");

/* ===============================
   OVERVIEW
=================================*/
exports.getOverview = async (req, res) => {
    try {
        const data = await dynamo.send(new ScanCommand({
            TableName: "api-request-logs"
        }));

        const items = data.Items || [];

        const totalRequests = items.length;

        const uniqueIPs = new Set(
            items.map(i => i.ipAddress?.S)
        ).size;

        const highRisk = items.filter(
            i => i.riskScore && parseInt(i.riskScore.N) >= 70
        ).length;

        const recent = items
            .sort((a, b) =>
                new Date(b.timestamp.S) - new Date(a.timestamp.S)
            )
            .slice(0, 20);

        res.json({
            totalRequests,
            uniqueIPs,
            highRisk,
            recent
        });

    } catch (err) {
        console.error("Overview error:", err);
        res.status(500).json({ error: "Overview failed" });
    }
};

/* ===============================
   TOP IPs
=================================*/
exports.getTopIPs = async (req, res) => {
    try {
        const data = await dynamo.send(new ScanCommand({
            TableName: "api-request-logs"
        }));

        const items = data.Items || [];

        const counter = {};

        items.forEach(item => {
            const ip = item.ipAddress?.S;
            if (!ip) return;
            counter[ip] = (counter[ip] || 0) + 1;
        });

        const sorted = Object.entries(counter)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        res.json(sorted);

    } catch (err) {
        console.error("Top IP error:", err);
        res.status(500).json({ error: "Top IP failed" });
    }
};

/* ===============================
   BANNED IPs (Redis)
=================================*/
exports.getBannedIPs = async (req, res) => {
    try {
        const keys = await redis.keys("ban:*");
        const banned = keys.map(k => k.replace("ban:", ""));

        res.json({
            bannedCount: banned.length,
            banned
        });

    } catch (err) {
        console.error("Ban list error:", err);
        res.status(500).json({ error: "Ban list failed" });
    }
};
