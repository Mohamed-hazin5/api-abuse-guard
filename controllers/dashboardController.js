const { ScanCommand } = require("@aws-sdk/client-dynamodb");
const dynamo = require("../services/dynamoService");
const redis = require("../redisClient");

/* ==============================
   OVERVIEW
============================== */
exports.getOverview = async (req, res) => {
    try {
        const data = await dynamo.send(new ScanCommand({
            TableName: "api-request-logs"
        }));

        const items = data.Items || [];

        const totalRequests = items.length;

        const uniqueIPs = new Set(
            items.map(i => i.ipAddress?.S).filter(Boolean)
        ).size;

        const highRisk = items.filter(
            i => parseInt(i.riskScore?.N || 0) >= 70
        ).length;

        const recent = items
            .sort((a, b) =>
                new Date(b.timestamp?.S || 0) -
                new Date(a.timestamp?.S || 0)
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

/* ==============================
   TOP IPS
============================== */
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

/* ==============================
   BANNED ENTITIES (IP + FP)
============================== */
exports.getBannedIPs = async (req, res) => {
    try {
        // Fetch both IP bans and fingerprint bans
        const ipKeys = await redis.keys("ban:*");
        const fpKeys = await redis.keys("fpban:*");

        const ipBans = ipKeys.map(k => k.replace("ban:", ""));
        const fingerprintBans = fpKeys.map(k => k.replace("fpban:", ""));

        res.json({
            ipBanCount: ipBans.length,
            fingerprintBanCount: fingerprintBans.length,
            ipBans,
            fingerprintBans
        });

    } catch (err) {
        console.error("Ban list error:", err);
        res.status(500).json({ error: "Ban list failed" });
    }
};
