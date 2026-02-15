const { ScanCommand } = require("@aws-sdk/client-dynamodb");
const dynamo = require("../services/dynamoService");
const redis = require("../redisClient");

exports.getBannedIPs = async (req, res) => {
    try {
        const keys = await redis.keys("ban:*");

        const bannedDevices = [];

        for (const key of keys) {

            // Remove "ban:" prefix
            const rawValue = key.replace("ban:", "");

            // If fingerprint-based ban
            if (rawValue.startsWith("fp:")) {

                const fingerprint = rawValue.replace("fp:", "");

                // Find latest IP used by this fingerprint
                const data = await dynamo.send(new ScanCommand({
                    TableName: "api-request-logs",
                    FilterExpression: "fingerprint = :fp",
                    ExpressionAttributeValues: {
                        ":fp": { S: fingerprint }
                    }
                }));

                const items = data.Items || [];

                let latestIP = "unknown";

                if (items.length > 0) {
                    items.sort((a, b) =>
                        new Date(b.timestamp.S) - new Date(a.timestamp.S)
                    );

                    latestIP = items[0].ipAddress?.S || "unknown";
                }

                bannedDevices.push({
                    ipAddress: latestIP,
                    fingerprint
                });

            } else {
                // IP-based ban
                bannedDevices.push({
                    ipAddress: rawValue,
                    fingerprint: null
                });
            }
        }

        res.json(bannedDevices);

    } catch (err) {
        console.error("Ban list error:", err);
        res.status(500).json({ error: "Ban list failed" });
    }
};
