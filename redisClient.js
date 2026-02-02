const Redis = require("ioredis");

const redis = new Redis({
    host: process.env.REDIS_HOST || "redis",
    port: 6379,
});

redis.on("connect", () => {
    console.log("✅ Connected to Redis");
});

module.exports = redis;
