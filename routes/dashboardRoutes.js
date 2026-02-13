const express = require("express");
const router = express.Router();

const {
    getOverview,
    getTopIPs,
    getBannedIPs
} = require("../controllers/dashboardController");

router.get("/overview", getOverview);
router.get("/top-ips", getTopIPs);
router.get("/banned-ips", getBannedIPs);

module.exports = router;
