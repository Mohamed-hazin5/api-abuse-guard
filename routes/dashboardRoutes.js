const express = require("express");
const router = express.Router();

const dashboardController = require("../controllers/dashboardController");

router.get("/overview", dashboardController.getOverview);
router.get("/top-ips", dashboardController.getTopIPs);
router.get("/banned-ips", dashboardController.getBannedIPs);

module.exports = router;
