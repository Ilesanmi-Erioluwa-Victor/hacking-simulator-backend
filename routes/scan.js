const express = require("express");
const { exec } = require("child_process");
const { promisify } = require("util");
const execAsync = promisify(exec);
const { authenticateToken } = require("../middleware/auth");
const { logger } = require("../utils/logger");
const router = express.Router();

// Validation function for targets
const isValidTarget = (target) => {
  const allowedTargets = [
    "localhost",
    "127.0.0.1",
    "example.com",
    "test.com",
    "example.org",
    "scanme.nmap.org", // Nmap's official test domain
  ];

  const invalidChars = /[;&|<>$`]/;
  if (invalidChars.test(target)) {
    return false;
  }

  // Allow only specific test domains or localhost
  return allowedTargets.includes(target);
};

// Nmap scan endpoint
router.post("/nmap", authenticateToken, async (req, res) => {
  try {
    const { target } = req.body;

    if (!target || !isValidTarget(target)) {
      return res.status(400).json({
        error: "Invalid target. Please provide a valid test target.",
      });
    }

    logger.info(
      `Nmap scan requested by user ${req.user._id} for target: ${target}`
    );

    // Run nmap scan with safe parameters (timeout after 30 seconds)
    const { stdout, stderr } = await execAsync(
      `timeout 30 nmap -sV -T4 ${target}`
    );

    // Log the successful scan
    logger.info(
      `Nmap scan completed for user ${req.user._id} on target ${target}`
    );

    res.json({
      output: stdout,
      target: target,
      timestamp: new Date().toISOString(),
      userId: req.user._id,
    });
  } catch (error) {
    logger.error("Nmap scan error:", error);

    if (error.killed || error.signal === "SIGTERM") {
      return res.status(408).json({
        error: "Scan timed out",
        message: "The scan took too long to complete",
      });
    }

    res.status(500).json({
      error: "Scan failed",
      message: error.message,
    });
  }
});

// Simulated SQLMap scan endpoint
router.post("/sqlmap", authenticateToken, async (req, res) => {
  try {
    const { target } = req.body;

    if (!target || !isValidTarget(target)) {
      return res.status(400).json({
        error: "Invalid target",
      });
    }

    logger.info(
      `SQLMap simulation requested by user ${req.user._id} for target: ${target}`
    );

    // Simulate sqlmap scan (in real implementation, this would run actual tool)
    const output = `[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL appears to be dynamic
[INFO] testing for SQL injection on parameter 'id'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[CRITICAL] parameter 'id' appears to be vulnerable`;

    // Simulate delay
    await new Promise((resolve) => setTimeout(resolve, 2000));

    res.json({
      output: output,
      target: target,
      timestamp: new Date().toISOString(),
      userId: req.user._id,
    });
  } catch (error) {
    logger.error("SQLMap simulation error:", error);
    res.status(500).json({
      error: "Scan failed",
      message: error.message,
    });
  }
});

// Get scan history for authenticated user
router.get("/history", authenticateToken, async (req, res) => {
  try {
    // In a real implementation, you would fetch from a database
    // For now, return mock data
    const history = [
      {
        id: 1,
        tool: "nmap",
        target: "example.com",
        timestamp: new Date(Date.now() - 86400000).toISOString(),
        status: "completed",
      },
      {
        id: 2,
        tool: "sqlmap",
        target: "test.com",
        timestamp: new Date(Date.now() - 172800000).toISOString(),
        status: "completed",
      },
    ];

    res.json({ history });
  } catch (error) {
    logger.error("History fetch error:", error);
    res.status(500).json({ error: "Error fetching history" });
  }
});

module.exports = router;
