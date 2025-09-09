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

    // Validate target
    if (!target || !isValidTarget(target)) {
      return res.status(400).json({
        error: "Invalid target. Please provide a valid test target.",
      });
    }

    // Perform the scan (real or simulated)
    const scanData = await performNmapScan(target);

    // Return successful response
    return res.json({
      output: scanData.output,
      target: target,
      timestamp: new Date().toISOString(),
      simulated: scanData.simulated,
      userId: req.user._id,
    });
  } catch (error) {
    // Handle errors
    return handleScanError(error, res);
  }
});

// Separate function for scanning
async function performNmapScan(target) {
  if (process.env.NODE_ENV === "production") {
    // Simulated scan for production
    return {
      output: `Nmap scan report for ${target}
Host is up (0.0020s latency).
Not shown: 995 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
3306/tcp open   mysql
8080/tcp closed http-proxy`,
      simulated: true,
    };
  } else {
    try {
      // For development, use real nmap with timeout
      const { stdout, stderr } = await execAsync(
        `timeout 30 nmap -sV -T4 ${target}`
      );
      return {
        output: stdout,
        simulated: false,
      };
    } catch (error) {
      // If nmap fails, fall back to simulation
      logger.warn(
        `Real nmap failed, falling back to simulation: ${error.message}`
      );
      return {
        output: `Nmap scan report for ${target} (simulated fallback)
Note: Real nmap scan failed, showing simulated results
Host is up (0.0020s latency).
Not shown: 995 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https`,
        simulated: true,
      };
    }
  }
}

// Separate function for error handling
function handleScanError(error, res) {
  logger.error("Nmap scan error:", error);

  if (error.killed || error.signal === "SIGTERM") {
    return res.status(408).json({
      error: "Scan timed out",
      message: "The scan took too long to complete",
    });
  }

  return res.status(500).json({
    error: "Scan failed",
    message:
      process.env.NODE_ENV === "production"
        ? "Scan operation failed"
        : error.message,
  });
}

// SQLMap scan endpoint (always simulated for safety)
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

    // Always use simulation for SQLMap (safer approach)
    const output = `[INFO] testing connection to the target URL: ${target}
[INFO] testing if the target URL content is stable
[INFO] target URL appears to be dynamic
[INFO] testing for SQL injection on parameter 'id'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[CRITICAL] parameter 'id' appears to be vulnerable

NOTE: This is a simulated SQL injection scan for educational purposes.
Real SQL injection attacks would be performed with proper authorization.`;

    // Simulate processing delay
    await new Promise((resolve) => setTimeout(resolve, 2000));

    return res.json({
      output: output,
      target: target,
      timestamp: new Date().toISOString(),
      userId: req.user._id,
      simulated: true, // Always true for SQLMap
      note: "Simulated results for educational purposes",
    });
  } catch (error) {
    logger.error("SQLMap simulation error:", error);
    return res.status(500).json({
      error: "Scan failed",
      message:
        process.env.NODE_ENV === "production"
          ? "SQL injection scan simulation failed"
          : error.message,
    });
  }
});

// Additional simulated tools endpoint
router.post("/:tool", authenticateToken, async (req, res) => {
  try {
    const { target } = req.body;
    const { tool } = req.params;

    if (!target || !isValidTarget(target)) {
      return res.status(400).json({
        error: "Invalid target",
      });
    }

    // List of supported tools
    const supportedTools = {
      burp: "Burp Suite Web Vulnerability Scanner",
      metasploit: "Metasploit Penetration Testing Framework",
      wireshark: "Wireshark Network Protocol Analyzer",
    };

    if (!supportedTools[tool]) {
      return res.status(400).json({
        error: "Unsupported tool",
        message: `Tool '${tool}' is not supported. Available tools: ${Object.keys(
          supportedTools
        ).join(", ")}`,
      });
    }

    logger.info(
      `${tool} simulation requested by user ${req.user._id} for target: ${target}`
    );

    // Generate simulated output based on tool
    const simulatedOutput = generateSimulatedOutput(tool, target);

    // Simulate processing delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    return res.json({
      output: simulatedOutput,
      target: target,
      tool: tool,
      toolName: supportedTools[tool],
      timestamp: new Date().toISOString(),
      userId: req.user._id,
      simulated: true,
      note: "Simulated results for educational purposes",
    });
  } catch (error) {
    logger.error(`${req.params.tool} simulation error:`, error);
    return res.status(500).json({
      error: "Scan failed",
      message:
        process.env.NODE_ENV === "production"
          ? "Security scan simulation failed"
          : error.message,
    });
  }
});

// Generate simulated output for different tools
function generateSimulatedOutput(tool, target) {
  const simulations = {
    burp: `Burp Suite Professional - Web Vulnerability Scanner
Target: ${target}
Scan started: ${new Date().toISOString()}

[INFO] Spidering target...
[INFO] Found 12 endpoints
[INFO] Testing for XSS vulnerabilities...
[INFO] Testing for SQL injection...
[INFO] Testing for CSRF vulnerabilities...
[WARNING] Potential XSS vulnerability found in /contact form
[WARNING] Potential SQL injection in /search parameter 'q'
[INFO] Scan completed: 3 potential vulnerabilities found

NOTE: This is a simulated Burp Suite scan for educational purposes.`,

    metasploit: `Metasploit Framework Console Simulation
Target: ${target}

[+] Scanning target for vulnerabilities...
[+] Found potential SMB vulnerability (MS17-010)
[+] Preparing exploit module: exploit/windows/smb/ms17_010_eternalblue
[+] Setting payload: windows/x64/meterpreter/reverse_tcp
[+] Attempting exploitation...
[+] Shell established successfully

NOTE: This is a simulated Metasploit session for educational purposes.
Real penetration testing requires proper authorization.`,

    wireshark: `Wireshark Network Protocol Analyzer Simulation
Capturing traffic for target: ${target}

[INFO] Capturing network packets...
[INFO] Analyzing protocol distribution:
  - TCP: 65%
  - UDP: 20% 
  - HTTP: 15%
  - HTTPS: 10%
[INFO] Detected unusual DNS queries
[INFO] Potential port scan activity detected from 192.168.1.15

NOTE: This is a simulated Wireshark analysis for educational purposes.`,
  };

  return simulations[tool] || `Simulated output for ${tool} scan on ${target}`;
}

// Get scan history for authenticated user
router.get("/history", authenticateToken, async (req, res) => {
  try {
    // In a real implementation, you would fetch from a database
    // For now, return mock data that's consistent with the simulation approach
    const history = [
      {
        id: 1,
        tool: "nmap",
        toolName: "Nmap Network Scanner",
        target: "scanme.nmap.org",
        timestamp: new Date(Date.now() - 86400000).toISOString(),
        status: "completed",
        simulated: process.env.NODE_ENV === "production", // Show if it was simulated
      },
      {
        id: 2,
        tool: "sqlmap",
        toolName: "SQLMap SQL Injection Tool",
        target: "test.com",
        timestamp: new Date(Date.now() - 172800000).toISOString(),
        status: "completed",
        simulated: true, // SQLMap is always simulated
      },
      {
        id: 3,
        tool: "burp",
        toolName: "Burp Suite Web Scanner",
        target: "example.com",
        timestamp: new Date(Date.now() - 259200000).toISOString(),
        status: "completed",
        simulated: true,
      },
    ];

    return res.json({
      history,
      note:
        process.env.NODE_ENV === "production"
          ? "All scans are simulated in production environment"
          : "Mixed real and simulated scans based on environment",
    });
  } catch (error) {
    logger.error("History fetch error:", error);
    return res.status(500).json({
      error: "Error fetching history",
      message:
        process.env.NODE_ENV === "production"
          ? "Unable to retrieve scan history"
          : error.message,
    });
  }
});

// Get available tools
router.get("/tools", authenticateToken, async (req, res) => {
  try {
    const tools = [
      {
        id: "nmap",
        name: "Nmap",
        description: "Network discovery and security auditing",
      },
      { id: "sqlmap", name: "SQLMap", description: "SQL injection testing" },
      {
        id: "metasploit",
        name: "Metasploit",
        description: "Penetration testing framework",
      },
      {
        id: "burp",
        name: "Burp Suite",
        description: "Web application security testing",
      },
      {
        id: "wireshark",
        name: "Wireshark",
        description: "Network protocol analyzer",
      },
    ];

    return res.json({ tools });
  } catch (error) {
    logger.error("Tools fetch error:", error);
    return res.status(500).json({
      error: "Error fetching tools list",
      message:
        process.env.NODE_ENV === "production"
          ? "Unable to retrieve tools list"
          : error.message,
    });
  }
});

module.exports = router;
