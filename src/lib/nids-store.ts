// NIDS AI - Data store and simulation engine backed by Prisma SQLite
import { db } from "@/lib/db";

const THREAT_SIGNATURES: Record<string, {
  patterns: string[];
  severity: string;
  ports: number[];
  description: string;
}> = {
  "SQL Injection": {
    patterns: ["UNION SELECT", "OR 1=1", "DROP TABLE", "' OR ", "admin'--", "1; WAITFOR"],
    severity: "critical",
    ports: [80, 443, 8080],
    description: "SQL injection attempt detected in HTTP request payload",
  },
  "XSS Attack": {
    patterns: ["<script>", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"],
    severity: "high",
    ports: [80, 443],
    description: "Cross-site scripting attack payload detected",
  },
  "DDoS Attack": {
    patterns: ["SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "HTTP_FLOOD"],
    severity: "critical",
    ports: [80, 443, 53],
    description: "Distributed denial of service attack pattern detected",
  },
  "Brute Force": {
    patterns: ["LOGIN_ATTEMPT_RAPID", "SSH_BRUTE", "FTP_BRUTE", "RDP_BRUTE"],
    severity: "high",
    ports: [22, 21, 3389, 8080],
    description: "Brute force login attempt detected",
  },
  "Port Scan": {
    patterns: ["PORT_SCAN_SYN", "PORT_SCAN_CONNECT", "PORT_SCAN_UDP"],
    severity: "medium",
    ports: [22, 80, 443, 3389, 8080, 3306, 5432],
    description: "Network port scanning activity detected",
  },
  "Malware C2": {
    patterns: ["C2_BEACON", "DNS_TUNNEL", "HTTP_C2", "ENCRYPTED_CHANNEL"],
    severity: "critical",
    ports: [443, 80, 53, 8080],
    description: "Command and control communication detected",
  },
  "Data Exfiltration": {
    patterns: ["LARGE_UPLOAD", "DNS_EXFIL", "HTTPS_EXFIL", "ICMP_TUNNEL"],
    severity: "critical",
    ports: [443, 53, 80],
    description: "Data exfiltration attempt detected",
  },
  "Privilege Escalation": {
    patterns: ["SUID_EXPLOIT", "KERNEL_EXPLOIT", "TOKEN_MANIPULATION"],
    severity: "high",
    ports: [22, 445],
    description: "Privilege escalation attempt detected",
  },
};

const SOURCE_IPS = [
  "192.168.1.100", "10.0.0.55", "172.16.0.23", "203.0.113.42",
  "198.51.100.17", "45.33.32.156", "91.218.114.11", "185.220.101.34",
  "104.248.12.67", "159.89.40.15", "128.199.212.52", "67.205.146.88",
  "138.68.61.49", "142.93.38.22", "167.172.12.85", "178.62.25.13",
  "206.189.45.67", "134.209.105.128", "64.225.8.192", "45.55.34.189",
];

const DEST_IPS = [
  "192.168.1.1", "10.0.0.1", "172.16.0.1", "192.168.1.50",
  "10.0.0.10", "172.16.0.5", "192.168.1.200", "10.0.0.100",
];

const PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP"];

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const MAX_EVENTS = 200;
const MAX_ALERTS = 100;
const MAX_HISTORY = 60;

let lastGenTime = 0;

async function seedDatabaseIfNeeded() {
  const statCount = await db.systemStat.count();
  if (statCount === 0) {
    await db.systemStat.create({
      data: {
        id: "global",
        totalPackets: 500,
        threatsDetected: 12,
        connectionsBlocked: 2,
        aiAnalyses: 0,
        startTime: new Date(Date.now() - 3600000 * 2) // 2 hours ago
      }
    });

    // Create some initial traffic history
    const historyData = [];
    const now = Date.now();
    for (let i = 20; i > 0; i--) {
      historyData.push({
        timestamp: new Date(now - i * 5000),
        packets_per_sec: randInt(2, 6),
        threats: Math.random() < 0.15 ? 1 : 0
      });
    }
    await db.trafficHistory.createMany({ data: historyData });

    // Seed some initial network events
    const seedEvents = [];
    for (let i = 50; i > 0; i--) {
      const isThreat = Math.random() < 0.15;
      const ts = new Date(now - i * 15000);
      if (isThreat) {
        const threatType = pick(Object.keys(THREAT_SIGNATURES));
        const sig = THREAT_SIGNATURES[threatType];
        const sourceIp = pick(SOURCE_IPS);
        seedEvents.push({
          timestamp: ts,
          source_ip: sourceIp,
          destination_ip: pick(DEST_IPS),
          source_port: randInt(49152, 65535),
          destination_port: pick(sig.ports),
          protocol: pick(PROTOCOLS),
          packet_size: randInt(40, 65535),
          is_threat: true,
          threat_type: threatType,
          severity: sig.severity,
          pattern_matched: pick(sig.patterns),
          description: sig.description,
          status: "detected"
        });
      } else {
        seedEvents.push({
          timestamp: ts,
          source_ip: pick(SOURCE_IPS),
          destination_ip: pick(DEST_IPS),
          source_port: randInt(49152, 65535),
          destination_port: pick([80, 443, 22, 53]),
          protocol: pick(PROTOCOLS),
          packet_size: randInt(40, 65535),
          is_threat: false,
          threat_type: null,
          severity: "info",
          pattern_matched: null,
          description: "Normal traffic",
          status: "allowed"
        });
      }
    }
    await db.networkEvent.createMany({ data: seedEvents });

    // Seed alerts for threats
    const threats = await db.networkEvent.findMany({
      where: { is_threat: true },
      take: 10
    });
    for (const t of threats) {
      if (t.severity === "critical" || t.severity === "high") {
        await db.alert.create({
          data: {
            id: t.id,
            timestamp: t.timestamp,
            type: t.threat_type || "Unknown",
            severity: t.severity,
            source_ip: t.source_ip,
            message: `${t.threat_type} detected from ${t.source_ip}`,
            status: "detected"
          }
        });
      }
    }
  }
}

async function cleanOldRecords() {
  // Keep latest MAX_EVENTS network events
  const totalEvents = await db.networkEvent.count();
  if (totalEvents > MAX_EVENTS) {
    const oldestToKeep = await db.networkEvent.findMany({
      orderBy: { timestamp: "desc" },
      skip: MAX_EVENTS,
      take: 1,
      select: { id: true, timestamp: true }
    });
    if (oldestToKeep.length > 0) {
      await db.networkEvent.deleteMany({
        where: { timestamp: { lte: oldestToKeep[0].timestamp } }
      });
    }
  }

  // Keep latest MAX_ALERTS alerts
  const totalAlerts = await db.alert.count();
  if (totalAlerts > MAX_ALERTS) {
    const oldestToKeep = await db.alert.findMany({
      orderBy: { timestamp: "desc" },
      skip: MAX_ALERTS,
      take: 1,
      select: { id: true, timestamp: true }
    });
    if (oldestToKeep.length > 0) {
      await db.alert.deleteMany({
        where: { timestamp: { lte: oldestToKeep[0].timestamp } }
      });
    }
  }

  // Keep latest MAX_HISTORY traffic histories
  const totalHistory = await db.trafficHistory.count();
  if (totalHistory > MAX_HISTORY) {
    const oldestToKeep = await db.trafficHistory.findMany({
      orderBy: { timestamp: "desc" },
      skip: MAX_HISTORY,
      take: 1,
      select: { id: true, timestamp: true }
    });
    if (oldestToKeep.length > 0) {
      await db.trafficHistory.deleteMany({
        where: { timestamp: { lte: oldestToKeep[0].timestamp } }
      });
    }
  }
}

async function generateEvents() {
  const now = Date.now();
  if (now - lastGenTime < 2000) return;
  lastGenTime = now;

  await seedDatabaseIfNeeded();

  const count = randInt(3, 8);
  let threats = 0;

  for (let i = 0; i < count; i++) {
    const isThreat = Math.random() < 0.15;
    const sourceIp = pick(SOURCE_IPS);

    // Check if source IP is blocked in the database
    const isBlocked = await db.blockedIP.findUnique({
      where: { ip: sourceIp }
    });

    if (isThreat) {
      const threatType = pick(Object.keys(THREAT_SIGNATURES));
      const sig = THREAT_SIGNATURES[threatType];
      const severity = sig.severity;
      const pattern = pick(sig.patterns);
      const status = isBlocked ? "blocked" : pick(["detected", "blocked", "investigating"]);

      const event = await db.networkEvent.create({
        data: {
          timestamp: new Date(),
          source_ip: sourceIp,
          destination_ip: pick(DEST_IPS),
          source_port: randInt(49152, 65535),
          destination_port: pick(sig.ports),
          protocol: pick(PROTOCOLS),
          packet_size: randInt(40, 65535),
          is_threat: true,
          threat_type: threatType,
          severity,
          pattern_matched: pattern,
          description: sig.description,
          status,
        }
      });

      // Update counters in SystemStat
      await db.systemStat.updateMany({
        where: { id: "global" },
        data: {
          threatsDetected: { increment: 1 },
          connectionsBlocked: isBlocked || status === "blocked" ? { increment: 1 } : undefined
        }
      });

      threats++;

      if (severity === "critical" || severity === "high") {
        await db.alert.create({
          data: {
            id: event.id,
            timestamp: event.timestamp,
            type: threatType,
            severity,
            source_ip: sourceIp,
            message: `${threatType} detected from ${sourceIp}`,
            status,
          }
        });
      }
    } else {
      const status = isBlocked ? "blocked" : "allowed";
      await db.networkEvent.create({
        data: {
          timestamp: new Date(),
          source_ip: sourceIp,
          destination_ip: pick(DEST_IPS),
          source_port: randInt(49152, 65535),
          destination_port: Math.random() > 0.3 ? pick([80, 443, 22, 53, 8080]) : randInt(1024, 65535),
          protocol: pick(PROTOCOLS),
          packet_size: randInt(40, 65535),
          is_threat: false,
          threat_type: null,
          severity: "info",
          pattern_matched: null,
          description: "Normal traffic",
          status,
        }
      });

      if (isBlocked) {
        await db.systemStat.updateMany({
          where: { id: "global" },
          data: { connectionsBlocked: { increment: 1 } }
        });
      }
    }

    // Increment packet count
    await db.systemStat.updateMany({
      where: { id: "global" },
      data: { totalPackets: { increment: 1 } }
    });
  }

  // Create TrafficHistory record
  await db.trafficHistory.create({
    data: {
      timestamp: new Date(),
      packets_per_sec: count,
      threats,
    }
  });

  // Clean up old records
  await cleanOldRecords();
}

// ─── Analysis Fallback ────────────────────────────────────────────────────────
function generateAnalysis(threat: any): string {
  const t = threat.threat_type || "Unknown";
  const s = threat.source_ip || "Unknown";
  const d = threat.destination_ip || "Unknown";
  const p = threat.destination_port || threat.port || "Unknown";

  const templates: Record<string, string> = {
    "SQL Injection": `**Threat Analysis: SQL Injection Attack**\n\nThis attack originates from ${s} targeting ${d} on port ${p}. SQL injection is one of the most critical web application vulnerabilities (OWASP Top 10).\n\n**Attack Vector**: The attacker targets login forms, search fields, or API endpoints that concatenate user input into SQL queries without parameterization.\n\n**Potential Impact**: Unauthorized data access, data modification, authentication bypass, or complete database compromise.\n\n**Recommended Actions**:\n1. Implement parameterized queries immediately\n2. Deploy WAF with SQL injection rules\n3. Apply input validation on all user inputs\n4. Block source IP ${s} at firewall level\n5. Conduct code review for SQL injection vulnerabilities`,

    "XSS Attack": `**Threat Analysis: Cross-Site Scripting (XSS)**\n\nXSS attack detected from ${s} targeting ${d}. Malicious client-side scripts injected into web pages.\n\n**Attack Vector**: Script payloads via reflected/stored XSS targeting vulnerable input fields.\n\n**Potential Impact**: Session hijacking, credential theft, defacement, malware distribution.\n\n**Recommended Actions**:\n1. Implement Content Security Policy headers\n2. Apply output encoding for user-controlled data\n3. Use HTTP-only and Secure cookie flags\n4. Block ${s} and investigate sessions\n5. Audit code for unescaped output`,

    "DDoS Attack": `**Threat Analysis: DDoS Attack**\n\nDDoS pattern from ${s} targeting ${d}. Flooding target with malicious traffic.\n\n**Attack Vector**: Volumetric/protocol-based attack leveraging botnets.\n\n**Potential Impact**: Service disruption, financial losses, reputation damage.\n\n**Recommended Actions**:\n1. Activate DDoS mitigation with upstream provider\n2. Enable rate limiting and traffic shaping\n3. Implement IP reputation filtering\n4. Scale infrastructure horizontally\n5. Monitor for secondary attacks`,

    "Brute Force": `**Threat Analysis: Brute Force Attack**\n\nBrute force from ${s} targeting ${d} on port ${p}. Systematic credential testing.\n\n**Attack Vector**: Automated tools testing credential combinations.\n\n**Potential Impact**: Unauthorized access, data breaches, lateral movement.\n\n**Recommended Actions**:\n1. Implement account lockout policies\n2. Enable multi-factor authentication\n3. Block ${s} and investigate\n4. Deploy CAPTCHA on auth forms\n5. Rotate credentials for targeted services`,

    "Port Scan": `**Threat Analysis: Port Scanning**\n\nPort scan from ${s}. Reconnaissance phase before targeted attacks.\n\n**Attack Vector**: SYN/CONNECT/UDP scanning to enumerate services.\n\n**Potential Impact**: Information disclosure for subsequent attacks.\n\n**Recommended Actions**:\n1. Close unnecessary ports\n2. Implement network segmentation\n3. Deploy IPS rules\n4. Add ${s} to monitoring watchlist\n5. Harden exposed services`,

    "Malware C2": `**Threat Analysis: C2 Communication**\n\nC2 detected from ${s} to ${d}. Compromised host communicating with attacker infrastructure.\n\n**Attack Vector**: Persistent encrypted channels with C2 server.\n\n**Potential Impact**: Complete system compromise, data exfiltration, ransomware.\n\n**Recommended Actions**:\n1. Immediately isolate host ${s}\n2. Block C2 server ${d}\n3. Perform forensic analysis\n4. Reset all accessed credentials\n5. Scan all hosts for C2 indicators`,

    "Data Exfiltration": `**Threat Analysis: Data Exfiltration**\n\nExfiltration from ${s} to ${d}. Sensitive data transfer outside the network.\n\n**Attack Vector**: DNS tunneling, HTTPS uploads, ICMP tunnels.\n\n**Potential Impact**: IP loss, data breaches, regulatory violations.\n\n**Recommended Actions**:\n1. Block exfiltration channel immediately\n2. Implement DLP solutions\n3. Investigate host ${s}\n4. Enable deep packet inspection\n5. Review data access logs`,

    "Privilege Escalation": `**Threat Analysis: Privilege Escalation**\n\nPrivilege escalation from ${s} targeting ${d}. Attempting to gain admin/root access.\n\n**Attack Vector**: SUID exploits, kernel vulnerabilities, token manipulation.\n\n**Potential Impact**: Full system compromise, persistent backdoors.\n\n**Recommended Actions**:\n1. Audit SUID binaries\n2. Apply security patches\n3. Implement least-privilege controls\n4. Monitor for privilege elevation\n5. Investigate initial compromise vector`,
  };

  return templates[t] || `**Threat Analysis: ${t}**\n\nNetwork threat from ${s} targeting ${d} on port ${p}. Requires immediate investigation.\n\n**Recommended Actions**:\n1. Investigate source IP ${s}\n2. Monitor traffic patterns\n3. Consider blocking the IP\n4. Review firewall rules\n5. Update threat intelligence`;
}

function chatResponse(message: string): string {
  const m = message.toLowerCase();
  if (m.includes("threat")) return "Based on the current threat landscape, I recommend implementing a layered defense strategy with network segmentation, IPS, and regular vulnerability assessments. The most critical threats are SQL injection and C2 communications.";
  if (m.includes("ddos")) return "DDoS mitigation: deploy traffic scrubbing, implement rate limiting, use CDN protection, ensure horizontal scalability. Monitor traffic patterns for early attack detection.";
  if (m.includes("vulnerability")) return "Key vulnerabilities: unpatched web apps, unnecessary open ports, weak authentication, insufficient logging. Prioritize CVE patching and zero-trust architecture.";
  if (m.includes("sql")) return "SQL injection prevention: parameterized queries, input validation, stored procedures, WAF deployment. Never concatenate user input into SQL.";
  if (m.includes("xss")) return "XSS prevention: output encoding, CSP headers, HTTP-only cookies, input sanitization. Always escape user-controlled data.";
  if (m.includes("brute")) return "Brute force prevention: account lockout policies, MFA, CAPTCHA, IP blocking, credential rotation.";
  return "I'm your AI security assistant. I can help analyze threats, recommend security measures, explain attack vectors, and provide incident response guidance. What would you like to discuss?";
}

export { generateEvents, THREAT_SIGNATURES, generateAnalysis, chatResponse, seedDatabaseIfNeeded };
