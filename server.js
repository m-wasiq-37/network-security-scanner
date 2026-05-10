const express = require('express');
const cors = require('cors');
const net = require('net');
const dgram = require('dgram');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080];

const SERVICE_MAP = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'TELNET',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPCBIND',
  123: 'NTP',
  135: 'RPC',
  137: 'NETBIOS',
  138: 'NETBIOS',
  139: 'NETBIOS-SSN',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'SHELL',
  587: 'SMTP-Submission',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'ORACLE',
  2049: 'NFS',
  2375: 'DOCKER',
  3000: 'WEB-APP',
  3306: 'MYSQL',
  3389: 'RDP',
  5432: 'POSTGRESQL',
  5900: 'VNC',
  6379: 'REDIS',
  8080: 'HTTP-PROXY',
  8443: 'HTTPS-ALT',
  9000: 'WEB-ADMIN'
};

function serviceName(port) {
  return SERVICE_MAP[port] || 'Unknown';
}

function parsePorts(input) {
  if (!input || !String(input).trim()) {
    return DEFAULT_PORTS;
  }

  const parts = String(input)
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);

  const ports = new Set();

  for (const part of parts) {
    if (part.includes('-')) {
      const [startRaw, endRaw] = part.split('-').map(v => v.trim());
      const start = Number.parseInt(startRaw, 10);
      const end = Number.parseInt(endRaw, 10);
      if (Number.isInteger(start) && Number.isInteger(end) && start > 0 && end > 0 && end >= start && end <= 65535) {
        for (let p = start; p <= end; p += 1) {
          ports.add(p);
        }
      }
    } else {
      const p = Number.parseInt(part, 10);
      if (Number.isInteger(p) && p > 0 && p <= 65535) {
        ports.add(p);
      }
    }
  }

  const list = [...ports].sort((a, b) => a - b);
  return list.length ? list : DEFAULT_PORTS;
}

function scanTcpPort(host, port, timeoutMs = 1000) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;

    const done = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      done({ port, service: serviceName(port), status: 'open' });
    });

    socket.once('timeout', () => {
      done({ port, service: serviceName(port), status: 'closed' });
    });

    socket.once('error', () => {
      done({ port, service: serviceName(port), status: 'closed' });
    });

    socket.connect(port, host);
  });
}

function scanUdpPort(host, port, timeoutMs = 1200) {
  return new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const done = result => {
      if (settled) return;
      settled = true;
      socket.close();
      resolve(result);
    };

    socket.on('message', () => {
      done({ port, service: serviceName(port), status: 'open' });
    });

    socket.on('error', err => {
      if (err.code === 'ECONNREFUSED') {
        done({ port, service: serviceName(port), status: 'closed' });
      } else {
        done({ port, service: serviceName(port), status: 'closed' });
      }
    });

    socket.send(Buffer.from('ping'), port, host, err => {
      if (err) {
        done({ port, service: serviceName(port), status: 'closed' });
      }
    });

    setTimeout(() => {
      done({ port, service: serviceName(port), status: 'open|filtered' });
    }, timeoutMs);
  });
}

async function scanHost(target, scanType, ports) {
  const results = [];

  if (scanType === 'UDP') {
    for (const port of ports) {
      results.push(await scanUdpPort(target, port));
    }
    return results;
  }

  for (const port of ports) {
    results.push(await scanTcpPort(target, port));
  }

  return results;
}

function matchRule(rule, packet) {
  const protocolMatch = rule.protocol === 'any' || rule.protocol === packet.protocol;
  const portMatch = rule.port === 'any' || Number(rule.port) === Number(packet.port);
  const sourceMatch = rule.ip === 'any' || rule.ip === packet.sourceIp;
  const destMatch = rule.ip === 'any' || rule.ip === packet.destIp;
  return protocolMatch && portMatch && (sourceMatch || destMatch);
}

function evaluateRules(rules, packet) {
  const sortedRules = [...rules].sort((a, b) => Number(a.priority) - Number(b.priority));
  for (const rule of sortedRules) {
    if (matchRule(rule, packet)) {
      return {
        decision: rule.action,
        matchedRule: rule
      };
    }
  }

  return {
    decision: 'allow',
    matchedRule: null
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/scan', async (req, res) => {
  try {
    const target = String(req.body.target || '').trim();
    const scanType = String(req.body.scanType || 'TCP Connect').trim();
    const portRange = String(req.body.portRange || '').trim();

    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    const ports = parsePorts(portRange);
    const results = await scanHost(target, scanType, ports);

    res.json({
      target,
      scanType,
      ports,
      results
    });
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', details: error.message });
  }
});

app.post('/api/simulate', (req, res) => {
  try {
    const rules = Array.isArray(req.body.rules) ? req.body.rules : [];
    const packet = {
      sourceIp: String(req.body.sourceIp || '').trim(),
      destIp: String(req.body.destIp || '').trim(),
      port: Number(req.body.port),
      protocol: String(req.body.protocol || 'tcp').toLowerCase()
    };

    const result = evaluateRules(rules, packet);
    res.json({ packet, ...result });
  } catch (error) {
    res.status(500).json({ error: 'Simulation failed', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
