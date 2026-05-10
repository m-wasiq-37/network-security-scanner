let firewallRules = [];

const scanForm = document.getElementById('scanForm');
const targetInput = document.getElementById('target');
const scanTypeInput = document.getElementById('scanType');
const portRangeInput = document.getElementById('portRange');
const scanResults = document.getElementById('scanResults');
const scanMeta = document.getElementById('scanMeta');

const ruleForm = document.getElementById('ruleForm');
const ruleAction = document.getElementById('ruleAction');
const ruleIp = document.getElementById('ruleIp');
const rulePort = document.getElementById('rulePort');
const ruleProtocol = document.getElementById('ruleProtocol');
const rulePriority = document.getElementById('rulePriority');
const ruleResults = document.getElementById('ruleResults');

const simulationForm = document.getElementById('simulationForm');
const sourceIp = document.getElementById('sourceIp');
const destIp = document.getElementById('destIp');
const simPort = document.getElementById('simPort');
const simProtocol = document.getElementById('simProtocol');
const simulationOutput = document.getElementById('simulationOutput');
const flowDiagram = document.getElementById('flowDiagram');

function badgeClass(status) {
  const value = String(status).toLowerCase();
  if (value.includes('open') && !value.includes('filtered')) return 'badge badge-open';
  if (value.includes('filtered')) return 'badge badge-filtered';
  if (value.includes('closed')) return 'badge badge-closed';
  if (value.includes('allow')) return 'badge badge-allow';
  if (value.includes('deny')) return 'badge badge-deny';
  return 'badge badge-neutral';
}

function renderScanResults(target, results) {
  scanResults.innerHTML = results.map(row => `
    <tr>
      <td>${escapeHtml(target)}</td>
      <td>${row.port}</td>
      <td>${escapeHtml(row.service)}</td>
      <td><span class="${badgeClass(row.status)}">${escapeHtml(row.status)}</span></td>
    </tr>
  `).join('');
}

function renderRules() {
  const sorted = [...firewallRules].sort((a, b) => a.priority - b.priority);
  ruleResults.innerHTML = sorted.map((rule, index) => `
    <tr>
      <td>${rule.priority}</td>
      <td>${escapeHtml(rule.action)}</td>
      <td>${escapeHtml(rule.ip)}</td>
      <td>${escapeHtml(rule.port)}</td>
      <td>${escapeHtml(rule.protocol)}</td>
      <td><button class="icon-btn" data-index="${index}">Delete</button></td>
    </tr>
  `).join('') || `
    <tr>
      <td colspan="6">No firewall rules added yet.</td>
    </tr>
  `;

  ruleResults.querySelectorAll('button[data-index]').forEach(button => {
    button.addEventListener('click', () => {
      const index = Number(button.getAttribute('data-index'));
      const sortedRules = [...firewallRules].sort((a, b) => a.priority - b.priority);
      const ruleToDelete = sortedRules[index];
      firewallRules = firewallRules.filter(rule => !(rule.priority === ruleToDelete.priority && rule.action === ruleToDelete.action && rule.ip === ruleToDelete.ip && rule.port === ruleToDelete.port && rule.protocol === ruleToDelete.protocol));
      renderRules();
    });
  });
}

function updateFlow(decision) {
  const nodes = flowDiagram.querySelectorAll('.flow-node');
  nodes.forEach(node => node.classList.remove('allowed', 'blocked'));
  if (decision === 'allow') {
    nodes.forEach(node => node.classList.add('allowed'));
  } else {
    nodes.forEach(node => node.classList.add('blocked'));
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

scanForm.addEventListener('submit', async event => {
  event.preventDefault();
  scanMeta.textContent = 'Scanning in progress...';
  scanResults.innerHTML = '';

  const payload = {
    target: targetInput.value.trim(),
    scanType: scanTypeInput.value,
    portRange: portRangeInput.value.trim()
  };

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      scanMeta.textContent = data.error || 'Scan failed';
      return;
    }

    scanMeta.textContent = `Scanned ${data.results.length} ports on ${data.target} using ${data.scanType}.`;
    renderScanResults(data.target, data.results);
  } catch (error) {
    scanMeta.textContent = 'Network error while scanning.';
  }
});

ruleForm.addEventListener('submit', event => {
  event.preventDefault();

  firewallRules.push({
    action: ruleAction.value,
    ip: ruleIp.value.trim() || 'any',
    port: rulePort.value.trim() || 'any',
    protocol: ruleProtocol.value,
    priority: Number(rulePriority.value) || 1
  });

  renderRules();
  ruleForm.reset();
  ruleAction.value = 'allow';
  ruleIp.value = 'any';
  rulePort.value = 'any';
  ruleProtocol.value = 'any';
  rulePriority.value = 1;
});

simulationForm.addEventListener('submit', async event => {
  event.preventDefault();

  const payload = {
    rules: firewallRules,
    sourceIp: sourceIp.value.trim(),
    destIp: destIp.value.trim(),
    port: Number(simPort.value),
    protocol: simProtocol.value
  };

  try {
    const response = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      simulationOutput.textContent = data.error || 'Simulation failed';
      return;
    }

    updateFlow(data.decision);

    if (data.matchedRule) {
      simulationOutput.textContent = `Decision: ${data.decision.toUpperCase()} by priority ${data.matchedRule.priority} rule. Action: ${data.matchedRule.action}, IP: ${data.matchedRule.ip}, Port: ${data.matchedRule.port}, Protocol: ${data.matchedRule.protocol}.`;
    } else {
      simulationOutput.textContent = `Decision: ${data.decision.toUpperCase()} because no matching rule was found.`;
    }
  } catch (error) {
    simulationOutput.textContent = 'Network error while simulating traffic.';
  }
});

renderRules();
