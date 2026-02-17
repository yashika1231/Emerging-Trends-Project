/**
 * PhishGuard AI — Frontend Application
 * Connects to the FastAPI backend and renders analysis results.
 * Supports email analysis, metadata parsing, app verification, and dataset management.
 */

// ─── Configuration ─────────────────────────────────────────
const API_BASE = window.location.origin && window.location.origin !== 'null' && window.location.protocol !== 'file:'
  ? window.location.origin
  : 'http://localhost:8000';

// App-wide config loaded from backend
let appConfig = null;

// ─── DOM References ────────────────────────────────────────
const emailInput = document.getElementById('email-input');
const headersInput = document.getElementById('headers-input');
const charCount = document.getElementById('char-count');
const btnAnalyze = document.getElementById('btn-analyze');
const errorBanner = document.getElementById('error-banner');
const errorText = document.getElementById('error-text');
const resultsPlaceholder = document.getElementById('results-placeholder');
const resultsPanel = document.getElementById('results-panel');
const resultsDetails = document.getElementById('results-details');
const metadataCheckbox = document.getElementById('metadata-checkbox');
const metadataContainer = document.getElementById('metadata-container');

// ─── Tab Switching ────────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  document.querySelector(`.tab-btn[data-tab="${tabId}"]`).classList.add('active');
  document.getElementById(`tab-${tabId}`).classList.add('active');

  // Load dataset stats when switching to dataset tab
  if (tabId === 'dataset') {
    loadDatasetStats();
  }
}

// ─── Metadata Toggle ─────────────────────────────────────
metadataCheckbox.addEventListener('change', () => {
  metadataContainer.style.display = metadataCheckbox.checked ? 'block' : 'none';
});

// ─── EML Upload Toggle ───────────────────────────────────
 const emlCheckbox = document.getElementById('eml-checkbox');
const emlContainer = document.getElementById('eml-container');
const emlDropZone = document.getElementById('eml-drop-zone');
const emlFileInput = document.getElementById('eml-file-input');
let selectedEmlFile = null;

emlCheckbox.addEventListener('change', () => {
  emlContainer.style.display = emlCheckbox.checked ? 'block' : 'none';
});

// EML file selection
emlDropZone.addEventListener('click', () => emlFileInput.click());
emlFileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) selectEmlFile(e.target.files[0]);
});
emlDropZone.addEventListener('dragover', (e) => { e.preventDefault(); emlDropZone.classList.add('drag-over'); });
emlDropZone.addEventListener('dragleave', () => emlDropZone.classList.remove('drag-over'));
emlDropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  emlDropZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length > 0) selectEmlFile(e.dataTransfer.files[0]);
});

function selectEmlFile(file) {
  if (!file.name.toLowerCase().endsWith('.eml')) {
    showError('Please select a .eml file');
    return;
  }
  selectedEmlFile = file;
  document.getElementById('eml-selected-file').style.display = 'flex';
  document.getElementById('eml-file-name').textContent = `${file.name} (${formatFileSize(file.size)})`;
  emlDropZone.style.display = 'none';
  hideError();
}

function clearEmlSelection() {
  selectedEmlFile = null;
  emlFileInput.value = '';
  document.getElementById('eml-selected-file').style.display = 'none';
  emlDropZone.style.display = 'flex';
}

// ─── Character Counter ────────────────────────────────────
emailInput.addEventListener('input', () => {
  const len = emailInput.value.length;
  charCount.textContent = `${len.toLocaleString()} character${len !== 1 ? 's' : ''}`;
});

// ─── Example Emails ───────────────────────────────────────
const EXAMPLES = {
  'phishing-account': `Subject: URGENT: Your Account Has Been Compromised!
From: security-alert@paypa1-support.com

Dear Valued Customer,

We have detected suspicious activity on your account. Your account has been temporarily limited. Please click the link below to verify your identity immediately or your account will be permanently suspended within 24 hours.

Click here to verify: http://paypa1-secure-login.suspicious-domain.com/verify

If you do not respond within 24 hours, your account will be permanently closed.

Thank you,
PayPal Security Team`,

  'phishing-lottery': `Subject: You've Won $1,000,000 - Claim Now!
From: prize-notification@lottery-intl.net

Congratulations! You have been selected as the winner of the International Online Lottery. Your email was randomly selected from a pool of 50,000,000 email addresses.

To claim your prize of $1,000,000 USD, please reply with the following information:
- Full Name
- Date of Birth
- Bank Account Number
- Social Security Number

Contact our claims agent: Dr. James Williams at claims@lottery-intl.net`,

  'phishing-ceo': `Subject: Wire Transfer Confirmation Needed
From: cfo@company-finance.biz

Hi,

I need you to process an urgent wire transfer of $25,000 to our new vendor. I'm currently in a meeting and cannot call. Please process this immediately and I'll provide the documentation later.

Wire to:
Bank: First International Bank
Account: 4829501738
Routing: 029384756

This is confidential. Do not discuss with anyone else.

Thanks,
CEO`,

  'legit-meeting': `Subject: Team Meeting - Updated Agenda for Friday
From: sarah.johnson@company.com

Hi everyone,

Just a quick update on our Friday team meeting. I've added a few items to the agenda:

1. Q3 project status updates
2. New client onboarding process review
3. Team lunch planning for next month

The meeting is at 2 PM in Conference Room B. Let me know if you have anything else to add.

Best,
Sarah`,

  'legit-order': `Subject: Your Amazon Order Has Shipped
From: ship-confirm@amazon.com

Hello,

Your order #112-4837562-9981234 has shipped!

Items:
- Wireless Bluetooth Headphones (1)
- USB-C Charging Cable (2)

Estimated delivery: March 28-30
Track your package on amazon.com/orders

Thank you for shopping with us!
Amazon.com`,
};

function loadExample(key) {
  emailInput.value = EXAMPLES[key] || '';
  emailInput.dispatchEvent(new Event('input'));
  emailInput.focus();
  hideError();
}

// ─── App Verification Examples ────────────────────────────
const APP_EXAMPLES = {
  'fake-zoom': {
    app: 'zoom',
    fileName: 'zo0m-update-v5.18.exe.pdf',
    domains: 'zoom-update.suspicious-cdn.net, download.zo0m-meeting.xyz',
    sender: 'security@z00m-verify.com',
    urls: 'https://zoom-verify.suspicious-domain.com/update, http://zo0m-meeting.xyz/download',
    process: 'zoomhelper32.exe',
  },
  'fake-teams': {
    app: 'microsoft_teams',
    fileName: 'MS-Teams-Update.scr',
    domains: 'teams-update.malware-cdn.net, microsft-teams.xyz',
    sender: 'update@microsft-teams-security.com',
    urls: 'https://teams-login.suspicious-domain.com/verify',
    process: 'teamsupdate.exe',
  },
  'legit-zoom': {
    app: 'zoom',
    fileName: 'ZoomInstaller.exe',
    domains: 'zoom.us, zoom.com',
    sender: 'no-reply@zoom.us',
    urls: 'https://zoom.us/j/1234567890',
    process: 'zoom.exe',
  },
  'legit-teams': {
    app: 'microsoft_teams',
    fileName: 'Teams_windows_x64.exe',
    domains: 'teams.microsoft.com, microsoft.com',
    sender: 'noreply@email.teams.microsoft.com',
    urls: 'https://teams.microsoft.com/l/meetup',
    process: 'ms-teams.exe',
  },
};

function loadAppExample(key) {
  const ex = APP_EXAMPLES[key];
  if (!ex) return;

  document.getElementById('app-select').value = ex.app;
  document.getElementById('app-filename').value = ex.fileName;
  document.getElementById('app-domains').value = ex.domains;
  document.getElementById('app-sender').value = ex.sender;
  document.getElementById('app-urls').value = ex.urls;
  document.getElementById('app-process').value = ex.process;

  const appErrorBanner = document.getElementById('app-error-banner');
  appErrorBanner.classList.remove('visible');
}

// ─── Analyze Email ────────────────────────────────────────
async function analyzeEmail() {
  // Check if EML upload mode is active
  if (emlCheckbox.checked && selectedEmlFile) {
    return analyzeEmlFile();
  }

  const text = emailInput.value.trim();

  if (text.length < 10) {
    showError('Please enter at least 10 characters of email text to analyze.');
    return;
  }

  hideError();
  setLoading(true, 'btn-analyze');

  try {
    const body = { email_text: text };

    if (metadataCheckbox.checked && headersInput.value.trim()) {
      body.email_headers = headersInput.value.trim();
    }

    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${response.status}`);
    }

    const data = await response.json();
    renderResults(data);
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      showError('Cannot connect to the backend. Make sure the server is running on port 8000.');
    } else {
      showError(err.message);
    }
  } finally {
    setLoading(false, 'btn-analyze');
  }
}

async function analyzeEmlFile() {
  if (!selectedEmlFile) {
    showError('Please select a .eml file to analyze.');
    return;
  }

  hideError();
  setLoading(true, 'btn-analyze');

  try {
    const formData = new FormData();
    formData.append('file', selectedEmlFile);

    const response = await fetch(`${API_BASE}/analyze-eml`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${response.status}`);
    }

    const data = await response.json();
    renderResults(data);
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      showError('Cannot connect to the backend. Make sure the server is running on port 8000.');
    } else {
      showError(err.message);
    }
  } finally {
    setLoading(false, 'btn-analyze');
  }
}

// ─── Verify App ──────────────────────────────────────────
async function verifyApp() {
  const appName = document.getElementById('app-select').value;
  const fileName = document.getElementById('app-filename').value.trim();
  const domainsRaw = document.getElementById('app-domains').value.trim();
  const sender = document.getElementById('app-sender').value.trim();
  const urlsRaw = document.getElementById('app-urls').value.trim();
  const processName = document.getElementById('app-process').value.trim();

  if (!fileName && !domainsRaw && !sender && !urlsRaw && !processName) {
    showAppError('Please provide at least one artifact to verify (file name, domains, sender, URLs, or process).');
    return;
  }

  hideAppError();
  setLoading(true, 'btn-verify');

  const body = { app_name: appName };
  if (fileName) body.file_name = fileName;
  if (domainsRaw) body.network_domains = domainsRaw.split(',').map(d => d.trim()).filter(Boolean);
  if (sender) body.email_sender = sender;
  if (urlsRaw) body.email_urls = urlsRaw.split(',').map(u => u.trim()).filter(Boolean);
  if (processName) body.process_name = processName;

  try {
    const response = await fetch(`${API_BASE}/verify-app`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${response.status}`);
    }

    const data = await response.json();
    renderAppResults(data);
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      showAppError('Cannot connect to the backend. Make sure the server is running on port 8000.');
    } else {
      showAppError(err.message);
    }
  } finally {
    setLoading(false, 'btn-verify');
  }
}

// ─── Dataset Management ──────────────────────────────────
const fileDropZone = document.getElementById('file-drop-zone');
const fileInput = document.getElementById('dataset-file-input');
let selectedFile = null;

// Click to browse
fileDropZone.addEventListener('click', () => fileInput.click());

// File selected via input
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    selectFile(e.target.files[0]);
  }
});

// Drag and drop
fileDropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDropZone.classList.add('drag-over');
});

fileDropZone.addEventListener('dragleave', () => {
  fileDropZone.classList.remove('drag-over');
});

fileDropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  fileDropZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length > 0) {
    selectFile(e.dataTransfer.files[0]);
  }
});

function selectFile(file) {
  const name = file.name.toLowerCase();
  if (!name.endsWith('.txt') && !name.endsWith('.csv')) {
    showDatasetError('Please select a .txt or .csv file');
    return;
  }
  selectedFile = file;
  document.getElementById('selected-file').style.display = 'flex';
  document.getElementById('selected-file-name').textContent = `${file.name} (${formatFileSize(file.size)})`;
  fileDropZone.style.display = 'none';
  hideDatasetError();
}

function clearFileSelection() {
  selectedFile = null;
  fileInput.value = '';
  document.getElementById('selected-file').style.display = 'none';
  fileDropZone.style.display = 'flex';
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

async function uploadDataset() {
  if (!selectedFile) {
    showDatasetError('Please select a file to upload');
    return;
  }

  const label = document.getElementById('dataset-label').value;
  hideDatasetError();
  hideDatasetSuccess();
  setLoading(true, 'btn-upload');

  try {
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('label', label);

    const response = await fetch(`${API_BASE}/upload-dataset`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Upload failed: ${response.status}`);
    }

    const data = await response.json();
    showDatasetSuccess(`${data.message} from "${data.filename}"`);
    clearFileSelection();

    // Refresh stats
    if (data.dataset_stats) {
      renderDatasetStats(data.dataset_stats);
    }
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      showDatasetError('Cannot connect to the backend. Make sure the server is running on port 8000.');
    } else {
      showDatasetError(err.message);
    }
  } finally {
    setLoading(false, 'btn-upload');
  }
}

async function loadDatasetStats() {
  try {
    const response = await fetch(`${API_BASE}/dataset-stats`);
    if (!response.ok) throw new Error('Failed to load stats');
    const data = await response.json();
    renderDatasetStats(data.stats);
  } catch (err) {
    console.error('Failed to load dataset stats:', err);
  }
}

async function resetDataset() {
  if (!confirm('Reset the dataset to defaults? This will remove all uploaded samples and reload the built-in dataset.')) return;

  try {
    const response = await fetch(`${API_BASE}/dataset`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to reset');
    const data = await response.json();
    showDatasetSuccess('Dataset reset to defaults');
    if (data.dataset_stats) {
      renderDatasetStats(data.dataset_stats);
    }
  } catch (err) {
    showDatasetError(`Reset failed: ${err.message}`);
  }
}

function renderDatasetStats(stats) {
  document.getElementById('stat-total').textContent = stats.total || 0;
  document.getElementById('stat-phishing').textContent = stats.phishing || 0;
  document.getElementById('stat-legitimate').textContent = stats.legitimate || 0;

  const total = stats.total || 1;
  const phishPct = ((stats.phishing || 0) / total * 100).toFixed(1);
  const legitPct = ((stats.legitimate || 0) / total * 100).toFixed(1);

  document.getElementById('stat-bar-phishing').style.width = `${phishPct}%`;
  document.getElementById('stat-bar-legitimate').style.width = `${legitPct}%`;
  document.getElementById('stat-phishing-pct').textContent = `${phishPct}%`;
  document.getElementById('stat-legitimate-pct').textContent = `${legitPct}%`;

  // Sources
  const sourcesEl = document.getElementById('stat-sources');
  if (stats.sources && Object.keys(stats.sources).length > 0) {
    sourcesEl.innerHTML = '<div class="sources-label">Data Sources:</div>' +
      Object.entries(stats.sources).map(([source, count]) =>
        `<span class="source-chip">${source}: ${count}</span>`
      ).join('');
  } else {
    sourcesEl.innerHTML = '';
  }
}

// ─── Render Email Results ─────────────────────────────────
function renderResults(data) {
  resultsPlaceholder.style.display = 'none';
  resultsPanel.classList.add('visible');
  resultsDetails.classList.add('visible');

  // Risk gauge
  animateGauge(data.risk_score, data.risk_level);

  // Classification badge
  const badge = document.getElementById('classification-badge');
  badge.className = `classification-badge ${data.classification}`;
  badge.innerHTML = `${getClassificationIcon(data.classification)} ${data.classification.toUpperCase()}`;

  // Meta info
  document.getElementById('analysis-time').textContent = `⏱️ ${data.analysis_time_ms}ms`;
  document.getElementById('analysis-model').textContent = `🤖 ${data.llm_source}`;
  document.getElementById('llm-source-badge').textContent = data.llm_source;

  // Explanation
  document.getElementById('explanation-text').textContent = data.explanation;
  document.getElementById('action-text').textContent = data.recommended_action;

  // Key findings
  renderFindings(data.key_findings);

  // Heuristic indicators
  renderIndicators(data.heuristic_indicators);

  // Metadata analysis
  renderMetadata(data.metadata_analysis);

  // Similarity matches
  renderMatches(data.similarity_matches);

  // Risk breakdown
  renderBreakdown(data.risk_breakdown);

  // URLs
  renderUrls(data.extracted_urls);

  // Scroll to results on mobile
  if (window.innerWidth < 900) {
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// ─── Render App Results ──────────────────────────────────
function renderAppResults(data) {
  document.getElementById('app-results-placeholder').style.display = 'none';
  document.getElementById('app-results-panel').classList.add('visible');
  document.getElementById('app-results-details').classList.add('visible');

  // Verdict
  const verdictIcon = document.getElementById('app-verdict-icon');
  const verdictLabel = document.getElementById('app-verdict-label');
  const verdictConf = document.getElementById('app-verdict-confidence');
  const verdictName = document.getElementById('app-verdict-name');

  const container = document.getElementById('app-verdict-container');

  if (data.is_legitimate === true) {
    verdictIcon.textContent = '✅';
    verdictLabel.textContent = 'LEGITIMATE';
    verdictLabel.className = 'app-verdict-label legitimate';
    container.className = 'app-verdict-container verdict-safe';
  } else if (data.is_legitimate === false) {
    verdictIcon.textContent = '🚨';
    verdictLabel.textContent = 'SUSPICIOUS';
    verdictLabel.className = 'app-verdict-label suspicious';
    container.className = 'app-verdict-container verdict-danger';
  } else {
    verdictIcon.textContent = '❓';
    verdictLabel.textContent = 'UNKNOWN';
    verdictLabel.className = 'app-verdict-label unknown';
    container.className = 'app-verdict-container verdict-unknown';
  }

  verdictConf.textContent = `${(data.confidence * 100).toFixed(0)}% confidence — ${data.risk_level.toUpperCase()} risk`;
  verdictName.textContent = data.app_name;

  // Recommendation
  document.getElementById('app-recommendation').textContent = data.recommendation;

  // Findings
  const findingsEl = document.getElementById('app-findings');
  if (data.findings && data.findings.length > 0) {
    findingsEl.innerHTML = data.findings.map(f => `
      <div class="indicator-item severity-${data.is_legitimate === false ? 'high' : 'low'}">
        <span class="indicator-detail">${escapeHtml(f)}</span>
      </div>
    `).join('');
  } else {
    findingsEl.innerHTML = '<div class="no-data">No specific findings</div>';
  }

  // Checks performed
  const checksEl = document.getElementById('app-checks');
  if (data.checks_performed && data.checks_performed.length > 0) {
    checksEl.innerHTML = data.checks_performed.map(c => {
      const sev = c.result === 'pass' ? 'low' : c.result === 'warning' ? 'medium' : 'high';
      const icon = c.result === 'pass' ? '✅' : c.result === 'warning' ? '⚠️' : '❌';
      return `
        <div class="indicator-item severity-${sev}">
          <span class="indicator-severity ${sev}">${icon} ${c.check.toUpperCase()}</span>
          <span class="indicator-detail">${escapeHtml(c.detail)}</span>
        </div>
      `;
    }).join('');
  } else {
    checksEl.innerHTML = '<div class="no-data">No checks performed</div>';
  }

  // Expected signatures
  const sigsEl = document.getElementById('app-signatures');
  if (data.expected_signatures) {
    const sigs = data.expected_signatures;
    let html = '';
    if (sigs.legitimate_domains) {
      html += `<div class="sig-group">
        <div class="sig-label">🌐 Legitimate Domains</div>
        <div class="sig-chips">${sigs.legitimate_domains.map(d => `<span class="sig-chip">${escapeHtml(d)}</span>`).join('')}</div>
      </div>`;
    }
    if (sigs.known_network_domains) {
      html += `<div class="sig-group">
        <div class="sig-label">🔗 Known Network Domains</div>
        <div class="sig-chips">${sigs.known_network_domains.map(d => `<span class="sig-chip">${escapeHtml(d)}</span>`).join('')}</div>
      </div>`;
    }
    if (sigs.known_ports) {
      html += `<div class="sig-group">
        <div class="sig-label">🔌 Known Ports</div>
        <div class="sig-chips">${sigs.known_ports.map(p => `<span class="sig-chip">${p}</span>`).join('')}</div>
      </div>`;
    }
    if (sigs.certificate_orgs) {
      html += `<div class="sig-group">
        <div class="sig-label">🏢 Certificate Organizations</div>
        <div class="sig-chips">${sigs.certificate_orgs.map(o => `<span class="sig-chip">${escapeHtml(o)}</span>`).join('')}</div>
      </div>`;
    }
    sigsEl.innerHTML = html || '<div class="no-data">No signature data</div>';
  } else {
    sigsEl.innerHTML = '<div class="no-data">No signature data available</div>';
  }

  // Scroll on mobile
  if (window.innerWidth < 900) {
    document.getElementById('app-results-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// ─── Risk Gauge Animation ─────────────────────────────────
function animateGauge(score, level) {
  const gaugeFill = document.getElementById('gauge-fill');
  const scoreValue = document.getElementById('score-value');
  const scoreLabel = document.getElementById('score-label');

  const circumference = 2 * Math.PI * 50;
  const offset = circumference - (score / 100) * circumference;

  const color = getRiskColor(level);

  gaugeFill.style.stroke = color;
  gaugeFill.style.strokeDashoffset = circumference; // Reset
  scoreValue.style.color = color;
  scoreLabel.style.color = color;

  // Animate after small delay
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      gaugeFill.style.strokeDashoffset = offset;
    });
  });

  // Counter animation
  animateCounter(scoreValue, 0, Math.round(score), 1200);
  scoreLabel.textContent = level.toUpperCase();
}

function animateCounter(element, from, to, duration) {
  const start = performance.now();
  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    const value = Math.round(from + (to - from) * eased);
    element.textContent = value;
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ─── Render Helpers ───────────────────────────────────────
function renderFindings(findings) {
  const list = document.getElementById('findings-list');
  if (!findings || findings.length === 0) {
    list.innerHTML = '<div class="no-data">No specific findings reported</div>';
    return;
  }
  list.innerHTML = findings.map(f => `<li>${escapeHtml(f)}</li>`).join('');
}

function renderIndicators(indicators) {
  const grid = document.getElementById('indicators-grid');
  if (!indicators || indicators.length === 0) {
    grid.innerHTML = '<div class="no-data">No heuristic indicators detected ✅</div>';
    return;
  }
  grid.innerHTML = indicators.map(ind => `
    <div class="indicator-item severity-${ind.severity}">
      <span class="indicator-severity ${ind.severity}">${ind.severity.toUpperCase()}</span>
      <span class="indicator-detail">${escapeHtml(ind.detail)}</span>
    </div>
  `).join('');
}

function renderMetadata(metadata) {
  const section = document.getElementById('metadata-section');
  const container = document.getElementById('metadata-results');

  if (!metadata || !metadata.parsed_headers || Object.keys(metadata.parsed_headers).length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';

  const h = metadata.parsed_headers;
  let html = '';

  // Auth status badges
  html += '<div class="metadata-auth-row">';
  html += renderAuthBadge('SPF', h.spf);
  html += renderAuthBadge('DKIM', h.dkim);
  html += renderAuthBadge('DMARC', h.dmarc);
  html += `<span class="metadata-score">Metadata Score: <strong>${metadata.score}/100</strong></span>`;
  html += '</div>';

  // Parsed headers table
  html += '<div class="metadata-details">';
  const fields = [
    ['From', h.from],
    ['From Domain', h.from_domain],
    ['Reply-To', h.reply_to],
    ['Return-Path', h.return_path],
    ['X-Mailer', h.x_mailer],
    ['Message-ID', h.message_id],
    ['Date', h.date],
    ['Received Hops', h.received_hops],
  ];
  for (const [label, value] of fields) {
    if (value) {
      html += `<div class="metadata-field"><span class="metadata-key">${label}</span><span class="metadata-val">${escapeHtml(String(value))}</span></div>`;
    }
  }
  html += '</div>';

  // Indicators
  if (metadata.indicators && metadata.indicators.length > 0) {
    html += '<div class="metadata-indicators">';
    html += metadata.indicators.map(ind => `
      <div class="indicator-item severity-${ind.severity}">
        <span class="indicator-severity ${ind.severity}">${ind.severity.toUpperCase()}</span>
        <span class="indicator-detail">${escapeHtml(ind.detail)}</span>
      </div>
    `).join('');
    html += '</div>';
  }

  container.innerHTML = html;
}

function renderAuthBadge(name, status) {
  const statusClass = status === 'pass' ? 'auth-pass' : status === 'fail' ? 'auth-fail' : status === 'softfail' ? 'auth-softfail' : 'auth-unknown';
  const icon = status === 'pass' ? '✅' : status === 'fail' ? '❌' : status === 'softfail' ? '⚠️' : '❓';
  return `<span class="auth-badge ${statusClass}">${icon} ${name}: ${(status || 'unknown').toUpperCase()}</span>`;
}

function renderMatches(matches) {
  const list = document.getElementById('matches-list');
  if (!matches || matches.length === 0) {
    list.innerHTML = '<div class="no-data">No similarity matches found</div>';
    return;
  }
  list.innerHTML = matches.map(m => {
    const simPercent = (m.similarity * 100).toFixed(1);
    const simClass = m.similarity > 0.7 ? 'high' : m.similarity > 0.4 ? 'medium' : 'low';
    return `
      <div class="match-item">
        <div class="match-header">
          <span class="match-label ${m.label}">${m.label.toUpperCase()}</span>
          <span class="match-similarity similarity-${simClass}">${simPercent}% similar</span>
        </div>
        <div class="match-text">${escapeHtml(m.text)}</div>
      </div>
    `;
  }).join('');
}

function renderBreakdown(breakdown) {
  const container = document.getElementById('breakdown-bars');
  if (!breakdown) {
    container.innerHTML = '<div class="no-data">No breakdown available</div>';
    return;
  }

  const items = [
    { label: 'Heuristic Analysis', key: 'heuristic', icon: '🔎' },
    { label: 'Vector Similarity', key: 'vector_similarity', icon: '📐' },
    { label: 'LLM Analysis', key: 'llm_analysis', icon: '🧠' },
    { label: 'Metadata Analysis', key: 'metadata', icon: '📋' },
  ];

  container.innerHTML = items
    .filter(item => breakdown[item.key])
    .map(item => {
      const data = breakdown[item.key] || {};
      const score = data.score || 0;
      const weight = ((data.weight || 0) * 100).toFixed(0);
      const weighted = data.weighted || 0;
      return `
        <div class="breakdown-item">
          <div class="breakdown-label">
            <span>${item.icon} ${item.label} (${weight}% weight)</span>
            <span class="score">${score.toFixed(1)} → ${weighted.toFixed(1)}</span>
          </div>
          <div class="breakdown-bar">
            <div class="breakdown-bar-fill" style="width: 0%;" data-target="${score}"></div>
          </div>
        </div>
      `;
    }).join('');

  // Animate bars
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      container.querySelectorAll('.breakdown-bar-fill').forEach(bar => {
        bar.style.width = `${bar.dataset.target}%`;
      });
    });
  });
}

function renderUrls(urls) {
  const list = document.getElementById('urls-list');
  if (!urls || urls.length === 0) {
    list.innerHTML = '<div class="no-data">No URLs extracted from email</div>';
    return;
  }
  list.innerHTML = urls.map(url => `
    <div class="url-item">
      <span class="url-icon">🔗</span>
      <span>${escapeHtml(url)}</span>
    </div>
  `).join('');
}

// ─── Utilities ────────────────────────────────────────────
function getRiskColor(level) {
  const colors = {
    low: '#34d399',
    medium: '#fbbf24',
    high: '#f97316',
    critical: '#ef4444',
  };
  return colors[level] || colors.medium;
}

function getClassificationIcon(classification) {
  const icons = {
    phishing: '🚨',
    legitimate: '✅',
    unknown: '❓',
  };
  return icons[classification] || '❓';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function setLoading(loading, btnId) {
  const btn = document.getElementById(btnId);
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

function showError(message) {
  errorText.textContent = message;
  errorBanner.classList.add('visible');
}

function hideError() {
  errorBanner.classList.remove('visible');
}

function showAppError(message) {
  document.getElementById('app-error-text').textContent = message;
  document.getElementById('app-error-banner').classList.add('visible');
}

function hideAppError() {
  document.getElementById('app-error-banner').classList.remove('visible');
}

function showDatasetError(message) {
  document.getElementById('dataset-error-text').textContent = message;
  document.getElementById('dataset-error-banner').classList.add('visible');
}

function hideDatasetError() {
  document.getElementById('dataset-error-banner').classList.remove('visible');
}

function showDatasetSuccess(message) {
  const banner = document.getElementById('dataset-success-banner');
  document.getElementById('dataset-success-text').textContent = message;
  banner.style.display = 'flex';
  // Auto-hide after 5s
  setTimeout(() => { banner.style.display = 'none'; }, 5000);
}

function hideDatasetSuccess() {
  document.getElementById('dataset-success-banner').style.display = 'none';
}

// ─── Keyboard shortcut ───────────────────────────────────
emailInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    analyzeEmail();
  }
});

// ─── Dynamic Config & App Loading ─────────────────────

const APP_ICONS = {
  zoom: '🎥',
  google_meet: '📹',
  microsoft_teams: '💬',
  teamviewer: '🖥️',
  slack: '💼',
  webex: '📞',
};

async function loadDynamicConfig() {
  const badge = document.getElementById('connection-badge');
  try {
    // Fetch config
    const configRes = await fetch(`${API_BASE}/config`);
    if (configRes.ok) {
      appConfig = await configRes.json();
      badge.textContent = `✅ Connected (${appConfig.llm_source})`;
      badge.style.background = 'rgba(52,211,153,0.15)';
      badge.style.color = '#34d399';
    } else {
      badge.textContent = '⚠️ Backend Error';
      badge.style.background = 'rgba(251,191,36,0.15)';
      badge.style.color = '#fbbf24';
    }
  } catch {
    badge.textContent = '❌ Offline';
    badge.style.background = 'rgba(239,68,68,0.15)';
    badge.style.color = '#ef4444';
  }

  // Fetch supported apps and populate selector
  try {
    const appsRes = await fetch(`${API_BASE}/supported-apps`);
    if (appsRes.ok) {
      const appsData = await appsRes.json();
      const select = document.getElementById('app-select');
      select.innerHTML = '';
      (appsData.apps || []).forEach(app => {
        const icon = APP_ICONS[app.id] || '📦';
        const option = document.createElement('option');
        option.value = app.id;
        option.textContent = `${icon} ${app.name}`;
        select.appendChild(option);
      });
    }
  } catch {
    // Keep default option if fetch fails
  }
}

// Load dynamic config on page load
loadDynamicConfig();
