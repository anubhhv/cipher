const API_BASE = 'http://localhost:5000';

const FAMILY_DATA = [
  { name: 'Ramnit', type: 'worm', icon: '🐛', desc: 'Multi-component worm targeting banking credentials, spreading via USB drives and network shares. Injects malicious code into HTML files.' },
  { name: 'Lollipop', type: 'adware', icon: '📺', desc: 'Aggressive adware that hijacks browser settings and injects unwanted advertisements. Known for persistent registry-based survival.' },
  { name: 'Kelihos ver3', type: 'backdoor', icon: '🕳', desc: 'Sophisticated botnet backdoor used for spam distribution, credential harvesting, and cryptocurrency theft. P2P-based C&C architecture.' },
  { name: 'Vundo', type: 'trojan', icon: '⚡', desc: 'Trojan that generates pop-up advertisements and downloads rogue security software. Exploits Java vulnerabilities for initial infection.' },
  { name: 'Simda', type: 'backdoor', icon: '👁', desc: 'Stealthy backdoor that disables security software and establishes persistent remote access for attackers.' },
  { name: 'Tracur', type: 'trojan', icon: '🔗', desc: 'Trojan downloader that uses sophisticated redirection techniques to download additional malware payloads onto infected systems.' },
  { name: 'Kelihos ver1', type: 'backdoor', icon: '📡', desc: 'Earlier variant of the Kelihos botnet. Used for spam campaigns and credential stealing with centralized C&C structure.' },
  { name: 'Obfuscator.ACY', type: 'trojan', icon: '🔒', desc: 'Highly obfuscated trojan that uses multiple layers of code obfuscation to evade detection. Serves as dropper for other malware.' },
  { name: 'Gatak', type: 'trojan', icon: '🎯', desc: 'Backdoor trojan often distributed through fake software license key generators. Establishes persistent access and exfiltrates data.' },
];

function initGlobe() {
  const canvas = document.getElementById('globeCanvas');
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  function resize() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
  }
  resize();
  window.addEventListener('resize', resize);

  const dots = [];
  const numDots = 600;

  for (let i = 0; i < numDots; i++) {
    const phi = Math.acos(-1 + (2 * i) / numDots);
    const theta = Math.sqrt(numDots * Math.PI) * phi;
    dots.push({ phi, theta });
  }

  let rotation = 0;

  function draw() {
    const rect = canvas.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;
    const cx = w / 2;
    const cy = h / 2;
    const r = Math.min(w, h) * 0.44;

    ctx.clearRect(0, 0, w, h);

    const gradient = ctx.createRadialGradient(cx - r * 0.2, cy - r * 0.2, r * 0.1, cx, cy, r);
    gradient.addColorStop(0, 'rgba(245,226,0,0.06)');
    gradient.addColorStop(0.5, 'rgba(245,226,0,0.03)');
    gradient.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.fill();

    for (const dot of dots) {
      const x3d = r * Math.sin(dot.phi) * Math.cos(dot.theta + rotation);
      const y3d = r * Math.cos(dot.phi);
      const z3d = r * Math.sin(dot.phi) * Math.sin(dot.theta + rotation);

      const perspective = 1.3;
      const scale = perspective / (perspective + z3d / r);
      const px = cx + x3d * scale;
      const py = cy + y3d * scale;

      const brightness = (z3d / r + 1) / 2;
      const size = scale * 1.2;
      const alpha = brightness * 0.7 + 0.1;

      ctx.beginPath();
      ctx.arc(px, py, size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(245,226,0,${alpha})`;
      ctx.fill();
    }

    rotation += 0.003;
    requestAnimationFrame(draw);
  }
  draw();
}

function initStats() {
  const counters = document.querySelectorAll('.stat-num[data-target]');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.target);
        const duration = 1200;
        const start = performance.now();
        function update(now) {
          const t = Math.min((now - start) / duration, 1);
          const eased = 1 - Math.pow(1 - t, 3);
          el.textContent = Math.floor(eased * target).toLocaleString();
          if (t < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.3 });
  counters.forEach(c => observer.observe(c));
}

function initFamilies() {
  const grid = document.getElementById('familiesGrid');
  FAMILY_DATA.forEach(f => {
    const card = document.createElement('div');
    card.className = 'family-card';
    card.innerHTML = `
      <div class="fc-icon">${f.icon}</div>
      <div class="fc-name">${f.name.toUpperCase()}</div>
      <span class="fc-type ${f.type}">${f.type.toUpperCase()}</span>
      <div class="fc-desc">${f.desc}</div>
    `;
    grid.appendChild(card);
  });
}

async function checkStatus() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (res.ok) {
      dot.className = 'status-dot online';
      text.textContent = 'ENGINE ONLINE';
    } else {
      throw new Error();
    }
  } catch {
    dot.className = 'status-dot offline';
    text.textContent = 'OFFLINE';
  }
}

let selectedFile = null;

function initUpload() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const clearBtn = document.getElementById('clearBtn');

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) setFile(fileInput.files[0]);
  });

  analyzeBtn.addEventListener('click', runAnalysis);
  clearBtn.addEventListener('click', clearFile);
}

function setFile(file) {
  selectedFile = file;
  document.getElementById('fiName').textContent = file.name;
  document.getElementById('fiSize').textContent = formatBytes(file.size);
  document.getElementById('fiType').textContent = file.type || 'UNKNOWN';
  document.getElementById('fileInfo').classList.remove('hidden');
}

function clearFile() {
  selectedFile = null;
  document.getElementById('fileInfo').classList.add('hidden');
  document.getElementById('resultsContent').classList.add('hidden');
  document.getElementById('resultsPlaceholder').classList.remove('hidden');
  document.getElementById('fileInput').value = '';
}

async function runAnalysis() {
  if (!selectedFile) return;

  document.getElementById('resultsPlaceholder').classList.add('hidden');
  document.getElementById('resultsContent').classList.add('hidden');
  document.getElementById('loadingState').classList.remove('hidden');

  const steps = ['ls1','ls2','ls3','ls4','ls5'];
  let stepIdx = 0;
  const stepInterval = setInterval(() => {
    if (stepIdx > 0) {
      document.getElementById(steps[stepIdx-1]).className = 'ls-step done';
    }
    if (stepIdx < steps.length) {
      document.getElementById(steps[stepIdx]).className = 'ls-step active';
      stepIdx++;
    } else {
      clearInterval(stepInterval);
    }
  }, 400);

  try {
    const formData = new FormData();
    formData.append('file', selectedFile);

    const res = await fetch(`${API_BASE}/api/classify`, {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    clearInterval(stepInterval);
    steps.forEach(s => document.getElementById(s).className = 'ls-step done');

    await new Promise(r => setTimeout(r, 300));
    document.getElementById('loadingState').classList.add('hidden');
    displayResults(data);
  } catch (err) {
    clearInterval(stepInterval);
    document.getElementById('loadingState').classList.add('hidden');
    document.getElementById('resultsPlaceholder').classList.remove('hidden');
    alert('ERROR: Could not connect to backend. Make sure app.py is running on port 5000.');
  }
}

function displayResults(data) {
  document.getElementById('resultsContent').classList.remove('hidden');

  const badge = document.getElementById('threatBadge');
  badge.className = `threat-badge ${data.threat_level}`;
  document.getElementById('threatLevel').textContent = data.threat_level;
  document.getElementById('rfName').textContent = data.predicted_family.toUpperCase();
  document.getElementById('rcValue').textContent = `${data.confidence.toFixed(1)}%`;

  document.getElementById('rgHash').textContent = data.sha256;
  document.getElementById('rgSize').textContent = formatBytes(data.file_size);
  document.getElementById('rgType').textContent = data.file_type;
  document.getElementById('rgEntropy').textContent = `${data.entropy.toFixed(4)} / 8.0`;

  renderProbBars(data.probabilities, data.predicted_family);
  renderEntropyHeatmap(data.chunk_entropies);
  renderHistogram(data.byte_histogram);
  renderSuspicious(data.suspicious_strings);
}

function renderProbBars(probs, predicted) {
  const container = document.getElementById('probBars');
  container.innerHTML = '';
  Object.entries(probs).forEach(([name, pct]) => {
    const row = document.createElement('div');
    row.className = 'prob-row';
    const isTop = name === predicted;
    row.innerHTML = `
      <div class="prob-name">${name}</div>
      <div class="prob-bar-track">
        <div class="prob-bar-fill ${isTop ? 'top' : ''}" style="width:0%" data-target="${pct}"></div>
      </div>
      <div class="prob-pct">${pct.toFixed(1)}%</div>
    `;
    container.appendChild(row);
  });
  setTimeout(() => {
    container.querySelectorAll('.prob-bar-fill').forEach(bar => {
      bar.style.width = bar.dataset.target + '%';
    });
  }, 50);
}

function renderEntropyHeatmap(entropies) {
  const container = document.getElementById('entropyHeatmap');
  container.innerHTML = '';
  entropies.forEach((val, i) => {
    const cell = document.createElement('div');
    cell.className = 'eh-cell';
    const normalized = val / 8.0;
    const r = Math.floor(normalized * 245);
    const g = Math.floor(normalized * 226);
    const b = 0;
    const alpha = 0.2 + normalized * 0.8;
    cell.innerHTML = `
      <div class="eh-cell-inner" style="background:rgba(${r},${g},${b},${alpha})"></div>
      <div class="eh-tooltip">CHUNK ${i+1}: ${val.toFixed(3)}</div>
    `;
    container.appendChild(cell);
  });
}

function renderHistogram(histogram) {
  const canvas = document.getElementById('histogramCanvas');
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 120 * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = 120;
  ctx.clearRect(0, 0, w, h);

  const max = Math.max(...histogram);
  const barW = w / 256;

  for (let i = 0; i < 256; i++) {
    const barH = (histogram[i] / max) * (h - 10);
    const brightness = i / 255;
    ctx.fillStyle = `rgba(245,226,0,${0.3 + brightness * 0.5})`;
    ctx.fillRect(i * barW, h - barH, barW - 0.5, barH);
  }
}

function renderSuspicious(strings) {
  const container = document.getElementById('suspTags');
  container.innerHTML = '';
  if (strings.length === 0) {
    container.innerHTML = '<span class="susp-none">✓ NO SUSPICIOUS INDICATORS FOUND</span>';
  } else {
    strings.forEach(s => {
      const tag = document.createElement('span');
      tag.className = 'susp-tag';
      tag.textContent = s;
      container.appendChild(tag);
    });
  }
  document.getElementById('suspiciousSection').classList.remove('hidden');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1024/1024).toFixed(2)} MB`;
}

document.addEventListener('DOMContentLoaded', () => {
  initGlobe();
  initStats();
  initFamilies();
  initUpload();
  checkStatus();
  setInterval(checkStatus, 10000);
});