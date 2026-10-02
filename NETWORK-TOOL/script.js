/**
 * Network Traffic Triage Tool (NT3)
 * Real-Time Multi-View Engine & Local Browser Triage Processor
 */

document.addEventListener('DOMContentLoaded', () => {

  // Global State
  const state = {
    packets: [],
    alerts: [],
    thresholds: {
      highVolume: 50,
      hostScan: 10,
      portScan: 10,
      icmp: 30,
      dns: 30,
      repeatedPair: 40,
      syn: 20
    },
    isDemoData: false,
    fileName: '',
    parsedSuccess: false,
    darkMode: false,
    activeView: 'dashboard'
  };

  // Color Mapping for Protocols
  const PROTOCOL_COLORS = {
    'TCP': '#3b82f6',
    'UDP': '#10b981',
    'DNS': '#f59e0b',
    'TLS': '#ef4444',
    'TLSV1.3': '#ef4444',
    'TLSV1.2': '#ef4444',
    'ICMP': '#8b5cf6',
    'HTTP': '#ec4899',
    'ARP': '#06b6d4',
    'SSDP': '#6366f1',
    'OTHER': '#94a3b8'
  };

  // DOM Elements
  const dom = {
    sidebarBtns: document.querySelectorAll('.sidebar-nav-btn'),
    viewPanels: document.querySelectorAll('.view-panel'),
    themeToggle: document.getElementById('btn-theme-toggle'),
    
    // Status Pills
    statusFilename: document.getElementById('status-filename'),
    statusPacketCount: document.getElementById('status-packet-count'),
    statusParsedBadge: document.getElementById('status-parsed-badge'),
    sidebarAlertCount: document.getElementById('sidebar-alert-count'),

    // Hero & Demo Buttons
    heroBtnUpload: document.getElementById('hero-btn-upload'),
    heroBtnHow: document.getElementById('hero-btn-how'),
    btnDemoNormal: document.getElementById('btn-demo-normal'),
    btnDemoVolume: document.getElementById('btn-demo-volume'),
    btnDemoMixed: document.getElementById('btn-demo-mixed'),
    btnResetAnalysis: document.getElementById('btn-reset-analysis'),

    // KPI Values
    kpiValTotal: document.getElementById('kpi-val-total'),
    kpiValSources: document.getElementById('kpi-val-sources'),
    kpiValDests: document.getElementById('kpi-val-dests'),
    kpiValTopSrc: document.getElementById('kpi-val-top-src'),
    kpiSubTopSrc: document.getElementById('kpi-sub-top-src'),
    kpiValTopDst: document.getElementById('kpi-val-top-dst'),
    kpiSubTopDst: document.getElementById('kpi-sub-top-dst'),
    kpiValTopProto: document.getElementById('kpi-val-top-proto'),
    kpiSubTopProto: document.getElementById('kpi-sub-top-proto'),
    kpiValAvgLen: document.getElementById('kpi-val-avg-len'),

    // Dashboard Tables & Donut
    tableTopSources: document.getElementById('table-top-sources'),
    tableTopDests: document.getElementById('table-top-dests'),
    donutSvg: document.getElementById('donut-svg'),
    donutCenterVal: document.getElementById('donut-center-val'),
    donutLegend: document.getElementById('donut-legend'),
    alertTableBody: document.getElementById('alert-table-body'),
    alertTableBodyDedicated: document.getElementById('alert-table-body-dedicated'),
    filterAlertSeverity: document.getElementById('filter-alert-severity'),
    filterAlertSeverityDedicated: document.getElementById('filter-alert-severity-dedicated'),

    // Analysis Results & Packet Explorer
    resultsSummaryContent: document.getElementById('results-summary-content'),
    fileInput: document.getElementById('csv-file-input'),
    fileInputPage: document.getElementById('csv-file-input-page'),
    dropzoneArea: document.getElementById('dropzone-area'),
    packetExplorerBody: document.getElementById('packet-explorer-body'),
    filterSearchPackets: document.getElementById('filter-search-packets'),

    // Settings Inputs
    setVol: document.getElementById('set-vol'),
    setScan: document.getElementById('set-scan'),
    setPort: document.getElementById('set-port'),
    setIcmp: document.getElementById('set-icmp'),
    setDns: document.getElementById('set-dns'),
    setPair: document.getElementById('set-pair'),
    setSyn: document.getElementById('set-syn'),
    btnResetDefaults: document.getElementById('btn-reset-defaults')
  };

  // Safe HTML Escaper
  function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  // Application Init
  function init() {
    bindNavigation();
    bindThemeToggle();
    bindFileUpload();
    bindDemoButtons();
    bindFilters();
    bindSettingsInputs();

    // Initial clean empty state (No hardcoded values)
    renderEmptyState();
  }

  // --- EMPTY STATE RENDERER ---
  function renderEmptyState() {
    state.packets = [];
    state.alerts = [];
    state.fileName = '';
    state.isDemoData = false;
    state.parsedSuccess = false;

    dom.statusFilename.textContent = 'File: No file loaded';
    dom.statusPacketCount.textContent = 'Packets loaded: 0';
    dom.statusParsedBadge.textContent = 'Status: Waiting for CSV';
    dom.statusParsedBadge.style.background = 'var(--bg-card)';
    dom.statusParsedBadge.style.color = 'var(--text-muted)';
    dom.statusParsedBadge.style.borderColor = 'var(--border-color)';
    dom.sidebarAlertCount.textContent = '0';

    dom.kpiValTotal.textContent = '—';
    dom.kpiValSources.textContent = '—';
    dom.kpiValDests.textContent = '—';
    dom.kpiValTopSrc.textContent = '—';
    dom.kpiSubTopSrc.textContent = '(0 packets)';
    dom.kpiValTopDst.textContent = '—';
    dom.kpiSubTopDst.textContent = '(0 packets)';
    dom.kpiValTopProto.textContent = '—';
    dom.kpiSubTopProto.textContent = '(0% of packets)';
    dom.kpiValAvgLen.textContent = '—';

    dom.tableTopSources.innerHTML = '<tr><td colspan="4" class="empty-state">No source data available</td></tr>';
    dom.tableTopDests.innerHTML = '<tr><td colspan="4" class="empty-state">No destination data available</td></tr>';

    dom.donutSvg.innerHTML = '<circle cx="80" cy="80" r="60" fill="none" stroke="#e2e8f0" stroke-width="24"/>';
    dom.donutCenterVal.textContent = '0';
    dom.donutLegend.innerHTML = '<div class="empty-state" style="padding: 0; font-size: 11px;">No protocol data available</div>';

    const emptyAlertHTML = '<tr><td colspan="7" class="empty-state">No traffic data available for analysis.</td></tr>';
    if (dom.alertTableBody) dom.alertTableBody.innerHTML = emptyAlertHTML;
    if (dom.alertTableBodyDedicated) dom.alertTableBodyDedicated.innerHTML = emptyAlertHTML;

    if (dom.packetExplorerBody) dom.packetExplorerBody.innerHTML = '<tr><td colspan="7" class="empty-state">No traffic data loaded</td></tr>';
    if (dom.resultsSummaryContent) dom.resultsSummaryContent.innerHTML = '<p class="empty-state">No traffic data loaded. Upload a CSV file or select a demo dataset above to view complete metrics.</p>';
  }

  // --- NAVIGATION ---
  function bindNavigation() {
    dom.sidebarBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.getAttribute('data-view');
        switchView(view);
      });
    });

    if (dom.heroBtnUpload) dom.heroBtnUpload.addEventListener('click', () => switchView('upload'));
    if (dom.heroBtnHow) dom.heroBtnHow.addEventListener('click', () => switchView('about'));
  }

  function switchView(viewName) {
    state.activeView = viewName;
    dom.sidebarBtns.forEach(b => {
      if (b.getAttribute('data-view') === viewName) {
        b.classList.add('active');
      } else {
        b.classList.remove('active');
      }
    });

    dom.viewPanels.forEach(panel => {
      if (panel.id === `view-${viewName}`) {
        panel.style.display = 'block';
      } else {
        panel.style.display = 'none';
      }
    });
  }

  // --- THEME TOGGLE ---
  function bindThemeToggle() {
    if (dom.themeToggle) {
      dom.themeToggle.addEventListener('click', () => {
        state.darkMode = !state.darkMode;
        if (state.darkMode) {
          document.body.classList.add('dark-mode');
        } else {
          document.body.classList.remove('dark-mode');
        }
      });
    }
  }

  // --- CSV FILE UPLOADER & PARSER ---
  function bindFileUpload() {
    const handleFileInputChange = (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFile(e.target.files[0]);
      }
    };

    if (dom.fileInput) dom.fileInput.addEventListener('change', handleFileInputChange);
    if (dom.fileInputPage) dom.fileInputPage.addEventListener('change', handleFileInputChange);

    if (dom.dropzoneArea) {
      dom.dropzoneArea.addEventListener('dragover', (e) => e.preventDefault());
      dom.dropzoneArea.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFile(e.dataTransfer.files[0]);
        }
      });
    }
  }

  function handleFile(file) {
    state.fileName = file.name;
    state.isDemoData = false;
    const reader = new FileReader();
    reader.onload = (e) => {
      processCSVContent(e.target.result, file.name);
      switchView('dashboard');
    };
    reader.readAsText(file);
  }

  function parseCSV(text) {
    const lines = text.split(/\r\n|\n/);
    const result = [];
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line) continue;
      let row = [];
      let insideQuote = false;
      let entry = '';
      for (let j = 0; j < line.length; j++) {
        let char = line[j];
        if (char === '"') {
          insideQuote = !insideQuote;
        } else if (char === ',' && !insideQuote) {
          row.push(entry.trim().replace(/^"|"$/g, ''));
          entry = '';
        } else {
          entry += char;
        }
      }
      row.push(entry.trim().replace(/^"|"$/g, ''));
      result.push(row);
    }
    return result;
  }

  function processCSVContent(rawCSVText, filename) {
    const rows = parseCSV(rawCSVText);
    if (rows.length < 2) {
      renderEmptyState();
      dom.statusFilename.textContent = `File: ${filename}`;
      dom.statusParsedBadge.textContent = 'Status: Parsing failed (Empty file)';
      return;
    }

    const headers = rows[0].map(h => h.toLowerCase().trim());
    const columnMap = {
      no: headers.findIndex(h => ['no.', 'no', 'number', 'frame.number', 'idx'].includes(h)),
      time: headers.findIndex(h => ['time', 'timestamp', 'frame.time_relative'].includes(h)),
      source: headers.findIndex(h => ['source', 'source ip', 'src', 'ip.src', 'source address'].includes(h)),
      destination: headers.findIndex(h => ['destination', 'destination ip', 'dst', 'ip.dst'].includes(h)),
      protocol: headers.findIndex(h => ['protocol', 'proto', 'trans protocol'].includes(h)),
      length: headers.findIndex(h => ['length', 'len', 'pkt length', 'bytes'].includes(h)),
      info: headers.findIndex(h => ['info', 'summary', 'details', 'description'].includes(h))
    };

    const parsedPackets = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (!row || row.length < 2) continue;
      parsedPackets.push({
        no: columnMap.no !== -1 ? (row[columnMap.no] || String(i)) : String(i),
        time: columnMap.time !== -1 ? (row[columnMap.time] || '0.000') : '0.000',
        source: columnMap.source !== -1 ? (row[columnMap.source] || 'Unknown') : 'Unknown',
        destination: columnMap.destination !== -1 ? (row[columnMap.destination] || 'Unknown') : 'Unknown',
        protocol: columnMap.protocol !== -1 ? (row[columnMap.protocol] || 'Other') : 'Other',
        length: columnMap.length !== -1 ? parseInt(row[columnMap.length], 10) || 0 : 0,
        info: columnMap.info !== -1 ? (row[columnMap.info] || '') : ''
      });
    }

    state.packets = parsedPackets;
    state.parsedSuccess = true;
    state.fileName = filename;

    runFullTriage();
  }

  // --- DEMO & RESET BUTTONS ---
  function bindDemoButtons() {
    if (dom.btnDemoNormal) dom.btnDemoNormal.addEventListener('click', () => loadSampleFile('samples/normal-traffic.csv', '[Demo Data] normal-traffic.csv'));
    if (dom.btnDemoVolume) dom.btnDemoVolume.addEventListener('click', () => loadSampleFile('samples/high-volume-traffic.csv', '[Demo Data] high-volume-traffic.csv'));
    if (dom.btnDemoMixed) dom.btnDemoMixed.addEventListener('click', () => loadSampleFile('samples/mixed-soc-lab.csv', '[Demo Data] mixed-soc-lab.csv'));
    if (dom.btnResetAnalysis) dom.btnResetAnalysis.addEventListener('click', () => renderEmptyState());
  }

  function loadSampleFile(path, name) {
    fetch(path)
      .then(res => res.text())
      .then(text => {
        state.isDemoData = true;
        processCSVContent(text, name);
      })
      .catch(err => console.error(err));
  }

  // --- FILTERS ---
  function bindFilters() {
    const handleSeverityFilter = () => renderAlertTable(state.alerts);
    if (dom.filterAlertSeverity) dom.filterAlertSeverity.addEventListener('change', handleSeverityFilter);
    if (dom.filterAlertSeverityDedicated) dom.filterAlertSeverityDedicated.addEventListener('change', handleSeverityFilter);
    if (dom.filterSearchPackets) dom.filterSearchPackets.addEventListener('input', () => renderPacketExplorer());
  }

  // --- SETTINGS INPUT BINDINGS ---
  function bindSettingsInputs() {
    const inputs = [
      { el: dom.setVol, key: 'highVolume' },
      { el: dom.setScan, key: 'hostScan' },
      { el: dom.setPort, key: 'portScan' },
      { el: dom.setIcmp, key: 'icmp' },
      { el: dom.setDns, key: 'dns' },
      { el: dom.setPair, key: 'repeatedPair' },
      { el: dom.setSyn, key: 'syn' }
    ];

    inputs.forEach(({ el, key }) => {
      if (el) {
        el.addEventListener('change', () => {
          const val = parseInt(el.value, 10);
          if (!isNaN(val) && val > 0) {
            state.thresholds[key] = val;
            if (state.packets.length > 0) runFullTriage();
          }
        });
      }
    });

    if (dom.btnResetDefaults) {
      dom.btnResetDefaults.addEventListener('click', () => {
        state.thresholds = { highVolume: 50, hostScan: 10, portScan: 10, icmp: 30, dns: 30, repeatedPair: 40, syn: 20 };
        if (dom.setVol) dom.setVol.value = 50;
        if (dom.setScan) dom.setScan.value = 10;
        if (dom.setPort) dom.setPort.value = 10;
        if (dom.setIcmp) dom.setIcmp.value = 30;
        if (dom.setDns) dom.setDns.value = 30;
        if (dom.setPair) dom.setPair.value = 40;
        if (dom.setSyn) dom.setSyn.value = 20;

        if (state.packets.length > 0) runFullTriage();
      });
    }
  }

  // --- TRIAGE & RULE ENGINE ---
  function runFullTriage() {
    state.alerts = [];
    const packets = state.packets;
    if (packets.length === 0) {
      renderEmptyState();
      return;
    }

    const sourceCounts = {};
    const destCounts = {};
    const protocolCounts = {};
    const sourceDestPairs = {};
    const sourceDestPorts = {};
    const sourceUniqueDests = {};
    const sourceIcmpCounts = {};
    const sourceDnsCounts = {};
    const sourceSynCounts = {};

    let totalBytes = 0;

    packets.forEach(pkt => {
      const src = pkt.source;
      const dst = pkt.destination;
      let proto = pkt.protocol.toUpperCase();
      if (proto.startsWith('TLS')) proto = 'TLS';
      const len = pkt.length || 0;
      totalBytes += len;

      sourceCounts[src] = (sourceCounts[src] || 0) + 1;
      destCounts[dst] = (destCounts[dst] || 0) + 1;
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;

      const pairKey = `${src} -> ${dst}`;
      sourceDestPairs[pairKey] = (sourceDestPairs[pairKey] || 0) + 1;

      if (!sourceUniqueDests[src]) sourceUniqueDests[src] = new Set();
      sourceUniqueDests[src].add(dst);

      if (pkt.info) {
        const portMatch = pkt.info.match(/(?:->\s*|Dst Port:\s*|:)(\d{1,5})/i);
        if (portMatch && portMatch[1]) {
          const port = portMatch[1];
          if (!sourceDestPorts[src]) sourceDestPorts[src] = {};
          if (!sourceDestPorts[src][dst]) sourceDestPorts[src][dst] = new Set();
          sourceDestPorts[src][dst].add(port);
        }
        if (proto.includes('TCP') && /\[SYN\]|SYN/i.test(pkt.info)) {
          sourceSynCounts[src] = (sourceSynCounts[src] || 0) + 1;
        }
      }

      if (proto.includes('ICMP')) sourceIcmpCounts[src] = (sourceIcmpCounts[src] || 0) + 1;
      if (proto.includes('DNS')) sourceDnsCounts[src] = (sourceDnsCounts[src] || 0) + 1;
    });

    // RULE 1: HIGH PACKET VOLUME
    Object.keys(sourceCounts).forEach(src => {
      const cnt = sourceCounts[src];
      if (cnt > state.thresholds.highVolume) {
        state.alerts.push({
          ruleName: 'High Packet Volume',
          severity: cnt > (state.thresholds.highVolume * 2) ? 'High' : 'Medium',
          evidence: `${cnt.toLocaleString()} packets from ${src}`,
          whyItMatters: 'Unusually high number of packets from a single host.',
          benignExplanation: 'File download, software update, backup activity.',
          suggestedInvestigation: 'Check what the host was doing during this time.'
        });
      }
    });

    // RULE 2: HOST SCANNING
    Object.keys(sourceUniqueDests).forEach(src => {
      const uniqueCount = sourceUniqueDests[src].size;
      if (uniqueCount > state.thresholds.hostScan) {
        state.alerts.push({
          ruleName: 'Multiple Connections to Different Hosts',
          severity: 'Medium',
          evidence: `${uniqueCount} unique destinations contacted by ${src}`,
          whyItMatters: 'Host contacting many systems in a short timeframe may indicate network discovery.',
          benignExplanation: 'Network management, monitoring tool, vulnerability scanner.',
          suggestedInvestigation: 'Verify destination host list and host authorization.'
        });
      }
    });

    // RULE 3: PORT SCANNING
    Object.keys(sourceDestPorts).forEach(src => {
      Object.keys(sourceDestPorts[src]).forEach(dst => {
        const ports = sourceDestPorts[src][dst].size;
        if (ports > state.thresholds.portScan) {
          state.alerts.push({
            ruleName: 'Possible Port Scanning',
            severity: 'Medium',
            evidence: `${ports} distinct destination ports probed on ${dst} by ${src}`,
            whyItMatters: 'Attempting connections across multiple ports on a single host.',
            benignExplanation: 'Application multi-port service discovery or security audit.',
            suggestedInvestigation: 'Inspect destination firewall logs and specific port list.'
          });
        }
      });
    });

    // RULE 4: HIGH ICMP
    Object.keys(sourceIcmpCounts).forEach(src => {
      const icmp = sourceIcmpCounts[src];
      if (icmp > state.thresholds.icmp) {
        state.alerts.push({
          ruleName: 'High ICMP Traffic Volume',
          severity: 'Low',
          evidence: `${icmp} ICMP packets from ${src}`,
          whyItMatters: 'High ICMP activity can stem from ping sweeps or network path diagnostics.',
          benignExplanation: 'Network latency testing or automated uptime monitoring.',
          suggestedInvestigation: 'Check ICMP type (Echo Request vs Unreachable).'
        });
      }
    });

    // RULE 5: HIGH DNS
    Object.keys(sourceDnsCounts).forEach(src => {
      const dns = sourceDnsCounts[src];
      if (dns > state.thresholds.dns) {
        state.alerts.push({
          ruleName: 'High DNS Query Volume',
          severity: 'Low',
          evidence: `${dns} DNS query packets from ${src}`,
          whyItMatters: 'Frequent DNS requests can stem from web browsing or automated lookups.',
          benignExplanation: 'Multiple web tabs, background service lookups, app updates.',
          suggestedInvestigation: 'Inspect domain name strings in packet Info field.'
        });
      }
    });

    // Render Data Across All Panels
    renderOverviewKPIs(packets.length, sourceCounts, destCounts, protocolCounts, totalBytes);
    renderTopSourceHostsTable(sourceCounts, packets.length);
    renderTopDestHostsTable(destCounts, packets.length);
    renderProtocolDonut(protocolCounts, packets.length);
    renderAlertTable(state.alerts);
    renderPacketExplorer();
    renderAnalysisResults(packets.length, sourceCounts, destCounts, protocolCounts, totalBytes);
  }

  // --- RENDER KPI OVERVIEW CARDS ---
  function renderOverviewKPIs(total, sourceCounts, destCounts, protocolCounts, totalBytes) {
    dom.statusFilename.textContent = state.isDemoData ? `${state.fileName}` : `File: ${state.fileName}`;
    dom.statusPacketCount.textContent = `Packets loaded: ${total.toLocaleString()}`;
    dom.statusParsedBadge.textContent = '✓ Parsed successfully';
    dom.statusParsedBadge.style.background = '#d1fae5';
    dom.statusParsedBadge.style.color = '#065f46';
    dom.statusParsedBadge.style.borderColor = '#a7f3d0';

    dom.sidebarAlertCount.textContent = state.alerts.length;

    dom.kpiValTotal.textContent = total.toLocaleString();
    dom.kpiValSources.textContent = Object.keys(sourceCounts).length.toLocaleString();
    dom.kpiValDests.textContent = Object.keys(destCounts).length.toLocaleString();

    // Top Source
    const sortedSrc = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);
    if (sortedSrc[0]) {
      dom.kpiValTopSrc.textContent = sortedSrc[0][0];
      dom.kpiSubTopSrc.textContent = `(${sortedSrc[0][1].toLocaleString()} packets)`;
    } else {
      dom.kpiValTopSrc.textContent = '—';
      dom.kpiSubTopSrc.textContent = '(0 packets)';
    }

    // Top Dest
    const sortedDst = Object.entries(destCounts).sort((a, b) => b[1] - a[1]);
    if (sortedDst[0]) {
      dom.kpiValTopDst.textContent = sortedDst[0][0];
      dom.kpiSubTopDst.textContent = `(${sortedDst[0][1].toLocaleString()} packets)`;
    } else {
      dom.kpiValTopDst.textContent = '—';
      dom.kpiSubTopDst.textContent = '(0 packets)';
    }

    // Top Protocol
    const sortedProto = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
    if (sortedProto[0]) {
      const pct = Math.round((sortedProto[0][1] / total) * 100);
      dom.kpiValTopProto.textContent = sortedProto[0][0];
      dom.kpiSubTopProto.textContent = `(${pct}% of packets)`;
    } else {
      dom.kpiValTopProto.textContent = '—';
      dom.kpiSubTopProto.textContent = '(0% of packets)';
    }

    // Avg Length
    const avgLen = Math.round(totalBytes / total);
    dom.kpiValAvgLen.textContent = avgLen.toLocaleString();
  }

  // --- RENDER TABLES (Top Sources & Top Destinations) ---
  function renderTopSourceHostsTable(sourceCounts, totalPackets) {
    const sorted = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (sorted.length === 0) {
      dom.tableTopSources.innerHTML = '<tr><td colspan="4" class="empty-state">No source data available</td></tr>';
      return;
    }

    dom.tableTopSources.innerHTML = sorted.map(([ip, cnt], i) => {
      const pct = ((cnt / totalPackets) * 100).toFixed(1);
      return `
        <tr>
          <td style="color: var(--text-muted); font-weight: 600;">${i + 1}</td>
          <td style="font-weight: 600; color: var(--text-main);">${escapeHTML(ip)}</td>
          <td>${cnt.toLocaleString()}</td>
          <td>
            <div class="pct-bar-wrapper">
              <span style="width: 40px; font-size: 11px;">${pct}%</span>
              <div class="pct-bar-track">
                <div class="pct-bar-fill-blue" style="width: ${pct}%;"></div>
              </div>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderTopDestHostsTable(destCounts, totalPackets) {
    const sorted = Object.entries(destCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (sorted.length === 0) {
      dom.tableTopDests.innerHTML = '<tr><td colspan="4" class="empty-state">No destination data available</td></tr>';
      return;
    }

    dom.tableTopDests.innerHTML = sorted.map(([ip, cnt], i) => {
      const pct = ((cnt / totalPackets) * 100).toFixed(1);
      return `
        <tr>
          <td style="color: var(--text-muted); font-weight: 600;">${i + 1}</td>
          <td style="font-weight: 600; color: var(--text-main);">${escapeHTML(ip)}</td>
          <td>${cnt.toLocaleString()}</td>
          <td>
            <div class="pct-bar-wrapper">
              <span style="width: 40px; font-size: 11px;">${pct}%</span>
              <div class="pct-bar-track">
                <div class="pct-bar-fill-green" style="width: ${pct}%;"></div>
              </div>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  // --- RENDER PROTOCOL DONUT ---
  function renderProtocolDonut(protocolCounts, totalPackets) {
    dom.donutCenterVal.textContent = totalPackets.toLocaleString();
    const sorted = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);

    if (sorted.length === 0) {
      dom.donutSvg.innerHTML = '<circle cx="80" cy="80" r="60" fill="none" stroke="#e2e8f0" stroke-width="24"/>';
      dom.donutLegend.innerHTML = '<div class="empty-state" style="padding: 0; font-size: 11px;">No protocol data available</div>';
      return;
    }

    let cumulativePercent = 0;
    const size = 160;
    const center = size / 2;
    const radius = 60;
    const strokeWidth = 24;

    const svgPaths = [];
    const legendItems = [];

    sorted.forEach(([proto, cnt]) => {
      const pct = (cnt / totalPackets) * 100;
      const color = PROTOCOL_COLORS[proto] || PROTOCOL_COLORS['OTHER'];

      const circumference = 2 * Math.PI * radius;
      const strokeDasharray = `${(pct / 100) * circumference} ${circumference}`;
      const strokeDashoffset = -((cumulativePercent / 100) * circumference);

      cumulativePercent += pct;

      svgPaths.push(`
        <circle cx="${center}" cy="${center}" r="${radius}" fill="none"
          stroke="${color}" stroke-width="${strokeWidth}"
          stroke-dasharray="${strokeDasharray}"
          stroke-dashoffset="${strokeDashoffset}"
          transform="rotate(-90 ${center} ${center})"/>
      `);

      legendItems.push(`
        <div class="legend-item">
          <div class="legend-left">
            <div class="legend-dot" style="background: ${color};"></div>
            <span class="legend-name">${escapeHTML(proto)}</span>
          </div>
          <span class="legend-val">${pct.toFixed(1)}% (${cnt.toLocaleString()})</span>
        </div>
      `);
    });

    dom.donutSvg.innerHTML = svgPaths.join('');
    dom.donutLegend.innerHTML = legendItems.join('');
  }

  // --- RENDER DETECTION ALERTS IN BOTH PLACES ---
  function renderAlertTable(alerts) {
    const filter = dom.filterAlertSeverity ? dom.filterAlertSeverity.value : 'ALL';
    const filterDed = dom.filterAlertSeverityDedicated ? dom.filterAlertSeverityDedicated.value : 'ALL';

    const renderTableHTML = (f) => {
      const filtered = alerts.filter(a => f === 'ALL' || a.severity === f);
      if (filtered.length === 0) {
        return '<tr><td colspan="7" class="empty-state">No traffic data available for analysis.</td></tr>';
      }
      return filtered.map((alert, i) => {
        const badgeClass = `badge-sev-${alert.severity.toLowerCase()}`;
        return `
          <tr>
            <td style="color: var(--text-muted); font-weight: 600;">${i + 1}</td>
            <td style="font-weight: 700; color: var(--text-main);">${escapeHTML(alert.ruleName)}</td>
            <td><span class="badge-sev ${badgeClass}">${escapeHTML(alert.severity)}</span></td>
            <td class="text-mono" style="font-size: 11px;">${escapeHTML(alert.evidence)}</td>
            <td>${escapeHTML(alert.whyItMatters)}</td>
            <td style="color: var(--text-muted);">${escapeHTML(alert.benignExplanation)}</td>
            <td style="color: var(--text-muted);">${escapeHTML(alert.suggestedInvestigation)}</td>
          </tr>
        `;
      }).join('');
    };

    if (dom.alertTableBody) dom.alertTableBody.innerHTML = renderTableHTML(filter);
    if (dom.alertTableBodyDedicated) dom.alertTableBodyDedicated.innerHTML = renderTableHTML(filterDed);
  }

  // --- RENDER ANALYSIS RESULTS VIEW ---
  function renderAnalysisResults(total, sourceCounts, destCounts, protocolCounts, totalBytes) {
    if (!dom.resultsSummaryContent) return;
    const sortedSrc = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);
    const sortedDst = Object.entries(destCounts).sort((a, b) => b[1] - a[1]);
    const sortedProto = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);

    dom.resultsSummaryContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
          <div style="background: var(--bg-input); padding: 12px; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 11px;">Total Capture Volume</div>
            <div style="font-size: 18px; font-weight: 700;">${total.toLocaleString()} Packets</div>
            <div style="font-size: 11px; color: var(--text-muted);">${(totalBytes/1024).toFixed(1)} KB Payload</div>
          </div>
          <div style="background: var(--bg-input); padding: 12px; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 11px;">Host Diversity</div>
            <div style="font-size: 18px; font-weight: 700;">${Object.keys(sourceCounts).length} Src / ${Object.keys(destCounts).length} Dst</div>
            <div style="font-size: 11px; color: var(--text-muted);">Unique IP addresses</div>
          </div>
          <div style="background: var(--bg-input); padding: 12px; border-radius: 6px;">
            <div style="color: var(--text-muted); font-size: 11px;">Dominant Flow</div>
            <div style="font-size: 18px; font-weight: 700;">${sortedSrc[0] ? sortedSrc[0][0] : 'None'}</div>
            <div style="font-size: 11px; color: var(--text-muted);">${sortedSrc[0] ? sortedSrc[0][1] : 0} outbound packets</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 8px;">
          <div>
            <h4 style="font-size: 13px; font-weight: 700; margin-bottom: 8px;">Protocol Breakdown</h4>
            <ul style="list-style: none; padding: 0;">
              ${sortedProto.map(([p, cnt]) => `
                <li style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border-color); font-size: 12px;">
                  <span>${escapeHTML(p)}</span>
                  <span class="text-mono">${cnt.toLocaleString()} pkts (${((cnt/total)*100).toFixed(1)}%)</span>
                </li>
              `).join('')}
            </ul>
          </div>

          <div>
            <h4 style="font-size: 13px; font-weight: 700; margin-bottom: 8px;">Active Detection Summary</h4>
            <div style="background: var(--bg-input); padding: 12px; border-radius: 6px; font-size: 12px;">
              <p style="margin-bottom: 6px;"><strong>${state.alerts.length} Rule Alert(s) Triggered</strong></p>
              ${state.alerts.map(a => `
                <div style="margin-bottom: 4px; display: flex; justify-content: space-between;">
                  <span>• ${escapeHTML(a.ruleName)}</span>
                  <span class="badge-sev badge-sev-${a.severity.toLowerCase()}">${escapeHTML(a.severity)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // --- RENDER PACKET EXPLORER ---
  function renderPacketExplorer() {
    if (!dom.packetExplorerBody) return;
    const search = dom.filterSearchPackets ? dom.filterSearchPackets.value.toLowerCase() : '';
    const packets = state.packets.filter(p => {
      if (!search) return true;
      return `${p.no} ${p.source} ${p.destination} ${p.protocol} ${p.info}`.toLowerCase().includes(search);
    });

    if (packets.length === 0) {
      dom.packetExplorerBody.innerHTML = '<tr><td colspan="7" class="empty-state">No traffic data loaded</td></tr>';
      return;
    }

    dom.packetExplorerBody.innerHTML = packets.slice(0, 100).map(p => `
      <tr style="border-bottom: 1px solid var(--border-color); font-family: var(--font-mono);">
        <td style="padding: 6px 8px;">${escapeHTML(p.no)}</td>
        <td style="padding: 6px 8px;">${escapeHTML(p.time)}</td>
        <td style="padding: 6px 8px; font-weight: 600;">${escapeHTML(p.source)}</td>
        <td style="padding: 6px 8px;">${escapeHTML(p.destination)}</td>
        <td style="padding: 6px 8px;"><span style="background: var(--bg-input); padding: 2px 6px; border-radius: 4px;">${escapeHTML(p.protocol)}</span></td>
        <td style="padding: 6px 8px;">${p.length}</td>
        <td style="padding: 6px 8px; color: var(--text-muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHTML(p.info)}</td>
      </tr>
    `).join('');
  }

  init();

});
