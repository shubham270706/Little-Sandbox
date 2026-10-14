/**
 * IBM Carbon Design System - Cloud Runtime Sandbox Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const htmlElement = document.documentElement;
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const continueBtn = document.getElementById('continueBtn');
  const workspaceSection = document.getElementById('workspaceSection');
  
  // File Uploader Elements
  const fileInput = document.getElementById('fileInput');
  const dropZone = document.getElementById('dropZone');
  const selectFilesBtn = document.getElementById('selectFilesBtn');
  const uploadBtn = document.getElementById('uploadBtn');
  const selectedFilesList = document.getElementById('selectedFilesList');
  const emptyFileState = document.getElementById('emptyFileState');
  const uploadNotification = document.getElementById('uploadNotification');
  const uploadNotificationMsg = document.getElementById('uploadNotificationMsg');

  // Control Elements
  const toolsDropdown = document.getElementById('toolsDropdown');
  const runBtn = document.getElementById('runBtn');
  const printDownloadBtn = document.getElementById('printDownloadBtn');
  const exportMenu = document.getElementById('exportMenu');
  const optDownloadJson = document.getElementById('optDownloadJson');
  const optDownloadLog = document.getElementById('optDownloadLog');
  const optPrintReport = document.getElementById('optPrintReport');

  // Telemetry Terminal
  const terminalWindow = document.getElementById('terminalWindow');
  const eventCountBadge = document.getElementById('eventCountBadge');
  const clearLogsBtn = document.getElementById('clearLogsBtn');
  const sandboxStatusPill = document.getElementById('sandboxStatusPill');

  // Gemma AI Elements
  const gemmaAiOptionBtn = document.getElementById('gemmaAiOptionBtn');
  const gemmaModal = document.getElementById('gemmaModal');
  const gemmaModalOverlay = document.getElementById('gemmaModalOverlay');
  const closeGemmaModalBtn = document.getElementById('closeGemmaModalBtn');
  const dismissGemmaBtn = document.getElementById('dismissGemmaBtn');
  const agreeGemmaBtn = document.getElementById('agreeGemmaBtn');
  const gemmaAccessBadge = document.getElementById('gemmaAccessBadge');
  const disableGemmaBtn = document.getElementById('disableGemmaBtn');
  const disableGemmaPanelBtn = document.getElementById('disableGemmaPanelBtn');
  const gemmaAnalyticsPanel = document.getElementById('gemmaAnalyticsPanel');
  const refreshGemmaAnalyticsBtn = document.getElementById('refreshGemmaAnalyticsBtn');
  const gemmaAiSummaryText = document.getElementById('gemmaAiSummaryText');
  const gemmaRiskScore = document.getElementById('gemmaRiskScore');
  const gemmaRiskDesc = document.getElementById('gemmaRiskDesc');
  const gemmaNetScore = document.getElementById('gemmaNetScore');
  const gemmaNetDesc = document.getElementById('gemmaNetDesc');
  const gemmaProcScore = document.getElementById('gemmaProcScore');
  const gemmaProcDesc = document.getElementById('gemmaProcDesc');

  // --- State Variables ---
  let selectedFiles = [];
  let isUploaded = false;
  let isRunning = false;
  let eventLogs = [];
  let streamInterval = null;
  let gemmaEnabled = false;

  // =========================================================================
  // 1. Theme Management (Light: White / Dark: g100)
  // =========================================================================
  const savedTheme = localStorage.getItem('carbon-theme') || 'g100';
  htmlElement.setAttribute('data-carbon-theme', savedTheme);

  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = htmlElement.getAttribute('data-carbon-theme');
    const newTheme = currentTheme === 'g100' ? 'white' : 'g100';
    htmlElement.setAttribute('data-carbon-theme', newTheme);
    localStorage.setItem('carbon-theme', newTheme);
  });

  // =========================================================================
  // 2. Continue Button & Enter Key Navigation
  // =========================================================================
  function proceedToUpload() {
    const uploadArea = document.getElementById('uploadSection') || document.getElementById('dropZone');
    if (uploadArea) {
      uploadArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Set focus to the "Select files" button for keyboard and accessibility flow
      const selectFilesBtn = document.getElementById('selectFilesBtn');
      if (selectFilesBtn) {
        setTimeout(() => {
          selectFilesBtn.focus({ preventScroll: true });
        }, 350);
      }
    }
  }

  continueBtn.addEventListener('click', proceedToUpload);

  // Global listener for Enter key when on the hero section or viewport is at the top
  window.addEventListener('keydown', (e) => {
    // Only trigger if user is not currently inside an input/select/button/dropzone
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
    if (e.key === 'Enter') {
      if (activeTag !== 'input' && activeTag !== 'select' && activeTag !== 'button' && activeTag !== 'textarea') {
        e.preventDefault();
        proceedToUpload();
      }
    }
  });

  // =========================================================================
  // 3. File Selection & Drag-and-Drop Management
  // =========================================================================
  selectFilesBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  // Drag and drop event handlers
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('drag-active');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drag-active');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      handleFiles(dt.files);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(e.target.files);
    }
  });

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function handleFiles(files) {
    const newFiles = Array.from(files);
    newFiles.forEach(file => {
      // Prevent duplicates by name and size
      if (!selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
        selectedFiles.push({
          file: file,
          name: file.name,
          size: file.size,
          uploaded: false
        });
      }
    });

    isUploaded = false;
    uploadNotification.style.display = 'none';
    renderFileList();
  }

  function renderFileList() {
    if (selectedFiles.length === 0) {
      emptyFileState.style.display = 'block';
      uploadBtn.disabled = true;
      selectedFilesList.innerHTML = '';
      selectedFilesList.appendChild(emptyFileState);
      return;
    }

    emptyFileState.style.display = 'none';
    uploadBtn.disabled = false;
    selectedFilesList.innerHTML = '';

    selectedFiles.forEach((item, index) => {
      const fileRow = document.createElement('div');
      fileRow.className = 'cds--file-item';
      
      const leftCol = document.createElement('div');
      leftCol.className = 'cds--file-item-left';

      // Carbon File Icon
      const iconSvg = `
        <svg width="18" height="18" viewBox="0 0 32 32" fill="var(--cds-primary)">
          <path d="M25.7 9.3l-7-7c-.2-.2-.4-.3-.7-.3H8c-1.1 0-2 .9-2 2v24c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V10c0-.3-.1-.5-.3-.7zM18 4.4l5.6 5.6H18V4.4zM24 28H8V4h8v7c0 .6.4 1 1 1h7v16z"/>
        </svg>
      `;
      leftCol.innerHTML = iconSvg;

      const detailsSpan = document.createElement('div');
      detailsSpan.innerHTML = `
        <div class="cds--file-item-name" title="${item.name}">${item.name}</div>
        <div class="cds--file-item-size">${formatFileSize(item.size)}</div>
      `;
      leftCol.appendChild(detailsSpan);

      const rightCol = document.createElement('div');
      rightCol.className = 'cds--file-item-right';

      const statusTag = document.createElement('span');
      statusTag.className = `cds--file-status-tag ${item.uploaded ? 'uploaded' : 'ready'}`;
      statusTag.textContent = item.uploaded ? 'Uploaded' : 'Ready to upload';
      rightCol.appendChild(statusTag);

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'cds--file-delete-btn';
      deleteBtn.title = 'Remove file';
      deleteBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
          <path d="M12 12h2v12h-2zm6 0h2v12h-2z"/>
          <path d="M4 6v2h2v20a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8h2V6h-6V4a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v2H4zm8-2h8v2h-8V4zm12 24H8V8h16v20z"/>
        </svg>
      `;
      deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        selectedFiles.splice(index, 1);
        renderFileList();
      });
      rightCol.appendChild(deleteBtn);

      fileRow.appendChild(leftCol);
      fileRow.appendChild(rightCol);
      selectedFilesList.appendChild(fileRow);
    });
  }

  // Upload action
  uploadBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (selectedFiles.length === 0) return;

    uploadBtn.disabled = true;
    uploadBtn.innerHTML = `
      <svg class="cds--btn__icon-left" style="animation: spin 1s linear infinite;" width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
        <path d="M16 2A14 14 0 1 0 30 16A14 14 0 0 0 16 2zm0 24a10 10 0 1 1 10-10A10 10 0 0 1 16 26z" opacity="0.3"/>
        <path d="M16 2A14 14 0 0 1 30 16h-4A10 10 0 0 0 16 6V2z"/>
      </svg>
      Uploading...
    `;

    setTimeout(() => {
      selectedFiles.forEach(item => { item.uploaded = true; });
      isUploaded = true;
      renderFileList();

      uploadBtn.disabled = false;
      uploadBtn.innerHTML = `
        <svg class="cds--btn__icon-left" width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
          <path d="M16 4L6 14l1.41 1.41L15 7.83V28h2V7.83l7.59 7.58L26 14 16 4z"/>
        </svg>
        Upload
      `;

      uploadNotification.style.display = 'flex';
      const fileCount = selectedFiles.length;
      uploadNotificationMsg.textContent = `${fileCount} ${fileCount === 1 ? 'artifact' : 'artifacts'} safely staged in ephemeral RAM disk. Ready for sandbox execution.`;

      appendLog('SYSTEM', `Staged ${fileCount} file(s) into isolated chroot namespace. Permissions: read-only.`);
    }, 700);
  });

  // =========================================================================
  // 4. Live Telemetry & Sandbox Execution (Headline & Subheadline Realization)
  // =========================================================================
  function getTimestamp() {
    const now = new Date();
    return now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  }

  function appendLog(category, message) {
    // Clear initial placeholder if first event
    const placeholder = terminalWindow.querySelector('.cds--terminal-placeholder');
    if (placeholder) {
      placeholder.remove();
    }

    const timestamp = getTimestamp();
    const logItem = { timestamp, category, message };
    eventLogs.push(logItem);

    const logRow = document.createElement('div');
    logRow.className = 'cds--log-line';

    let tagClass = 'cds--log-tag--system';
    if (category === 'FILE_READ') tagClass = 'cds--log-tag--read';
    else if (category === 'NET_CALL') tagClass = 'cds--log-tag--net';
    else if (category === 'PROC_SPAWN') tagClass = 'cds--log-tag--spawn';
    else if (category === 'BLOCKED') tagClass = 'cds--log-tag--block';
    else if (category === 'GEMMA_AI') tagClass = 'cds--log-tag--gemma';

    logRow.innerHTML = `
      <span class="cds--log-time">${timestamp}</span>
      <span class="cds--log-tag ${tagClass}">[${category}]</span>
      <span class="cds--log-content">${escapeHtml(message)}</span>
    `;

    terminalWindow.appendChild(logRow);
    terminalWindow.scrollTop = terminalWindow.scrollHeight;

    eventCountBadge.textContent = `${eventLogs.length} events captured`;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  clearLogsBtn.addEventListener('click', () => {
    eventLogs = [];
    terminalWindow.innerHTML = `
      <div class="cds--terminal-placeholder">
        $ Terminal logs cleared. Select files and click <strong style="color:var(--cds-primary)">Run</strong> to stream runtime events.
      </div>
    `;
    eventCountBadge.textContent = '0 events captured';
  });

  // Synthetic real-time event generator reflecting the subheadline:
  // "streams every file read, network call, and process spawned in real time—before it touches your system."
  runBtn.addEventListener('click', () => {
    if (isRunning) return;

    const selectedTool = toolsDropdown.value;
    const toolLabel = toolsDropdown.options[toolsDropdown.selectedIndex].text;
    const targetFileName = selectedFiles.length > 0 ? selectedFiles[0].name : 'untrusted_sample.bin';

    isRunning = true;
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <svg class="cds--btn__icon-left" style="animation: spin 1s linear infinite;" width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
        <path d="M16 2A14 14 0 1 0 30 16A14 14 0 0 0 16 2zm0 24a10 10 0 1 1 10-10A10 10 0 0 1 16 26z" opacity="0.3"/>
        <path d="M16 2A14 14 0 0 1 30 16h-4A10 10 0 0 0 16 6V2z"/>
      </svg>
      <span>Executing...</span>
    `;

    sandboxStatusPill.querySelector('.cds--status-dot').classList.add('active');
    sandboxStatusPill.querySelector('.cds--status-text').textContent = 'Live Sandboxing';

    appendLog('SYSTEM', `Initializing microVM container with ${toolLabel}`);
    appendLog('SYSTEM', `Loading target binary: ${targetFileName}`);

    const baseEvents = [
      { cat: 'PROC_SPAWN', msg: `clone() -> new child process pid=4921 uid=1001 (sandbox-runner)` },
      { cat: 'FILE_READ', msg: `openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) -> fd 3` },
      { cat: 'FILE_READ', msg: `read(fd 3, buf[4096]) -> 1842 bytes [libc.so.6, libcrypto.so]` }
    ];

    if (gemmaEnabled) {
      baseEvents.push({ cat: 'GEMMA_AI', msg: `Heuristic check: Dynamic linker shared libraries verified authentic (glibc-2.38).` });
    }

    baseEvents.push(
      { cat: 'PROC_SPAWN', msg: `execve("/bin/sh", ["/bin/sh", "-c", "uname -a"], [/* 18 vars */]) -> trapped by eBPF` },
      { cat: 'FILE_READ', msg: `openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY) -> emulated fake sandbox CPU` },
      { cat: 'NET_CALL', msg: `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) -> intercepted before network bridge` },
      { cat: 'NET_CALL', msg: `connect(fd 4, {sin_family=AF_INET, sin_port=443, sin_addr=198.51.100.42}) -> intercepted` },
      { cat: 'BLOCKED', msg: `EPERM: Outbound network call to 198.51.100.42 dropped. Zero-trust isolation enforced.` }
    );

    if (gemmaEnabled) {
      baseEvents.push({ cat: 'GEMMA_AI', msg: `Anomaly detected: Outbound socket connection to external IP 198.51.100.42 intercepted and dropped.` });
    }

    baseEvents.push(
      { cat: 'FILE_READ', msg: `readlink("/proc/self/exe") -> redirected to virtual memory mapping` },
      { cat: 'PROC_SPAWN', msg: `prctl(PR_SET_NO_NEW_PRIVS, 1) -> sandbox privilege escalation locked` }
    );

    if (gemmaEnabled) {
      baseEvents.push({ cat: 'GEMMA_AI', msg: `Safety verdict: Process execution trapped without root elevation. MicroVM boundary preserved.` });
    }

    baseEvents.push(
      { cat: 'SYSTEM', msg: `Execution finalized without host side effects. Total memory footprint: 14.2 MB.` }
    );

    let step = 0;
    streamInterval = setInterval(() => {
      if (step < baseEvents.length) {
        const item = baseEvents[step];
        appendLog(item.cat, item.msg);
        step++;
      } else {
        clearInterval(streamInterval);
        isRunning = false;
        runBtn.disabled = false;
        runBtn.innerHTML = `
          <svg class="cds--btn__icon-left" width="16" height="16" viewBox="0 0 32 32" fill="currentColor">
            <path d="M7 28a1 1 0 0 1-1-1V5a1 1 0 0 1 1.482-.876l20 11a1 1 0 0 1 0 1.752l-20 11A1 1 0 0 1 7 28zM8 6.84v18.32L24.654 16z"/>
          </svg>
          <span>Run</span>
        `;
        sandboxStatusPill.querySelector('.cds--status-dot').classList.remove('active');
        sandboxStatusPill.querySelector('.cds--status-text').textContent = 'Execution Complete';

        if (gemmaEnabled) {
          updateGemmaAnalytics();
        }
      }
    }, 420);
  });

  // =========================================================================
  // 5. Gemma AI Disclaimer Modal & Analytics Controller
  // =========================================================================
  function openGemmaModal() {
    if (gemmaModal) {
      gemmaModal.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    }
  }

  function closeGemmaModal() {
    if (gemmaModal) {
      gemmaModal.style.display = 'none';
      document.body.style.overflow = '';
    }
  }

  if (gemmaAiOptionBtn) {
    gemmaAiOptionBtn.addEventListener('click', () => {
      if (!gemmaEnabled) {
        openGemmaModal();
      } else {
        // Toggle view or scroll to the analytics dashboard
        if (gemmaAnalyticsPanel) {
          gemmaAnalyticsPanel.style.display = 'block';
          gemmaAnalyticsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      }
    });
  }

  if (closeGemmaModalBtn) closeGemmaModalBtn.addEventListener('click', closeGemmaModal);
  if (gemmaModalOverlay) gemmaModalOverlay.addEventListener('click', closeGemmaModal);

  // When Dismiss is pressed, nothing changes
  if (dismissGemmaBtn) {
    dismissGemmaBtn.addEventListener('click', () => {
      closeGemmaModal();
    });
  }

  // When Agree and Continue is pressed, user is allowed to access analytics and logs
  if (agreeGemmaBtn) {
    agreeGemmaBtn.addEventListener('click', () => {
      gemmaEnabled = true;
      closeGemmaModal();

      if (gemmaAccessBadge) {
        gemmaAccessBadge.textContent = 'Active';
        gemmaAccessBadge.classList.remove('cds--gemma-badge--locked');
        gemmaAccessBadge.classList.add('cds--gemma-badge--active');
      }

      // Show the option to disable Gemma AI now that it is active
      if (disableGemmaBtn) {
        disableGemmaBtn.style.display = 'inline-flex';
      }

      if (gemmaAnalyticsPanel) {
        gemmaAnalyticsPanel.style.display = 'block';
        gemmaAnalyticsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      updateGemmaAnalytics();

      appendLog('GEMMA_AI', 'User consent verified. Gemma AI telemetry analysis engine connected and active.');
      appendLog('GEMMA_AI', 'Ready to parse submitted file bytecode and live kernel streams.');
    });
  }

  // Disable Gemma AI function (reverts state and hides analytics & disable option)
  function disableGemmaAI() {
    gemmaEnabled = false;

    // Hide disable options
    if (disableGemmaBtn) {
      disableGemmaBtn.style.display = 'none';
    }

    // Reset badge state
    if (gemmaAccessBadge) {
      gemmaAccessBadge.textContent = 'Requires Opt-in';
      gemmaAccessBadge.classList.remove('cds--gemma-badge--active');
      gemmaAccessBadge.classList.add('cds--gemma-badge--locked');
    }

    // Hide analytics panel
    if (gemmaAnalyticsPanel) {
      gemmaAnalyticsPanel.style.display = 'none';
    }

    appendLog('SYSTEM', 'Gemma AI disabled. Analysis disconnected and local sandbox isolation reinstated.');
  }

  if (disableGemmaBtn) {
    disableGemmaBtn.addEventListener('click', disableGemmaAI);
  }

  if (disableGemmaPanelBtn) {
    disableGemmaPanelBtn.addEventListener('click', disableGemmaAI);
  }

  function updateGemmaAnalytics() {
    if (!gemmaAnalyticsPanel) return;
    const fileCount = selectedFiles.length;
    const currentTool = toolsDropdown.options[toolsDropdown.selectedIndex].text;
    
    if (gemmaRiskScore) {
      gemmaRiskScore.textContent = fileCount > 0 ? 'LOW (11.4/100)' : 'BASELINE (5.0/100)';
    }
    if (gemmaRiskDesc) {
      gemmaRiskDesc.textContent = `Analyzed ${fileCount} artifact(s) against ${currentTool}. No anomalous buffer overflow or heap corruptions found.`;
    }
    if (gemmaNetScore) {
      gemmaNetScore.textContent = 'Interception Active';
    }
    if (gemmaNetDesc) {
      gemmaNetDesc.textContent = 'Zero-trust network bridge active. External socket exfiltration blocked.';
    }
    if (gemmaProcScore) {
      gemmaProcScore.textContent = 'Constrained';
    }
    if (gemmaProcDesc) {
      gemmaProcDesc.textContent = 'eBPF security probe confirmed NO_NEW_PRIVS bit set. Child processes trapped.';
    }
    if (gemmaAiSummaryText) {
      gemmaAiSummaryText.textContent = `Gemma AI evaluated ${eventLogs.length} runtime events for "${selectedFiles.length > 0 ? selectedFiles[0].name : 'untrusted_sample.bin'}". Telemetry signature matches secure testing profile.`;
    }
  }

  if (refreshGemmaAnalyticsBtn) {
    refreshGemmaAnalyticsBtn.addEventListener('click', () => {
      updateGemmaAnalytics();
      appendLog('GEMMA_AI', `Heuristic evaluation refreshed for ${selectedFiles.length} file(s). Risk score updated.`);
    });
  }

  // Keyboard shortcut for modal dismissal: Escape key
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && gemmaModal && gemmaModal.style.display === 'flex') {
      closeGemmaModal();
    }
  });

  // =========================================================================
  // 5. Print & Download Options
  // =========================================================================
  printDownloadBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle('open');
  });

  // Close menu on click outside
  document.addEventListener('click', (e) => {
    if (!printDownloadBtn.contains(e.target) && !exportMenu.contains(e.target)) {
      exportMenu.classList.remove('open');
    }
  });

  // Action 1: Download JSON Report
  optDownloadJson.addEventListener('click', () => {
    exportMenu.classList.remove('open');
    const reportData = {
      product: 'IBM Carbon Runtime Sandbox',
      timestamp: new Date().toISOString(),
      toolchain: toolsDropdown.options[toolsDropdown.selectedIndex].text,
      filesStaged: selectedFiles.map(f => ({ name: f.name, size: f.size })),
      telemetryLogCount: eventLogs.length,
      events: eventLogs
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ibm-sandbox-telemetry-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Action 2: Download Raw Log (.log)
  optDownloadLog.addEventListener('click', () => {
    exportMenu.classList.remove('open');
    let logText = `=== IBM CLOUD RUNTIME SANDBOX TELEMETRY LOG ===\n`;
    logText += `Generated: ${new Date().toISOString()}\n`;
    logText += `Engine: ${toolsDropdown.options[toolsDropdown.selectedIndex].text}\n`;
    logText += `------------------------------------------------\n\n`;

    if (eventLogs.length === 0) {
      logText += `No events recorded in current session.\n`;
    } else {
      eventLogs.forEach(entry => {
        logText += `[${entry.timestamp}] [${entry.category}] ${entry.message}\n`;
      });
    }

    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `runtime-sandbox-${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Action 3: Print Audit Sheet
  optPrintReport.addEventListener('click', () => {
    exportMenu.classList.remove('open');
    window.print();
  });
});

