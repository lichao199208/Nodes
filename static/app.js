const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
const APP_BASE = (document.querySelector('meta[name="app-base"]')?.content || '').replace(/\/$/, '');
const state = {
  dashboard: null,
  exports: null,
  settings: null,
  currentView: 'dashboard',
  accountTab: 'list',
  settingsTab: 'registration',
};

const titles = {
  dashboard: ['仪表盘', '库存与质检拉取'],
  sources: ['代理源', '拉代理 API · 外部拉取 / 本地短路'],
  quality: ['质检规则', 'ARP / 延迟 / 国家 · dry-run 试跑'],
  exports: ['出口订阅', '质检推荐 · 8892 兼容 · 账号池出口'],
  accounts: ['账号', '账号池供给 · 注册补号与任务'],
  settings: ['设置', '注册出网 · 邮箱 · 打码'],
};

const settingFields = {
  sources: [
    'pull_api_base', 'pull_api_user', 'pull_api_pass', 'pull_api_shuliang', 'pull_api_id',
    'export_proxy_protocol',
  ],
  quality: [
    'quality_profile_id', 'export_quality_profile',
    'proxy_quality_enabled', 'proxy_max_latency_ms', 'proxy_exclude_countries',
    'proxy_quality_workers', 'proxy_quality_cache_ttl_sec',
    'proxy_arp_check_enabled', 'proxy_arp_probe_url', 'arp_publish_url', 'arp_publish_token',
  ],
  registration: ['proxy_enabled', 'http_proxy', 'https_proxy', 'no_proxy'],
  mail: ['mail_provider', 'mail_type', 'mail_suffix', 'mail_domain', 'mail_api_base', 'mail_api_key', 'yyds_api_key', 'yyds_domain'],
  captcha: ['captcha_provider', 'captcha_timeout', 'captcha_poll_interval', 'turnstile_extension_path', 'captcha_api_base', 'captcha_api_key'],
  exports: ['export_quality_profile'],
};

function appUrl(path) {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${APP_BASE}${normalized}`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[ch]);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  if ((options.method || 'GET') !== 'GET') headers['X-CSRF-Token'] = csrf;
  const response = await fetch(appUrl(path), { ...options, headers, credentials: 'same-origin' });
  if (response.status === 401) {
    window.location.href = appUrl('/login');
    throw new Error('会话已过期');
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function formatDate(value) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(value));
}

function statusLabel(status) {
  return ({ queued: '排队中', running: '运行中', success: '成功', partial: '部分成功', failed: '失败', interrupted: '已中断' })[status] || status;
}

function statusChip(status) {
  return `<span class="status-chip ${escapeHtml(status)}">${escapeHtml(statusLabel(status))}</span>`;
}

let toastTimer;
function toast(message, error = false) {
  const element = document.getElementById('toast');
  element.textContent = message;
  element.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.className = 'toast'; }, 3200);
}

async function copyField(id) {
  const value = document.getElementById(id)?.value || '';
  if (!value) return;
  await navigator.clipboard.writeText(value);
  toast('已复制');
}

function showAccountTab(tab) {
  state.accountTab = tab;
  document.querySelectorAll('[data-account-tab]').forEach(item => {
    item.classList.toggle('active', item.dataset.accountTab === tab);
  });
  document.querySelectorAll('.account-tab').forEach(item => {
    item.classList.toggle('active', item.id === `account-tab-${tab}`);
  });
  if (tab === 'list') loadAccounts();
  if (tab === 'tasks') loadTasks();
}

function showSettingsTab(tab) {
  state.settingsTab = tab;
  document.querySelectorAll('[data-settings-tab]').forEach(item => {
    item.classList.toggle('active', item.dataset.settingsTab === tab);
  });
  document.querySelectorAll('.settings-tab').forEach(item => {
    item.classList.toggle('active', item.id === `settings-tab-${tab}`);
  });
}

function showView(view, options = {}) {
  state.currentView = view;
  document.querySelectorAll('.view').forEach(item => item.classList.toggle('active', item.id === `view-${view}`));
  document.querySelectorAll('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.view === view));
  document.getElementById('pageTitle').textContent = titles[view][0];
  document.getElementById('pageSubtitle').textContent = titles[view][1];
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarScrim').classList.remove('show');
  if (view === 'accounts') {
    showAccountTab(options.tab || state.accountTab || 'list');
  }
  if (view === 'settings') {
    showSettingsTab(options.tab || state.settingsTab || 'registration');
    loadSettings();
  }
  if (view === 'sources' || view === 'quality') loadSettings(view === 'sources' ? 'sources' : 'quality');
  if (view === 'quality') loadQualityAudit();
  if (view === 'exports') {
    loadExports();
    loadSettings('exports');
  }
}

function renderPool(pool) {
  if (!pool) return;
  const live = pool.live_slots || 0;
  const accounts = pool.live_accounts || 0;
  const slots = `${live} 可连（${accounts}×8）`;
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  const setVal = (id, value) => { const el = document.getElementById(id); if (el) el.value = value ?? ''; };
  setText('poolAccounts', accounts || '—');
  setText('poolSlots', slots);
  setText('poolNeeded', pool.needed_accounts ?? 0);
  setText('poolAuto', pool.auto_register ? '开' : '关');
  setVal('poolResinUrl', pool.subscription_url || '');
  setVal('poolGptUrl', pool.gpt_subscription_url || '');
  setVal('poolClashUrl', pool.clash_subscription_url || '');
  setVal('poolLadderUrl', pool.ladder_subscription_url || '');
  setVal('poolGptSample', pool.gpt_gateway_sample || '');
  const qualified = pool.qualified_subscription_url || pool.qualified_url || '';
  setVal('poolQualifiedUrl', qualified);
  setVal('dashQualifiedUrl', qualified);
  setText('metricSlots', `${live}/${pool.needed_accounts ?? 0}`);
  setText('metricSlotsNote', slots);
  setText('invSlots', slots);
}

function renderInventory(inventory, history) {
  const inv = inventory || {};
  document.getElementById('metricQualified').textContent = inv.accepted ?? '—';
  document.getElementById('metricRejected').textContent = inv.rejected ?? '—';
  document.getElementById('metricQualifiedNote').textContent = inv.enabled === false ? '质检已关闭' : `profile ${inv.profile_id || 'default'}`;
  document.getElementById('metricRejectedNote').textContent = inv.enabled === false ? '—' : '质检未通过';
  document.getElementById('invScanned').textContent = inv.scanned ?? '—';
  document.getElementById('invAccepted').textContent = inv.accepted ?? '—';
  document.getElementById('invRejected').textContent = inv.rejected ?? '—';
  const reasons = inv.reasons || [];
  const box = document.getElementById('invReasons');
  if (!reasons.length) {
    box.innerHTML = '<div class="empty-cell">暂无拒绝原因</div>';
  } else {
    box.innerHTML = reasons.map(item => `
      <div class="reason-row">
        <span>${escapeHtml(item.reason || 'unknown')}</span>
        <strong>${item.count}</strong>
      </div>`).join('');
  }
  renderHistoryChart(history || []);
}

function renderHistoryChart(history) {
  const chart = document.getElementById('invHistoryChart');
  if (!chart) return;
  const rows = Array.isArray(history) ? history.slice(-24) : [];
  if (!rows.length) {
    chart.innerHTML = '<div class="empty-cell" style="min-height:48px;padding:8px 0">暂无历史点（保存规则或补齐容量后开始落盘）</div>';
    return;
  }
  const max = Math.max(1, ...rows.map(item => Number(item.accepted || 0) + Number(item.rejected || 0)));
  chart.innerHTML = rows.map(item => {
    const accepted = Number(item.accepted || 0);
    const rejected = Number(item.rejected || 0);
    const total = accepted + rejected;
    const height = Math.max(4, Math.round((total / max) * 56));
    const title = `${item.recorded_at || ''} · 合格 ${accepted} / 拒绝 ${rejected}`;
    return `<div class="history-bar" title="${escapeHtml(title)}" style="height:${height}px"></div>`;
  }).join('');
}

function fillProfileSelects(profilesPayload) {
  const profiles = profilesPayload?.profiles || [];
  if (!profiles.length) return;
  ['quality_profile_id', 'export_quality_profile', 'export_quality_profile_exports'].forEach(id => {
    const select = document.getElementById(id);
    if (!select) return;
    const current = select.value;
    select.innerHTML = profiles.map(item =>
      `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name || item.id)}</option>`
    ).join('');
    const preferred = id.includes('export')
      ? (profilesPayload.export_id || current)
      : (profilesPayload.active_id || current);
    if (preferred && [...select.options].some(opt => opt.value === preferred)) {
      select.value = preferred;
    }
  });
}

async function loadQualityAudit() {
  try {
    const data = await api('/api/audit?kind=quality&limit=30');
    const body = document.getElementById('qualityAuditBody');
    if (!body) return;
    const rows = data.entries || [];
    body.innerHTML = rows.length ? rows.map(item => {
      const detail = item.detail || {};
      const text = detail.profile_id
        ? `${detail.profile_id} v${detail.version ?? '—'} · latency=${detail.max_latency_ms ?? '—'} · arp=${detail.arp_check_enabled ?? '—'}`
        : (detail.export_quality_profile ? `export→${detail.export_quality_profile}` : JSON.stringify(detail));
      return `<tr>
        <td>${escapeHtml(formatDate(item.at))}</td>
        <td>${escapeHtml(item.action || '')}</td>
        <td title="${escapeHtml(text)}">${escapeHtml(text)}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="3" class="empty-cell">暂无记录</td></tr>';
  } catch (error) {
    /* ignore on first paint */
  }
}

function renderPullStatus(pullApi) {
  const data = pullApi || {};
  const chip = document.getElementById('pullConfiguredChip');
  const status = document.getElementById('dashSourceStatus');
  const mode = data.pull_mode || (data.local_shortcircuit ? 'local_shortcircuit' : (data.configured ? 'external' : 'unconfigured'));
  if (!data.configured) {
    chip.textContent = '未配置代理源';
    chip.className = 'status-chip queued';
    status.innerHTML = '代理源：<strong>未配置</strong> · <button type="button" class="text-button" data-go="sources">去代理源</button>';
  } else if (mode === 'local_shortcircuit') {
    chip.textContent = '本地短路';
    chip.className = 'status-chip partial';
    status.innerHTML = `代理源：<strong>已配置 · 本地短路</strong>（不请求外部） · scheme=<code>${escapeHtml(data.scheme || 'http')}</code> · <button type="button" class="text-button" data-go="sources">管理</button>`;
  } else {
    chip.textContent = '已配置 · 外部拉取';
    chip.className = 'status-chip ready';
    status.innerHTML = `代理源：<strong>已配置 · 外部拉取</strong> · scheme=<code>${escapeHtml(data.scheme || 'http')}</code> · <button type="button" class="text-button" data-go="sources">管理</button>`;
  }
  status.querySelectorAll('[data-go]').forEach(btn => {
    btn.addEventListener('click', () => showView(btn.dataset.go));
  });

  const sample = document.getElementById('compatApiSample');
  if (sample) {
    sample.value = data.compat_url_masked || data.request_url_masked || (data.configured ? `${data.api || ''}?user=***&pass=***` : '');
  }

  const title = document.getElementById('sourcesModeTitle');
  const hint = document.getElementById('sourcesModeHint');
  if (title && hint) {
    if (!data.configured) {
      title.textContent = '未配置';
      hint.textContent = '填写上游地址与账号后保存。外部上游与本地 8892/api 短路互斥，不会同时生效。';
    } else if (mode === 'local_shortcircuit') {
      title.textContent = '当前：本地短路（账号池）';
      hint.textContent = 'base 指向本机 /api 或 :8892，质检流水线读本地账号池，不会再 HTTP 拉外部列表。若要外部拉取，请改成真实上游 URL。';
    } else {
      title.textContent = '当前：外部拉取';
      hint.textContent = '质检流水线会向该上游 HTTP 拉取列表再过滤。若改成指向本机 /api 或 :8892，将切换为本地短路。';
    }
  }
}

function renderQualityMeta(settings) {
  const version = settings?.version ?? settings?.proxy_quality_version ?? settings?.quality_version;
  const updated = settings?.updated_at ?? settings?.proxy_quality_updated_at ?? settings?.quality_updated_at;
  const chip = document.getElementById('qualityVersionChip');
  if (chip) chip.textContent = `version ${version ?? '—'} · ${updated ? formatDate(updated) : '未更新'}`;
  const hint = document.getElementById('qualityMetaHint');
  if (hint) {
    hint.textContent = updated
      ? `规则 version=${version ?? '—'}，更新于 ${formatDate(updated)}。保存后 version 自增。`
      : '规则尚未写入 version；首次保存质检规则后生成。';
  }
}

function renderTasks(tasks, target, compact = false) {
  const body = document.getElementById(target);
  if (!body) return;
  if (!tasks.length) {
    body.innerHTML = `<tr><td colspan="${compact ? 5 : 7}" class="empty-cell">暂无任务</td></tr>`;
    return;
  }
  body.innerHTML = tasks.map(task => `
    <tr class="clickable" data-task-id="${escapeHtml(task.id)}">
      <td title="${escapeHtml(task.id)}">${escapeHtml(task.id)}</td>
      ${compact ? '' : `<td>${task.requested}</td>`}
      <td>${compact ? `${task.completed}/${task.requested}` : task.completed}</td>
      ${compact ? '' : `<td>${task.successes}</td>`}
      <td>${task.proxy_count || 0}</td>
      <td>${statusChip(task.status)}</td>
      <td>${formatDate(task.started_at || task.created_at)}</td>
    </tr>`).join('');
  body.querySelectorAll('[data-task-id]').forEach(row => row.addEventListener('click', () => openTask(row.dataset.taskId)));
}

async function refreshDashboard() {
  try {
    const data = await api('/api/dashboard');
    state.dashboard = data;
    document.getElementById('metricAccounts').textContent = data.summary.accounts;
    document.getElementById('metricAccountsNote').textContent = `${data.summary.verified || 0} 已验证 · ${data.summary.successful_accounts || 0} 有产出`;
    document.getElementById('runtimeMail').textContent = data.chain.mail;
    document.getElementById('runtimeCaptcha').textContent = data.chain.captcha;
    const proxyEl = document.getElementById('runtimeProxy');
    if (proxyEl) {
      proxyEl.textContent = data.chain.proxy === 'enabled' ? '出口开' : '出口关';
    }
    renderPool(data.pool);
    renderInventory(data.inventory || data.pool?.quality, data.inventory_history);
    renderPullStatus(data.pull_api);
    if (data.quality_profiles) fillProfileSelects(data.quality_profiles);
    if (data.quality_meta || data.settings_meta) {
      renderQualityMeta(data.quality_meta || data.settings_meta);
    }
    const active = Boolean(data.active_task);
    const activity = document.getElementById('activity');
    activity.classList.toggle('running', active);
    activity.querySelector('span:last-child').textContent = active ? `任务 ${data.active_task} 运行中` : '无活动任务';
    const startButton = document.getElementById('startButton');
    if (startButton) {
      startButton.disabled = active;
      startButton.textContent = active ? '任务运行中' : '启动任务';
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function formatBytes(value) {
  if (value == null || value === '') return '—';
  const amount = Number(value);
  if (!Number.isFinite(amount)) return '—';
  if (amount >= 1e12) return `${(amount / 1e12).toFixed(2)} TB`;
  if (amount >= 1e9) return `${(amount / 1e9).toFixed(2)} GB`;
  if (amount >= 1e6) return `${(amount / 1e6).toFixed(1)} MB`;
  if (amount >= 1e3) return `${(amount / 1e3).toFixed(0)} KB`;
  return `${amount} B`;
}

function formatExpiry(account) {
  if (account.expired) return '已过期';
  if (!account.expires_at) return '—';
  const date = new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(account.expires_at));
  return account.days_remaining != null ? `${date} · ${account.days_remaining}天` : date;
}

function selectedAccountEmails() {
  return Array.from(document.querySelectorAll('#accountsBody .account-select:checked')).map(item => item.value);
}

function updateDeleteSelectedState() {
  const button = document.getElementById('deleteSelectedAccounts');
  const selected = selectedAccountEmails();
  button.disabled = selected.length === 0;
  button.textContent = selected.length ? `删除所选 (${selected.length})` : '删除所选';
}

async function loadAccounts() {
  try {
    const data = await api('/api/accounts');
    if (Array.isArray(data.pruned_expired) && data.pruned_expired.length) {
      toast(`已自动删除 ${data.pruned_expired.length} 个过期账号`);
    }
    const body = document.getElementById('accountsBody');
    body.innerHTML = data.accounts.length ? data.accounts.map(account => `
      <tr class="clickable" data-email="${escapeHtml(account.email)}">
        <td class="check-col"><input type="checkbox" class="account-select" value="${escapeHtml(account.email)}"></td>
        <td title="${escapeHtml(account.email)}">${escapeHtml(account.email)}</td>
        <td>${account.verified ? statusChip('success') : statusChip('failed')}</td>
        <td class="${account.expired ? 'is-expired' : ''}">${escapeHtml(formatExpiry(account))}</td>
        <td title="${escapeHtml(formatBytes(account.bandwidth_used))} / ${escapeHtml(formatBytes(account.bandwidth_total))}">${escapeHtml(formatBytes(account.bandwidth_remaining))}</td>
        <td>${account.proxy_count}</td>
        <td>${account.has_api_key ? '<span class="status-chip success">已保存</span>' : '<span class="status-chip queued">未创建</span>'}</td>
        <td class="row-actions">
          <button type="button" class="text-button account-edit" data-email="${escapeHtml(account.email)}">查看</button>
          <button type="button" class="text-button danger-text account-delete" data-email="${escapeHtml(account.email)}">删除</button>
        </td>
      </tr>`).join('') : '<tr><td colspan="8" class="empty-cell">暂无账号</td></tr>';
    document.getElementById('accountSelectAll').checked = false;
    updateDeleteSelectedState();
    body.querySelectorAll('tr[data-email]').forEach(row => {
      row.addEventListener('click', event => {
        if (event.target.closest('button, input')) return;
        openAccount(row.dataset.email);
      });
    });
    body.querySelectorAll('.account-edit').forEach(button => {
      button.addEventListener('click', event => {
        event.stopPropagation();
        openAccount(button.dataset.email);
      });
    });
    body.querySelectorAll('.account-delete').forEach(button => {
      button.addEventListener('click', event => {
        event.stopPropagation();
        deleteAccounts([button.dataset.email]);
      });
    });
    body.querySelectorAll('.account-select').forEach(box => {
      box.addEventListener('click', event => event.stopPropagation());
      box.addEventListener('change', updateDeleteSelectedState);
    });
  } catch (error) { toast(error.message, true); }
}

function setField(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  if (element.type === 'checkbox') element.checked = Boolean(value);
  else element.value = value ?? '';
}

function renderPermissions(catalog, selected) {
  const selectedSet = new Set(selected || []);
  const root = document.getElementById('accountPermissions');
  const structure = catalog?.structure || {};
  const groups = [];
  ['account', 'product'].forEach(kind => {
    (structure[kind]?.sub_types || []).forEach(group => groups.push(group));
  });
  if (!groups.length) {
    root.innerHTML = '<p class="empty-cell">没有权限目录</p>';
    return;
  }
  root.innerHTML = groups.map(group => `
    <article class="perm-group">
      <h4>${escapeHtml(group.name || '')}</h4>
      <p>${escapeHtml(group.description || '')}</p>
      ${(group.permissions || []).map(permission => `
        <label class="check-row">
          <input type="checkbox" name="acc_permission" value="${escapeHtml(permission.id)}" ${selectedSet.has(permission.id) ? 'checked' : ''}>
          <span>${escapeHtml(permission.name)} · ${escapeHtml(permission.id)}</span>
        </label>`).join('')}
    </article>`).join('');
}

function fillAccount(account) {
  state.account = account;
  document.getElementById('accountDialogEmail').textContent = account.email || '';
  document.getElementById('accountDialogStats').innerHTML = `
    <div><span>验证</span><strong>${account.verified ? '已验证' : '未验证'}</strong></div>
    <div><span>到期</span><strong class="${account.expired ? 'is-expired' : ''}">${escapeHtml(formatExpiry(account))}</strong></div>
    <div><span>剩余流量</span><strong>${escapeHtml(formatBytes(account.bandwidth_remaining))}</strong></div>
    <div><span>已用 / 总量</span><strong>${escapeHtml(formatBytes(account.bandwidth_used))} / ${escapeHtml(formatBytes(account.bandwidth_total))}</strong></div>`;
  setField('acc_email', account.email);
  setField('acc_password', account.password);
  setField('acc_account_id', account.account_id);
  setField('acc_notes', account.notes);
  setField('acc_access_token', account.access_token);
  setField('acc_proxy_username', account.proxy_username);
  setField('acc_proxy_password', account.proxy_password);
  setField('acc_proxy_url_template', account.api?.proxy_url_template || '');
  setField('acc_account_key', account.account_key);
  setField('acc_api_key_name', account.api_key_name);
  setField('acc_api_key_id', account.api_key_id);
  setField('acc_api_token', account.api_token);
  setField('acc_public_proxy_list', account.api?.public_proxy_list || '');
  setField('acc_curl_public', account.api?.curl_public_proxy_list || '');
  setField('acc_dashboard_overview', account.api?.dashboard_overview || '');
  const selected = (account.permissions && account.permissions.length)
    ? account.permissions
    : (account.permission_catalog?.allowed_permissions || []);
  renderPermissions(account.permission_catalog, selected);
}

function collectAccountPayload() {
  const permissions = Array.from(document.querySelectorAll('input[name="acc_permission"]:checked')).map(item => item.value);
  const subaccount = document.getElementById('acc_account_id').value.trim();
  return {
    password: document.getElementById('acc_password').value,
    access_token: document.getElementById('acc_access_token').value,
    account_id: subaccount,
    notes: document.getElementById('acc_notes').value,
    proxy_username: document.getElementById('acc_proxy_username').value,
    proxy_password: document.getElementById('acc_proxy_password').value,
    account_key: document.getElementById('acc_account_key').value,
    api_key_name: document.getElementById('acc_api_key_name').value,
    api_key_id: document.getElementById('acc_api_key_id').value,
    api_token: document.getElementById('acc_api_token').value,
    permissions,
    allowed_subaccounts: subaccount ? [subaccount] : [],
  };
}

async function openAccount(email) {
  try {
    const { account } = await api(`/api/accounts/${encodeURIComponent(email)}`);
    fillAccount(account);
    document.getElementById('accountDialog').showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadExports() {
  try {
    const data = await api('/api/exports');
    state.exports = data;
    const list = document.getElementById('proxyFiles');
    list.innerHTML = data.proxies.length ? data.proxies.map(file => `
      <div class="file-row"><span class="file-name">${escapeHtml(file.name)}</span>
      <span class="file-meta">${file.count} 条</span><span class="file-meta">${formatDate(file.modified_at)}</span>
      <a class="download-link" href="${appUrl('/download/proxies/' + encodeURIComponent(file.name))}">下载</a></div>`).join('') : '<div class="empty-cell">暂无代理文件</div>';
    const latest = data.accounts[0];
    const button = document.getElementById('downloadLatestAccounts');
    button.disabled = !latest;
    button.onclick = () => { if (latest) window.location.href = appUrl(`/download/accounts/${encodeURIComponent(latest.name)}`); };
  } catch (error) { toast(error.message, true); }
}

async function loadTasks() {
  try {
    const data = await api('/api/tasks');
    renderTasks(data.tasks, 'allTasksBody', false);
  } catch (error) { toast(error.message, true); }
}

async function openTask(taskId) {
  try {
    const { task } = await api(`/api/tasks/${encodeURIComponent(taskId)}`);
    document.getElementById('dialogTaskId').textContent = task.id;
    document.getElementById('dialogStats').innerHTML = `
      <div><span>进度</span><strong>${task.completed}/${task.requested}</strong></div>
      <div><span>成功</span><strong>${task.successes}</strong></div>
      <div><span>代理</span><strong>${task.proxy_count}</strong></div>
      <div><span>状态</span><strong>${escapeHtml(statusLabel(task.status))}</strong></div>`;
    document.getElementById('dialogLogs').innerHTML = (task.logs || []).map(log => `<div class="log-entry">${escapeHtml(log)}</div>`).join('');
    document.getElementById('taskDialog').showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

function fillSettings(settings) {
  state.settings = settings;
  Object.entries(settings || {}).forEach(([key, value]) => {
    const element = document.getElementById(key);
    if (!element) return;
    if (element.type === 'checkbox') element.checked = Boolean(value);
    else element.value = value ?? '';
  });
  const exportSelect = document.getElementById('export_quality_profile_exports');
  if (exportSelect && settings?.export_quality_profile) {
    exportSelect.value = settings.export_quality_profile;
  }
  renderQualityMeta(settings);
}

async function loadSettings(group) {
  try {
    const path = group ? `/api/settings?group=${encodeURIComponent(group)}` : '/api/settings';
    const data = await api(path);
    fillSettings(data.settings || data.group || data);
    if (data.quality_profiles) fillProfileSelects(data.quality_profiles);
    if (data.pull_api) renderPullStatus(data.pull_api);
    else if (state.dashboard?.pull_api) renderPullStatus(state.dashboard.pull_api);
  } catch (error) {
    toast(error.message, true);
  }
}

function collectSettings(keys) {
  const payload = {};
  keys.forEach(key => {
    const element = document.getElementById(key);
    if (!element) return;
    if (element.type === 'checkbox') payload[key] = element.checked;
    else if (element.type === 'number') payload[key] = Number(element.value);
    else payload[key] = element.value;
  });
  return payload;
}

async function saveSettingsGroup(event, group, keys, successText) {
  event.preventDefault();
  const button = event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const body = { group, ...collectSettings(keys) };
    if (group === 'exports') {
      const el = document.getElementById('export_quality_profile_exports');
      if (el) body.export_quality_profile = el.value;
    }
    const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(body) });
    fillSettings(data.settings);
    if (data.quality_profiles) fillProfileSelects(data.quality_profiles);
    if (data.pull_api) renderPullStatus(data.pull_api);
    toast(successText);
    refreshDashboard();
    if (group === 'quality') loadQualityAudit();
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => showView(item.dataset.view)));
document.querySelectorAll('[data-go]').forEach(item => item.addEventListener('click', () => {
  showView(item.dataset.go, { tab: item.dataset.tab });
}));
document.querySelectorAll('[data-account-tab]').forEach(item => {
  item.addEventListener('click', () => showAccountTab(item.dataset.accountTab));
});
document.querySelectorAll('[data-settings-tab]').forEach(item => {
  item.addEventListener('click', () => showSettingsTab(item.dataset.settingsTab));
});

document.querySelectorAll('.segment-button').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.segment-button').forEach(item => item.classList.toggle('active', item === button));
  const single = button.dataset.mode === 'single';
  const count = document.getElementById('countInput');
  const concurrency = document.getElementById('concurrencyInput');
  count.disabled = single; count.value = single ? 1 : Math.max(2, Number(count.value));
  concurrency.value = single ? 1 : Math.min(Number(count.value), Math.max(1, Number(concurrency.value)));
}));
document.getElementById('countInput').disabled = true;
document.getElementById('countInput').addEventListener('input', event => {
  const concurrency = document.getElementById('concurrencyInput');
  concurrency.max = Math.min(8, Number(event.target.value) || 1);
  if (Number(concurrency.value) > Number(concurrency.max)) concurrency.value = concurrency.max;
});
document.getElementById('taskForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = document.getElementById('startButton');
  button.disabled = true;
  try {
    const payload = {
      count: Number(document.getElementById('countInput').value),
      concurrency: Number(document.getElementById('concurrencyInput').value),
    };
    const data = await api('/api/tasks', { method: 'POST', body: JSON.stringify(payload) });
    toast(`任务 ${data.task.id} 已启动`);
    await refreshDashboard();
    showAccountTab('tasks');
  } catch (error) {
    toast(error.message, true);
    button.disabled = false;
  }
});
document.getElementById('logoutButton').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  window.location.href = appUrl('/login');
});
document.getElementById('closeDialog').addEventListener('click', () => document.getElementById('taskDialog').close());
document.getElementById('closeAccountDialog').addEventListener('click', () => document.getElementById('accountDialog').close());
document.getElementById('permSelectAll').addEventListener('click', () => {
  document.querySelectorAll('input[name="acc_permission"]').forEach(item => { item.checked = true; });
});
document.getElementById('permSelectNone').addEventListener('click', () => {
  document.querySelectorAll('input[name="acc_permission"]').forEach(item => { item.checked = false; });
});
document.getElementById('accountForm').addEventListener('submit', async event => {
  event.preventDefault();
  const email = document.getElementById('acc_email').value;
  const button = event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const data = await api(`/api/accounts/${encodeURIComponent(email)}`, {
      method: 'PUT',
      body: JSON.stringify(collectAccountPayload()),
    });
    fillAccount(data.account);
    toast('账号已保存到后台');
    loadAccounts();
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
});
document.getElementById('refreshAccountButton').addEventListener('click', async () => {
  const email = document.getElementById('acc_email').value;
  const button = document.getElementById('refreshAccountButton');
  button.disabled = true;
  try {
    const data = await api(`/api/accounts/${encodeURIComponent(email)}/refresh`, { method: 'POST', body: '{}' });
    fillAccount(data.account);
    toast('已同步到期时间和剩余流量');
    loadAccounts();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});

async function deleteAccounts(emails) {
  const list = emails.filter(Boolean);
  if (!list.length) return;
  const preview = list.length === 1 ? list[0] : `${list.length} 个账号`;
  if (!window.confirm(`确定删除 ${preview}？删除后可再导入恢复。`)) return;
  try {
    const data = await api('/api/accounts/delete', {
      method: 'POST',
      body: JSON.stringify({ emails: list }),
    });
    const dialog = document.getElementById('accountDialog');
    if (dialog.open) dialog.close();
    toast(`已删除 ${data.deleted.length} 个账号`);
    await loadAccounts();
  } catch (error) {
    toast(error.message, true);
  }
}

async function syncUsage(emails) {
  const button = document.getElementById('syncUsageButton');
  button.disabled = true;
  try {
    const payload = emails && emails.length ? { emails } : {};
    const data = await api('/api/accounts/sync-usage', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const failText = data.failed.length ? `，失败 ${data.failed.length}` : '';
    toast(`已同步 ${data.synced.length} 个账号的到期时间和剩余流量${failText}`, Boolean(data.failed.length));
    if (Array.isArray(data.pruned_expired) && data.pruned_expired.length) {
      toast(`已自动删除 ${data.pruned_expired.length} 个过期账号`);
    }
    await loadAccounts();
    const openEmail = document.getElementById('acc_email').value;
    if (openEmail && document.getElementById('accountDialog').open) {
      const { account } = await api(`/api/accounts/${encodeURIComponent(openEmail)}`);
      fillAccount(account);
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

document.getElementById('syncApiKeyButton').addEventListener('click', async () => {
  const email = document.getElementById('acc_email').value;
  const button = document.getElementById('syncApiKeyButton');
  button.disabled = true;
  try {
    const data = await api(`/api/accounts/${encodeURIComponent(email)}/api-key`, {
      method: 'POST',
      body: JSON.stringify(collectAccountPayload()),
    });
    fillAccount(data.account);
    toast('API 密钥已同步到 ProxyScrape');
    loadAccounts();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});
document.getElementById('deleteAccountButton').addEventListener('click', () => {
  deleteAccounts([document.getElementById('acc_email').value]);
});
document.getElementById('deleteSelectedAccounts').addEventListener('click', () => {
  deleteAccounts(selectedAccountEmails());
});
document.getElementById('accountSelectAll').addEventListener('change', event => {
  document.querySelectorAll('#accountsBody .account-select').forEach(item => {
    item.checked = event.target.checked;
  });
  updateDeleteSelectedState();
});
document.getElementById('syncUsageButton').addEventListener('click', () => {
  syncUsage(selectedAccountEmails());
});
document.getElementById('importAccountsButton').addEventListener('click', () => {
  document.getElementById('importText').value = '';
  document.getElementById('importFile').value = '';
  document.getElementById('importDialog').showModal();
});
document.getElementById('closeImportDialog').addEventListener('click', () => document.getElementById('importDialog').close());
document.getElementById('importFile').addEventListener('change', async event => {
  const file = event.target.files?.[0];
  if (!file) return;
  document.getElementById('importText').value = await file.text();
});
document.getElementById('importForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const data = await api('/api/accounts/import', {
      method: 'POST',
      body: JSON.stringify({ text: document.getElementById('importText').value }),
    });
    document.getElementById('importDialog').close();
    const restored = data.restored ? data.restored.length : 0;
    toast(`已导入 ${data.imported} 个账号${restored ? `，恢复 ${restored} 个` : ''}`);
    await loadAccounts();
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
});
document.getElementById('menuButton').addEventListener('click', () => {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebarScrim').classList.add('show');
});
document.getElementById('sidebarScrim').addEventListener('click', () => {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarScrim').classList.remove('show');
});

document.getElementById('sourcesSettingsForm').addEventListener('submit', event => {
  saveSettingsGroup(event, 'sources', settingFields.sources, '代理源已保存');
});
document.getElementById('qualitySettingsForm').addEventListener('submit', event => {
  saveSettingsGroup(event, 'quality', settingFields.quality, '质检规则已保存');
});
document.getElementById('registrationSettingsForm').addEventListener('submit', event => {
  saveSettingsGroup(event, 'registration', settingFields.registration, '注册出网已保存');
});
document.getElementById('mailSettingsForm').addEventListener('submit', event => {
  saveSettingsGroup(event, 'registration', settingFields.mail, '邮箱设置已同步');
});
document.getElementById('captchaSettingsForm').addEventListener('submit', event => {
  saveSettingsGroup(event, 'registration', settingFields.captcha, '打码设置已同步');
});
document.getElementById('exportsSettingsForm')?.addEventListener('submit', event => {
  saveSettingsGroup(event, 'exports', settingFields.exports, '出口绑定已保存');
});
document.getElementById('activateProfileButton')?.addEventListener('click', async () => {
  const id = document.getElementById('quality_profile_id')?.value;
  if (!id) return;
  try {
    const data = await api('/api/quality/profiles/activate', {
      method: 'POST',
      body: JSON.stringify({ id }),
    });
    fillSettings(data.settings);
    if (data.quality_profiles) fillProfileSelects(data.quality_profiles);
    toast(`已切换到 profile ${id}`);
    loadQualityAudit();
    refreshDashboard();
  } catch (error) {
    toast(error.message, true);
  }
});
document.getElementById('quality_profile_id')?.addEventListener('change', async event => {
  const id = event.target.value;
  try {
    const data = await api('/api/quality/profiles');
    fillProfileSelects(data);
    const row = (data.profiles || []).find(item => item.id === id);
    if (row) {
      settingFields.quality.forEach(key => {
        if (key === 'quality_profile_id' || key === 'export_quality_profile') return;
        if (row[key] != null) setField(key, row[key]);
      });
      document.getElementById('quality_profile_id').value = id;
    }
  } catch (error) {
    toast(error.message, true);
  }
});

document.getElementById('qualityDryRunForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const data = await api('/api/quality/dry-run', {
      method: 'POST',
      body: JSON.stringify({
        text: document.getElementById('dryRunProxies').value,
        limit: 50,
        rule: document.getElementById('quality_profile_id')?.value,
      }),
    });
    const body = document.getElementById('dryRunBody');
    const rows = data.report?.results || [];
    body.innerHTML = rows.length ? rows.map(row => `
      <tr>
        <td title="${escapeHtml(row.proxy)}">${escapeHtml(row.proxy || '')}</td>
        <td>${row.ok ? statusChip('success') : statusChip('failed')}</td>
        <td>${row.latency_ms ?? '—'}</td>
        <td>${escapeHtml(row.country_code || row.country || '—')}</td>
        <td title="${escapeHtml(row.reason || '')}">${escapeHtml(row.reason || '')}</td>
      </tr>`).join('') : '<tr><td colspan="5" class="empty-cell">无结果</td></tr>';
    toast(`试跑完成（${data.rule_id || 'default'}）：合格 ${data.report?.accepted ?? 0} / 扫描 ${data.report?.scanned ?? 0}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
});

document.getElementById('ensureCapacityButton').addEventListener('click', async () => {
  const button = document.getElementById('ensureCapacityButton');
  button.disabled = true;
  try {
    const data = await api('/api/pool/ensure-capacity', { method: 'POST', body: JSON.stringify({ auto_register: true }) });
    renderPool(data.pool);
    if (data.task?.id) toast(`已启动补号任务 ${data.task.id}`);
    else if ((data.pool?.shortage_slots || 0) <= 0) toast('槽位已够，不用补号');
    else toast(data.pool?.active_task ? '已有注册任务在跑' : '未启动新任务');
    refreshDashboard();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', () => copyField(button.dataset.copy).catch(error => toast(error.message, true)));
});
document.getElementById('downloadClashButton')?.addEventListener('click', () => {
  window.location.href = appUrl('/api/export/clash.yml');
});

refreshDashboard();
loadExports();
loadSettings();
setInterval(() => {
  refreshDashboard();
  if (state.currentView === 'accounts' && state.accountTab === 'tasks') loadTasks();
}, 4000);
