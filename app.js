const CONFIG = {
    COOLDOWN_SECONDS: 60,
    REQUEST_TIMEOUT: 5000,
    TRUSTED_BRANDS: [
        'google', 'sberbank', 'tinkoff', 'yandex', 'vk', 'gosuslugi',
        'apple', 'microsoft', 'amazon', 'facebook', 'instagram', 'telegram',
        'whatsapp', 'paypal', 'netflix', 'spotify', 'twitter', 'linkedin',
        'github', 'gitlab', 'mail', 'ozon', 'wildberries', 'avito'
    ],
    PROBE_PATHS: [
        { path: '/admin/', name: 'Панель /admin/', type: 'admin' },
        { path: '/wp-admin/', name: 'WordPress Admin', type: 'admin' },
        { path: '/administrator/', name: 'Joomla Admin', type: 'admin' },
        { path: '/.git/', name: 'GIT репозиторий', type: 'git', critical: true },
        { path: '/.git/config', name: 'GIT config', type: 'git', critical: true },
        { path: '/.env', name: 'Файл .env', type: 'env', critical: true },
        { path: '/config.php', name: 'Config PHP', type: 'env', critical: true },
        { path: '/.htaccess', name: '.htaccess', type: 'config' }
    ],
    XSS_PATTERNS: [
        /onerror\s*=/gi,
        /onclick\s*=/gi,
        /onload\s*=/gi,
        /onmouseover\s*=/gi,
        /onfocus\s*=/gi,
        /onsubmit\s*=/gi,
        /javascript\s*:/gi,
        /<script[^>]*>[^<]*<\/script>/gi,
        /eval\s*\(/gi,
        /document\.write\s*\(/gi
    ]
};

async function fetchWithTimeout(url, options = {}, timeout = CONFIG.REQUEST_TIMEOUT) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        throw error;
    }
}

async function safeFetchJSON(url, timeout = CONFIG.REQUEST_TIMEOUT) {
    try {
        const response = await fetchWithTimeout(url, {}, timeout);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`Fetch error for ${url}:`, error.message);
        return null;
    }
}

function levenshteinDistance(str1, str2) {
    const m = str1.length;
    const n = str2.length;
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }
    return dp[m][n];
}

function checkPhishing(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '').split('.')[0];
    const results = [];
    
    for (const brand of CONFIG.TRUSTED_BRANDS) {
        if (cleanDomain === brand) continue;
        
        const distance = levenshteinDistance(cleanDomain, brand);
        if (distance > 0 && distance <= 2) {
            results.push({
                brand,
                distance,
                severity: distance === 1 ? 'critical' : 'warning'
            });
        }
    }
    
    return results;
}

function checkHomograph(domain) {
    const issues = [];

    if (domain.includes('xn--')) {
        issues.push({
            type: 'punycode',
            message: 'Punycode (xn--) — возможна IDN-атака'
        });
    }

    const hasCyrillic = /[а-яё]/i.test(domain);
    const hasLatin = /[a-z]/i.test(domain);
    
    if (hasCyrillic && hasLatin) {
        issues.push({
            type: 'mixed_scripts',
            message: 'Смешение кириллицы и латиницы'
        });
    }

    const homoglyphs = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 
        'у': 'y', 'х': 'x', 'А': 'A', 'В': 'B', 'Е': 'E'
    };
    
    for (const [cyrillic, latin] of Object.entries(homoglyphs)) {
        if (domain.includes(cyrillic)) {
            issues.push({
                type: 'homoglyph',
                message: `Омоглиф: "${cyrillic}" похож на "${latin}"`
            });
            break;
        }
    }
    
    return issues;
}

function validateInput(input) {
    const trimmed = input.trim();

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(trimmed)) {
        const parts = trimmed.split('.').map(Number);
        const validIP = parts.every(p => p >= 0 && p <= 255);
        if (validIP) {
            return { type: 'ip', value: trimmed, valid: true };
        }
    }
    
    // URL
    try {
        let urlString = trimmed;
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'https://' + urlString;
        }
        const url = new URL(urlString);
        return { 
            type: 'url', 
            value: urlString, 
            domain: url.hostname,
            origin: url.origin,
            valid: true 
        };
    } catch {
        return { type: 'unknown', value: trimmed, valid: false };
    }
}

function detectTechnologies(html) {
    const techs = [];
    const htmlLower = html.toLowerCase();
    
    if (htmlLower.includes('wp-content') || htmlLower.includes('wp-includes') || htmlLower.includes('wordpress')) {
        techs.push({ name: 'WordPress', icon: 'box' });
    }
    
    if (htmlLower.includes('tilda') || htmlLower.includes('t-records') || htmlLower.includes('tildacdn')) {
        techs.push({ name: 'Tilda', icon: 'layout' });
    }
    
    if (htmlLower.includes('bitrix') || htmlLower.includes('bx.')) {
        techs.push({ name: '1C-Битрикс', icon: 'box' });
    }
    
    if (htmlLower.includes('__next_data__') || htmlLower.includes('_next/')) {
        techs.push({ name: 'Next.js', icon: 'triangle' });
    }
    
    if (htmlLower.includes('react') || htmlLower.includes('reactdom')) {
        techs.push({ name: 'React', icon: 'atom' });
    }
    
    if (htmlLower.includes('vue') || htmlLower.includes('nuxt')) {
        techs.push({ name: 'Vue.js', icon: 'hexagon' });
    }
    
    if (htmlLower.includes('jquery')) {
        techs.push({ name: 'jQuery', icon: 'code' });
    }
    
    if (htmlLower.includes('bootstrap')) {
        techs.push({ name: 'Bootstrap', icon: 'layout' });
    }
    
    if (htmlLower.includes('cloudflare') || htmlLower.includes('cf-browser')) {
        techs.push({ name: 'Cloudflare', icon: 'cloud' });
    }
    
    if (htmlLower.includes('google-analytics') || htmlLower.includes('gtag') || htmlLower.includes('ga.js')) {
        techs.push({ name: 'Google Analytics', icon: 'bar-chart' });
    }
    
    if (htmlLower.includes('mc.yandex.ru') || htmlLower.includes('metrika')) {
        techs.push({ name: 'Яндекс.Метрика', icon: 'bar-chart-2' });
    }
    
    return techs;
}

function analyzeXSS(html, headers = {}) {
    const results = {
        hasCSP: false,
        cspValue: null,
        inlineScripts: 0,
        dangerousPatterns: [],
        riskLevel: 'low'
    };

    const cspHeader = headers['content-security-policy'] || 
                      headers['Content-Security-Policy'] ||
                      headers['x-content-security-policy'];
    
    if (cspHeader) {
        results.hasCSP = true;
        results.cspValue = cspHeader.substring(0, 100) + (cspHeader.length > 100 ? '...' : '');
    }

    const cspMetaMatch = html.match(/<meta[^>]*http-equiv=["']?Content-Security-Policy["']?[^>]*content=["']([^"']+)["']/i);
    if (cspMetaMatch) {
        results.hasCSP = true;
        results.cspValue = cspMetaMatch[1].substring(0, 100);
    }

    const inlineScriptMatches = html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
    results.inlineScripts = inlineScriptMatches.filter(s => !s.includes('src=')).length;

    for (const pattern of CONFIG.XSS_PATTERNS) {
        const matches = html.match(pattern);
        if (matches && matches.length > 0) {
            results.dangerousPatterns.push({
                pattern: pattern.source,
                count: matches.length
            });
        }
    }

    if (results.dangerousPatterns.length > 3 && !results.hasCSP) {
        results.riskLevel = 'high';
    } else if (results.dangerousPatterns.length > 0 || !results.hasCSP) {
        results.riskLevel = 'medium';
    }
    
    return results;
}

async function probePath(baseUrl, pathInfo) {
    try {
        const fullUrl = baseUrl.replace(/\/$/, '') + pathInfo.path;
        const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(fullUrl)}`;
        
        const response = await fetchWithTimeout(proxyUrl, {}, 3000);
        const data = await response.json();

        const httpCode = data.status?.http_code;
        const content = data.contents || '';

        if (httpCode === 200 && content.length > 50) {
            if (pathInfo.type === 'git' && (content.includes('[core]') || content.includes('repositoryformatversion'))) {
                return { found: true, critical: true, path: pathInfo.path, name: pathInfo.name };
            }

            if (pathInfo.type === 'env' && (content.includes('=') || content.includes('DB_') || content.includes('API_KEY'))) {
                return { found: true, critical: true, path: pathInfo.path, name: pathInfo.name };
            }

            if (pathInfo.type === 'admin' && (content.includes('login') || content.includes('password') || content.includes('admin'))) {
                return { found: true, critical: false, path: pathInfo.path, name: pathInfo.name };
            }
            
            return { found: false, path: pathInfo.path };
        }
        
        return { found: false, path: pathInfo.path };
    } catch {
        return { found: false, path: pathInfo.path, error: true };
    }
}

async function getUserIP() {
    const data = await safeFetchJSON('https://api.ipify.org?format=json');
    return data?.ip || null;
}

async function dnsQuery(domain, type = 'A') {
    let data = await safeFetchJSON(`https://dns.google/resolve?name=${domain}&type=${type}`);

    if (!data) {
        try {
            const response = await fetchWithTimeout(
                `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`,
                { headers: { 'Accept': 'application/dns-json' } }
            );
            data = await response.json();
        } catch {
            data = null;
        }
    }
    
    return data;
}

async function getIPFromDomain(domain) {
    const data = await dnsQuery(domain, 'A');
    if (data?.Answer && data.Answer.length > 0) {
        return data.Answer[0].data;
    }
    return null;
}

async function getIPInfo(ip) {
    const data = await safeFetchJSON(`https://ipinfo.io/${ip}/geo`);
    return data;
}

async function fetchPageContent(url) {
    try {
        const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
        const response = await fetchWithTimeout(proxyUrl, {}, CONFIG.REQUEST_TIMEOUT);
        const data = await response.json();
        return {
            content: data.contents || '',
            status: data.status?.http_code || null,
            headers: data.status?.headers || {}
        };
    } catch {
        return { content: '', status: null, headers: {} };
    }
}

function getCooldownRemaining() {
    const lastScan = localStorage.getItem('sic_last_scan');
    if (!lastScan) return 0;
    
    const elapsed = (Date.now() - parseInt(lastScan)) / 1000;
    const remaining = CONFIG.COOLDOWN_SECONDS - elapsed;
    return Math.max(0, Math.ceil(remaining));
}

function setCooldown() {
    localStorage.setItem('sic_last_scan', Date.now().toString());
}

let consoleElement = null;
let statusBadge = null;
let scanBtn = null;
let scanBtnText = null;

function initScannerUI() {
    consoleElement = document.getElementById('console-body');
    statusBadge = document.getElementById('status-badge');
    scanBtn = document.getElementById('scan-btn');
    scanBtnText = document.getElementById('scan-btn-text');
}

function log(message, type = 'info') {
    if (!consoleElement) return;
    
    const timestamp = new Date().toLocaleTimeString('ru-RU');
    const colors = {
        info: 'status-info',
        success: 'status-safe',
        warning: 'status-warning',
        error: 'status-danger',
        system: 'status-muted'
    };
    
    const entry = document.createElement('div');
    entry.className = `console-entry ${colors[type]}`;
    entry.innerHTML = `<span class="console-time">[${timestamp}]</span> <span>${message}</span>`;
    consoleElement.appendChild(entry);
    consoleElement.scrollTop = consoleElement.scrollHeight;
}

function clearConsole() {
    if (consoleElement) {
        consoleElement.innerHTML = '<div class="status-muted">// Введите URL для начала анализа</div>';
    }
}

function setStatus(text, type = 'idle') {
    if (!statusBadge) return;
    
    statusBadge.textContent = text;
    statusBadge.className = `status-badge status-badge-${type}`;
}

function updateCooldownUI() {
    if (!scanBtn || !scanBtnText) return;
    
    const remaining = getCooldownRemaining();
    
    if (remaining > 0) {
        scanBtn.disabled = true;
        scanBtnText.textContent = `${remaining}с`;
        setTimeout(updateCooldownUI, 1000);
    } else {
        scanBtn.disabled = false;
        scanBtnText.textContent = 'Проверить';
    }
}

function updateVerdict(score, title, subtitle, type) {
    const verdictCard = document.getElementById('verdict-card');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictSubtitle = document.getElementById('verdict-subtitle');
    const verdictScoreValue = document.getElementById('verdict-score-value');
    
    if (!verdictCard) return;
    
    const configs = {
        safe: { bg: 'rgba(34, 197, 94, 0.2)', icon: 'shield-check', color: 'var(--accent-green)' },
        warning: { bg: 'rgba(234, 179, 8, 0.2)', icon: 'shield-alert', color: 'var(--accent-yellow)' },
        danger: { bg: 'rgba(239, 68, 68, 0.2)', icon: 'shield-x', color: 'var(--accent-red)' }
    };
    
    const config = configs[type] || configs.safe;
    
    verdictIcon.style.background = config.bg;
    verdictIcon.innerHTML = `<i data-lucide="${config.icon}" style="color: ${config.color}"></i>`;
    verdictTitle.textContent = title;
    verdictTitle.style.color = config.color;
    verdictSubtitle.textContent = subtitle;
    verdictScoreValue.textContent = score;
    verdictScoreValue.style.color = config.color;
    
    lucide.createIcons();
}

function updateVulnUI(vulnResults) {
    const cspEl = document.getElementById('vuln-csp');
    const adminEl = document.getElementById('vuln-admin');
    const gitEl = document.getElementById('vuln-git');
    const envEl = document.getElementById('vuln-env');
    
    if (cspEl) {
        if (vulnResults.csp.enabled) {
            cspEl.textContent = 'Защищён';
            cspEl.className = 'vuln-value status-safe';
        } else {
            cspEl.textContent = 'Отсутствует';
            cspEl.className = 'vuln-value status-warning';
        }
    }
    
    if (adminEl) {
        if (vulnResults.admin.found) {
            adminEl.textContent = 'Найдена';
            adminEl.className = 'vuln-value status-warning';
        } else {
            adminEl.textContent = 'Скрыта';
            adminEl.className = 'vuln-value status-safe';
        }
    }
    
    if (gitEl) {
        if (vulnResults.git.found) {
            gitEl.textContent = 'УТЕЧКА';
            gitEl.className = 'vuln-value status-danger';
        } else {
            gitEl.textContent = 'Безопасно';
            gitEl.className = 'vuln-value status-safe';
        }
    }
    
    if (envEl) {
        if (vulnResults.env.found) {
            envEl.textContent = 'УТЕЧКА';
            envEl.className = 'vuln-value status-danger';
        } else {
            envEl.textContent = 'Безопасно';
            envEl.className = 'vuln-value status-safe';
        }
    }
}

async function performScan() {
    const urlInput = document.getElementById('url-input');
    const input = urlInput?.value || '';
    const validation = validateInput(input);
    
    if (!validation.valid) {
        log('Некорректный ввод. Введите URL или IP-адрес.', 'error');
        return;
    }
    
    if (getCooldownRemaining() > 0) {
        log('Подождите завершения кулдауна', 'warning');
        return;
    }

    setCooldown();
    updateCooldownUI();

    let riskScore = 0;
    let criticalVuln = false;
    clearConsole();

    const vulnResults = {
        csp: { enabled: false },
        admin: { found: false, path: null },
        git: { found: false },
        env: { found: false }
    };
    
    const dashboard = document.getElementById('results-dashboard');
    if (dashboard) dashboard.classList.remove('hidden');
    
    setStatus('Сканирование...', 'scanning');
    log(`Начало анализа: ${validation.value}`, 'system');
    log(`Тип: ${validation.type === 'url' ? 'URL' : 'IP-адрес'}`, 'info');
    
    const domain = validation.type === 'url' ? validation.domain : null;
    const baseUrl = validation.type === 'url' ? validation.origin : null;
    let targetIP = validation.type === 'ip' ? validation.value : null;

    const securityResults = document.getElementById('security-results');
    let securityHTML = '';
    
    if (domain) {
        // Омографы
        log('Проверка на омографы...', 'system');
        const homographIssues = checkHomograph(domain);
        
        if (homographIssues.length > 0) {
            homographIssues.forEach(issue => {
                log(`⚠️ ${issue.message}`, 'warning');
                riskScore += 30;
            });
            securityHTML += `<div class="status-danger" style="display: flex; align-items: center; gap: 0.5rem;">
                <i data-lucide="alert-triangle" style="width: 1rem; height: 1rem;"></i> 
                Омографическая атака
            </div>`;
        } else {
            log('Омографы не обнаружены', 'success');
        }

        log('Эвристический анализ (Левенштейн)...', 'system');
        const phishingResults = checkPhishing(domain);
        
        if (phishingResults.length > 0) {
            phishingResults.forEach(result => {
                if (result.severity === 'critical') {
                    log(`ФИШИНГ: похож на "${result.brand}" (расст.: ${result.distance})`, 'error');
                    riskScore += 50;
                } else {
                    log(`Подозрительно: похож на "${result.brand}"`, 'warning');
                    riskScore += 25;
                }
            });
            securityHTML += `<div class="status-danger" style="display: flex; align-items: center; gap: 0.5rem;">
                <i data-lucide="skull" style="width: 1rem; height: 1rem;"></i> 
                Подозрение на фишинг (${phishingResults[0].brand})
            </div>`;
        } else {
            log('✓ Фишинговые паттерны не найдены', 'success');
        }
        
        if (homographIssues.length === 0 && phishingResults.length === 0) {
            securityHTML = `<div class="status-safe" style="display: flex; align-items: center; gap: 0.5rem;">
                <i data-lucide="check-circle" style="width: 1rem; height: 1rem;"></i> 
                Эвристические проверки пройдены
            </div>`;
        }
    } else {
        securityHTML = '<div class="status-muted">Проверка недоступна для IP</div>';
    }
    
    if (securityResults) {
        securityResults.innerHTML = securityHTML;
        lucide.createIcons();
    }

    const dnsResultsEl = document.getElementById('dns-results');
    
    if (domain) {
        log('Запрос DNS записей...', 'system');
        
        const [aRecords, mxRecords, txtRecords] = await Promise.all([
            dnsQuery(domain, 'A'),
            dnsQuery(domain, 'MX'),
            dnsQuery(domain, 'TXT')
        ]);
        
        let dnsHTML = '';
        
        if (aRecords?.Answer && aRecords.Answer.length > 0) {
            targetIP = aRecords.Answer[0].data;
            const ips = aRecords.Answer.map(a => a.data).join(', ');
            dnsHTML += `<div class="data-row"><span class="data-label">A:</span> <span class="data-value">${ips}</span></div>`;
            log(`A: ${ips}`, 'success');
        } else {
            dnsHTML += `<div class="data-row"><span class="data-label">A:</span> <span class="status-muted">Не найдено</span></div>`;
            log('A записи не найдены', 'warning');
            riskScore += 10;
        }
        
        if (mxRecords?.Answer && mxRecords.Answer.length > 0) {
            const mx = mxRecords.Answer.slice(0, 2).map(m => m.data.split(' ').pop()).join(', ');
            dnsHTML += `<div class="data-row"><span class="data-label">MX:</span> <span class="data-value">${mx}</span></div>`;
            log('MX записи найдены', 'success');
        } else {
            dnsHTML += `<div class="data-row"><span class="data-label">MX:</span> <span class="status-muted">Не найдено</span></div>`;
        }
        
        if (txtRecords?.Answer && txtRecords.Answer.length > 0) {
            const hasSPF = txtRecords.Answer.some(t => t.data.includes('spf'));
            if (hasSPF) {
                dnsHTML += `<div class="data-row"><span class="data-label">SPF:</span> <span class="status-safe">Настроен</span></div>`;
            }
        }
        
        if (dnsResultsEl) dnsResultsEl.innerHTML = dnsHTML;
    } else {
        if (dnsResultsEl) dnsResultsEl.innerHTML = '<div class="status-muted">Не применимо для IP</div>';
    }

    const infraResultsEl = document.getElementById('infra-results');
    
    if (targetIP) {
        log(`Получение данных об IP: ${targetIP}...`, 'system');
        
        const ipInfo = await getIPInfo(targetIP);
        
        if (ipInfo && !ipInfo.error) {
            let infraHTML = `
                <div class="data-row"><span class="data-label">IP:</span> <span class="data-value">${targetIP}</span></div>
                <div class="data-row"><span class="data-label">Страна:</span> <span class="data-value">${ipInfo.country || 'Не определено'}</span></div>
                <div class="data-row"><span class="data-label">Город:</span> <span class="data-value">${ipInfo.city || 'Не определено'}</span></div>
                <div class="data-row"><span class="data-label">Провайдер:</span> <span class="data-value">${ipInfo.org || 'Не определено'}</span></div>
            `;
            if (infraResultsEl) infraResultsEl.innerHTML = infraHTML;
            log(`Страна: ${ipInfo.country}, Провайдер: ${ipInfo.org}`, 'info');
        } else {
            if (infraResultsEl) infraResultsEl.innerHTML = `
                <div class="data-row"><span class="data-label">IP:</span> <span class="data-value">${targetIP}</span></div>
                <div class="status-muted">Дополнительная информация недоступна</div>
            `;
            log('Не удалось получить данные об IP', 'warning');
        }
    } else {
        if (infraResultsEl) infraResultsEl.innerHTML = '<div class="status-muted">IP не определён</div>';
        log('IP-адрес не найден', 'warning');
        riskScore += 15;
    }

    const techResultsEl = document.getElementById('tech-results');
    
    if (validation.type === 'url') {
        log('Получение содержимого страницы...', 'system');
        
        const pageData = await fetchPageContent(validation.value);
        
        if (pageData.content && pageData.content.length > 100) {
            const techs = detectTechnologies(pageData.content);
            
            if (techs.length > 0) {
                let techHTML = '<div class="tech-tags">';
                techs.forEach(tech => {
                    techHTML += `<span class="tech-tag"><i data-lucide="${tech.icon}"></i> ${tech.name}</span>`;
                });
                techHTML += '</div>';
                if (techResultsEl) techResultsEl.innerHTML = techHTML;
                log(`Технологии: ${techs.map(t => t.name).join(', ')}`, 'info');
            } else {
                if (techResultsEl) techResultsEl.innerHTML = '<div class="status-muted">Технологии не определены</div>';
                log('Технологии не обнаружены', 'info');
            }

            log('Анализ XSS уязвимостей...', 'system');
            const xssResults = analyzeXSS(pageData.content, pageData.headers);
            
            vulnResults.csp.enabled = xssResults.hasCSP;
            
            if (xssResults.hasCSP) {
                log('CSP заголовок обнаружен — защита от XSS', 'success');
            } else {
                log('Отсутствует Content-Security-Policy — риск XSS', 'warning');
                riskScore += 10;
            }
            
            if (xssResults.dangerousPatterns.length > 0) {
                log(`Найдено опасных паттернов: ${xssResults.dangerousPatterns.length}`, 'warning');
                riskScore += xssResults.dangerousPatterns.length * 5;
            }
            
            log('Анализ содержимого завершён', 'success');
        } else {
            if (techResultsEl) techResultsEl.innerHTML = '<div class="status-muted">Содержимое недоступно или скрыто</div>';
            log('Не удалось получить содержимое (WAF/блокировка)', 'warning');
            riskScore += 5;
        }

        if (baseUrl) {
            log('> Поиск панелей управления...', 'system');
            log('> Проверка целостности репозитория...', 'system');
            
            const probePromises = CONFIG.PROBE_PATHS.map(pathInfo => probePath(baseUrl, pathInfo));
            const probeResults = await Promise.all(probePromises);
            
            for (const result of probeResults) {
                if (result.found) {
                    if (result.critical) {
                        log(`КРИТИЧЕСКАЯ УТЕЧКА: ${result.name}`, 'error');
                        criticalVuln = true;
                        riskScore += 100;
                        
                        if (result.path.includes('.git')) {
                            vulnResults.git.found = true;
                        }
                        if (result.path.includes('.env') || result.path.includes('config')) {
                            vulnResults.env.found = true;
                        }
                    } else {
                        log(`Обнаружено: ${result.name}`, 'warning');
                        vulnResults.admin.found = true;
                        vulnResults.admin.path = result.path;
                        riskScore += 15;
                    }
                }
            }
            
            if (!probeResults.some(r => r.found)) {
                log('✓ Критические пути защищены', 'success');
            }
        }
    } else {
        if (techResultsEl) techResultsEl.innerHTML = '<div class="status-muted">Не применимо для IP</div>';
    }

    updateVulnUI(vulnResults);
    lucide.createIcons();
    
    log(`Итоговый балл риска: ${riskScore}`, 'system');

    if (criticalVuln) {
        setStatus('КРИТИЧЕСКИ', 'error');
        updateVerdict(riskScore, 'НЕТ, ОПАСНО!', 'Обнаружена критическая утечка данных', 'danger');
        log('КРИТИЧЕСКАЯ УЯЗВИМОСТЬ — НЕ ПОСЕЩАТЬ', 'error');
    } else if (riskScore >= 50) {
        setStatus('ОПАСНО', 'error');
        updateVerdict(riskScore, 'Высокий риск', 'Обнаружены критические угрозы', 'danger');
        log('НЕ РЕКОМЕНДУЕТСЯ посещать этот ресурс', 'error');
    } else if (riskScore >= 20) {
        setStatus('Подозрительно', 'warning');
        updateVerdict(riskScore, 'Требует внимания', 'Обнаружены потенциальные риски', 'warning');
        log('Соблюдайте осторожность', 'warning');
    } else {
        setStatus('Безопасно', 'success');
        updateVerdict(riskScore, 'Вероятно безопасен', 'Серьёзных угроз не обнаружено', 'safe');
        log('Ресурс выглядит безопасным', 'success');
    }
    
    log('Сканирование завершено', 'system');
}

document.addEventListener('DOMContentLoaded', async () => {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const inputHint = document.getElementById('input-hint');
    
    if (scanBtn && urlInput) {
        initScannerUI();
        updateCooldownUI();

        urlInput.addEventListener('input', (e) => {
            const validation = validateInput(e.target.value);
            if (e.target.value.length > 0) {
                if (validation.valid) {
                    inputHint.textContent = validation.type === 'url' 
                        ? `Домен: ${validation.domain}` 
                        : `IP-адрес: ${validation.value}`;
                    inputHint.className = 'input-hint status-safe';
                } else {
                    inputHint.textContent = 'Некорректный формат';
                    inputHint.className = 'input-hint status-danger';
                }
            } else {
                inputHint.textContent = '';
                inputHint.className = 'input-hint';
            }
        });

        scanBtn.addEventListener('click', performScan);

        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !scanBtn.disabled) {
                performScan();
            }
        });
    }
});
