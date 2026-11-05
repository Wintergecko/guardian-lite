/* Guardian Lite top navigation. All server-rendered content stays available without JS. */
(function () {
  'use strict';
  function init() {
    var root = document.querySelector('.guardian');
    document.querySelectorAll('.guardian-world-map').forEach(function (mapObject) {
      function paintMap() {
        try {
          var counts = JSON.parse(mapObject.getAttribute('data-country-counts') || '{}');
          var mapDocument = mapObject.contentDocument;
          if (!mapDocument) return;
          var maximum = Math.max.apply(Math, Object.keys(counts).map(function (key) { return Number(counts[key]) || 0; }).concat([1]));
          Object.keys(counts).forEach(function (code) {
            var country = mapDocument.querySelector('[data-country="' + code.replace(/[^A-Z]/gi, '') + '"]');
            if (!country) return;
            var count = Number(counts[code]) || 0;
            var strength = Math.max(0.28, Math.min(1, count / maximum));
            country.style.fill = 'rgb(' + Math.round(112 - strength * 72) + ',' + Math.round(155 - strength * 91) + ',' + Math.round(224 - strength * 50) + ')';
            country.style.stroke = '#ffffff';
            country.style.strokeWidth = '0.55';
            country.setAttribute('data-blocked-count', String(count));
            country.setAttribute('title', code + ': ' + count + ' gesperrte IP' + (count === 1 ? '' : 's'));
          });
        } catch (e) { /* Map enhancement is optional; the country list remains available. */ }
      }
      mapObject.addEventListener('load', paintMap);
      try { if (mapObject.contentDocument && mapObject.contentDocument.readyState === 'complete') paintMap(); } catch (e) { /* object may still be loading */ }
    });
    if (!root || root.querySelector('.guardian-menu-enhanced')) return;
    var sections = [
      {id: 'overview', label: 'Dashboard', items: [['guardian-dashboard-top', 'Angriffskarte & Status'], ['guardian-overview', 'Systemstatus']]},
      {id: 'incidents', label: 'Incidents', items: [['guardian-waf-events', 'WAF-Ereignisse'],
        ['guardian-incidents', 'Meldungen & Audit-Log']]},
      {id: 'firewall', label: 'Firewall', items: [['guardian-fail2ban', 'Fail2Ban'],
        ['guardian-firewall', 'Plesk Firewall']]},
      {id: 'malware', label: 'Malware Scanner', items: [['guardian-scan-start', 'Scan starten'],
        ['guardian-scan-report', 'Letzter Bericht'], ['guardian-changes', 'Dateiänderungen'],
        ['guardian-monitor', 'Live-Dateiwache'], ['guardian-history', 'Scan-Historie'],
        ['guardian-malware-repair', 'Baselines & Wiederherstellung'],
        ['guardian-malware-ignore', 'Ignore List'], ['guardian-cms-integrity', 'CMS- & Cron-Prüfung']]},
      {id: 'more', label: 'Webschutz & PHP', items: [['guardian-webshield', 'HTTP-Botlimits'],
        ['guardian-webshield-config', 'WAF-Regeln'], ['guardian-turnstile', 'Login-Challenge'],
        ['guardian-runtime', 'PHP Runtime · Schutzstatus'], ['guardian-php-config', 'Handler & Rollback'],
        ['guardian-reputation', 'IP-Reputation']]},
      {id: 'settings', label: 'Verwaltung', items: [['guardian-management', 'Firewall-Debugausgabe'],
        ['guardian-settings-storage', 'Speicher & Backups'], ['guardian-service-keys', 'Dienst-Schlüssel'],
        ['guardian-updater', 'Updates'], ['guardian-management-diagnostics', 'Diagnose'],
        ['guardian-roadmap', 'Funktionsumfang']]}
    ];
    sections = sections.map(function (group) {
      group.items = (group.items || []).filter(function (entry) { return !!document.getElementById(entry[0]); });
      return group;
    }).filter(function (group) { return group.items.length > 0; });
    if (!sections.length) return;
    var shell = root.querySelector('.guardian-shell');
    if (!shell) {
      shell = document.createElement('div');
      shell.className = 'guardian-shell';
    }
    var nav = shell.querySelector('.guardian-menu');
    if (!nav) {
      nav = document.createElement('nav');
      nav.className = 'guardian-menu';
      nav.setAttribute('aria-label', 'Guardian Lite Hauptmenü');
      shell.insertBefore(nav, shell.firstChild);
    }
    var content = shell.querySelector('.guardian-pages');
    if (!content) {
      content = document.createElement('main');
      content.className = 'guardian-pages';
      shell.appendChild(content);
    }
    while (nav.firstChild) nav.removeChild(nav.firstChild);
    nav.classList.remove('guardian-menu-static');
    nav.classList.add('guardian-menu-enhanced');
    var brand = document.createElement('a');
    brand.className = 'guardian-brand';
    brand.href = '#guardian-overview';
    var mark = document.createElement('span');
    mark.className = 'guardian-mark';
    mark.setAttribute('aria-hidden', 'true');
    mark.textContent = '✥';
    var wordmark = document.createElement('span');
    wordmark.appendChild(document.createTextNode('guardian'));
    var lite = document.createElement('span');
    lite.textContent = 'lite';
    var small = document.createElement('small');
    small.textContent = 'security';
    wordmark.appendChild(lite);
    wordmark.appendChild(small);
    brand.appendChild(mark);
    brand.appendChild(wordmark);
    nav.appendChild(brand);
    brand.addEventListener('click', function (event) {
      event.preventDefault();
      openMenu = null;
      activate('overview', false, true);
    });
    var items = {};
    var targets = {};
    var openMenu = null;
    var currentGroup = 'overview';
    sections.forEach(function (group) {
      var menuGroup = document.createElement('div');
      menuGroup.className = 'guardian-menu-group';
      menuGroup.setAttribute('data-menu-group', group.id);
      var button = document.createElement('button');
      button.type = 'button';
      button.id = 'guardian-tab-' + group.id;
      button.className = 'guardian-tab';
      button.textContent = group.label;
      button.setAttribute('aria-controls', 'guardian-submenu-' + group.id);
      button.setAttribute('aria-expanded', 'false');
      menuGroup.appendChild(button);
      if (group.badge) {
        var badge = document.createElement('span');
        badge.className = 'guardian-menu-note';
        badge.textContent = group.badge;
        menuGroup.appendChild(badge);
      }
      var submenu = document.createElement('ul');
      submenu.className = 'guardian-submenu';
      submenu.id = 'guardian-submenu-' + group.id;
      submenu.hidden = true;
      var moduleViews = {};
      (group.items || []).forEach(function (entry) {
        var li = document.createElement('li');
        var link = document.createElement('a');
        link.href = '#' + entry[0];
        link.setAttribute('data-menu-target', entry[0]);
        link.textContent = entry[1];
        targets[entry[0]] = group.id;
        li.appendChild(link);
        submenu.appendChild(li);

        var target = document.getElementById(entry[0]);
        var view = document.createElement('section');
        view.className = 'guardian-tab-panel guardian-module-view';
        view.id = 'guardian-panel-' + entry[0];
        view.setAttribute('role', 'region');
        view.setAttribute('aria-label', entry[1]);
        view.hidden = true;
        view.appendChild(target);
        content.appendChild(view);
        moduleViews[entry[0]] = view;
      });
      menuGroup.appendChild(submenu);
      nav.appendChild(menuGroup);
      items[group.id] = {button: button, submenu: submenu, menuGroup: menuGroup,
        moduleViews: moduleViews, firstTarget: group.items[0][0]};
    });
    ['guardian-scan', 'guardian-shield', 'guardian-network'].forEach(function (id) {
      var legacyGrid = document.getElementById(id);
      if (legacyGrid && legacyGrid.children.length === 0) legacyGrid.remove();
    });
    if (!shell.parentNode) {
      var footer = root.querySelector('.guardian-foot');
      if (!footer) return;
      root.insertBefore(shell, footer);
    }
    var aliases = {attacks: 'firewall', management: 'settings', updates: 'settings', roadmap: 'settings'};
    function normalize(id) { return aliases[id] || id; }
    function isValid(id) { return Object.prototype.hasOwnProperty.call(items, normalize(id)); }
    function fromHash() {
      var match = /^#guardian-tab-([a-z]+)$/.exec(window.location.hash);
      return match && isValid(match[1]) ? normalize(match[1]) : null;
    }
    function activate(id, focus, updateHash, targetId) {
      id = isValid(id) ? normalize(id) : 'overview';
      var selected = targetId && targets[targetId] === id ? targetId : items[id].firstTarget;
      currentGroup = id;
      sections.forEach(function (group) {
        var active = group.id === id;
        items[group.id].button.setAttribute('aria-expanded', openMenu === group.id ? 'true' : 'false');
        items[group.id].menuGroup.classList.toggle('is-active', active);
        items[group.id].submenu.hidden = openMenu !== group.id;
        Object.keys(items[group.id].moduleViews).forEach(function (target) {
          items[group.id].moduleViews[target].hidden = !active || target !== selected;
        });
      });
      Array.prototype.forEach.call(nav.querySelectorAll('[data-menu-target]'), function (link) {
        var current = link.getAttribute('data-menu-target') === selected;
        link.classList.toggle('is-current', current);
        if (current) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      });
      if (focus) items[id].button.focus();
      try {
        window.sessionStorage.setItem('guardian_active_tab', id);
        window.sessionStorage.setItem('guardian_active_module', selected);
      } catch (e) { /* storage optional */ }
      if (updateHash && window.history && window.history.replaceState) {
        window.history.replaceState(null, '', '#guardian-tab-' + id);
      }
    }
    sections.forEach(function (group, index) {
      var button = items[group.id].button;
      button.addEventListener('click', function () {
        var wasOpen = openMenu === group.id;
        openMenu = wasOpen ? null : group.id;
        if (currentGroup !== group.id) activate(group.id, false, true);
        else {
          sections.forEach(function (entry) {
            items[entry.id].button.setAttribute('aria-expanded', openMenu === entry.id ? 'true' : 'false');
            items[entry.id].submenu.hidden = openMenu !== entry.id;
          });
        }
      });
      button.addEventListener('keydown', function (event) {
        var next;
        if (event.key === 'ArrowRight') next = (index + 1) % sections.length;
        else if (event.key === 'ArrowLeft') next = (index + sections.length - 1) % sections.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = sections.length - 1;
        else return;
        event.preventDefault();
        openMenu = null;
        activate(sections[next].id, true, true);
      });
    });
    Array.prototype.forEach.call(nav.querySelectorAll('[data-menu-target]'), function (link) {
      link.addEventListener('click', function (event) {
        event.preventDefault();
        var targetId = link.getAttribute('data-menu-target');
        var target = document.getElementById(targetId);
        var groupId = targets[targetId];
        if (!target || !groupId || !isValid(groupId)) return;
        openMenu = null;
        activate(groupId, false, true, targetId);
        window.scrollTo(0, 0);
      });
    });
    // Show a readable domain independently of native select styling and Plesk skins.
    var domainSelect = document.getElementById('guardian-domain');
    var selectedName = document.getElementById('guardian-domain-selection-value');
    if (domainSelect && selectedName) {
      function showSelectedDomain() {
        selectedName.textContent = domainSelect.value || 'Keine';
      }
      domainSelect.addEventListener('change', showSelectedDomain);
      showSelectedDomain();
    }
    // Visible progress while Plesk processes the form; server also persists feedback.
    Array.prototype.forEach.call(document.querySelectorAll('.guardian-schedule-form'), function (form) {
      form.addEventListener('submit', function () {
        var button = form.querySelector('button[type="submit"]');
        if (button) { button.textContent = 'Wird gespeichert ...'; button.setAttribute('aria-busy', 'true'); }
      });
    });
    // Always tell the administrator that the update check form was submitted.
    // The server response remains a normal POST/redirect: no JavaScript required.
    var checkForm = document.getElementById('guardian-update-check-form');
    if (checkForm) {
      checkForm.addEventListener('submit', function () {
        var progress = document.getElementById('guardian-update-progress');
        if (progress) progress.hidden = false;
      });
    }
    var firewallTable = document.getElementById('guardian-firewall-inventory');
    var firewallSearch = document.getElementById('guardian-firewall-search');
    var firewallFilter = document.getElementById('guardian-firewall-filter');
    var firewallResults = document.getElementById('guardian-firewall-results');
    if (firewallTable && firewallSearch && firewallFilter) {
      var firewallRows = Array.prototype.slice.call(firewallTable.querySelectorAll('tbody tr'));
      function filterFirewallRules() {
        var query = firewallSearch.value.trim().toLocaleLowerCase();
        var action = firewallFilter.value;
        var shown = 0;
        firewallRows.forEach(function (row) {
          var matches = (!query || row.textContent.toLocaleLowerCase().indexOf(query) !== -1) &&
            (action === 'all' || row.getAttribute('data-firewall-action') === action);
          row.hidden = !matches;
          if (matches) shown += 1;
        });
        if (firewallResults) firewallResults.textContent = shown + ' von ' + firewallRows.length + ' angezeigt';
      }
      firewallSearch.addEventListener('input', filterFirewallRules);
      firewallFilter.addEventListener('change', filterFirewallRules);
      filterFirewallRules();
    }
    var incidentDashboard = root.querySelector('[data-incident-dashboard]');
    var incidentTable = document.getElementById('guardian-incidents-table');
    var incidentSearch = document.getElementById('guardian-incident-search');
    var incidentSeverity = document.getElementById('guardian-incident-severity');
    if (incidentDashboard && incidentTable && incidentSearch && incidentSeverity) {
      var incidentRows = Array.prototype.slice.call(incidentTable.querySelectorAll('tbody tr'));
      var rangeButtons = Array.prototype.slice.call(incidentDashboard.querySelectorAll('[data-incident-range]'));
      var incidentChart = incidentDashboard.querySelector('[data-incident-chart]');
      var incidentCaption = incidentDashboard.querySelector('[data-incident-chart-caption]');
      var incidentResults = incidentDashboard.querySelector('[data-incident-results]');
      var incidentRange = '7d';
      function renderIncidents() {
        var now = Date.now();
        var span = incidentRange === '24h' ? 24 * 60 * 60 * 1000 :
          (incidentRange === '7d' ? 7 * 24 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000);
        var bins = incidentRange === '24h' ? 24 : (incidentRange === '7d' ? 7 : 30);
        var start = now - span;
        var counts = {total: 0, critical: 0, warning: 0, malware: 0};
        var histogram = [];
        for (var i = 0; i < bins; i += 1) histogram.push(0);
        var query = incidentSearch.value.trim().toLocaleLowerCase();
        var level = incidentSeverity.value;
        var shown = 0;
        incidentRows.forEach(function (row) {
          var timestamp = Date.parse(row.getAttribute('data-incident-time') || '');
          var severity = row.getAttribute('data-incident-severity') || '';
          var type = row.getAttribute('data-incident-type') || '';
          var inRange = !isNaN(timestamp) && timestamp >= start && timestamp <= now;
          var matches = inRange && (level === 'all' || severity === level) &&
            (!query || row.textContent.toLocaleLowerCase().indexOf(query) !== -1);
          row.hidden = !matches;
          if (matches) shown += 1;
          if (!inRange) return;
          counts.total += 1;
          if (severity === 'critical') counts.critical += 1;
          if (severity === 'warning') counts.warning += 1;
          if (type === 'malware_detected') counts.malware += 1;
          var bin = Math.min(bins - 1, Math.floor(((timestamp - start) / span) * bins));
          histogram[bin] += 1;
        });
        Object.keys(counts).forEach(function (key) {
          var output = incidentDashboard.querySelector('[data-incident-count="' + key + '"]');
          if (output) output.textContent = String(counts[key]);
        });
        if (incidentResults) incidentResults.textContent = shown + ' von ' + incidentRows.length + ' angezeigt';
        rangeButtons.forEach(function (button) {
          button.setAttribute('aria-pressed', button.getAttribute('data-incident-range') === incidentRange ? 'true' : 'false');
        });
        if (!incidentChart) return;
        while (incidentChart.firstChild) incidentChart.removeChild(incidentChart.firstChild);
        var maximum = Math.max.apply(Math, histogram.concat([1]));
        var labels = [];
        histogram.forEach(function (value, index) {
          var binDate = new Date(start + (index + 0.5) * span / bins);
          var label = incidentRange === '24h' ?
            String(binDate.getHours()).padStart(2, '0') + ':00' :
            String(binDate.getDate()).padStart(2, '0') + '.' + String(binDate.getMonth() + 1).padStart(2, '0');
          labels.push(label + ': ' + value);
          var bar = document.createElement('span');
          bar.className = 'guardian-incident-bar';
          bar.style.height = value ? Math.max(5, value * 100 / maximum) + '%' : '0%';
          bar.title = label + ': ' + value;
          bar.setAttribute('aria-hidden', 'true');
          incidentChart.appendChild(bar);
        });
        incidentChart.setAttribute('aria-label', 'Ereignisse nach Zeitintervall: ' + labels.join(', '));
        if (incidentCaption) incidentCaption.textContent = counts.total + ' Ereignisse in ' +
          (incidentRange === '24h' ? '24 Stunden' : (incidentRange === '7d' ? '7 Tagen' : '30 Tagen')) +
          ' · Verlauf der gespeicherten maximal 200 letzten Eintraege';
        if (!counts.total) {
          var empty = document.createElement('span');
          empty.className = 'guardian-small';
          empty.textContent = 'Keine Ereignisse in diesem Zeitraum';
          incidentChart.appendChild(empty);
        }
      }
      rangeButtons.forEach(function (button) {
        button.addEventListener('click', function () {
          incidentRange = button.getAttribute('data-incident-range') || '7d';
          renderIncidents();
        });
      });
      incidentSearch.addEventListener('input', renderIncidents);
      incidentSeverity.addEventListener('change', renderIncidents);
      renderIncidents();
    }
    var saved = null;
    try { saved = window.sessionStorage.getItem('guardian_active_tab'); } catch (e) { /* storage optional */ }
    var requested = fromHash();
    var report = new URLSearchParams(window.location.search).has('report');
    var initialGroup = requested || (report ? 'malware' : (isValid(saved) ? saved : 'overview'));
    var savedTarget = null;
    try { savedTarget = window.sessionStorage.getItem('guardian_active_module'); } catch (e) { /* storage optional */ }
    activate(initialGroup, false, false, report ? 'guardian-scan-report' : savedTarget);
    window.addEventListener('hashchange', function () {
      var next = fromHash();
      if (next) {
        openMenu = null;
        activate(next, false, false);
      }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
