/* Guardian Lite sidebar navigation. All server-rendered content stays visible without JS. */
(function () {
  'use strict';
  function init() {
    var root = document.querySelector('.guardian');
    if (!root || root.querySelector('.guardian-menu-enhanced')) return;
    var sections = [
      {id: 'overview', label: 'Dashboard', sections: ['guardian-overview'],
        items: [['guardian-overview', 'Systemstatus']]},
      {id: 'malware', label: 'Malware Scanner', sections: ['guardian-scan', 'guardian-changes',
        'guardian-monitor', 'guardian-history', 'guardian-malware-repair', 'guardian-malware-ignore', 'guardian-cms-integrity'],
        items: [['guardian-scan', 'Scans & Berichte'], ['guardian-changes', 'Dateiänderungen'],
          ['guardian-monitor', 'Live-Dateiwache'], ['guardian-history', 'Scan-Historie'],
          ['guardian-malware-repair', 'Baselines & Wiederherstellung'],
          ['guardian-malware-ignore', 'Ignore List'], ['guardian-cms-integrity', 'CMS- & Cron-Prüfung']]},
      {id: 'incidents', label: 'Incidents', sections: ['guardian-waf-events', 'guardian-incidents'],
        items: [['guardian-waf-events', 'WAF-Ereignisse'], ['guardian-incidents', 'Meldungen & Audit-Log']]},
      {id: 'firewall', label: 'Firewall', sections: ['guardian-fail2ban', 'guardian-firewall'],
        items: [['guardian-fail2ban', 'Fail2Ban'], ['guardian-firewall', 'Plesk Firewall']]},
      {id: 'webshield', label: 'WebShield', badge: 'Teilweise', sections: ['guardian-webshield', 'guardian-webshield-config', 'guardian-turnstile'],
        items: [['guardian-webshield', 'HTTP-Botlimits'], ['guardian-webshield-config', 'WAF-Regeln'],
          ['guardian-turnstile', 'Login-Challenge']]},
      {id: 'runtime', label: 'PHP Runtime', badge: 'Teilfunktion', sections: ['guardian-runtime', 'guardian-php-config'],
        items: [['guardian-runtime', 'Schutzstatus'], ['guardian-php-config', 'Handler & Rollback']]},
      {id: 'reputation', label: 'Reputation Management', badge: 'manuell', sections: ['guardian-reputation'],
        items: [['guardian-reputation', 'IP-Abfrage']]},
      {id: 'settings', label: 'Einstellungen', sections: ['guardian-settings-storage', 'guardian-service-keys',
        'guardian-management', 'guardian-management-diagnostics', 'guardian-updater', 'guardian-roadmap'],
        items: [['guardian-management', 'Firewall-Debugausgabe'], ['guardian-settings-storage', 'Speicher & Backups'],
          ['guardian-service-keys', 'Dienst-Schlüssel'],
          ['guardian-updater', 'Updates'], ['guardian-management-diagnostics', 'Diagnose'],
          ['guardian-roadmap', 'Funktionsumfang']]}
    ];
    sections = sections.map(function (group) {
      group.sections = group.sections.filter(function (id) { return !!document.getElementById(id); });
      group.items = (group.items || []).filter(function (entry) { return !!document.getElementById(entry[0]); });
      return group;
    }).filter(function (group) { return group.sections.length > 0; });
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
    var items = {};
    sections.forEach(function (group) {
      var menuGroup = document.createElement('div');
      menuGroup.className = 'guardian-menu-group';
      var button = document.createElement('button');
      button.type = 'button';
      button.id = 'guardian-tab-' + group.id;
      button.className = 'guardian-tab';
      button.textContent = group.label;
      button.setAttribute('aria-controls', 'guardian-panel-' + group.id);
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
      (group.items || []).forEach(function (entry) {
        var li = document.createElement('li');
        var link = document.createElement('a');
        link.href = '#' + entry[0];
        link.setAttribute('data-menu-target', entry[0]);
        link.textContent = entry[1];
        li.appendChild(link);
        submenu.appendChild(li);
      });
      menuGroup.appendChild(submenu);
      nav.appendChild(menuGroup);
      var panel = document.createElement('div');
      panel.className = 'guardian-tab-panel';
      panel.id = 'guardian-panel-' + group.id;
      panel.setAttribute('role', 'region');
      panel.setAttribute('aria-labelledby', button.id);
      panel.setAttribute('tabindex', '-1');
      group.sections.forEach(function (id) { panel.appendChild(document.getElementById(id)); });
      content.appendChild(panel);
      items[group.id] = {button: button, panel: panel, submenu: submenu, menuGroup: menuGroup};
    });
    ['guardian-shield', 'guardian-network'].forEach(function (id) {
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
    function activate(id, focus, updateHash) {
      id = isValid(id) ? normalize(id) : 'overview';
      sections.forEach(function (group) {
        var active = group.id === id;
        items[group.id].button.setAttribute('aria-expanded', active ? 'true' : 'false');
        items[group.id].menuGroup.classList.toggle('is-active', active);
        items[group.id].submenu.hidden = !active;
        items[group.id].panel.hidden = !active;
      });
      if (focus) items[id].button.focus();
      try { window.sessionStorage.setItem('guardian_active_tab', id); } catch (e) { /* storage optional */ }
      if (updateHash && window.history && window.history.replaceState) {
        window.history.replaceState(null, '', '#guardian-tab-' + id);
      }
    }
    sections.forEach(function (group, index) {
      var button = items[group.id].button;
      button.addEventListener('click', function () { activate(group.id, false, true); });
      button.addEventListener('keydown', function (event) {
        var next;
        if (event.key === 'ArrowRight') next = (index + 1) % sections.length;
        else if (event.key === 'ArrowLeft') next = (index + sections.length - 1) % sections.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = sections.length - 1;
        else return;
        event.preventDefault();
        activate(sections[next].id, true, true);
      });
    });
    Array.prototype.forEach.call(nav.querySelectorAll('[data-menu-target]'), function (link) {
      link.addEventListener('click', function (event) {
        event.preventDefault();
        var target = document.getElementById(link.getAttribute('data-menu-target'));
        var group = sections.find(function (entry) { return entry.sections.indexOf(link.getAttribute('data-menu-target')) !== -1; });
        if (!target || !group) return;
        Array.prototype.forEach.call(nav.querySelectorAll('[data-menu-target]'), function (entry) {
          entry.classList.remove('is-current');
          entry.removeAttribute('aria-current');
        });
        link.classList.add('is-current');
        link.setAttribute('aria-current', 'location');
        activate(group.id, false, true);
        target.scrollIntoView({behavior: 'smooth', block: 'start'});
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
    var saved = null;
    try { saved = window.sessionStorage.getItem('guardian_active_tab'); } catch (e) { /* storage optional */ }
    var requested = fromHash();
    var report = new URLSearchParams(window.location.search).has('report');
    activate(requested || (report ? 'malware' : (isValid(saved) ? saved : 'overview')), false, false);
    window.addEventListener('hashchange', function () {
      var next = fromHash();
      if (next) activate(next, false, false);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
