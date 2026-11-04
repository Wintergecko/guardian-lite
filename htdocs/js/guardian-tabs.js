/* Guardian Lite navigation. Progressive enhancement: all content stays visible without JS. */
(function () {
  'use strict';
  function init() {
    var root = document.querySelector('.guardian');
    if (!root || root.querySelector('.guardian-tabs')) return;
    var sections = [
      {id: 'overview', label: 'Übersicht', sections: ['guardian-overview']},
      {id: 'malware', label: 'Malware & Dateien', sections: ['guardian-scan', 'guardian-changes', 'guardian-history']},
      {id: 'attacks', label: 'Angriffe & Schutz', sections: ['guardian-shield', 'guardian-network']},
      {id: 'updates', label: 'Updates', sections: ['guardian-updater']},
      {id: 'incidents', label: 'Incidents', sections: ['guardian-incidents']},
      {id: 'roadmap', label: 'Feature-Liste', sections: ['guardian-roadmap']}
    ];
    if (sections.some(function (group) {
      return group.sections.some(function (id) { return !document.getElementById(id); });
    })) return;
    var nav = document.createElement('nav');
    nav.className = 'guardian-tabs';
    nav.setAttribute('role', 'tablist');
    nav.setAttribute('aria-label', 'Guardian Lite Navigation');
    var items = {};
    sections.forEach(function (group) {
      var button = document.createElement('button');
      button.type = 'button';
      button.id = 'guardian-tab-' + group.id;
      button.className = 'guardian-tab';
      button.textContent = group.label;
      button.setAttribute('role', 'tab');
      button.setAttribute('aria-controls', 'guardian-panel-' + group.id);
      button.setAttribute('aria-selected', 'false');
      button.tabIndex = -1;
      nav.appendChild(button);
      var panel = document.createElement('div');
      panel.className = 'guardian-tab-panel';
      panel.id = 'guardian-panel-' + group.id;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', button.id);
      panel.tabIndex = 0;
      group.sections.forEach(function (id) { panel.appendChild(document.getElementById(id)); });
      items[group.id] = {button: button, panel: panel};
    });
    // Each existing section is moved into its corresponding panel.
    var footer = root.querySelector('.guardian-foot');
    if (!footer) return;
    root.insertBefore(nav, footer);
    sections.forEach(function (group) { root.insertBefore(items[group.id].panel, footer); });
    function isValid(id) { return Object.prototype.hasOwnProperty.call(items, id); }
    function fromHash() {
      var match = /^#guardian-tab-([a-z]+)$/.exec(window.location.hash);
      return match && isValid(match[1]) ? match[1] : null;
    }
    function activate(id, focus, updateHash) {
      if (!isValid(id)) id = 'overview';
      sections.forEach(function (group) {
        var active = group.id === id;
        items[group.id].button.setAttribute('aria-selected', active ? 'true' : 'false');
        items[group.id].button.tabIndex = active ? 0 : -1;
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
    // Always tell the administrator that the update check form was submitted.
    // The server response remains a normal POST/redirect: no JavaScript required.
    var checkForm = document.getElementById('guardian-update-check-form');
    if (checkForm) {
      checkForm.addEventListener('submit', function () {
        var progress = document.getElementById('guardian-update-progress');
        if (progress) progress.hidden = false;
      });
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
