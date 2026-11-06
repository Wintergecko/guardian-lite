import { createRoot } from 'react-dom/client';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import './styles.css';

type EventRow = {
  time: string;
  severity: string;
  type: string;
  detail: string;
};

type FirewallInventoryItem = {
  id: string;
  name: string;
  action: 'allow' | 'deny';
  direction: string;
  source: string;
  ports: string;
  class: string;
};

type FirewallStatus = {
  known: boolean;
  active: boolean;
  installed: boolean;
  available: boolean;
  inventoryLimited: boolean;
  counts: { all: number; inputAllow: number; inputDeny: number; portAllow: number; portDeny: number };
  inventory: FirewallInventoryItem[];
};

type WafEvent = {
  epoch: number | null;
  rule: string;
  severity: string;
  ip: string | null;
  blocked: boolean;
};

type Incident = {
  time: string;
  type: string;
  severity: string;
  domain: string;
  path: string;
  detail: string;
};

function normalizeSeverity(value: string): string {
  const severity = value.trim().toLowerCase();
  if (['emergency', 'alert', 'critical', 'crit'].includes(severity)) return 'critical';
  if (['error', 'err'].includes(severity)) return 'error';
  if (['warning', 'warn'].includes(severity)) return 'warning';
  if (['notice'].includes(severity)) return 'notice';
  if (['info', 'informational'].includes(severity)) return 'info';
  return severity;
}

function SettingsModule({ language, onNavigate }: {
  language: 'de' | 'en';
  onNavigate: (target: string) => void;
}) {
  const isGerman = language === 'de';
  const sections = isGerman
    ? [
      {
        title: 'Speicher & Wiederherstellung',
        description: 'Speicherbelegung, Backups, Aufbewahrung und Wiederherstellungspunkte verwalten.',
        items: [{ target: 'guardian-settings-storage', title: 'Speicher & Backups', description: 'Quotas, Speicherverbrauch und sichere Bereinigung.' }],
      },
      {
        title: 'Zugangsdaten & Integrationen',
        description: 'Externe Dienste und vertrauliche API-Zugangsdaten konfigurieren.',
        items: [{ target: 'guardian-service-keys', title: 'Dienst-Schlüssel', description: 'AbuseIPDB- und Turnstile-Schlüssel sowie Einwilligung.' }],
      },
      {
        title: 'Wartung & System',
        description: 'Erweiterungsaktualisierungen und technische Diagnose.',
        items: [
          { target: 'guardian-updater', title: 'Updates', description: 'Version prüfen und verfügbare Erweiterungsupdates verwalten.' },
          { target: 'guardian-management-diagnostics', title: 'Diagnose', description: 'System-, Dienst- und Berechtigungsstatus prüfen.' },
        ],
      },
    ]
    : [
      {
        title: 'Storage & recovery',
        description: 'Review storage use, backups, retention, and recovery points.',
        items: [{ target: 'guardian-settings-storage', title: 'Storage & backups', description: 'Quotas, storage usage, and safe cleanup.' }],
      },
      {
        title: 'Credentials & integrations',
        description: 'Configure external services and confidential API credentials.',
        items: [{ target: 'guardian-service-keys', title: 'Service keys', description: 'AbuseIPDB and Turnstile keys and consent.' }],
      },
      {
        title: 'Maintenance & system',
        description: 'Extension updates and technical diagnostics.',
        items: [
          { target: 'guardian-updater', title: 'Updates', description: 'Check the version and manage available extension updates.' },
          { target: 'guardian-management-diagnostics', title: 'Diagnostics', description: 'Review system, service, and permission status.' },
        ],
      },
    ];

  return (
    <main className="sentinel-react-content sentinel-settings" aria-labelledby="sentinel-settings-title">
      <header className="sentinel-settings-heading">
        <p>{isGerman ? 'KONFIGURATION & WARTUNG' : 'CONFIGURATION & MAINTENANCE'}</p>
        <h2 id="sentinel-settings-title">{isGerman ? 'Verwaltung' : 'Administration'}</h2>
        <span>{isGerman
          ? 'Einstellungen nach Aufgabe gruppiert. Wähle einen Bereich, um Details und verfügbare Aktionen zu öffnen.'
          : 'Settings grouped by task. Choose a section to review details and available actions.'}</span>
      </header>
      <div className="sentinel-settings-groups">
        {sections.map((section) => (
          <section className="sentinel-settings-group" key={section.title}>
            <header><h3>{section.title}</h3><p>{section.description}</p></header>
            <div className="sentinel-settings-cards">
              {section.items.map((item) => (
                <button type="button" className="sentinel-settings-card" key={item.target}
                  onClick={() => onNavigate(item.target)}>
                  <span>{item.title}</span><small>{item.description}</small>
                  <strong>{isGerman ? 'Bereich öffnen' : 'Open section'} <span aria-hidden="true">→</span></strong>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
      <p className="sentinel-settings-note">{isGerman
        ? 'Änderungen werden weiterhin über die geschützten Plesk-Verwaltungsaktionen ausgeführt. Zugangsschlüssel werden nicht im Klartext angezeigt.'
        : 'Changes continue to use protected Plesk administration actions. Service keys are never displayed in plain text.'}</p>
    </main>
  );
}

function PleskFirewallModule({ firewall, language }: { firewall: FirewallStatus; language: 'de' | 'en' }) {
  const [query, setQuery] = useState('');
  const [action, setAction] = useState<'all' | 'allow' | 'deny'>('all');
  const isGerman = language === 'de';
  const labels = isGerman
    ? {
      description: 'Read-only-Übersicht der von Plesk gemeldeten Firewall-Regeln. Angezeigt werden maximal 300 Regeln; Änderungen an Firewall-Regeln werden nicht automatisch vorgenommen.',
      active: 'Aktiv · Regeln lesbar', activeUnreadable: 'Aktiv · Regeln nicht lesbar',
      stopped: 'Nicht aktiv', unavailable: 'Regeln nicht lesbar',
      installed: 'Installiert, Status unbekannt', readableUnknown: 'Status unbekannt · Regeln lesbar', missing: 'Nicht installiert',
      allow: 'Erlauben', deny: 'Sperren', portsAllow: 'Portfreigaben', portsDeny: 'Portsperren',
      all: 'Alle Regeln', list: 'Liste', direction: 'Richtung', name: 'Regel',
      source: 'Quelle', ports: 'Port', class: 'Klasse', search: 'Regeln suchen',
      filter: 'Aktion', allActions: 'Alle', shown: 'angezeigt', empty: 'Keine Regeln entsprechen dem Filter.',
      limited: 'Die Liste ist auf 300 Regeln begrenzt.', noInventory: 'Plesk hat keine Firewall-Regeln zurückgegeben.',
      input: 'Eingehend', output: 'Ausgehend', unknown: 'Unbekannt',
    }
    : {
      description: 'Read-only overview of firewall rules reported by Plesk. At most 300 rules are shown; firewall rules are not changed automatically.',
      active: 'Active · rules readable', activeUnreadable: 'Active · rules unavailable',
      stopped: 'Not active', unavailable: 'Rules unavailable',
      installed: 'Installed, status unknown', readableUnknown: 'Status unknown · rules readable', missing: 'Not installed',
      allow: 'Allow', deny: 'Deny', portsAllow: 'Port allows', portsDeny: 'Port denies',
      all: 'All rules', list: 'List', direction: 'Direction', name: 'Rule',
      source: 'Source', ports: 'Port', class: 'Class', search: 'Search rules',
      filter: 'Action', allActions: 'All', shown: 'shown', empty: 'No rules match the filter.',
      limited: 'The list is limited to 300 rules.', noInventory: 'Plesk returned no firewall rules.',
      input: 'Inbound', output: 'Outbound', unknown: 'Unknown',
    };
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const rows = firewall.inventory.filter((item) => {
    const matchesAction = action === 'all' || item.action === action;
    const text = `${item.name} ${item.source} ${item.ports} ${item.class} ${item.direction}`.toLocaleLowerCase();
    return matchesAction && (!normalizedQuery || text.includes(normalizedQuery));
  });
  const firewallState = !firewall.installed ? labels.missing
    : firewall.active ? (firewall.available ? labels.active : labels.activeUnreadable)
      : firewall.known ? labels.stopped
        : firewall.available ? labels.readableUnknown : labels.installed;

  return (
    <main className="sentinel-react-content sentinel-firewall" aria-label={labels.all}>
      <p className="sentinel-module-description">{labels.description}</p>
      <div className="sentinel-firewall-status" role="status">{firewallState}</div>
      <div className="sentinel-firewall-kpis">
        <article><span>{labels.allow}</span><strong>{firewall.counts.inputAllow}</strong></article>
        <article><span>{labels.deny}</span><strong>{firewall.counts.inputDeny}</strong></article>
        <article><span>{labels.portsAllow}</span><strong>{firewall.counts.portAllow}</strong></article>
        <article><span>{labels.portsDeny}</span><strong>{firewall.counts.portDeny}</strong></article>
      </div>
      {!firewall.available ? (
        <p className="sentinel-detail-error" role="status">{labels.unavailable}</p>
      ) : (
        <section className="sentinel-event-table" aria-labelledby="sentinel-firewall-rules-title">
          <header><h2 id="sentinel-firewall-rules-title">{labels.all}</h2><span>{rows.length} {labels.shown} / {firewall.counts.all}</span></header>
          <div className="sentinel-event-toolbar">
            <label>{labels.search}<input type="search" maxLength={120} value={query} onChange={(event) => setQuery(event.currentTarget.value)} /></label>
            <label>{labels.filter}
              <select value={action} onChange={(event) => {
                const value = event.currentTarget.value;
                setAction(value === 'allow' || value === 'deny' ? value : 'all');
              }}>
                <option value="all">{labels.allActions}</option><option value="allow">{labels.allow}</option><option value="deny">{labels.deny}</option>
              </select>
            </label>
          </div>
          {firewall.inventoryLimited && <p className="sentinel-detail-error" role="status">{labels.limited}</p>}
          <div className="sentinel-table-scroll"><table><thead><tr>
            <th>{labels.list}</th><th>{labels.direction}</th><th>{labels.name}</th>
            <th>{labels.source}</th><th>{labels.ports}</th><th>{labels.class}</th>
          </tr></thead><tbody>
            {rows.map((item) => (
              <tr key={item.id}>
                <td>{item.action === 'allow' ? labels.allow : labels.deny}</td>
                <td>{item.direction === 'input' ? labels.input : item.direction === 'output' ? labels.output : item.direction || labels.unknown}</td>
                <td>{item.name}</td><td><code>{item.source || '—'}</code></td>
                <td>{item.ports || '—'}</td><td>{item.class || '—'}</td>
              </tr>
            ))}
          </tbody></table></div>
          {rows.length === 0 && <p className="sentinel-detail-message">{firewall.inventory.length ? labels.empty : labels.noInventory}</p>}
        </section>
      )}
    </main>
  );
}

type DashboardStatus = {
  available: boolean;
  fail2ban: { installed: boolean; running: boolean; jails: number; jailNames: string[]; banned: number };
  firewall: FirewallStatus;
  blockedIps: number | null;
  eventsTotal: number;
  events: EventRow[];
  wafAvailable: boolean;
  wafNote: string;
  wafEvents: WafEvent[];
  incidents: Incident[];
};

type Fail2banDetails = {
  jail: string;
  managed: boolean;
  override_sha256: string;
  backups: { id: string; created_at: string }[];
  settings: {
    maxretry: number | null;
    findtime: number | null;
    bantime: number | null;
    filter_regex_count: number | null;
    actions: string[];
  };
};

type Fail2banBackup = { id: string; created_at: string };

type MenuItem = { target: string; label: string; english: string };
type MenuGroup = { id: string; label: string; english: string; items: MenuItem[] };

const menu: MenuGroup[] = [
  {
    id: 'overview',
    label: 'Dashboard',
    english: 'Dashboard',
    items: [
      { target: 'guardian-dashboard-top', label: 'Angriffskarte & Status', english: 'Threat map & status' },
      { target: 'guardian-overview', label: 'Systemstatus', english: 'System status' },
    ],
  },
  {
    id: 'incidents',
    label: 'Ereignisse',
    english: 'Events',
    items: [
      { target: 'guardian-waf-events', label: 'Webschutz-Ereignisse', english: 'Web protection events' },
      { target: 'guardian-incidents', label: 'Meldungen & Audit-Log', english: 'Incidents & audit log' },
    ],
  },
  {
    id: 'firewall',
    label: 'Firewall',
    english: 'Firewall',
    items: [
      { target: 'guardian-fail2ban', label: 'Fail2ban & Sperrlisten', english: 'Fail2ban & ban lists' },
      { target: 'guardian-firewall', label: 'Plesk-Regeln', english: 'Plesk rules' },
      { target: 'guardian-ip-rules', label: 'IP-Regeln', english: 'IP rules' },
      { target: 'guardian-ports', label: 'Portregeln', english: 'Port rules' },
      { target: 'guardian-crowdsec', label: 'CrowdSec & Diagnose', english: 'CrowdSec & diagnostics' },
      { target: 'guardian-management', label: 'Firewall-Protokoll', english: 'Firewall log' },
    ],
  },
  {
    id: 'malware',
    label: 'Malware Scanner',
    english: 'Malware scanner',
    items: [
      { target: 'guardian-scan-start', label: 'Scan starten', english: 'Start a scan' },
      { target: 'guardian-scan-report', label: 'Letzter Bericht', english: 'Latest report' },
      { target: 'guardian-changes', label: 'Dateiänderungen', english: 'File changes' },
      { target: 'guardian-monitor', label: 'Live-Dateiwache', english: 'Live file monitor' },
      { target: 'guardian-history', label: 'Scan-Historie', english: 'Scan history' },
      { target: 'guardian-malware-repair', label: 'Baselines & Wiederherstellung', english: 'Baselines & restore' },
      { target: 'guardian-malware-ignore', label: 'Ignore List', english: 'Ignore list' },
      { target: 'guardian-cms-integrity', label: 'CMS- & Cron-Prüfung', english: 'CMS & cron audit' },
    ],
  },
  {
    id: 'more',
    label: 'Webschutz & PHP',
    english: 'Web protection & PHP',
    items: [
      { target: 'guardian-webshield', label: 'HTTP-Botlimits', english: 'HTTP bot limits' },
      { target: 'guardian-webshield-domains', label: 'Domains · Schutzaktionen', english: 'Domains · protection' },
      { target: 'guardian-webshield-config', label: 'WAF-Regeln', english: 'WAF rules' },
      { target: 'guardian-turnstile', label: 'Login-Challenge', english: 'Login challenge' },
      { target: 'guardian-runtime', label: 'PHP Runtime · Schutzstatus', english: 'PHP runtime · status' },
      { target: 'guardian-php-config', label: 'PHP Handler & Rollback', english: 'PHP handler & rollback' },
      { target: 'guardian-reputation', label: 'IP-Reputation', english: 'IP reputation' },
    ],
  },
  {
    id: 'settings',
    label: 'Verwaltung',
    english: 'Administration',
    items: [
      { target: 'guardian-settings-overview', label: 'Verwaltungsübersicht', english: 'Administration overview' },
      { target: 'guardian-settings-storage', label: 'Speicher & Backups', english: 'Storage & backups' },
      { target: 'guardian-service-keys', label: 'Dienst-Schlüssel', english: 'Service keys' },
      { target: 'guardian-updater', label: 'Updates', english: 'Updates' },
      { target: 'guardian-management-diagnostics', label: 'Diagnose', english: 'Diagnostics' },
    ],
  },
];

function readStatus(element: HTMLElement): DashboardStatus {
  const parsed: unknown = JSON.parse(element.dataset.status || '{}');
  if (!isRecord(parsed) || typeof parsed.available !== 'boolean' ||
      !isRecord(parsed.fail2ban) || typeof parsed.fail2ban.installed !== 'boolean' ||
      typeof parsed.fail2ban.running !== 'boolean' || !isFiniteNumber(parsed.fail2ban.jails) ||
      !Array.isArray(parsed.fail2ban.jailNames) ||
      !parsed.fail2ban.jailNames.every((name: unknown) => typeof name === 'string') ||
      !isFiniteNumber(parsed.fail2ban.banned) || !isFirewallStatus(parsed.firewall) ||
      (parsed.blockedIps !== null && !isFiniteNumber(parsed.blockedIps)) ||
      !isFiniteNumber(parsed.eventsTotal) || !Array.isArray(parsed.events) ||
      !parsed.events.every((event: unknown) => isRecord(event) &&
        typeof event.time === 'string' && typeof event.severity === 'string' &&
          typeof event.type === 'string' && typeof event.detail === 'string') ||
        typeof parsed.wafAvailable !== 'boolean' || typeof parsed.wafNote !== 'string' ||
        !Array.isArray(parsed.wafEvents) ||
        !parsed.wafEvents.every((event: unknown) => isRecord(event) &&
          (event.epoch === null || isFiniteNumber(event.epoch)) &&
          typeof event.rule === 'string' && typeof event.severity === 'string' &&
          (event.ip === null || typeof event.ip === 'string') && typeof event.blocked === 'boolean') ||
        !Array.isArray(parsed.incidents) ||
        !parsed.incidents.every((event: unknown) => isRecord(event) &&
          typeof event.time === 'string' && typeof event.type === 'string' &&
          typeof event.severity === 'string' && typeof event.domain === 'string' &&
          typeof event.path === 'string' && typeof event.detail === 'string')) {
    throw new Error('Sentinel dashboard data is invalid.');
  }
  return {
    available: parsed.available,
    fail2ban: {
      installed: parsed.fail2ban.installed,
      running: parsed.fail2ban.running,
      jails: parsed.fail2ban.jails,
      jailNames: parsed.fail2ban.jailNames,
      banned: parsed.fail2ban.banned,
    },
    firewall: parsed.firewall,
    blockedIps: parsed.blockedIps,
    eventsTotal: parsed.eventsTotal,
    events: parsed.events,
    wafAvailable: parsed.wafAvailable,
    wafNote: parsed.wafNote,
    wafEvents: parsed.wafEvents,
    incidents: parsed.incidents,
  };
}

function parseFail2banDetails(value: unknown): Fail2banDetails {
  if (!isRecord(value) || value.ok !== true || !isRecord(value.settings) ||
      typeof value.jail !== 'string' ||
      typeof value.managed !== 'boolean' || typeof value.override_sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.override_sha256) || !Array.isArray(value.backups) ||
      !value.backups.every(isFail2banBackup) ||
      !isNullableNumber(value.settings.maxretry) ||
      !isNullableNumber(value.settings.findtime) ||
      !isNullableNumber(value.settings.bantime) ||
      !isNullableNumber(value.settings.filter_regex_count) ||
      !Array.isArray(value.settings.actions) ||
      !value.settings.actions.every((action: unknown) => typeof action === 'string')) {
    throw new Error('Fail2ban detail response is invalid.');
  }
  return {
    jail: value.jail,
    managed: value.managed,
    override_sha256: value.override_sha256,
    backups: value.backups,
    settings: {
      maxretry: value.settings.maxretry,
      findtime: value.settings.findtime,
      bantime: value.settings.bantime,
      filter_regex_count: value.settings.filter_regex_count,
      actions: value.settings.actions,
    },
  };
}

function isFail2banBackup(value: unknown): value is Fail2banBackup {
  return isRecord(value) && typeof value.id === 'string' &&
    /^[a-f0-9]{32}$/.test(value.id) && typeof value.created_at === 'string';
}

function isFirewallInventoryItem(value: unknown): value is FirewallInventoryItem {
  return isRecord(value) && typeof value.id === 'string' && typeof value.name === 'string' &&
    (value.action === 'allow' || value.action === 'deny') &&
    typeof value.direction === 'string' && typeof value.source === 'string' &&
    typeof value.ports === 'string' && typeof value.class === 'string';
}

function isFirewallStatus(value: unknown): value is FirewallStatus {
  return isRecord(value) && typeof value.known === 'boolean' && typeof value.active === 'boolean' &&
    typeof value.installed === 'boolean' && typeof value.available === 'boolean' &&
    typeof value.inventoryLimited === 'boolean' && isRecord(value.counts) &&
    isFiniteNumber(value.counts.all) && isFiniteNumber(value.counts.inputAllow) &&
    isFiniteNumber(value.counts.inputDeny) && isFiniteNumber(value.counts.portAllow) &&
    isFiniteNumber(value.counts.portDeny) && Array.isArray(value.inventory) &&
    value.inventory.every(isFirewallInventoryItem);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || isFiniteNumber(value);
}

function navigateTo(target: string): void {
  const group = menu.find((entry) => entry.items.some((item) => item.target === target));
  if (!group) {
    throw new Error(`Guardian panel is unavailable: ${target}`);
  }
  window.dispatchEvent(new CustomEvent('guardian:navigate', { detail: { target } }));
}

function EventsModule({ status, language, exportUrl }: {
  status: DashboardStatus;
  language: 'de' | 'en';
  exportUrl: string;
}) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [range, setRange] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const isGerman = language === 'de';
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const cutoff = range === 'all' ? 0 : Date.now() - Number(range);
  const wafEvents = status.wafEvents.filter((event) => {
    const time = event.epoch === null ? 0 : event.epoch * 1000;
    const inRange = !cutoff || (time >= cutoff && time <= Date.now());
    const matchesSeverity = severity === 'all' || normalizeSeverity(event.severity) === severity;
    const searchable = `${event.rule} ${event.severity} ${event.ip || ''}`.toLocaleLowerCase();
    return inRange && matchesSeverity && (!normalizedQuery || searchable.includes(normalizedQuery));
  });
  const incidents = status.incidents.filter((event) => {
    const time = Date.parse(event.time);
    const inRange = !cutoff || (Number.isFinite(time) && time >= cutoff && time <= Date.now());
    const matchesSeverity = severity === 'all' || normalizeSeverity(event.severity) === severity;
    const searchable = `${event.type} ${event.severity} ${event.domain} ${event.path} ${event.detail}`.toLocaleLowerCase();
    return inRange && matchesSeverity && (!normalizedQuery || searchable.includes(normalizedQuery));
  });

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => window.location.reload(), 30000);
    return () => window.clearInterval(timer);
  }, [autoRefresh]);

  const formatTime = (epoch: number | null, isoTime?: string) => {
    const date = epoch === null ? (isoTime ? new Date(isoTime) : null) : new Date(epoch * 1000);
    return date && Number.isFinite(date.getTime())
      ? date.toLocaleString(isGerman ? 'de-DE' : 'en-GB')
      : '—';
  };
  const labels = isGerman
    ? {
      description: 'ModSecurity-WAF-Ereignisse und Guardian-Audit-Einträge aus den aktuell verfügbaren Serverdaten.',
      waf: 'Webschutz-Ereignisse', incidents: 'Guardian-Meldungen & Audit-Log',
      search: 'Ereignisse suchen', severity: 'Schweregrad', all: 'Alle',
      allTime: 'Gesamter verfügbarer Ausschnitt', day: 'Letzte 24 Stunden',
      week: 'Letzte 7 Tage', month: 'Letzte 30 Tage', auto: 'Automatisch aktualisieren (30 s)',
      time: 'Zeit', rule: 'Regel', ip: 'Quell-IP', blocked: 'Blockiert',
      yes: 'Ja', unknown: 'Unbekannt', type: 'Typ', location: 'Domain / Pfad',
      no: 'Nein', critical: 'Kritisch', error: 'Fehler', warning: 'Warnung',
      notice: 'Hinweis', info: 'Info',
      detail: 'Hinweis', export: 'Audit-Log als JSON exportieren',
      unavailable: 'ModSecurity-Audit-Log ist nicht verfügbar.',
      empty: 'Keine passenden Einträge im gewählten Zeitraum.',
      showing: 'angezeigt', countWaf: 'WAF-Ereignisse', countIncidents: 'Audit-Einträge',
    }
    : {
      description: 'ModSecurity WAF events and Guardian audit entries from currently available server data.',
      waf: 'Web protection events', incidents: 'Guardian incidents & audit log',
      search: 'Search events', severity: 'Severity', all: 'All',
      allTime: 'All available entries', day: 'Last 24 hours',
      week: 'Last 7 days', month: 'Last 30 days', auto: 'Auto-refresh (30 s)',
      time: 'Time', rule: 'Rule', ip: 'Source IP', blocked: 'Blocked',
      yes: 'Yes', unknown: 'Unknown', type: 'Type', location: 'Domain / path',
      no: 'No', critical: 'Critical', error: 'Error', warning: 'Warning',
      notice: 'Notice', info: 'Info',
      detail: 'Details', export: 'Export audit log as JSON',
      unavailable: 'ModSecurity audit log is unavailable.',
      empty: 'No matching entries in the selected range.',
      showing: 'shown', countWaf: 'WAF events', countIncidents: 'Audit entries',
    };

  return (
    <main className="sentinel-react-content sentinel-events" aria-label={labels.waf}>
      <p className="sentinel-module-description">{labels.description}</p>
      <div className="sentinel-event-toolbar">
        <label>{labels.search}<input type="search" maxLength={120} value={query} onChange={(event) => setQuery(event.currentTarget.value)} /></label>
        <label>{labels.severity}
          <select value={severity} onChange={(event) => setSeverity(event.currentTarget.value)}>
            <option value="all">{labels.all}</option>
              <option value="critical">{labels.critical}</option><option value="error">{labels.error}</option>
              <option value="warning">{labels.warning}</option><option value="notice">{labels.notice}</option>
              <option value="info">{labels.info}</option>
          </select>
        </label>
        <label>{isGerman ? 'Zeitraum' : 'Time range'}
          <select value={range} onChange={(event) => setRange(event.currentTarget.value)}>
            <option value="all">{labels.allTime}</option>
            <option value={String(24 * 60 * 60 * 1000)}>{labels.day}</option>
            <option value={String(7 * 24 * 60 * 60 * 1000)}>{labels.week}</option>
            <option value={String(30 * 24 * 60 * 60 * 1000)}>{labels.month}</option>
          </select>
        </label>
        <label className="sentinel-event-refresh"><input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.currentTarget.checked)} />{labels.auto}</label>
      </div>
      <section className="sentinel-event-table" aria-labelledby="sentinel-waf-events-title">
        <header><h2 id="sentinel-waf-events-title">{labels.waf}</h2><span>{wafEvents.length} {labels.showing} / {status.wafEvents.length} {labels.countWaf}</span></header>
        {!status.wafAvailable && <p className="sentinel-detail-error" role="status">{status.wafNote || labels.unavailable}</p>}
        <div className="sentinel-table-scroll"><table><thead><tr><th>{labels.time}</th><th>{labels.rule}</th><th>{labels.severity}</th><th>{labels.ip}</th><th>{labels.blocked}</th></tr></thead>
          <tbody>{wafEvents.map((event, index) => (
            <tr key={`${event.epoch}-${event.rule}-${index}`}>
              <td><time>{formatTime(event.epoch)}</time></td><td>{event.rule}</td>
              <td>{event.severity || '—'}</td><td><code>{event.ip || '—'}</code></td>
              <td>{event.blocked ? labels.yes : labels.no}</td>
            </tr>
          ))}</tbody></table></div>
        {status.wafAvailable && wafEvents.length === 0 && <p className="sentinel-detail-message">{labels.empty}</p>}
      </section>
      <section className="sentinel-event-table" aria-labelledby="sentinel-incidents-title">
        <header><h2 id="sentinel-incidents-title">{labels.incidents}</h2><span>{incidents.length} {labels.showing} / {status.incidents.length} {labels.countIncidents}</span></header>
        <div className="sentinel-table-scroll"><table><thead><tr><th>{labels.time}</th><th>{labels.severity}</th><th>{labels.type}</th><th>{labels.location}</th><th>{labels.detail}</th></tr></thead>
          <tbody>{incidents.map((event, index) => (
            <tr key={`${event.time}-${event.type}-${index}`}>
              <td><time dateTime={event.time}>{formatTime(null, event.time)}</time></td>
              <td>{event.severity || '—'}</td><td>{event.type}</td>
              <td>{[event.domain, event.path].filter(Boolean).join(' / ') || '—'}</td><td>{event.detail}</td>
            </tr>
          ))}</tbody></table></div>
        {incidents.length === 0 && <p className="sentinel-detail-message">{labels.empty}</p>}
        <a className="sentinel-event-export" href={exportUrl}>{labels.export}</a>
      </section>
    </main>
  );
}

function currentModuleTarget(): string | null {
  const activeLink = document.querySelector<HTMLAnchorElement>(
    '.guardian-menu-enhanced [data-menu-target][aria-current="location"]',
  );
  const target = activeLink?.dataset.menuTarget;
  return target && target !== 'guardian-dashboard-top' ? target : null;
}

const THEME_STORAGE_KEY = 'guardian-lite.sentinel.theme';

function readThemePreference(): boolean {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) !== 'light';
  } catch (error: unknown) {
    console.error('Sentinel theme preference could not be read.', error);
    return true;
  }
}

function App({ status, exportUrl }: { status: DashboardStatus; exportUrl: string }) {
  const [language, setLanguage] = useState<'de' | 'en'>('de');
  const [darkMode, setDarkMode] = useState(readThemePreference);
  const [activeGroup, setActiveGroup] = useState('overview');
  const [openGroup, setOpenGroup] = useState('');
  const [activeTarget, setActiveTarget] = useState<string | null>(currentModuleTarget);
  const [selectedJail, setSelectedJail] = useState(status.fail2ban.jailNames[0] || '');
  const [jailDetails, setJailDetails] = useState<Fail2banDetails | null>(null);
  const [jailDetailsError, setJailDetailsError] = useState('');
  const [jailDetailsLoading, setJailDetailsLoading] = useState(false);
  const [jailValues, setJailValues] = useState({ maxretry: '', findtime: '', bantime: '' });
  const [jailRefresh, setJailRefresh] = useState(0);
  const [jailSaving, setJailSaving] = useState(false);
  const [jailMutationError, setJailMutationError] = useState('');
  const [jailMutationMessage, setJailMutationMessage] = useState('');
  const activeMenuItem = menu.flatMap((group) =>
    group.items.map((item) => ({ ...item, group })),
  ).find((item) => item.target === activeTarget);

  useEffect(() => {
    const shell = document.querySelector('.guardian-shell');
    const page = document.querySelector('.guardian');
    if (!shell || !page) {
      throw new Error('Sentinel mount point is missing.');
    }
    document.getElementById('sentinel-app-root')?.removeAttribute('hidden');
    shell.classList.add('sentinel-ready');
    page.classList.add('sentinel-enabled');
    return () => {
      shell.classList.remove('sentinel-ready');
      page.classList.remove('sentinel-enabled', 'sentinel-dark', 'sentinel-light', 'sentinel-module-active', 'sentinel-dashboard-active', 'sentinel-react-page-active');
    };
  }, []);

  useEffect(() => {
    const target = activeTarget;
    const group = menu.find((entry) => entry.items.some((item) => item.target === target));
    if (group) {
      setActiveGroup(group.id);
    }
    document.querySelector('.guardian')?.classList.toggle('sentinel-module-active', Boolean(target));
    document.querySelector('.guardian')?.classList.toggle('sentinel-dashboard-active', !target);
    const isReactPage = target === 'guardian-waf-events' || target === 'guardian-incidents' || target === 'guardian-firewall';
    document.querySelector('.guardian')?.classList.toggle('sentinel-react-page-active', isReactPage);
    document.querySelector('.guardian')?.setAttribute('data-sentinel-target', target || '');
  }, [activeTarget]);

  useEffect(() => {
    const page = document.querySelector('.guardian');
    page?.classList.toggle('sentinel-dark', darkMode);
    page?.classList.toggle('sentinel-light', !darkMode);
    page?.setAttribute('data-sentinel-theme', darkMode ? 'dark' : 'light');
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, darkMode ? 'dark' : 'light');
    } catch (error: unknown) {
      console.error('Sentinel theme preference could not be saved.', error);
    }
  }, [darkMode]);

  useEffect(() => {
    if (!status.available || !selectedJail) {
      setJailDetails(null);
      setJailDetailsError('');
      setJailDetailsLoading(false);
      return;
    }
    const root = document.getElementById('sentinel-app-root');
    const endpoint = root?.dataset.fail2banUrl;
    if (!endpoint) {
      setJailDetailsError('Fail2ban-Statusroute fehlt.');
      return;
    }
    const url = new URL(endpoint, window.location.href);
    if (url.origin !== window.location.origin) {
      setJailDetailsError('Fail2ban-Statusroute ist nicht lokal.');
      return;
    }
    url.searchParams.set('jail', selectedJail);
    const controller = new AbortController();
    setJailDetails(null);
    setJailDetailsError('');
    setJailDetailsLoading(true);
    fetch(url, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    }).then((response) => {
      if (!response.ok) {
        throw new Error(`Fail2ban-Status konnte nicht geladen werden (HTTP ${response.status}).`);
      }
      return response.json() as Promise<unknown>;
    }).then((value) => {
      const details = parseFail2banDetails(value);
      setJailDetails(details);
      setJailValues({
        maxretry: details.settings.maxretry === null ? '' : String(details.settings.maxretry),
        findtime: details.settings.findtime === null ? '' : String(details.settings.findtime),
        bantime: details.settings.bantime === null ? '' : String(details.settings.bantime),
      });
    }).catch((error: unknown) => {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      setJailDetailsError(error instanceof Error ? error.message : 'Fail2ban-Status konnte nicht geladen werden.');
    }).finally(() => {
      if (!controller.signal.aborted) setJailDetailsLoading(false);
    });
    return () => controller.abort();
  }, [selectedJail, status.available, jailRefresh]);

  async function submitJailChange(values: Record<string, string>, urlKey: 'fail2banSetUrl' | 'fail2banRestoreUrl'): Promise<void> {
    const root = document.getElementById('sentinel-app-root');
    const endpoint = root?.dataset[urlKey];
    const csrf = root?.dataset.csrf;
    if (!endpoint || !csrf) {
      setJailMutationError(language === 'de' ? 'Plesk-Endpunkt oder CSRF-Token fehlt.' : 'Plesk endpoint or CSRF token is missing.');
      return;
    }
    const url = new URL(endpoint, window.location.href);
    if (url.origin !== window.location.origin) {
      setJailMutationError(language === 'de' ? 'Plesk-Endpunkt ist nicht lokal.' : 'Plesk endpoint is not local.');
      return;
    }
    setJailSaving(true);
    setJailMutationError('');
    setJailMutationMessage('');
    try {
      const body = new URLSearchParams({ ...values, csrf });
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
        body,
      });
      const result: unknown = await response.json();
      if (!response.ok || !isRecord(result) || result.ok !== true) {
        const message = isRecord(result) && typeof result.error === 'string'
          ? result.error : `HTTP ${response.status}`;
        throw new Error(message);
      }
      setJailMutationMessage(typeof result.message === 'string'
        ? result.message : (language === 'de' ? 'Fail2ban-Aktion abgeschlossen.' : 'Fail2ban action completed.'));
      setJailRefresh((value) => value + 1);
    } catch (error: unknown) {
      setJailMutationError(error instanceof Error ? error.message :
        (language === 'de' ? 'Fail2ban-Aktion fehlgeschlagen.' : 'Fail2ban action failed.'));
    } finally {
      setJailSaving(false);
    }
  }

  function applyJailSettings(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!jailDetails) return;
    const maxretry = Number(jailValues.maxretry);
    const findtime = Number(jailValues.findtime);
    const bantime = Number(jailValues.bantime);
    if (!Number.isInteger(maxretry) || maxretry < 1 || maxretry > 100 ||
        !Number.isInteger(findtime) || findtime < 1 || findtime > 604800 ||
        !Number.isInteger(bantime) || bantime < -1 || bantime > 31536000) {
      setJailMutationError(language === 'de'
        ? 'Erlaubt: MaxRetry 1–100, FindTime 1–604800 Sekunden, BanTime −1–31536000 Sekunden.'
        : 'Allowed: MaxRetry 1–100, FindTime 1–604800 seconds, BanTime −1–31536000 seconds.');
      return;
    }
    const confirmText = language === 'de'
      ? `Jail ${selectedJail} mit Backup ändern und Fail2ban neu laden? Bei Fehlern wird automatisch zurückgerollt.`
      : `Back up and change jail ${selectedJail}, then reload Fail2ban? Failures trigger automatic rollback.`;
    if (!window.confirm(confirmText)) return;
    void submitJailChange({
      jail: selectedJail,
      maxretry: String(maxretry),
      findtime: String(findtime),
      bantime: String(bantime),
      sha256: jailDetails.override_sha256,
    }, 'fail2banSetUrl');
  }

  function restoreJailBackup(backup: Fail2banBackup): void {
    if (!jailDetails) return;
    const confirmText = language === 'de'
      ? `Fail2ban-Jail ${selectedJail} auf das Backup vom ${backup.created_at} zurücksetzen? Die aktuelle Konfiguration wird vorher ebenfalls gesichert.`
      : `Restore Fail2ban jail ${selectedJail} from backup ${backup.created_at}? The current configuration will also be backed up first.`;
    if (!window.confirm(confirmText)) return;
    void submitJailChange({
      jail: selectedJail,
      backup_id: backup.id,
      sha256: jailDetails.override_sha256,
    }, 'fail2banRestoreUrl');
  }

  const labels = language === 'de'
    ? { subtitle: 'Sicherheitsverwaltung für Plesk', available: 'Serverstatus geladen', unavailable: 'Status nicht verfügbar', running: 'Aktiv', stopped: 'Gestoppt', missing: 'Nicht installiert', unknown: 'Unbekannt', blocked: 'Gesperrte IPs', jails: 'Aktive Jails', events: 'Ereignisse (max. 200)', firewall: 'Plesk-Firewall', recent: 'Letzte Ereignisse', noEvents: 'Keine Ereignisse gespeichert.', language: 'Sprache', theme: darkMode ? 'Helles Design' : 'Dunkles Design', apply: 'Änderungen sichern und anwenden', backups: 'Sichere Wiederherstellung', noBackups: 'Noch keine Fail2ban-Backups vorhanden.', restore: 'Wiederherstellen' }
    : { subtitle: 'Security management for Plesk', available: 'Server status loaded', unavailable: 'Status unavailable', running: 'Active', stopped: 'Stopped', missing: 'Not installed', unknown: 'Unknown', blocked: 'Blocked IPs', jails: 'Active jails', events: 'Events (max. 200)', firewall: 'Plesk firewall', recent: 'Recent events', noEvents: 'No events recorded.', language: 'Language', theme: darkMode ? 'Light theme' : 'Dark theme', apply: 'Back up and apply changes', backups: 'Safe restore points', noBackups: 'No Fail2ban backups yet.', restore: 'Restore' };
  const lang = language === 'de' ? 'label' : 'english';

  return (
    <>
      <aside className="sentinel-sidebar" aria-label={language === 'de' ? 'Hauptnavigation' : 'Main navigation'}>
        <a className="sentinel-brand" href="#guardian-dashboard-top" onClick={(event) => {
          event.preventDefault();
          setActiveGroup('overview');
          setOpenGroup('');
          setActiveTarget(null);
          navigateTo('guardian-dashboard-top');
        }}>
          <span className="sentinel-brand-mark" aria-hidden="true">S</span>
          <span><strong>Sentinel</strong><small>SECURITY</small></span>
        </a>
        <nav className="sentinel-nav" aria-label={language === 'de' ? 'Module' : 'Modules'}>
          {menu.map((group) => (
            <section className="sentinel-nav-group" key={group.id}>
              <button
                type="button"
                className={`${activeGroup === group.id ? 'is-active' : ''}${openGroup === group.id ? ' is-open' : ''}`}
                aria-expanded={openGroup === group.id}
                onClick={() => {
                  setActiveGroup(group.id);
                  setOpenGroup(openGroup === group.id ? '' : group.id);
                }}
              >
                <span>{language === 'de' ? group.label : group.english}</span><span aria-hidden="true">{openGroup === group.id ? '−' : '+'}</span>
              </button>
              {openGroup === group.id && (
                <ul>
                  {group.items.map((item) => (
                    <li key={item.target}>
                      <a href={`#${item.target}`} onClick={(event) => {
                        event.preventDefault();
                        navigateTo(item.target);
                        setActiveGroup(group.id);
                        setOpenGroup('');
                        setActiveTarget(item.target);
                      }}>{item[lang]}</a>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </nav>
        <div className="sentinel-sidebar-controls">
          <label htmlFor="sentinel-language">{labels.language}</label>
          <select id="sentinel-language" value={language} onChange={(event) => setLanguage(event.currentTarget.value === 'en' ? 'en' : 'de')}>
            <option value="de">Deutsch</option><option value="en">English</option>
          </select>
          <button
            type="button"
            className="sentinel-theme-toggle"
            aria-pressed={darkMode}
            aria-label={language === 'de'
              ? `Aktuelles Design: ${darkMode ? 'dunkel' : 'hell'}. ${darkMode ? 'Zum hellen Design wechseln' : 'Zum dunklen Design wechseln'}.`
              : `Current theme: ${darkMode ? 'dark' : 'light'}. Switch to ${darkMode ? 'light' : 'dark'} theme.`}
            onClick={() => setDarkMode((current) => !current)}
          >{labels.theme}</button>
        </div>
      </aside>
      {activeMenuItem && (
        <header className="sentinel-route-header">
          <p>{language === 'de' ? activeMenuItem.group.label : activeMenuItem.group.english}</p>
          <h1>{activeMenuItem[language === 'de' ? 'label' : 'english']}</h1>
        </header>
      )}
      {(activeTarget === 'guardian-waf-events' || activeTarget === 'guardian-incidents') && (
        <EventsModule status={status} language={language} exportUrl={exportUrl} />
      )}
      {activeTarget === 'guardian-firewall' && <PleskFirewallModule firewall={status.firewall} language={language} />}
      {activeTarget === 'guardian-settings-overview' && (
        <SettingsModule language={language} onNavigate={(target) => {
          navigateTo(target);
          setActiveGroup('settings');
          setOpenGroup('');
          setActiveTarget(target);
        }} />
      )}
      <section className="sentinel-overview" hidden={Boolean(activeTarget)} aria-label={language === 'de' ? 'Sicherheitsstatus' : 'Security status'}>
        <header className="sentinel-overview-heading">
          <div><p>{labels.subtitle}</p><h1>Sentinel Security</h1></div>
          <span className={`sentinel-live-state ${status.available ? 'is-live' : 'is-unknown'}`}>
            <i aria-hidden="true" />{status.available ? labels.available : labels.unavailable}
          </span>
        </header>
        <div className="sentinel-kpis">
          <article><span>{labels.jails}</span><strong>{status.available ? status.fail2ban.jails : '—'}</strong><small>{status.available ? (status.fail2ban.running ? labels.running : status.fail2ban.installed ? labels.stopped : labels.missing) : labels.unknown}</small></article>
          <article><span>{labels.blocked}</span><strong>{status.available && status.blockedIps !== null ? status.blockedIps : '—'}</strong><small>{status.available ? status.fail2ban.banned : labels.unknown} {language === 'de' ? 'aus Fail2ban gesperrt' : 'banned by Fail2ban'}</small></article>
          <article><span>{labels.firewall}</span><strong>{status.available ? (status.firewall.active ? labels.running : status.firewall.known ? labels.stopped : labels.unknown) : '—'}</strong><small>{status.available ? (status.firewall.active ? 'Plesk' : language === 'de' ? 'Dienststatus' : 'Service status') : labels.unknown}</small></article>
          <article><span>{labels.events}</span><strong>{status.available ? status.eventsTotal : '—'}</strong><small>{labels.recent}</small></article>
        </div>
        <section className="sentinel-fail2ban" aria-labelledby="sentinel-fail2ban-heading">
          <div className="sentinel-fail2ban-heading">
            <h2 id="sentinel-fail2ban-heading">{language === 'de' ? 'Fail2ban · Jail-Details' : 'Fail2ban · jail details'}</h2>
            {status.fail2ban.jailNames.length > 0 && (
              <label>
                <span className="sentinel-visually-hidden">{language === 'de' ? 'Jail auswählen' : 'Select jail'}</span>
                <select value={selectedJail} onChange={(event) => setSelectedJail(event.currentTarget.value)}>
                  {status.fail2ban.jailNames.map((name) => <option key={name} value={name}>{name}</option>)}
                </select>
              </label>
            )}
          </div>
          {jailDetailsLoading && <p className="sentinel-detail-message" aria-live="polite">{language === 'de' ? 'Effektive Fail2ban-Konfiguration wird gelesen …' : 'Reading effective Fail2ban configuration …'}</p>}
          {jailDetailsError && <p className="sentinel-detail-error" role="alert">{jailDetailsError}</p>}
          {jailDetails && (
            <>
              <dl className="sentinel-jail-settings">
                <div><dt>MaxRetry</dt><dd>{jailDetails.settings.maxretry ?? '—'}</dd></div>
                <div><dt>{language === 'de' ? 'FindTime' : 'Find time'}</dt><dd>{jailDetails.settings.findtime === null ? '—' : `${jailDetails.settings.findtime} s`}</dd></div>
                <div><dt>{language === 'de' ? 'BanTime' : 'Ban time'}</dt><dd>{jailDetails.settings.bantime === null ? '—' : jailDetails.settings.bantime < 0 ? (language === 'de' ? 'Dauerhaft' : 'Permanent') : `${jailDetails.settings.bantime} s`}</dd></div>
                <div><dt>{language === 'de' ? 'Aktive Filter-Regexe' : 'Active filter regexes'}</dt><dd>{jailDetails.settings.filter_regex_count ?? '—'}</dd></div>
                <div><dt>{language === 'de' ? 'Jail-Actions' : 'Jail actions'}</dt><dd>{jailDetails.settings.actions.length ? jailDetails.settings.actions.join(', ') : '—'}</dd></div>
              </dl>
              <p className="sentinel-detail-note">{language === 'de' ? 'Effektive Laufzeitwerte von Fail2ban. Änderungen verwenden eine separate Guardian-Datei; Plesk-Konfigurationen werden nicht überschrieben.' : 'Effective Fail2ban runtime values. Changes use a separate Guardian file and do not overwrite Plesk configuration.'}</p>
              <form className="sentinel-fail2ban-form" onSubmit={applyJailSettings}>
                <h3>{language === 'de' ? 'Jail-Einstellungen' : 'Jail settings'}</h3>
                <label>MaxRetry
                  <input type="number" min="1" max="100" step="1" required
                    value={jailValues.maxretry}
                    onChange={(event) => setJailValues({ ...jailValues, maxretry: event.currentTarget.value })} />
                </label>
                <label>{language === 'de' ? 'FindTime (Sekunden)' : 'Find time (seconds)'}
                  <input type="number" min="1" max="604800" step="1" required
                    value={jailValues.findtime}
                    onChange={(event) => setJailValues({ ...jailValues, findtime: event.currentTarget.value })} />
                </label>
                <label>{language === 'de' ? 'BanTime in Sekunden (−1 = dauerhaft)' : 'Ban time in seconds (−1 = permanent)'}
                  <input type="number" min="-1" max="31536000" step="1" required
                    value={jailValues.bantime}
                    onChange={(event) => setJailValues({ ...jailValues, bantime: event.currentTarget.value })} />
                </label>
                <p className="sentinel-detail-note">{jailDetails.managed
                  ? (language === 'de' ? 'Dieses Jail enthält einen Guardian-Override.' : 'This jail has a Guardian override.')
                  : (language === 'de' ? 'Das Jail wird derzeit nicht durch Sentinel überschrieben.' : 'This jail is not currently overridden by Sentinel.')}</p>
                <button type="submit" disabled={jailSaving || jailDetailsLoading}>
                  {jailSaving ? (language === 'de' ? 'Wird geprüft und angewendet …' : 'Testing and applying …') : labels.apply}
                </button>
              </form>
              <section className="sentinel-fail2ban-backups" aria-label={labels.backups}>
                <h3>{labels.backups}</h3>
                {jailDetails.backups.length
                  ? <ul>{jailDetails.backups.map((backup) => (
                    <li key={backup.id}>
                      <time dateTime={backup.created_at}>{backup.created_at}</time>
                      <button type="button" disabled={jailSaving || jailDetailsLoading}
                        onClick={() => restoreJailBackup(backup)}>{labels.restore}</button>
                    </li>
                  ))}</ul>
                  : <p>{labels.noBackups}</p>}
              </section>
            </>
          )}
          {jailMutationError && <p className="sentinel-detail-error" role="alert">{jailMutationError}</p>}
          {jailMutationMessage && <p className="sentinel-detail-success" role="status">{jailMutationMessage}</p>}
          {!status.fail2ban.jailNames.length && <p className="sentinel-detail-message">{language === 'de' ? 'Keine aktiven Jails verfügbar.' : 'No active jails available.'}</p>}
        </section>
        <div className="sentinel-recent-events">
          <h2>{labels.recent}</h2>
          {status.available && status.events.length > 0 ? (
            <ul>{status.events.slice(0, 3).map((event, index) => {
              const severity = ['critical', 'error', 'warning'].includes(event.severity.toLowerCase())
                ? event.severity.toLowerCase() : 'info';
              return <li key={`${event.time}-${index}`}><span className={`sentinel-severity severity-${severity}`}>{event.severity}</span><span><strong>{event.type}</strong><small>{event.detail || event.time}</small></span></li>;
            })}</ul>
          ) : <p>{status.available ? labels.noEvents : labels.unavailable}</p>}
          <button type="button" onClick={() => {
            navigateTo('guardian-incidents');
            setActiveGroup('incidents');
            setActiveTarget('guardian-incidents');
          }}>
            {language === 'de' ? 'Ereignisprotokoll öffnen' : 'Open event log'} <span aria-hidden="true">→</span>
          </button>
        </div>
      </section>
    </>
  );
}

const mount = document.getElementById('sentinel-app-root');
if (mount) {
  const root = createRoot(mount);
  const exportUrl = mount.dataset.incidentsExportUrl || '';
  const exportLink = exportUrl ? new URL(exportUrl, window.location.href) : null;
  if (!exportLink || exportLink.origin !== window.location.origin) {
    throw new Error('Sentinel export route is invalid.');
  }
  root.render(<App status={readStatus(mount)} exportUrl={exportLink.href} />);
}
