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

type DashboardStatus = {
  available: boolean;
  fail2ban: { installed: boolean; running: boolean; jails: number; jailNames: string[]; banned: number };
  firewall: { known: boolean; active: boolean };
  blockedIps: number | null;
  eventsTotal: number;
  events: EventRow[];
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
      !isFiniteNumber(parsed.fail2ban.banned) || !isRecord(parsed.firewall) ||
      typeof parsed.firewall.known !== 'boolean' || typeof parsed.firewall.active !== 'boolean' ||
      (parsed.blockedIps !== null && !isFiniteNumber(parsed.blockedIps)) ||
      !isFiniteNumber(parsed.eventsTotal) || !Array.isArray(parsed.events) ||
      !parsed.events.every((event: unknown) => isRecord(event) &&
        typeof event.time === 'string' && typeof event.severity === 'string' &&
        typeof event.type === 'string' && typeof event.detail === 'string')) {
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
    firewall: { known: parsed.firewall.known, active: parsed.firewall.active },
    blockedIps: parsed.blockedIps,
    eventsTotal: parsed.eventsTotal,
    events: parsed.events,
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
  const links = document.querySelectorAll<HTMLAnchorElement>('.guardian-menu-enhanced [data-menu-target]');
  const link = Array.from(links).find((candidate) => candidate.dataset.menuTarget === target);
  if (!link) {
    throw new Error(`Guardian panel is unavailable: ${target}`);
  }
  link.click();
}

function App({ status }: { status: DashboardStatus }) {
  const [language, setLanguage] = useState<'de' | 'en'>('de');
  const [darkMode, setDarkMode] = useState(true);
  const [activeGroup, setActiveGroup] = useState('overview');
  const [selectedJail, setSelectedJail] = useState(status.fail2ban.jailNames[0] || '');
  const [jailDetails, setJailDetails] = useState<Fail2banDetails | null>(null);
  const [jailDetailsError, setJailDetailsError] = useState('');
  const [jailDetailsLoading, setJailDetailsLoading] = useState(false);
  const [jailValues, setJailValues] = useState({ maxretry: '', findtime: '', bantime: '' });
  const [jailRefresh, setJailRefresh] = useState(0);
  const [jailSaving, setJailSaving] = useState(false);
  const [jailMutationError, setJailMutationError] = useState('');
  const [jailMutationMessage, setJailMutationMessage] = useState('');

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
      page.classList.remove('sentinel-enabled', 'sentinel-dark');
    };
  }, []);

  useEffect(() => {
    const activeLink = document.querySelector<HTMLAnchorElement>(
      '.guardian-menu-enhanced [data-menu-target][aria-current="location"]',
    );
    const target = activeLink?.dataset.menuTarget;
    const group = menu.find((entry) => entry.items.some((item) => item.target === target));
    if (group) {
      setActiveGroup(group.id);
    }
  }, []);

  useEffect(() => {
    document.querySelector('.guardian')?.classList.toggle('sentinel-dark', darkMode);
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
          navigateTo('guardian-dashboard-top');
          setActiveGroup('overview');
        }}>
          <span className="sentinel-brand-mark" aria-hidden="true">S</span>
          <span><strong>Sentinel</strong><small>SECURITY</small></span>
        </a>
        <nav className="sentinel-nav" aria-label={language === 'de' ? 'Module' : 'Modules'}>
          {menu.map((group) => (
            <section className="sentinel-nav-group" key={group.id}>
              <button
                type="button"
                className={activeGroup === group.id ? 'is-active' : ''}
                aria-expanded={activeGroup === group.id}
                onClick={() => setActiveGroup(activeGroup === group.id ? '' : group.id)}
              >
                <span>{language === 'de' ? group.label : group.english}</span><span aria-hidden="true">{activeGroup === group.id ? '−' : '+'}</span>
              </button>
              {activeGroup === group.id && (
                <ul>
                  {group.items.map((item) => (
                    <li key={item.target}>
                      <a href={`#${item.target}`} onClick={(event) => {
                        event.preventDefault();
                        navigateTo(item.target);
                        setActiveGroup(group.id);
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
          <button type="button" className="sentinel-theme-toggle" onClick={() => setDarkMode(!darkMode)}>{labels.theme}</button>
        </div>
      </aside>
      <section className="sentinel-overview" aria-label={language === 'de' ? 'Sicherheitsstatus' : 'Security status'}>
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
          <button type="button" onClick={() => navigateTo('guardian-incidents')}>
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
  root.render(<App status={readStatus(mount)} />);
}
