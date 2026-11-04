## 0.13.0 – Zeitbegrenzte Plesk-Firewall-Sperren

- Guardian-Firewall-Regeln koennen dauerhaft oder fuer 1 Stunde, 24 Stunden beziehungsweise 7 Tage gesetzt werden.
- Ablaufzeiten werden erst nach erfolgreicher Plesk-Bestaetigung gespeichert; der stündliche Plesk-Scheduler nimmt nur Guardian-eigene Regeln zurueck.
- Automatische Entsperrung nutzt Plesks Apply/Confirm-Rollback und protokolliert Fehler; maximal zehn abgelaufene Regeln werden pro Lauf bearbeitet.
- Dashboard zeigt Ablaufzeiten und weist auf bis zu eine Stunde Scheduler-Verzoegerung hin.
- Regressionstests fuer TTL-Validierung, Ablaufmetadaten, sichere Entsperrung und Panel-Weitergabe.

## 0.12.0 – Plesk-Firewall-IP-Sperrliste

- Manuelle IP-/CIDR-Deny-Regeln ausschliesslich ueber die installierte Plesk-Firewall-CLI.
- Admin-Verbindungs-IP wird vor Sperren abgeglichen; IPv4-Netze breiter als /24, IPv6 breiter als /64 sowie lokale/reservierte Netze werden abgelehnt.
- Jede Aenderung nutzt Plesks 60-Sekunden-Rollback und bleibt unbestaetigt, bis ein separater Verbindungstest bestaetigt wurde.
- Fremde Plesk-Regeln werden nicht bearbeitet; Firewall-Aktivierung und automatische Reputation bleiben aus.
- Tests fuer Regelisolation, Lockout-Schutz, CIDR-Grenzen, Rollback/Bestaetigung und CSRF-geschuetzten Panel-Aufruf.

## 0.11.0 – WordPress.org-Pluginpruefsummen

- Manuelle WP-CLI-Pruefung fuer installierte Plugins mit verfuegbaren WordPress.org-Pruefsummen.
- Kommerzielle/eigene Plugins ohne oeffentliche Pruefsummen werden als nicht geprueft aufgelistet; der Status bleibt teilweise statt sauber.
- Treffer laufen als Website-UID, werden getrennt vom Core-Bericht gespeichert und veraendern keine Dateien.
- Regressionstests fuer Plugin-Abweichungen, ausgelassene kommerzielle Plugins, sicheren Aufruf und Statuskennzeichnung.

## 0.10.0 – WordPress-Core-Pruefsummen

- Neue manuelle Pruefung vergleicht WordPress-Core-Dateien ueber WP-CLI mit WordPress.org-Pruefsummen.
- WP-CLI laeuft mit festen Argumenten und Umgebungsvariablen als Website-UID, ohne Plugins/Themes/Packages und ohne unsicheren TLS-Fallback.
- Treffer werden begrenzt im Panel/Incident-Log gezeigt. Kein automatisches Reparieren; Plugins, Themes und eigene Dateien bleiben ausserhalb dieser Core-Pruefung.
- Regressionstests fuer saubere und abweichende Core-Dateien, sichere Ausgabe und unveraenderte Website-Dateien.

## 0.9.1 – Plattformunabhaengige Release-Pakete

- Der ZIP-Build normalisiert jetzt auch eingebettete Markdown-Dateien in Unterordnern auf LF, damit Windows- und Linux-Builds dieselben Paketdateiinhalte enthalten.
- Regressionstest fuer die Zeilenenden im Security-Dokument.

## 0.9.0 – Cronjob-Sicherheitspruefung

- Neue read-only Admin-Pruefung ueblicher System- und Benutzer-Cronpfade auf ausgewaehlte verdächtige Befehlsmuster.
- Ergebnis zeigt nur Quelle, Zeile, Regel und Schweregrad; Cronjob-Inhalte werden nicht exportiert und nichts wird automatisch geaendert oder geloescht.
- Gepruefte Grenzen (Anzahl/Groesse), ausgelassene Quellen und heuristischer Charakter werden im Ergebnis ausgewiesen; Funde gehen in den Incident-Verlauf.
- Regressionstest fuer Erkennung, Symlink-Ausschluss und Unveraendertheit der Cron-Dateien.

## 0.8.0 – Malware-Ignore-Liste und Imunify360-Abgleich

- Plesk-Admin kann exakte Datei-SHA-256-Funde je Domain administrativ ignorieren und wieder freigeben. Treffer bleiben sichtbar/gescannt; Warnung und automatische Baseline-Reparatur werden fuer diesen Inhalt unterdrueckt.
- Ignore-Liste hat Domain-/Gesamtlimits, Audit-Vorfaelle und Schutz fuer manuelle/automatische Reparatur gegen veraltete Berichte.
- Vollscan, Live-Wache, Scanbericht und Historie zeigen die Ausnahmen getrennt an.
- Imunify360-Paritaetsabgleich mit Produktgrenzen und priorisiertem Plesk-Implementierungsplan ergaenzt.

## 0.7.1 – Abhaengigkeiten und Firewall-Status

- Plesk-Firewall-Erkennung prueft die aktuellen sowie bisherigen systemd-Service-Namen und unterscheidet installierte Erweiterung von aktivierten Regeln.
- Funktionsbezogene Betriebssystem- und Plesk-Komponenten dokumentiert; unnoetige globale Paketinstallation vermeiden.

## 0.7.0 – Opt-in-Schutzverwaltung und Diagnose

- Neuer Tab Verwaltung & Diagnose mit CSRF-geschuetzten festen Aktionen; Plesk >=18.0.55 wegen sicherer stdin-Uebergabe erforderlich.
- Snuffleupagus 0.14.0 aus festem Upstream-Commit als eigener Build-Benutzer installieren; Simulation/Aktivierung mit PHP-Probe, FPM-Konfigurationspruefung, Backup und Rollback.
- Guardian-ModSecurity-Regeln mit Vorschau, IP-Limit, Erkennungs-/Sperrmodus, Include-/Syntaxpruefung, Apache-Reload und Rollback; Domain-WAF-Modus via Plesk CLI.
- AbuseIPDB: ausdrueckliche Zustimmung, oeffentliche IPs, feste HTTPS-API, Schema-Pruefung und Stunden-Cache.
- Turnstile fuer PHP-Anmeldepfade via .user.ini: serverseitige Tokenvalidierung, signierte Clearance-Cookies, Ruecknahme mit Aenderungspruefung.
- Admin-freigegebene Good-File-Baselines; opt-in automatische Reparatur passender Vollscan-Funde, Originale in Quarantaene und kontrollierter Rollback. Kein Hersteller-Abgleich.
- Diagnose-JSON und optional kurzlebige HTTPS-PHP-Probe fuer Plesk-Praxistests.
- Neue isolierte Management-, PHP-HTTP- und echte Apache/ModSecurity-HTTP-Tests. Echte Plesk-Integrationstests fuehrt der Betreiber separat durch.

## 0.6.4 – Zuverlaessige Scanplanung und Verzeichniswechsel

- Geplante Scans ermitteln den letzten Lauf aus allen aufbewahrten Berichten; die Anzeigegrenze von 30 Berichten beeinflusst den 24-Stunden-Abstand nicht mehr.
- Live-Dateiwache entfernt Watches verschobener/geloeschter Teilbaeume und erfasst hineingeschobene Verzeichnisse unter ihrem neuen Pfad. Bei verschobenem/geloeschtem Document-Root wird der Monitor beendet.
- Regressionstests fuer viele neuere manuelle Scans sowie heraus- und hineinverschobene verschachtelte Verzeichnisse.
- Funktionsliste und Dokumentation auf den aktuellen Implementierungsstand gebracht.
- Plesk-End-to-End-Pruefung erfolgt separat auf dem Testserver; keine automatische Aktivierung zusaetzlicher Schutzregeln.

## 0.6.3 – Plesk-Document-Root-Resolver und automatische Release-Veröffentlichung

- Scanner, geplante Scans, Dateiwache und Quarantaene verwenden den zu jeder Domain in der Plesk-Hosting-Datenbank gespeicherten Document-Root statt `/var/www/vhosts/<domain>/httpdocs`.
- Zusatzdomains in gemeinsamen Abonnements und individuell konfigurierte Document-Roots werden unterstuetzt.
- Sicherheitspruefung: Kanonischer Pfad muss unter dem zugeordneten Plesk-Webspace liegen, ausserhalb liegende Symlinks sowie root-eigene Ziele werden abgelehnt.
- Plesk-Domainliste zeigt nur Domains mit Website-Hosting; der letzte manuelle Scan-Zielname bleibt bei der Rueckmeldung erhalten.
- Neue Tests fuer Zusatzdomains, Webspace-Isolation und Plesk-Datenbankantworten.
- Diese Version wird per freigegebenem GitHub-Release-Workflow nach bestandenen Tests veroeffentlicht.

## 0.6.2 – Domainauswahl und Scanplanung in Plesk

- Alle Formularaktionen benutzen die offizielle Plesk-URL via pm_Context::getActionUrl.
- Erzwungene kontrastreiche Auswahlfeld-Farben, unabhaengig von Plesk-Skins; ausgewaehlte Domain wird zusaetzlich als Text angezeigt.
- Opt-in-Planungsaktionen zeigen Erfolg oder Fehler direkt im Malware-Tab, auch nach einem Redirect.
- Der Malware-Tab bleibt nach Scan-/Planungsaktionen geoeffnet.
- Scanplanung validiert die Antwort des privilegierten Helfers, bevor Erfolg angezeigt wird.
- Tests fuer Plesk-Formular-URLs, Domainanzeige, Statusfeedback und Version.
- Keine automatisch aktivierten Scans, WAF- oder PHP-Schutzregeln. Kein echter VPS-End-to-End-Test.

## 0.6.1 – Update-Pruefung zeigt zuverlaessig Rueckmeldung

- Update-Formular nutzt offizielle Plesk-Action-URLs.
- Nach dem POST bleibt der Updates-Tab ueber URL-Fragment aktiv.
- Letzter Pruefstatus und GitHub-Fehler werden in Plesk sichtbar gespeichert.
- Pruefresultat ist maximal 30 Minuten lang zur Installationsbestaetigung gueltig.
- Der Button zeigt unmittelbar nach dem Absenden eine Statusmeldung.
- Keine stillen automatischen Updates; Installation weiterhin nur mit Admin-Bestaetigung.

## 0.6.0 – Opt-in-Echtzeit-Dateiwache und Incident-Zentrale

- Linux-inotify Echtzeitueberwachung pro freigegebener Plesk-Domain (max. 5 Domains / 450 Verzeichnisse je Domain), standardmaessig AUS.
- Neue/geaenderte PHP-Dateien: optionale ClamAV-Einzeldateipruefung als Website-UID, ohne automatische Dateiveraenderungen.
- Root-private Incident-Protokollierung mit begrenzter Groesse und JSON-Export aus Plesk (nur Administrator).
- Opt-in E-Mail-Warnungen fuer ClamAV-Malwareereignisse ueber lokalen Mail-Transport; Versand gedrosselt und Testfunktion.
- Neue Plesk-Registerkarte „Incidents“ mit Echtzeitmonitor, Protokoll und E-Mail-Konfiguration.
- Dry-run-nahe PHP-Handler-Konfigurationssicherung plus SHA-geschuetzter manueller Rollback-CLI-Helfer; keine Aktivierung auf Live-Websites.
- Beispiel eines stufenweisen ModSecurity-Botlimits (zunaechst nur Monitoring, keine automatische Sperre).
- GitHub CI mit Python 3.11 bis 3.13 und Ubuntu 22.04/24.04; echte Plesk-Multidistributions-Integrationstests stehen aus.
- Keine vollautomatische Malware-Reparatur, Snuffleupagus-Aktivierung, Bot-Challenges oder Cloud-Reputation ohne produktiv getestete Voraussetzungen.

## 0.5.2 – Updater-Button immer sichtbar

- Das Guardian-Repository Wintergecko/guardian-lite wird automatisch als Default verwendet, wenn noch keine Repository-Einstellung gespeichert ist.
- Die Schaltflaeche zum Pruefen auf neue Versionen ist im Updates-Tab immer sichtbar und kann ohne vorheriges Speichern benutzt werden.
- Manuell gespeicherte vertrauenswuerdige Repositories bleiben erhalten.
- Versionsnummern und Tests aktualisiert. Keine automatische Installation oder Aenderung aktiver Schutzregeln.

## 0.5.1 – GitHub-Updater Release-Pipeline repariert

- GitHub Actions testet die root-gebundenen Helper-Funktionen mit Root-Rechten auf isolierten Runnern.
- Python-3.11-kompatibles Path-Mocking im PHP-Runtime-Test.
- Release-Workflow baut erst nach bestandenen Tests eine installierbare ZIP-Datei mit SHA-256.
- Keine automatischen Änderungen am Schutzstatus, WAF, PHP oder Firewall.

## 0.5.0 – Uebersichtliche Plesk-Tabs und Feature-Liste

- Fuenf Bereiche: Uebersicht, Malware & Dateien, Angriffe & Schutz, Updates, Feature-Liste.
- Tastaturbedienbare Tabs mit ARIA-Rollen, Hash-Links und Wiederherstellung des letzten Tabs.
- Alle vorhandenen Formulare und POST-Aktionen bleiben bestehen.
- Ohne JavaScript bleiben alle Abschnitte sichtbar.
- Feature-Liste unterscheidet implementierte, manuell vorbereitete und offene Funktionen.
- Die Laufzeit-/Bot-Policies werden weiterhin nicht automatisch aktiviert.

## 0.4.1

- Updater-Repository-Feld akzeptiert nun owner/repo oder vollständige GitHub-URL.
- Prüfung, ob die Repository-Einstellung gespeichert wurde.
- Hinweis: Private GitHub-Releases sind noch nicht mit dem Updater nutzbar.

# 0.4.0 – PHP-Runtime-/HTTP-Bot-Integration (Opt-in)

- Konservative Anzeige von Plesk-PHP-Konfigurationen und WAF-Log-Bereitschaft.
- Snuffleupagus- und ModSecurity-Regelvorlagen mit Test-/Rollback-Hinweisen; standardmaessig deaktiviert.
- Keine automatischen produktiven Firewall-, NGINX-, PHP- oder WAF-Aenderungen.

# Changelog

## 0.3.0 – 2026-11-04

- Opt-in-Scanplanung ueber Plesk-Scheduler; stündliche Faelligkeitspruefung und Schutz vor parallelen Scans.
- Root-private Scan-Historie mit Einzelberichten und Rotation aelterer sauberer Berichte.
- Admin-bestaetigte Quarantaene und Wiederherstellung mit Fingerprint-, Pfad- und Nicht-Ueberschreiben-Pruefungen.
- Lesende WAF-Ereignisuebersicht aus dem Plesk-ModSecurity-Audit-Log.
- Manuelle Fail2Ban-IP-Sperre und Entsperre mit Validierung.
- Periodische Metadaten-Dateiaenderungspruefung fuer Websites mit aktivierter Planung.
- Erweiterte Tests, Datenschutz- und Sicherheitsdokumentation.
- GitHub-Release-Updater mit manueller Installation, ZIP-Verifikation und Release-Build-Workflow.

## 0.1.0

- Erstes Admin-Dashboard fuer Fail2Ban/ModSecurity/Firewall, manueller ClamAV-On-Demand-Scan.
