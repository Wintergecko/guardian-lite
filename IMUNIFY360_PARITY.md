# Imunify360-Funktionsabgleich fuer Guardian Lite

Stand: 2026-11-05. Grundlage ist die oeffentliche Imunify360-Produktdokumentation. Dieses Dokument trennt vorhandene Guardian-Funktionen von echter Funktionsgleichheit und externen Abhaengigkeiten.

## Kurzfassung

Guardian Lite deckt bereits Teilbereiche der Malware-Erkennung, Quarantaene, Dateiueberwachung, PHP-Konfiguration, Web-Anmeldeschutz, ModSecurity und Ereignisverwaltung ab. Das ist noch keine Imunify360-Paritaet.

Imunify360 kombiniert einen serverweiten Netzwerk-Firewall-Agenten, dynamische IP-Reputationslisten und Challenge-Proxy, verwaltete WAF-/Angriffsdaten, Live-Datei- und Upload-Scanning, Cloud-gestuetzte Malware-Erkennung, PHP-Verhaltensanalyse, Datenbankbereinigung, Reputationspruefung und optionales Kernel-Patching. Teile davon haengen von CloudLinux-Daten, lizenzierten Diensten oder KernelCare ab; dieselben Erkennungsdaten und proprietaeren Algorithmen kann Guardian nicht aus der Produktdokumentation nachbauen. Guardian kann vergleichbare Ablaufe mit offen verfuegbaren Signaturen, explizit gewaehlen APIs und eigenen Integrationen bereitstellen, muss diese Herkunft aber klar ausweisen.

## Funktionsabgleich

| Imunify360-Bereich | Guardian Lite heute | Fuer vergleichbare Funktion fehlt |
|---|---|---|
| Malwaredatei-Scan, Bericht und Historie | Manuelle und geplante ClamAV-Scans pro Domain, Berichte, Historie, FIFO-Warteschlange bis 100 und strikt serielle Worker mit niedriger CPU-Prioritaet | Flexible Zeitplaene, gezielte globale Scan-Auftraege, sichtbare feinere Ressourcenbudgets und ressourcenschonendes Wiederholungsscanning |
| RapidScan / Cloud-Scan | Lokaler Cache fuer unveraenderte, saubere Dateien; gebunden an Dateisystem-Metadaten, ClamAV-Binary und Signaturdatei-Metadaten; Cache ist begrenzt und invalidiert bei Aenderung | Kein Cloud-Hashabgleich/Whitelist-Feed und keine 5–20x-Leistungszusage; externe Reputations-/Hashquelle benoetigt Datenschutz-/Anbieterfreigabe |
| System- und Benutzer-Cronjobs | Read-only Heuristiken plus optional lokaler ClamAV-Signaturscan der erfassten Cron-Dateien; 4-MiB-/45-Sekunden-Grenzen, zeigt Regel/Pfad/Zeile oder Signaturname, aendert nichts | Erweiterte Distributionenabdeckung und kuratierte, mit echten Plesk-Distributionen validierte Erkennungsregeln; lokale ClamAV-Signaturen sind kein vollstaendiger Malware-Nachweis |
| Live-Datei- und Upload-Scanning | Opt-in inotify-Wache mit gezielter ClamAV-Pruefung | fanotify-Abdeckung, FTP-/HTTP-Upload-Hooks, Dateiarchiv-Workflows, Overflow-/Wiederanlauf-Abdeckung und nachvollziehbare Vollstaendigkeit |
| Bereinigung und Wiederherstellung | Manuelle Quarantaene; opt-in Reparatur nur aus bestaetigter Baseline nach sauberem Vollscan; Storage-Ansicht, 512-MiB-Baseline- und 256-MiB-/200-Eintraege-Backup-Quota sowie bestaetigte manuelle Loeschung | Sichere Vorschlaege fuer unbekannte Funde, granularere Aufbewahrungsregeln, Backup-Import und Bulk-Aktionen |
| Ignore List | SHA-256-Ignore-Liste je Domain plus globale domainuebergreifende Hash-Ausnahmen; Inhalte werden weiter gescannt und als ignoriert angezeigt, Warnung/Reparatur wird fuer exakten Inhalt unterdrueckt | Kontrollierte Pfad-Ausnahmen mit Erklaerung/Audit; globale Ausnahmen haben bewusst groesseren Wirkungsradius als Imunify-Pfadfilter |
| Malware Database Scanner | Teilabdeckung: WordPress-SQL-Heuristik plus optionale direkte ClamAV-Streams fuer WordPress, Joomla und Magento (512-MiB-/5-Minuten-Limit; kein Dump auf Platte); Joomla/Magento-Konfigurationswerte werden statisch geparst und Passwoerter nur temporaer in einer privaten Clientdatei genutzt | Keine Imunify-MDS-Signaturen, Datenbankbereinigung, Backup oder Rollback; dynamische PHP-Konfigurationen und andere Datenbanktreiber werden abgelehnt; grosse Datenbanken koennen das Scanlimit ueberschreiten |
| Hersteller-Pruefsummen fuer CMS-Dateien | WordPress-Core und Plugins via WP-CLI; WordPress.org-Themes werden read-only mit dem HTTPS-Archiv der exakt installierten Version verglichen | Eigene/kommerzielle Theme-Versionen koennen ungeprueft bleiben; Theme-Archiv ist kein signierter Pruefwert; Joomla/Magento, vollstaendige Good-File-Backups und Reparatur fehlen |
| PHP Proactive Defense | Snuffleupagus-Installation, feste Regeln zum Blockieren bestimmter Shell-Funktionen; kein Aufruf-/Verhaltensmonitor | Instrumentierung/Telemetrie je Handler, Log-only-Policy, reproduzierbare Test-Signaturen, Ereigniszuordnung und dann vorsichtige Blockierregeln. Das ist kein gleichwertiges ML-/Cloud-Modell. |
| WAF / Managed ModSecurity | Loganzeige und eine Guardian-Regeldatei fuer begrenzte Host-/IP-Ratenlimits | Verwaltete, signierte Regelpakete mit sicherem Update/Rollback, Regel-Ausnahmen, Regeln pro Domain und strukturierte Incidents |
| Netzwerk-Firewall / IP-Listen | Manuelle Guardian-Deny-Regeln in aktiver Plesk Firewall fuer IPv4/IPv6 und Netze bis /24 bzw. /64; Admin-IP-Schutz, 1h/24h/7d TTL und Plesk-60-Sekunden-Rollback. Quell-IP-gebundene TCP-/UDP-Portfreigaben fuer einzelne IPs und Portsperren fuer begrenzte Quellnetze; Entfernen nur eigener Regeln per ID. Kommentierte Guardian-IP-Ausnahmen verhindern eigene Guardian-Deny-Aktionen fuer diese Netze, aendern aber keine Plesk-/Provider-Regel. | Echte Firewall-weite Allowlist-Prioritaet, Greylist, zeitbegrenzte Portregeln, globale blockierte Ports, Bedrohungsfeeds und provider-unabhaengige Firewall |
| Greylist / Anti-Bot-Challenge | Cloudflare Turnstile auf bestimmten PHP-Anmeldepfaden | Generische HTTP-Request-Challenge vor der Anwendung, zeitweise Greylist von Angreifer-IPs, CDN-real-IP-Integration, API/Webhook-Ausnahmen und missbrauchssichere Freigabe |
| Rate Limits / DoS | Feste Guardian-Regelvorlage fuer einen Host auf Apache ModSecurity | Auswertbare Limits je Host/Pfad/Port, adaptive Erkennung, Aktionen `log/allow/deny/challenge`, laufende Metriken und abgestufter Schutz. Kein volumetrischer DDoS-Schutz auf Anwendungsebene. |
| Website-/IP-Reputation | Manuelle AbuseIPDB-Abfrage einzelner IPs | Regelmaessige pruefbare Domain-/IP-Abfragen, mehrere Quellen, nachvollziehbare Treffer und Freigabe vor Firewall-Aktion |
| IDS / Incidents | ModSecurity-Logs, Fail2Ban-Status, Guardian-Incidents | OSSEC/aehnliche Server-Audit-Sensoren, Ereigniskorrelation, Severity, Land/ASN-Zuordnung, Filter und Zeitreihen-Dashboard |
| Brute-Force fuer SSH/Mail | Bestehende Fail2Ban-Jails anzeigen und manuell bedienen | Vorgepruefte Jail-Vorlagen und Zuordnung von Login-Fehlern zu zeitlich begrenzten Aktionen. PAM/Dovecot-/Exim-Module muessen mit Plesk-Diensten kompatibel getestet werden. |
| Benachrichtigungen und Hooks | Gedrosselte Mailwarnungen und JSON-Ereignisexport | Zuverlaessige Warteschlange/Retry, konfigurierbare Ereignistypen, sichere lokale Hooks/Webhooks und Zustellstatus |
| Admin-Tools-Erkennung | Begrenzte read-only Kandidatenpruefung fuer Adminer/TinyFileManager nach Dateiname und Quelltextmarker; getrennte Warnung mit SHA-256, keine Dateiaktion | Breitere, gepflegte Tool-/Versionsmarker und weitere Testfixtures. Imunify kann solche Dateien automatisch leeren; Guardian fordert manuelle Bewertung und Aktion |
| Low-Resource-Modus | Kein globaler Ressourcenmodus; einzelne Scanner/Waechter sind begrenzt | Sichtbare CPU-/RAM- und Zeitbudgets mit pausierbaren Hintergrundaufgaben. Schutzmodule duerfen dabei nicht stillschweigend abgeschaltet werden |
| KernelCare / Patch Management | Nicht umgesetzt | Status-/Lizenzintegration mit KernelCare. Rebootlose Kernel-Patches sind ein separater, lizenzierter Dienst und werden nicht von Guardian selbst entwickelt. |
| Dashboard, Advisor, Nutzerfunktionen | Plesk-Statuskarten, JSON-Diagnose, Admin-Aktionen | Zeitreihen/Heatmaps, Sicherheits-Advisor, rollen-/kundenbezogene Freigaben und Feature-Steuerung pro Subscription |

## Plesk-Geltungsbereich

Die Dokumentation enthaelt auch cPanel-, WHMCS- und DirectAdmin-Funktionen. Sie gehoeren nicht zur Plesk-Erweiterung. Insbesondere cPanel-only Exim/Dovecot-/Panel-Challenges werden nicht als Guardian-Plesk-Funktionen behandelt. Ein Plesk-Feature muss die Plesk-API, Abonnementgrenzen, Domain-/Handlerzuordnung und Deinstallations-Ruecknahme verwenden.

## Zusaetzliche Doku-Funktionen und genaue Abgrenzung

Die Imunify360-Dokumentation beschreibt auch die folgenden Oberflaechen- und Betriebsfunktionen. Sie sind Teil des Paritaetsziels, sofern sie auf Plesk sinnvoll und ohne Imunify-Lizenz oder proprietaere Cloud-Daten umsetzbar sind:

| Dokumentierter Bereich | Guardian-Abdeckung | Konsequenz fuer die Roadmap |
|---|---|---|
| Firewall-Listen: Blacklist, Whitelist, Greylist und gesperrte Ports | Manuelle Guardian-IP-Deny-Regeln mit TTL plus quell-IP-gebundene Port-Allow-/Deny-Regeln ueber Plesks Firewall; Guardian-interne kommentierte Ausnahmeliste schuetzt nur vor kuenftigen eigenen Sperren. Kein globales Plesk-Whitelist-/Greylist-Modell oder globale Port-Policy-Verwaltung | Echte Allowlist-Prioritaet nur mit dokumentierter Plesk-Regelprioritaet bzw. getesteter Firewall-Integration. Auf separater Testinstanz mit regulaerer Admin-Verbindung pruefen; keine parallelen iptables/nftables-Regeln einfuehren. |
| Externe IP-Listen und globale Malware-Hash-Ausnahmen | Globale 2.000-Eintraege-SHA-256-Ausnahmeliste plus domainbezogene Ausnahmen; kommentierte Guardian-IP-Ausnahmen fuer eigene deny-Aktionen; keine externen IP-Feeds oder firewall-weite globale Allowlist | Externe/weite Listen brauchen Herkunft, Aktualitaet, Kommentar, atomare Validierung und Konfliktregeln. Guardian-Ausnahmen duerfen nicht als Plesk-/Provider-Freischaltung missverstanden werden. |
| WebShield: Under Attack Mode, Greylist-Challenge, L7-Rate-Limits und CDN-Real-IP | Turnstile nur fuer bestimmte PHP-Loginpfade; Apache-ModSecurity-Vorlage fuer einen Host | Generische Challenge und Grenzwerte koennen nur als sichere Plesk-/Proxy-Integration umgesetzt werden. Vor Aktivierung muessen echte Client-IP, CDN-Vertrauen, API-Ausnahmen und Caching getestet sein. |
| Malware-Dateiverwaltung: Trefferstatus, Cleanup, Delete, Restore, Ignore und Verlauf | Guardian hat Scanberichte, manuelle Quarantaene und baselinegestuetzte Reparatur mit Rollback; keine Bulk-Aktionen oder automatische Bereinigung | Funktionen erweitern, ohne unbekannte Funde automatisch zu veraendern. Jede Reparatur braucht gepruefte Quelle, Vorher-Backup, Konflikterkennung und Ruecknahme. |
| Dashboard, Vorfallsfilter, Zeitreihen, Heatmaps und Advisor | Statuskarten, Diagnose, JSON-Export und Incident-Protokoll; keine zeitbasierte Korrelation/Heatmaps oder Empfehlungspruefung | Vereinheitlichte, filterbare Incident-Daten vor Visualisierungen; Empfehlungen zunaechst nur read-only und mit Erklaerung. |
| Benachrichtigungen und Ereignis-Hooks | Gedrosselte E-Mail-Warnungen und JSON-Export; keine konfigurierbaren lokalen Hooks/Webhooks mit Retry-Status | Ereignistypen, sichere feste Zieltypen und Zustellwarteschlange ergaenzen; keine beliebigen Shell-Kommandos aus der UI. |
| Einstellungen: Low-Resource-Modus, WAF-Regelversionen und signierte Regelupdates | Einzelne Aufgaben sind begrenzt; keine globale Ressourcensteuerung und keine verwalteten signierten ModSecurity-Pakete | Sichtbare Ressourcenbudgets und ein unabhaengiger, signierter WAF-Regelkanal mit Test, Reload-Healthcheck und Rollback waeren noetig. |
| Reputation, KernelCare und Multi-Server-Dashboard | Einzelne manuelle AbuseIPDB-Abfrage; KernelCare-/Mehrserverstatus nicht vorhanden | Reputation kann nur nach expliziter Anbieterzustimmung abgefragt werden. KernelCare bleibt eine optionale TuxCare-Integration; Mehrserverfunktionen benoetigen ein eigenes authentifiziertes Transport- und Rollenmodell. |

Die Doku-Hauptseite fuehrt Imunify AV/AV+, Imunify Email und Imunify Patch als separate Produktdokumentationen auf. Diese sind nicht automatisch Bestandteil der Guardian-Lite-Plesk-Erweiterung; eine spaetere Integration waere ein eigener, optionaler Connector. Ebenso ist ein lokaler ClamAV-Scan keine Gleichheit mit Imunify-eigenen Cloud-Signaturen, RapidScan-Hashdiensten oder der Malware Database Scanner-Bereinigung samt CSV-Restore.

## Umsetzung in sicheren Abschnitten

1. **Malware-Arbeitsablauf:** SHA-256-Ausnahmen je Domain, WordPress-Core-/Plugin-Pruefsummen, WordPress.org-Theme-Archivvergleich, WordPress-Datenbankindikatoren und optionale lokale ClamAV-Streamscans fuer WordPress/Joomla/Magento; danach CMS-Herstellerquellen sowie ein Datenbank-Backup/Rollback vor jeglicher Bereinigung. Lokale ClamAV-Treffer und Datenbankheuristiktreffer bleiben Hinweise; unbekannte Dateifunde bleiben bis zur Freigabe unveraendert.
2. **Ereignisse und Abwehr:** Vereinheitlichte Incidents aus ClamAV, ModSecurity, Fail2Ban und PHP-Proben; filterbarer Verlauf; E-Mail-Warteschlange und sichere, feste Webhook/Hooks.
3. **HTTP/WAF:** Signierte Regelquellen, klare Versions-/Regel-Ausnahmen, Testmodus, spezifische Pfad-/IP-Ratenlimits und Wiederherstellung bei fehlgeschlagenem Reload.
4. **Netzwerk-IP-Schutz:** Guardian-Deny-Regeln und quell-IP-gebundene Port-Allow-/Deny-Regeln verwenden Plesks native Firewall mit getrenntem Verbindungstest und Rollback; Guardian-IP-Ausnahmen schuetzen vor versehentlichen eigenen Sperren. Eine Plesk-weite priorisierte Allowlist bleibt offen, bis ihr Verhalten gegen Systemrichtlinien auf dem separaten Plesk-VPS bestaetigt ist. Danach AbuseIPDB-Freigabeworkflow und CIDR-/Porttests. Kein paralleler nftables-/iptables-Backendmix.
5. **PHP-Laufzeiterkennung:** Zunaechst messbarer Log-Modus mit Testfixtures und PHP-Handlermatrix; Blockieren bleibt Opt-in und wird nur fuer nachweislich abgedeckte Handler angeboten.
6. **Datenbank und externe Dienste:** Read-only SQL-Scan und Anbieter-/Datenschutzentscheidung vor Bereinigung oder neuen Cloud-Reputationsquellen.
7. **Optionale Betriebssystem-Patches:** KernelCare-Status/Integration separat; keine automatische Kernel-/Paketaktualisierung innerhalb der Guardian-Erweiterung.
8. **Server-Integritaet:** Cronjob-Signaturpruefung und Heuristiken mit Distributionenpfaden und Testfixtures erweitern; danach Systemdienst-/Konfigurationsauffaelligkeiten und weitere Admin-Tool-Marker erfassen. Nur lesend und mit manueller Bewertung.

Alle systemweiten Aktionen bleiben standardmaessig aus und werden ausschliesslich auf dem separaten Plesk-Testserver geprueft. Keine echte Plesk-Installation oder Firewall-Aktivierung wird durch CI vorgetaeuscht.

## Quellen

- [Imunify360 overview](https://docs.imunify360.com/introduction/)
- [Imunify360 feature configuration](https://docs.imunify360.com/features/)
- [Imunify360 admin dashboard, firewall, incidents, reputation and KernelCare](https://docs.imunify360.com/dashboard/)
- [Imunify360 end-user files, history, ignore list and WebShield](https://docs.imunify360.com/user_interface/)
- [Imunify360 installation, Plesk compatibility and conflicting firewall tooling](https://docs.imunify360.com/installation/)
- [Plesk Firewall custom IP/port rules and separate-connection confirmation](https://support.plesk.com/hc/en-us/articles/12377519983511-How-to-manage-local-firewall-rules-using-Plesk-Firewall-in-Plesk-for-Linux)
- [Plesk Firewall apply, confirmation and automatic rollback behavior](https://support.plesk.com/hc/en-us/articles/12376965151383-How-does-the-Plesk-Firewall-CLI-tool-update-and-restore-configuration)
- [WP-CLI core checksum verification](https://developer.wordpress.org/cli/commands/core/verify-checksums/)
- [WP-CLI database export to stdout](https://developer.wordpress.org/cli/commands/db/export/)
- [ClamAV scan input modes and size limits](https://docs.clamav.net/manual/Usage/Scanning.html)
- [WordPress.org Theme API](https://developer.wordpress.org/reference/functions/themes_api/)
- [Admin interface: Malware Scanner, Proactive Defense, reputation and KernelCare](https://docs.imunify360.com/dashboard/)
- [User interface: customer-facing WebShield](https://docs.imunify360.com/user_interface/)
- [Installation requirements and panel compatibility](https://docs.imunify360.com/installation/)
