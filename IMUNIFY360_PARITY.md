# Imunify360-Funktionsabgleich fuer Guardian Lite

Stand: 2026-11-04. Grundlage ist die oeffentliche Imunify360-Produktdokumentation. Dieses Dokument trennt vorhandene Guardian-Funktionen von echter Funktionsgleichheit und externen Abhaengigkeiten.

## Kurzfassung

Guardian Lite deckt bereits Teilbereiche der Malware-Erkennung, Quarantaene, Dateiueberwachung, PHP-Konfiguration, Web-Anmeldeschutz, ModSecurity und Ereignisverwaltung ab. Das ist noch keine Imunify360-Paritaet.

Imunify360 kombiniert einen serverweiten Netzwerk-Firewall-Agenten, dynamische IP-Reputationslisten und Challenge-Proxy, verwaltete WAF-/Angriffsdaten, Live-Datei- und Upload-Scanning, Cloud-gestuetzte Malware-Erkennung, PHP-Verhaltensanalyse, Datenbankbereinigung, Reputationspruefung und optionales Kernel-Patching. Teile davon haengen von CloudLinux-Daten, lizenzierten Diensten oder KernelCare ab; dieselben Erkennungsdaten und proprietaeren Algorithmen kann Guardian nicht aus der Produktdokumentation nachbauen. Guardian kann vergleichbare Ablaufe mit offen verfuegbaren Signaturen, explizit gewaehlen APIs und eigenen Integrationen bereitstellen, muss diese Herkunft aber klar ausweisen.

## Funktionsabgleich

| Imunify360-Bereich | Guardian Lite heute | Fuer vergleichbare Funktion fehlt |
|---|---|---|
| Malwaredatei-Scan, Bericht und Historie | Manuelle und geplante ClamAV-Scans pro Domain, Berichte, Historie, FIFO-Warteschlange bis 100 und strikt serielle Worker mit niedriger CPU-Prioritaet | Flexible Zeitplaene, gezielte globale Scan-Auftraege, sichtbare feinere Ressourcenbudgets und ressourcenschonendes Wiederholungsscanning |
| RapidScan / Cloud-Scan | Begrenzter Metadatenvergleich; ClamAV scannt weiterhin lokal | Verifizierter Hash-Cache und externe Reputations-/Hashquelle; Lizenz-/Datenschutzentscheidung fuer Cloud-Abfragen |
| System- und Benutzer-Cronjobs | Neue read-only Heuristikpruefung gaengiger System-/Benutzer-Cronpfade; zeigt Fundregel, Quelldatei und Zeilennummer, aendert nichts | Erweiterte Distributionenabdeckung, kuratierte Erkennungsregeln und validierte Testfixtures; keine vollstaendige Malware-Erkennung |
| Live-Datei- und Upload-Scanning | Opt-in inotify-Wache mit gezielter ClamAV-Pruefung | fanotify-Abdeckung, FTP-/HTTP-Upload-Hooks, Dateiarchiv-Workflows, Overflow-/Wiederanlauf-Abdeckung und nachvollziehbare Vollstaendigkeit |
| Bereinigung und Wiederherstellung | Manuelle Quarantaene; opt-in Reparatur nur aus bestaetigter Baseline nach sauberem Vollscan | Sichere Vorschlaege fuer unbekannte Funde, Backup-Wiederherstellung, Aufbewahrungs-/Quota-Verwaltung und Bulk-Aktionen |
| Ignore List / Erkennung von Admin-Tools | SHA-256-Ignore-Liste pro Domain; exakter Inhalt bleibt im Scanbericht sichtbar und wird weiter gescannt, aber nicht automatisch repariert oder gemeldet | Sichere Pfadausnahmen, CMS-/Regel-bezogene Ausnahmen und nachvollziehbare Admin-Tool-Erkennung; bekannte Werkzeuge nur melden, nie ohne Freigabe loeschen |
| Malware Database Scanner | Nicht umgesetzt | Read-only SQL-Scanner fuer WordPress/Joomla/Magento, anschliessend optionale Bereinigung mit konsistentem DB-Backup und Rollback |
| Hersteller-Pruefsummen fuer CMS-Dateien | WordPress-Core und Plugins via WP-CLI gegen WordPress.org, als Website-UID; Plugins ohne verfuegbare Checksums werden als unvollstaendig angezeigt | Themes, Joomla/Magento, vollstaendige Good-File-Backups und signierte Pruefwerte fehlen; keine Reparatur |
| PHP Proactive Defense | Snuffleupagus-Installation, feste Regeln zum Blockieren bestimmter Shell-Funktionen; kein Aufruf-/Verhaltensmonitor | Instrumentierung/Telemetrie je Handler, Log-only-Policy, reproduzierbare Test-Signaturen, Ereigniszuordnung und dann vorsichtige Blockierregeln. Das ist kein gleichwertiges ML-/Cloud-Modell. |
| WAF / Managed ModSecurity | Loganzeige und eine Guardian-Regeldatei fuer begrenzte Host-/IP-Ratenlimits | Verwaltete, signierte Regelpakete mit sicherem Update/Rollback, Regel-Ausnahmen, Regeln pro Domain und strukturierte Incidents |
| Netzwerk-Firewall / IP-Listen | Manuelle Guardian-Deny-Regeln in aktiver Plesk Firewall fuer IPv4/IPv6 und Netze bis /24 bzw. /64; Admin-IP-Schutz, 1h/24h/7d TTL und Plesk-60-Sekunden-Rollback. Stuendlicher Scheduler verarbeitet bis zu zehn Ablaufe pro Lauf; Rueckstaende werden protokolliert. | Allow-/Greylist, Kommentare, automatisierte Bedrohungsfeeds, Portregeln, provider-unabhaengige Firewall und vollstaendige Statusabdeckung |
| Greylist / Anti-Bot-Challenge | Cloudflare Turnstile auf bestimmten PHP-Anmeldepfaden | Generische HTTP-Request-Challenge vor der Anwendung, zeitweise Greylist von Angreifer-IPs, CDN-real-IP-Integration, API/Webhook-Ausnahmen und missbrauchssichere Freigabe |
| Rate Limits / DoS | Feste Guardian-Regelvorlage fuer einen Host auf Apache ModSecurity | Auswertbare Limits je Host/Pfad/Port, adaptive Erkennung, Aktionen `log/allow/deny/challenge`, laufende Metriken und abgestufter Schutz. Kein volumetrischer DDoS-Schutz auf Anwendungsebene. |
| Website-/IP-Reputation | Manuelle AbuseIPDB-Abfrage einzelner IPs | Regelmaessige pruefbare Domain-/IP-Abfragen, mehrere Quellen, nachvollziehbare Treffer und Freigabe vor Firewall-Aktion |
| IDS / Incidents | ModSecurity-Logs, Fail2Ban-Status, Guardian-Incidents | OSSEC/aehnliche Server-Audit-Sensoren, Ereigniskorrelation, Severity, Land/ASN-Zuordnung, Filter und Zeitreihen-Dashboard |
| Brute-Force fuer SSH/Mail | Bestehende Fail2Ban-Jails anzeigen und manuell bedienen | Vorgepruefte Jail-Vorlagen und Zuordnung von Login-Fehlern zu zeitlich begrenzten Aktionen. PAM/Dovecot-/Exim-Module muessen mit Plesk-Diensten kompatibel getestet werden. |
| Benachrichtigungen und Hooks | Gedrosselte Mailwarnungen und JSON-Ereignisexport | Zuverlaessige Warteschlange/Retry, konfigurierbare Ereignistypen, sichere lokale Hooks/Webhooks und Zustellstatus |
| Admin-Tools-Erkennung | Nicht gesondert umgesetzt; SHA-256-Ausnahmen muessen manuell gepflegt werden | Erkennung bekannter Datei-Manager/Administrationswerkzeuge als eigener Befundtyp. Nicht mit Malware gleichsetzen und niemals ungefragt entfernen |
| Low-Resource-Modus | Kein globaler Ressourcenmodus; einzelne Scanner/Waechter sind begrenzt | Sichtbare CPU-/RAM- und Zeitbudgets mit pausierbaren Hintergrundaufgaben. Schutzmodule duerfen dabei nicht stillschweigend abgeschaltet werden |
| KernelCare / Patch Management | Nicht umgesetzt | Status-/Lizenzintegration mit KernelCare. Rebootlose Kernel-Patches sind ein separater, lizenzierter Dienst und werden nicht von Guardian selbst entwickelt. |
| Dashboard, Advisor, Nutzerfunktionen | Plesk-Statuskarten, JSON-Diagnose, Admin-Aktionen | Zeitreihen/Heatmaps, Sicherheits-Advisor, rollen-/kundenbezogene Freigaben und Feature-Steuerung pro Subscription |

## Plesk-Geltungsbereich

Die Dokumentation enthaelt auch cPanel-, WHMCS- und DirectAdmin-Funktionen. Sie gehoeren nicht zur Plesk-Erweiterung. Insbesondere cPanel-only Exim/Dovecot-/Panel-Challenges werden nicht als Guardian-Plesk-Funktionen behandelt. Ein Plesk-Feature muss die Plesk-API, Abonnementgrenzen, Domain-/Handlerzuordnung und Deinstallations-Ruecknahme verwenden.

## Umsetzung in sicheren Abschnitten

1. **Malware-Arbeitsablauf:** SHA-256-Ausnahmen je Domain sowie WordPress-Core-/Plugin-Pruefsummen (implementiert); danach Scan-Warteschlange, flexible Zeitplaene, lokale Hash-Caches, weitere CMS-Hersteller-Pruefsummen und sichtbare Quota/Aufbewahrung. Unbekannte Funde bleiben bis zur Freigabe unveraendert.
2. **Ereignisse und Abwehr:** Vereinheitlichte Incidents aus ClamAV, ModSecurity, Fail2Ban und PHP-Proben; filterbarer Verlauf; E-Mail-Warteschlange und sichere, feste Webhook/Hooks.
3. **HTTP/WAF:** Signierte Regelquellen, klare Versions-/Regel-Ausnahmen, Testmodus, spezifische Pfad-/IP-Ratenlimits und Wiederherstellung bei fehlgeschlagenem Reload.
4. **Netzwerk-IP-Schutz:** Guardian-Deny-Regeln verwenden Plesks native Firewall mit Rollback und begrenzten Ablaufzeiten; danach priorisierte Allow-/Notfalllisten, AbuseIPDB-Freigabeworkflow und CIDR-Tests auf dem separaten Plesk-VPS. Kein paralleler nftables-/iptables-Backendmix.
5. **PHP-Laufzeiterkennung:** Zunaechst messbarer Log-Modus mit Testfixtures und PHP-Handlermatrix; Blockieren bleibt Opt-in und wird nur fuer nachweislich abgedeckte Handler angeboten.
6. **Datenbank und externe Dienste:** Read-only SQL-Scan und Anbieter-/Datenschutzentscheidung vor Bereinigung oder neuen Cloud-Reputationsquellen.
7. **Optionale Betriebssystem-Patches:** KernelCare-Status/Integration separat; keine automatische Kernel-/Paketaktualisierung innerhalb der Guardian-Erweiterung.
8. **Server-Integritaet:** Cronjob-Heuristiken um Distributionenpfade und Testfixtures erweitern; danach Systemdienst-/Konfigurationsauffaelligkeiten und erkannte Admin-Werkzeuge in den Incident-Verlauf aufnehmen. Nur lesend und mit manueller Bewertung.

Alle systemweiten Aktionen bleiben standardmaessig aus und werden ausschliesslich auf dem separaten Plesk-Testserver geprueft. Keine echte Plesk-Installation oder Firewall-Aktivierung wird durch CI vorgetaeuscht.

## Quellen

- [Imunify360 overview](https://docs.imunify360.com/introduction/)
- [Imunify360 feature configuration](https://docs.imunify360.com/features/)
- [Admin interface: Malware Scanner, Proactive Defense, reputation and KernelCare](https://docs.imunify360.com/dashboard/)
- [User interface: customer-facing WebShield](https://docs.imunify360.com/user_interface/)
- [Installation requirements and panel compatibility](https://docs.imunify360.com/installation/)
