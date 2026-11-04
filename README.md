# Guardian Lite 0.16.0 – Plesk Security (Linux)

Open-Source-Sicherheitszentrale fuer Plesk Obsidian **18.0.55 oder neuer** auf Linux, Python >=3.8. Beta: aktive Schutzfunktionen zuerst auf einem separaten Testserver pruefen. Keine offizielle Plesk-/Imunify360-Software.

## Funktionsumfang

| Bereich | Implementiert | Grenze / Voraussetzung |
|---|---|---|
| ClamAV | Manuelle und pro Domain aktivierbare geplante Vollscans, Berichte, Historie, exakte SHA-256-Ignore-Liste je Domain | `clamscan` und aktuelle Signaturen separat installieren; Debian/Ubuntu: `apt install clamav clamav-freshclam`; Ignore markiert bekannte Hashes weiter im Bericht |
| Scanplanung | Stuendlicher Plesk-Task; FIFO-Warteschlange bis 100 Auftraege, einzelne Scans mit niedriger CPU-Prioritaet, mindestens 24h Abstand zwischen Scanstarts je Domain | Keine parallelen Scans; Scans brauchen weiterhin ClamAV lokal |
| Document-Roots | Aufloesung aus Plesk-Hostingdaten, einschliesslich Zusatzdomains | Ziel muss im zugeordneten Webspace liegen und nicht root-eigen sein |
| Quarantaene | Manuelles Verschieben verifizierter Funde und Wiederherstellen | Fingerprint-Kontrolle; kein Ueberschreiben; gleiches Dateisystem erforderlich |
| Dateiwache | Opt-in-inotify und gezielte ClamAV-Einzeldateipruefung | Maximal 5 Domains / 450 Verzeichnisse je Domain; keine Ausfuehrungsblockade |
| Metadatenvergleich | Periodische Stichprobe fuer Domains mit Scanplanung | Bis 1500 Dateien; keine vollstaendige Integritaetspruefung |
| Incidents / E-Mail | Privates Ereignisprotokoll, JSON-Export, gedrosselte Warnungen | Mailtransport lokal erforderlich; Uebergabe ist kein Zustellnachweis |
| Fail2Ban | Status bestehender Jails und manuelle IP-Sperren/-Freigaben | `fail2ban-client` und konfigurierte Jails; erstellt keine Jails oder globale Firewall-Policies |
| Plesk Firewall | Manuelle Guardian-Deny-Regeln fuer IPv4/IPv6 und CIDR; optionale 1h/24h/7d Ablaufzeit, stuendlicher Ablauf-Worker, Plesk-60-Sekunden-Rollback und Admin-IP-Schutz | Plesk Firewall installiert und aktiv; getrennten Verbindungstest vor expliziter Bestaetigung ausfuehren; keine automatischen Reputations-Sperren |
| WAF | ModSecurity-Loganzeige, Domain-Modus und Guardian-Regelverwaltung | Apache ModSecurity v2, `mod_unique_id` und `SecDataDir` erforderlich; Plesk-WAF muss fuer Blockieren aktiv sein |
| HTTP-Botlimits | Guardian-Regeln fuer einen Zielhost, Vorschau, Erkennen/429-Sperren, Rollback | Korrekte Real-IP-Konfiguration; kein Netzwerk-DDoS-Schutz |
| PHP-Runtime | Snuffleupagus-Build aus festem Commit, Simulation, Aktivierung | Passendes Plesk-Entwicklerpaket plus git/gcc/make/autoconf; PHP 8.0–8.5; pro Handler wirksam |
| PHP-Backup/Rollback | GUI mit Fingerprint-Pruefung, Recovery-Backup und FPM-Pruefung/Reload | Echte Plesk-Requests und Handler-Zuordnung auf dem Testserver pruefen |
| Good-File-Reparatur | Baselines, manuelle und opt-in automatische Reparatur nach Vollscans, Rollback | Admin-freigegebene Quelle; keine Hersteller-Signatur; unbekannte Dateien bleiben unveraendert |
| Speicherverwaltung | Speicherbedarf und freier Datentraeger; Baseline-Quota 512 MiB, Backup-Quota 256 MiB / 200 Eintraege; manuelle Loeschung | Keine automatische Bereinigung; aktive Rollback-Quellen sind geschuetzt |
| Admin-Tool-Pruefung | Domain-Scan erkennt begrenzt Adminer/TinyFileManager-Kandidaten und zeigt sie getrennt von Malware | Namens-/Quelltextmarker sind heuristisch und keine vollstaendige Tool-Datenbank; keine automatische Aenderung |
| Cloud-Reputation | Manuelle AbuseIPDB-Abfrage, Schema-Pruefung und Stunden-Cache | Eigener API-Key und Zustimmung; keine automatischen Meldungen/Sperren |
| Bot-Challenges | Cloudflare Turnstile auf ausgewaehlten PHP-Anmeldepfaden | Eigene Keys, HTTPS, PHP-cURL fuer den Domain-Handler, freie auto_prepend_file-Konfiguration |
| Diagnose | Sanitisiertes JSON und optionale kurzlebige HTTPS-PHP-Probe | Plesk-Praxistests fuehrt der Betreiber durch |
| Cronjob-Audit | Manuelle read-only Heuristikpruefung ueblicher System-/Benutzer-Cronpfade, Treffer im Incident-Verlauf | Wenige verdächtige Muster; keine vollstaendige Malware-Erkennung und keine Aenderungen an Jobs |
| WordPress-Core | Manuelle WordPress.org-Pruefsummenverifikation via WP-CLI und HTTPS | Root-eigene WP-CLI-Binary und ausgehendes HTTPS; keine Plugins, Themes oder automatische Reparatur |
| WordPress.org-Plugins | Manuelle Pruefung mit WP-CLI, nicht abgedeckte Plugins werden als uebersprungen aufgefuehrt | Nur Plugins mit WordPress.org-Pruefsummen; kommerzielle/eigene Plugins bleiben ungeprueft; keine Reparatur |
| GitHub-Updater | Oeffentliche Releases pruefen und nach Admin-Klick installieren | Passendes ZIP und GitHub-SHA-256 erforderlich; keine stillen Updates |

Alle neuen aktiven Funktionen sind standardmaessig aus. Details zu Aktivierung, Grenzen, Voraussetzungen und Fehlerfaellen stehen in [MANAGEMENT.md](MANAGEMENT.md).

Der systematische Funktionsabgleich und die Plesk-spezifische Umsetzungsreihenfolge sind in [IMUNIFY360_PARITY.md](IMUNIFY360_PARITY.md) dokumentiert. Gleichwertige Ablaufe werden klar von externen Cloud-/Lizenzdiensten unterschieden.

## Installation und Upgrade

Nur bei Bedarf installieren: ClamAV samt aktuellen Signaturen (`apt install clamav clamav-freshclam`), Fail2Ban (`fail2ban`), sowie die passenden Plesk-Komponenten fuer ModSecurity und PHP-Handler. Plesk-Firewall ist optional und wird getrennt aktiviert. Vollstaendigen Snapshot und externe Backups vorhalten. Die Paketliste je Funktion steht in [MANAGEMENT.md](MANAGEMENT.md).

Das installierbare ZIP liegt im [GitHub-Release](https://github.com/Wintergecko/guardian-lite/releases). Als root installieren oder aktualisieren:

```bash
# Neuinstallation
plesk bin extension -i /root/guardian-lite-0.16.0.zip
# Vorhandene Installation aktualisieren
plesk bin extension -g /root/guardian-lite-0.16.0.zip
# Installierte Erweiterungen anzeigen
plesk bin extension -l
```

In Plesk als direkt angemeldeter Administrator unter **Erweiterungen → Guardian Lite** oeffnen. Impersonierte Sitzungen sind gesperrt. Die Oberflaeche bietet Uebersicht, Malware & Dateien, Angriffe & Schutz, Updates, Incidents, Verwaltung & Diagnose sowie Feature-Liste.

Der automatisch registrierte Stundentask startet ohne pro Domain aktivierte Scanplanung keinen Scan. Faellige Scans werden einzeln und in FIFO-Reihenfolge ausgefuehrt; die Warteschlange nimmt bis zu 100 Auftraege an und zeigt ihren Status in der Oberflaeche. Der Mindestabstand von 24 Stunden gilt zwischen tatsaechlichen Scanstarts je Domain. Die neue Schutzverwaltung verlangt jeweils eine ausdrueckliche Aktivierung. Snuffleupagus benoetigt die zum gewaehlten Plesk-PHP-Handler passenden Entwicklungswerkzeuge; fehlende Voraussetzungen werden angezeigt. Paketinstallation und Freigaben auf dem Testserver nimmt der Betreiber vor.

## Daten und Rechte

- Schreibende Webaktionen erfordern Admin-Sitzung, POST und CSRF-Token.
- Privilegierte Helfer akzeptieren feste Aktionen mit validierten Argumenten; keine frei eingegebenen Shell-Befehle oder Serverpfade.
- API-Schluessel werden per stdin an den Manager uebergeben und unter `/var/lib/guardian-lite/management/` root-privat gespeichert.
- Berichte, Quarantaene, Incidents, Baselines und Backups liegen unter `/var/lib/guardian-lite/`. Verzeichnisse 0700, JSON standardmaessig 0600.
- Quarantaene und Reparatur koennen die laufende Website veraendern. Originale bleiben fuer Wiederherstellung erhalten. Gleichzeitig schreibende Websites koennen eine manuelle Nacharbeit erfordern.
- Deinstallation nimmt aktive Guardian-Policies zurueck. Fremde Konfigurationsaenderungen koennen die sichere Ruecknahme verhindern und fuehren dann zum Abbruch. Wiederherstellungsdaten, Module und Build-Benutzer bleiben erhalten.

Siehe [SECURITY.md](SECURITY.md) fuer das Sicherheitsmodell.

## Tests und Diagnose

```bash
php tests/php_scan_controller_smoke.php
php tests/plesk_updater_smoke.php
php tests/php_management_smoke.php
sudo python3 -m unittest discover -s tests -v
python3 tools/build_release.py --tag v0.16.0
```

Die Linux-CI prueft Python 3.11/3.12/3.13 auf Ubuntu 22.04/24.04, PHP-Controller und Templates, lokale PHP-HTTP-Requests und echte ModSecurity-HTTP-Limits. Ein gesonderter nativer Buildtest kompiliert Snuffleupagus und prueft Simulation, Blockieren und Rollback mit System-PHP in einer isolierten VM. Das ist kein Nachweis fuer produktive Plesk-FPM-Requests.

Fuer deinen separaten Plesk-Testserver steht die [Testreihenfolge mit Diagnoseexport](MANAGEMENT.md#diagnose-und-testreihenfolge-in-plesk) bereit. Provider-Pruefungen mit eigenen API-Schluesseln, echte Handler-Reloads, Proxy-/WAF-Verhalten und Mailzustellung werden dort geprueft.

## Weitere Entwicklung

[FEATURES.md](FEATURES.md) priorisiert weitere Features. Die wichtigsten naechsten Schritte sind Hersteller-Pruefsummen fuer CMS-Dateien, eine granulare Allowlist mit Notfall-Freischaltung sowie eine Baseline-/Backup-Verwaltung mit Aufbewahrungsregeln.

## Referenzen und Lizenz

[Plesk Extension-Aufbau](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-extensions-basics/extension-structure.71076/) · [Plesk Scheduler](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-features-available-for-extensions/scheduling-tasks.71094/) · [Extension-CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/extension-extensions.71031/)

MIT fuer Guardian Lite; Drittsoftware unter eigenen Lizenzen. Keine proprietaeren Imunify360-Bestandteile. Aeltere Entwicklungsstaende sind in [CHANGES.md](CHANGES.md) dokumentiert.
