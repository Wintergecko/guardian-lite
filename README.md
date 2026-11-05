# Guardian Lite 0.28.24 – Plesk Security (Linux)

Open-Source-Sicherheitszentrale fuer Plesk Obsidian **18.0.55 oder neuer** auf Linux, Python >=3.8. Beta: aktive Schutzfunktionen zuerst auf einem separaten Testserver pruefen. Keine offizielle Plesk-/Imunify360-Software.

## Funktionsumfang

| Bereich | Implementiert | Grenze / Voraussetzung |
|---|---|---|
| ClamAV | Manuelle/geplante Dateiscans, Berichte, Historie, exakte SHA-256-Ignore-Liste, lokaler RapidScan-Cache und optionaler gestreamter WordPress-/Joomla-/Magento-Datenbankexport-Scan | `clamscan` und aktuelle Signaturen separat installieren; Debian/Ubuntu: `apt install clamav clamav-freshclam`; Datenbankexport ist auf 512 MiB begrenzt, Cache lokal und kein Cloud-Hashdienst |
| Scanplanung | Stuendlicher Plesk-Task; FIFO-Warteschlange bis 100 Auftraege, einzelne Scans mit niedriger CPU-Prioritaet, mindestens 24h Abstand zwischen Scanstarts je Domain | Keine parallelen Scans; Scans brauchen weiterhin ClamAV lokal |
| Document-Roots | Aufloesung aus Plesk-Hostingdaten, einschliesslich Zusatzdomains | Ziel muss im zugeordneten Webspace liegen und nicht root-eigen sein |
| Quarantaene | Manuelles Verschieben verifizierter Funde und Wiederherstellen | Fingerprint-Kontrolle; kein Ueberschreiben; gleiches Dateisystem erforderlich |
| Dateiwache | Opt-in-inotify und gezielte ClamAV-Einzeldateipruefung | Maximal 5 Domains / 450 Verzeichnisse je Domain; keine Ausfuehrungsblockade |
| Metadatenvergleich | Periodische Stichprobe fuer Domains mit Scanplanung | Bis 1500 Dateien; keine vollstaendige Integritaetspruefung |
| Incidents / E-Mail | Privates Ereignisprotokoll mit 24h/7d/30d-Zeitreihe und Filtern fuer bis zu 200 aktuelle Eintraege, JSON-Export, gedrosselte Malwarewarnungen mit begrenzter Outbox und Wiederholungen | Kein Langzeit-/Zeitreihenspeicher; lokale Mailannahme ist kein Zustellnachweis; maximal 100 offene Warnungen und sechs Versuche |
| Fail2Ban | Status bestehender Jails und manuelle IP-Sperren/-Freigaben | `fail2ban-client` und konfigurierte Jails; erstellt keine Jails oder globale Firewall-Policies |
| CrowdSec | Optionaler, begrenzter Read-only-Status lokaler Entscheidungen und AppSec-Bereitschaft; einzelne `ban`-IP-Adressen koennen per Admin-Klick im bestehenden Plesk-Firewall-Bestaetigungsablauf vorbereitet werden | CrowdSec (MIT) und Apache-Bouncer muessen separat installiert werden; Guardian installiert/aktiviert sie nicht und misst keinen echten HTTP-Schutz |
| Plesk Firewall | Guardian-IP-Sperren mit TTL, kommentierte Guardian-IP-Ausnahmen und manuelle Plesk-Portfreigaben/-sperren fuer einzelne Quell-IPs; Plesk-60-Sekunden-Rollback und explizite Bestaetigung | Plesk Firewall installiert/aktiv; IP-Ausnahmen schuetzen nur vor kuenftigen Guardian-Sperren und heben keine Plesk-/Provider-Regeln auf; globale Port-Policies und Greylist fehlen |
| Firewall-Dashboard | Zaehler, Suche/Filter und Anzeige von Plesks Erlauben-/Sperrregeln; globaler Modul-Debugschalter fuer Helper, Verwaltungsmanager, Updater und Firewall, standardmaessig aus | Greylist, Bot-Challenge, externe Reputation und Aenderung fremder Regeln fehlen; nur Plesk-native Regeln werden gelesen |
| Dashboard-Karte fuer Sperr-IP-Adressen | Laenderkarte fuer aktuell sichtbare Fail2Ban-/CrowdSec-IP-Sperren und die letzten blockierten WAF-IP-Adressen; rein lokale DB-IP-Lite-Abfrage | Benötigt `python3-maxminddb` und die monatlich aktualisierte DB-IP-Lite Country MMDB unter `/var/lib/guardian-lite/management/dbip-country-lite.mmdb`; Listen sind begrenzt und Geo-IP-Standorte ungenau, insbesondere bei VPN/Proxy/Anycast |
| WAF | ModSecurity-Loganzeige, Domain-Modus und Guardian-Regelverwaltung | Apache ModSecurity v2, `mod_unique_id` und `SecDataDir` erforderlich; Plesk-WAF muss fuer Blockieren aktiv sein |
| OWASP Core Rule Set | Signaturgeprueftes CRS-v4-Minimalpaket bereitstellen, getrennt aktivieren und zur vorherigen Guardian-Konfiguration zurueckrollen | `gnupg`, Apache ModSecurity v2 und `mod_unique_id`; Aktivierung ist eine globale Apache-Regelquelle und muss zuerst im Erkennungsmodus auf einer Testdomain geprueft werden; Guardian schaltet keine Plesk-WAF-Modi um |
| HTTP-Botlimits | Guardian-Regeln fuer einen Zielhost, Vorschau, Erkennen/429-Sperren, Rollback | Korrekte Real-IP-Konfiguration; kein Netzwerk-DDoS-Schutz |
| PHP-Runtime | Snuffleupagus-Build aus festem Commit, Simulation, Aktivierung | Passendes Plesk-Entwicklerpaket plus git/gcc/make/autoconf; PHP 8.0–8.5; pro Handler wirksam |
| PHP-Backup/Rollback | GUI mit Fingerprint-Pruefung, Recovery-Backup und FPM-Pruefung/Reload | Echte Plesk-Requests und Handler-Zuordnung auf dem Testserver pruefen |
| Good-File-Reparatur | Baselines, manuelle und opt-in automatische Reparatur nach Vollscans, Rollback | Admin-freigegebene Quelle; keine Hersteller-Signatur; unbekannte Dateien bleiben unveraendert |
| Speicherverwaltung | Speicherbedarf und freier Datentraeger; Baseline-Quota 512 MiB, Backup-Quota 256 MiB / 200 Eintraege; manuelle Einzelloeschung und bestaetigte Aufbewahrungsvorschau | Keine automatische Bereinigung; aktive Rollback-Quellen und die drei neuesten Wiederherstellungspunkte je Typ/Ziel bleiben geschuetzt |
| Admin-Tool-Pruefung | Domain-Scan erkennt begrenzt Adminer/TinyFileManager-Kandidaten und zeigt sie getrennt von Malware | Namens-/Quelltextmarker sind heuristisch und keine vollstaendige Tool-Datenbank; keine automatische Aenderung |
| Cloud-Reputation | Manuelle AbuseIPDB-Abfrage, Schema-Pruefung und Stunden-Cache | Eigener API-Key und Zustimmung; keine automatischen Meldungen/Sperren |
| Malware-Ignore-Listen | SHA-256-Ausnahmen je Domain und domainuebergreifende globale Hash-Liste; Dateien werden weiter gescannt und angezeigt | Globale Ausnahmen unterdruecken Warnungen/Reparaturen auf allen Domains und muessen fuer jeden Inhalt bewusst geprueft werden |
| Bot-Challenges | Cloudflare Turnstile auf ausgewaehlten PHP-Anmeldepfaden | Eigene Keys, HTTPS, PHP-cURL fuer den Domain-Handler, freie auto_prepend_file-Konfiguration |
| Diagnose | Sanitisiertes JSON und optionale kurzlebige HTTPS-PHP-Probe | Plesk-Praxistests fuehrt der Betreiber durch |
| Cronjob-Audit | Manuelle read-only Heuristikpruefung plus optional ClamAV-Signaturscan ueblicher System-/Benutzer-Crondateien; Treffer im Incident-Verlauf | 4-MiB-/45-Sekunden-Limits; keine vollstaendige Malware-Erkennung und keine Aenderungen an Jobs |
| WordPress-Core | Manuelle WordPress.org-Pruefsummenverifikation via WP-CLI und HTTPS | Root-eigene WP-CLI-Binary und ausgehendes HTTPS; keine Plugins, Themes oder automatische Reparatur |
| WordPress.org-Plugins | Manuelle Pruefung mit WP-CLI, nicht abgedeckte Plugins werden als uebersprungen aufgefuehrt | Nur Plugins mit WordPress.org-Pruefsummen; kommerzielle/eigene Plugins bleiben ungeprueft; keine Reparatur |
| WordPress.org-Themes | Read-only Dateivergleich mit HTTPS-Archiv der exakt installierten Version; Abweichungen als Incident | Nur passende WordPress.org-Versionen; keine signierte Herstellerpruefsumme, eigene/kommerzielle Themes ungeprueft, keine Reparatur |
| CMS-Datenbank | WordPress-SQL-Heuristik; optionaler WordPress-Export via WP-CLI und statisch ausgelesene Joomla-/Magento-Konfiguration mit `mysqldump`; alle Exporte direkt per Pipe zu lokalen ClamAV-Signaturen | WP-CLI fuer WordPress; `mysqldump`/`mariadb-dump` fuer Joomla/Magento; nur statische PHP-Konfiguration und MySQL/MariaDB; keine MDS-Herstellersignaturen, Exportgrenze 512 MiB, keine Dumps gespeichert, Bereinigung oder Aenderungen |
| GitHub-Updater | Oeffentliche Releases pruefen und nach Admin-Klick installieren | Passendes ZIP und GitHub-SHA-256 erforderlich; keine stillen Updates |

Alle neuen aktiven Funktionen sind standardmaessig aus. Details zu Aktivierung, Grenzen, Voraussetzungen und Fehlerfaellen stehen in [MANAGEMENT.md](MANAGEMENT.md).

Der systematische Funktionsabgleich und die Plesk-spezifische Umsetzungsreihenfolge sind in [IMUNIFY360_PARITY.md](IMUNIFY360_PARITY.md) dokumentiert. Gleichwertige Ablaufe werden klar von externen Cloud-/Lizenzdiensten unterschieden.

## Installation und Upgrade

Nur bei Bedarf installieren: ClamAV samt aktuellen Signaturen (`apt install clamav clamav-freshclam`), Fail2Ban (`fail2ban`), sowie die passenden Plesk-Komponenten fuer ModSecurity und PHP-Handler. Fuer die Laenderkarte kommen `python3-maxminddb` und die kostenfreie DB-IP-Lite Country MMDB hinzu; die Datenbank wird getrennt monatlich bereitgestellt. Plesk-Firewall ist optional und wird getrennt aktiviert. Vollstaendigen Snapshot und externe Backups vorhalten. Die Paketliste je Funktion steht in [MANAGEMENT.md](MANAGEMENT.md).

Das installierbare ZIP liegt im [GitHub-Release](https://github.com/Wintergecko/guardian-lite/releases). Als root installieren oder aktualisieren:

```bash
# Neuinstallation
plesk bin extension -i /root/guardian-lite-0.28.24.zip
# Vorhandene Installation aktualisieren
plesk bin extension -g /root/guardian-lite-0.28.24.zip
# Installierte Erweiterungen anzeigen
plesk bin extension -l
```

In Plesk als direkt angemeldeter Administrator unter **Erweiterungen → Guardian Lite** oeffnen. Impersonierte Sitzungen sind gesperrt. Das Menue gruppiert einzelne Ansichten in Dashboard, Malware Scanner, Incidents, Firewall, Webschutz & PHP und Verwaltung. Scanstart und letzter Bericht sind getrennte Ansichten; die Modulseite zeigt jeweils nur den gewaehlten Bereich. Teilweise Funktionen und manuelle Anbieterabfragen sind im Menue als solche gekennzeichnet.

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
python3 tools/build_release.py --tag v0.28.24
```

Die Linux-CI prueft Python 3.11/3.12/3.13 auf Ubuntu 22.04/24.04, PHP-Controller und Templates, lokale PHP-HTTP-Requests und echte ModSecurity-HTTP-Limits. Ein gesonderter nativer Buildtest kompiliert Snuffleupagus und prueft Simulation, Blockieren und Rollback mit System-PHP in einer isolierten VM. Das ist kein Nachweis fuer produktive Plesk-FPM-Requests.

Fuer deinen separaten Plesk-Testserver steht die [Testreihenfolge mit Diagnoseexport](MANAGEMENT.md#diagnose-und-testreihenfolge-in-plesk) bereit. Provider-Pruefungen mit eigenen API-Schluesseln, echte Handler-Reloads, Proxy-/WAF-Verhalten und Mailzustellung werden dort geprueft.

## Weitere Entwicklung

[IMUNIFY360_PARITY.md](IMUNIFY360_PARITY.md) dokumentiert den laufend geprueften Funktionsabgleich. Offene groessere Bereiche sind generische Proxy-Challenges und Greylisting, dauerhafte Ereignisaggregation, ein konfigurierbarer Hook-/Webhook-Ablauf, verifizierte Firewall-Listen mit Plesk-Prioritaet sowie externe Reputation. Proprietare Cloud-Erkennung und lizenzierte Kernel-Patches sind keine Guardian-Funktionen.

## Referenzen und Lizenz

[Plesk Extension-Aufbau](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-extensions-basics/extension-structure.71076/) · [Plesk Scheduler](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-features-available-for-extensions/scheduling-tasks.71094/) · [Extension-CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/extension-extensions.71031/)

MIT fuer Guardian Lite; Drittsoftware unter eigenen Lizenzen. Keine proprietaeren Imunify360-Bestandteile. Aeltere Entwicklungsstaende sind in [CHANGES.md](CHANGES.md) dokumentiert.
