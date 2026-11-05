# Guardian Lite 0.28.5 – Schutzverwaltung und Plesk-Praxistest

## Navigation

Die Guardian-Oberflaeche ist an die Hauptbereiche im Imunify360-Dashboard angelehnt. **Dashboard**, **Malware Scanner**, **Incidents**, **Firewall**, **Webschutz & PHP** und **Verwaltung** enthalten nur Guardian-Funktionen. Jeder Unterpunkt zeigt eine eigene Modulansicht; Scanstart und letzter Bericht sind getrennt. Webschutz, PHP-Runtime und Reputation sind in Guardian Teil-/Manuell-Integrationen, keine Imunify360-Paritaet.

## Voraussetzungen und Reichweite

Plesk Obsidian **18.0.55 oder neuer**, Linux und Python >=3.8. Die sichere stdin-Schnittstelle von `pm_ApiCli::callSbin` wird fuer API-Schluessel verwendet. Nur direkt angemeldete Administratoren koennen Verwaltungsaktionen ausfuehren. Alle neuen aktiven Funktionen sind nach Installation aus.

## Systemkomponenten je Funktion

Es muessen nur die Komponenten fuer Funktionen installiert werden, die du verwendest. Guardian installiert keine Betriebssystempakete selbst.

| Funktion | Benoetigt |
|---|---|
| Scans, Historie, Quarantaene, Baselines/Reparatur | ClamAV `clamscan` und aktuelle Signaturen, z. B. unter Debian/Ubuntu `apt install clamav clamav-freshclam`; Signaturen mit `freshclam` aktualisieren. |
| Fail2Ban-Anzeige und IP-Aktionen | Fail2Ban (`fail2ban-client`) und mindestens ein konfiguriertes Jail. Guardian erstellt keine Jails. |
| E-Mail-Warnungen | Lokaler Sendmail-kompatibler Mailtransport oder in Plesk funktionierender Mailtransport. |

Fehlgeschlagene Malware-Warnungen werden bis zu 100 Eintraege root-privat gespeichert und beim stuendlichen Plesk-Task mit wachsendem Abstand bis zu sechs Mal erneut uebergeben. Der Administrator kann den Versuch manuell starten. Plesk zeigt Warteschlangenstand und letzten Transportfehler; eine erfolgreiche lokale Annahme belegt nicht die Zustellung zum Empfaenger.
| Dateiwache | Linux `inotify` (Kernel-Schnittstelle); kein zusaetzliches PHP-Modul. |
| Plesk-Firewall-Status | Optionale Plesk-Erweiterung **Firewall**. Die Installation allein aktiviert keine Regeln. Die Erweiterung ist keine Voraussetzung fuer andere Guardian-Funktionen. |
| Plesk-Firewall-Regeln | Plesk Firewall muss installiert und aktiv sein; Plesk-CLI `plesk ext firewall` und der dazugehoerige Dienst muessen funktionieren. `firewalld` darf laut Plesk nicht parallel betrieben werden. |

Die kommentierte Guardian-IP-Ausnahmeliste verhindert nur kuenftige Guardian-eigene Sperren fuer eingetragene Netze. Sie ist keine Freischaltung in der Plesk-, Betriebssystem- oder Provider-Firewall.
| Guardian-WAF/HTTP-Limits | Apache-ModSecurity **v2**, geladenes `mod_unique_id`, `SecDataDir` und Plesk-WAF fuer wirksames Blockieren. In Plesk ueber Installer/Komponentenverwaltung einrichten und danach Guardian-Vorschau pruefen. |
| Snuffleupagus | Pro verwaltetem Plesk-PHP-FPM-Handler das passende Entwicklerpaket, z. B. `plesk-php83-dev`, ausserdem `git`, `gcc`, `make`, `autoconf`; Handler-Version 8.0–8.5. Beispiel Debian/Ubuntu: `apt install plesk-php83-dev git gcc make autoconf`. |
| Turnstile-Bot-Challenge | PHP-cURL fuer genau den ausgewählten Plesk-PHP-Handler, HTTPS-Ausgangsverbindung und eigene Cloudflare-Site-/Secret-Keys. Kein globales `php-curl`, falls die Domain einen separaten Plesk-Handler nutzt. |
| WordPress-Core-Pruefsummen | WP-CLI als root-eigene Datei unter `/usr/local/bin/wp`, `/usr/bin/wp` oder `/bin/wp`; systemweite PHP-CLI und ausgehender HTTPS-Zugriff auf WordPress.org. Guardian installiert WP-CLI nicht. |
| WordPress.org-Themes | Root-Verwaltung, lesbarer WordPress-Docroot und HTTPS-Zugriff auf `api.wordpress.org` und `downloads.wordpress.org`; WP-CLI wird hier nicht benoetigt. Pro Domain maximal 40 Theme-Verzeichnisse, 128 MiB Theme-Archive und 512 MiB entpackte Daten je Pruefung. |
| CMS-Datenbank-Signaturscan | WordPress: root-eigene WP-CLI; Joomla/Magento: root-eigenes `mysqldump` oder `mariadb-dump`; jeweils aktuelle ClamAV-Signaturen. Joomla/Magento benoetigen statische Datenbankwerte in den CMS-PHP-Konfigurationen. Der Export wird bis 512 MiB durch eine Pipe geleitet, nicht auf Platte geschrieben. |
| AbuseIPDB | HTTPS-Ausgangsverbindung und eigener API-Key; kein Serverpaket. |

## Speicher, Quotas und Aufbewahrung

Unter **Verwaltung → Speicher & Backups** zeigt Guardian pro Bereich die belegten Bytes und Dateien sowie den freien Speicher des Dateisystems an. Die gemessenen Bereiche sind PHP-/WAF-Backups, Good-File-Baselines, Reparaturprotokolle und Scan-Berichte. Eine unvollstaendige Dateisystemmessung wird markiert.

Baselines sind auf 20 Verzeichnisse, 512 MiB Gesamtspeicher, 64 MiB und 5000 Dateien pro Baseline begrenzt. PHP-/WAF-Backups sind auf 200 Eintraege und 256 MiB begrenzt. Bei voller Quote wird eine neue Sicherung vor einer Aenderung abgelehnt. Guardian loescht alte Sicherungen nie automatisch. Nicht mehr benoetigte Baselines und verwaltete Backups koennen einzeln nach ausdruecklicher Bestaetigung geloescht werden. Baselines, die fuer automatische Reparatur ausgewaehlt sind, und das aktuelle WAF-Rollback-Backup koennen erst nach Deaktivierung beziehungsweise Ablosung entfernt werden. Vor jeder Bereinigung VPS-Snapshot und externe Sicherung pruefen.

## Malware-Scan-Warteschlange

Manuelle und geplante Vollscans werden FIFO aus einer root-privaten Warteschlange gestartet. Der Plesk-Stundentask kann alle faelligen Domains einreihen; pro Domain bleiben mindestens 24 Stunden zwischen tatsaechlichen Scanstarts. Gleichzeitig laeuft immer nur ein ClamAV-Vollscan. Maximal 100 Auftraege koennen warten; bei voller Queue wird der Auftrag abgelehnt und die Oberflaeche zeigt die wartenden Domains an. Der Worker startet den naechsten Auftrag nach Abschluss oder Fehler des vorherigen. Fuer jeden Scan gelten weiterhin die vorhandenen Dateigroessen-, Dateianzahl-, Laufzeit- und CPU-Prioritaetsgrenzen.

Nach einem ClamAV-Vollscan prueft Guardian ausserdem begrenzt auf Adminer- und TinyFileManager-Kandidaten. Die read-only Pruefung nutzt bekannte PHP-Dateinamen plus Textmarker, maximal 5000 Dateien, 10000 Dateisystemeintraege, 2 MiB je Kandidatendatei, 16 Verzeichnisebenen, zehn Sekunden und 25 Meldungen. Symlinks und andere Dateisysteme werden nicht verfolgt; erkannte Begrenzungen erscheinen als unvollstaendig/begrenzt. Treffer sind Admin-Tool-Hinweise, keine Malware-Befunde; sie zeigen Pfad und SHA-256, aber keinen Quelltext. Guardian deaktiviert, quarantiniert oder loescht diese Dateien nie automatisch.

### Lokaler RapidScan-Cache

ClamAV-Vollscans erfassen bei vollstaendigem, begrenztem No-follow-Inventar einen root-privaten Cache fuer bis zu 16 Domains. Saubere reguläre Dateien werden bei Folgescans nur uebersprungen, wenn Geraet, Inode, Groesse, mtime, ctime, Modus, Besitzer und Linkzahl identisch sind. Der Cache ist an SHA-256 des root-eigenen ClamAV-Programms, dessen Versionsausgabe und den Metadatenstand lokaler Signaturdateien gebunden. Bei fehlenden/unsicheren Signaturen, unvollstaendigem Inventar, Pfaden, die sich nicht eindeutig als Liste darstellen lassen, oder Scannerwarnungen wird kein Cachetreffer vertraut und der Vollscan verwendet.

Geaenderte/neue Dateien werden explizit per ClamAV-Dateiliste geprueft; Dateien mit Malwarefund werden nie als sauber gecacht. Nach dem Scan inventarisiert Guardian erneut und speichert nur unveraenderte, fehlerfrei gepruefte Dateien. Der Cache wird bei Signatur-/Binary-Wechsel verworfen, auf maximal 16 Domain-Dateien und 4 MiB pro Domain begrenzt und erscheint in der Speicheranzeige. Das ist lokales inkrementelles Scannen, keine Cloud-Reputation und kein Ersatz fuer einen gelegentlichen Vollscan. Bei Datenbank-/Dateisystem-Restore Cache loeschen oder Vollscan ausfuehren.

Plesk-Pakete/Handler-Komponenten koennen je nach Betriebssystem und PHP-Version abweichen. System-PHP-Entwicklungspakete ersetzen nicht die zum Plesk-Handler gehoerigen Pakete.

Automatisierte Tests ersetzen die Plesk-Praxistests nicht. Die Tests des Betreibers finden auf einem separaten Plesk-Testserver statt. Guardian fuehrt keine pauschale Aktivierung auf vorhandenen Domains durch.

## Plesk-Firewall-Dashboard, Diagnose und IP-/Portregeln

Im Angriffe-&-Schutz-Bereich zeigt Guardian Zaehler und ein durchsuchbares Inventar der von Plesk gemeldeten Regeln. Die Inventaransicht ist auf 300 Regeln begrenzt. Plesk-Erlauben-Regeln werden als Allow/White, Sperrregeln als Deny/Black bezeichnet; dies ist keine separate Guardian-Prioritaetssteuerung. Greylist, Bot-Challenges und Cloud-Reputation werden nicht von dieser Plesk-Firewall bereitgestellt.

Die Debugausgabe ist standardmaessig deaktiviert und kann im Firewall-Bereich sowie unter **Schutzverwaltung und Diagnose** ein- und ausgeschaltet werden. Beide Stellen steuern dieselbe Einstellung. Bei Aktivierung protokolliert Guardian Zeit, CLI-Schritt, Ergebniscode, Laufzeit und Ausgabeumfang in einer root-privaten JSONL-Datei mit maximal 256 KiB. CLI-Argumente und Standardausgabe werden nicht gespeichert. Das Panel zeigt die letzten begrenzten Ereignisse. Zum Support kann die Diagnose kurzzeitig aktiviert, nach dem Nachstellen wieder deaktiviert und der Status im Panel geprueft werden.

Guardian zeigt eigene IP-Sperren und quell-IP-gebundene Portregeln, die es in der Plesk-Firewall angelegt hat. Neben eingehenden Deny-Regeln kann es einen einzelnen TCP-/UDP-Port fuer eine einzelne Quell-IP erlauben oder fuer ein begrenztes Quellnetz sperren. Jede Regel nutzt `plesk ext firewall --set-rule`; Entfernen ist nur fuer exakt gelistete Guardian-Portregeln per numerischer ID und Guardian-IP-Sperren per exakt passendem Netz moeglich. Andere Regeln werden weder veraendert noch geloescht. Plesk Firewall muss bereits aktiv sein; Guardian aktiviert sie nicht.

Unterstuetzt sind einzelne IPv4-/IPv6-Adressen und CIDR-Netze bis maximal IPv4 `/24` bzw. IPv6 `/64`. Loopback-, unspecified-, link-local- und Multicast-Netze sowie die aktuelle `REMOTE_ADDR` der Plesk-Admin-Verbindung werden abgelehnt. Weitergeleitete Proxy-Header werden nicht als Admin-IP verwendet. Ein Admin hinter Proxy/CDN muss nach dem ersten Plesk-Test die tatsaechlich ankommende Verbindung beruecksichtigen.

Beim Anlegen kann eine Sperre dauerhaft oder fuer 1 Stunde, 24 Stunden beziehungsweise 7 Tage angelegt werden. Die Ablaufzeit wird erst nach manueller Bestaetigung gespeichert. Der vorhandene stuendliche Plesk-Scheduler entfernt bis zu zehn abgelaufene Guardian-Regeln je Lauf; eine einzelne Entsperrung kann bis zu einer Stunde spaeter erfolgen, groessere Rueckstaende entsprechend laenger. Verbleibende Faelle werden als Incident protokolliert. Entsperrungen nutzen Plesks `--apply`/`--confirm` Ablauf. Bei offener Admin-Aenderung oder nicht lesbarer Firewall-Regelliste aendert Guardian nichts und protokolliert den Fehler; fremde Regeln werden nie entfernt.

Nach jeder Aenderung fuehrt Plesk `--apply` aus und startet sein 60-Sekunden-Rollback. Teste zuerst in einer unabhaengigen SSH- oder Plesk-Admin-Verbindung, dass Panel und erforderliche Dienste erreichbar bleiben; bestaetige erst danach im Guardian-Panel. Ohne Bestaetigung stellt Plesk die vorherige aktive Konfiguration wieder her. Eine quell-IP-Portfreigabe ueberschreibt nicht notwendigerweise globale Plesk-Systemrichtlinien oder Provider-Firewalls. Globale IP-Allowlisten, zeitbegrenzte Portregeln, Greylisting und automatische IP-Reputation sind noch nicht enthalten.

Guardian verhindert die Deinstallation, solange eigene Port-Allow-Regeln aktiv sind. Entferne sie zuerst aus diesem Panel und bestaetige die jeweilige Aenderung nach Verbindungstest; sonst koennte das Entfernen der Ausnahme den Adminzugriff unterbrechen.

Plesk warnt vor gleichzeitig aktivem `firewalld`, weil beide Dienste dieselben Firewallregeln verwalten koennen. Guardian blockiert deshalb Aenderungen, wenn `firewalld` als aktiv erkannt wird. [Plesk Firewall: Regeln und Rollback](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-for-linux-the-plesk-firewall.72046/) · [Plesk CLI und quell-IP-gebundene Portregeln](https://support.plesk.com/hc/en-us/articles/12377519983511-How-to-manage-local-firewall-rules-using-Plesk-Firewall-in-Plesk-for-Linux)

## PHP-Handler und Snuffleupagus

Unter **PHP Runtime → Handler & Rollback** werden unterstuetzte Plesk-PHP-Handler 8.0–8.5 angezeigt. Ein Handler gilt fuer alle ihm zugeordneten Websites. Keine automatische Umschaltung von Domains auf andere Handler.

1. **Backup erstellen** speichert php.ini root-privat mit SHA-256.
2. **Modul installieren** startet einen Hintergrundauftrag. Voraussetzungen: die zum Handler passenden `phpize`/`php-config`, git, gcc, make und autoconf. Fehlende Pakete werden nicht ungefragt installiert. Der Build verwendet Snuffleupagus 0.14.0 mit festem Commit `1d8614af85a1baa52656f3adbd4684772df91288`. Build-Schritte laufen unter dem gesonderten Systembenutzer `guardian-build`; nur das fertige Modul wird als root installiert. Ein vorhandenes Modul wird nicht ueberschrieben.
3. **Simulation** oder **Blockieren** prueft Modul/Regeln und eine harmlose PHP-CLI-Probe. Guardian ergaenzt einen markierten php.ini-Block, testet FPM und laedt nur den gewaehlten FPM-Dienst neu. Bei Fehler wird die vorherige Konfiguration zurueckgeschrieben. Fremde Snuffleupagus-Konfigurationen werden nicht uebernommen.
4. **Rollback** verweigert das Ueberschreiben einer seit dem Seitenaufruf geaenderten Konfiguration. Vor dem Rollback wird erneut ein Recovery-Backup erstellt.

Die Policy betrifft `system`, `shell_exec`, `passthru`, `exec`, `proc_open` und `popen`. Blockieren kann legitime CMS-/Backup-Funktionen beeintraechtigen. CLI-Proben und FPM-Syntaxtests beweisen noch keine Wirksamkeit unter echten Webrequests. System-PHP, Apache-PHP und herstellerspezifische TuxCare-Handler werden nicht automatisch verwaltet. Fuer CGI-/FastCGI-Handler ohne passenden FPM-Dienst scheitert die Aktivierung und wird zurueckgenommen.

Fehlende Build-Werkzeuge werden je Handler in der Oberflaeche angezeigt. Beispiel fuer PHP 8.3 auf Debian/Ubuntu, vom Betreiber als root auszufuehren: `apt install plesk-php83-dev git gcc make autoconf`. Fuer andere Handler das passende Entwicklungs-Paket verwenden. [Plesk dokumentiert die handler-spezifischen Entwicklerpakete](https://support.plesk.com/hc/en-us/articles/12377651968023-How-to-install-uninstall-memcached-PHP-extension-for-Plesk-PHP-handlers).

Referenzen: [Snuffleupagus-Installation](https://snuffleupagus.readthedocs.io/installation.html), [Konfiguration und Simulation](https://snuffleupagus.readthedocs.io/config.html).

## WAF und HTTP-Botlimits

Guardian verwaltet ausschliesslich `zz-guardian.conf` in einem unterstuetzten Apache-ModSecurity-Include-Verzeichnis. Es wird **ein Zielhost** verwaltet; ein neues Ziel ersetzt das bisherige Guardian-Ziel. Die Regel-IDs 9974100–9974103 sind reserviert. Bestehende Drittanbieter-Regeln werden nicht editiert.

- **Vorschau** zeigt die erzeugten Regeln ohne Installation.
- **Nur protokollieren** schreibt bei Ueberschreitung einen Logeintrag.
- **Sperren** verwendet HTTP 429 oberhalb des Limits in einem festen 60-Sekunden-IP-Fenster.
- **Deaktivieren** entfernt die aktiven Guardian-Regeln aus der eigenen Datei.
- **WAF-Rollback** stellt ein Guardian-Backup nach Fingerprint-Pruefung wieder her.

Apache muss ModSecurity v2 und `mod_unique_id` geladen haben und ein vorhandenes `SecDataDir` verwenden. Guardian prueft Syntax und tatsaechliche Einbindung, bevor Apache neu geladen wird. Die Plesk-WAF muss fuer wirksames Blockieren eingeschaltet sein. Der Domain-WAF-Modus wird ueber die dokumentierte Plesk-CLI gesetzt.

Hinter CDN/Reverse-Proxy muss die vertrauenswuerdige Real-IP-Konfiguration bereits stimmen. Guardian interpretiert keine ungeprueften Forwarded-Header. NAT-Nutzer teilen sich ein Limit. Andere Aliase als der gewaehlte Hostname, statische NGINX-Antworten und volumetrische DDoS-Angriffe koennen ausserhalb dieser Apache-Regeln liegen.

Referenzen: [Plesk Custom Rules](https://support.plesk.com/hc/en-us/articles/12388798361495-How-to-add-a-custom-rule-to-Web-Application-Firewall-ModSecurity-in-Plesk), [Plesk WAF CLI](https://support.plesk.com/hc/en-us/articles/12377452876439-How-to-manage-Web-Application-Firewall-ModSecurity-on-Plesk-server-via-CLI).

## AbuseIPDB und Turnstile

Schluessel unter **Verwaltung → Dienst-Schluessel** eingeben und Uebermittlung ausdruecklich erlauben. Die private Datei `/var/lib/guardian-lite/management/config.json` hat Modus 0600; Status und Diagnose geben keine Schluessel aus. Leere Formularfelder behalten gespeicherte Werte.

AbuseIPDB fragt nur oeffentliche IPs ueber den festen CHECK-Endpunkt ab und prueft IP sowie Score der Antwort. Ergebnisse werden eine Stunde zwischengespeichert. Keine automatischen Meldungen, Reports oder IP-Sperren. API-Limits/Verbindungsfehler erzeugen einen Fehler, keinen vermeintlich sicheren Score.

Turnstile wird pro Domain ueber einen markierten `.user.ini`-Eintrag `auto_prepend_file` eingebunden. Eine schon vorhandene Prepend-Konfiguration wird abgelehnt. Der Guard liegt ausserhalb des Document-Roots im Webspace, ist root-eigen und fuer die Website-Gruppe lesbar. Er schuetzt PHP-Anmeldepfade (`wp-login.php`, `xmlrpc.php`, `administrator/`, `login`) und verwendet:

- HTTPS und PHP-cURL;
- serverseitige Siteverify-Pruefung mit festem HTTPS-Endpunkt und ohne Redirects;
- Pruefung von `success`, Hostname und Action;
- zeitlich begrenzte, signierte Formularzustaende;
- signierte, User-Agent-gebundene `__Host-guardian_clearance`-Cookies fuer 30 Minuten, Secure/HttpOnly/SameSite=Lax.

Requests ohne gueltige Freigabe erreichen den geschuetzten PHP-Endpunkt nicht. Anmelde-POSTs werden nicht zwischengespeichert oder automatisch wiederholt. XML-RPC-Clients koennen blockiert werden. Fuer REST-/API-Ausnahmen gibt es in dieser Version keine freie Konfiguration.

Der PHP-INI-Cache kann eine Aenderung bis zu fuenf Minuten verzoegern. Nach Deaktivierung bleibt die Guard-Datei fuer ausstehende INI-Caches erhalten. Eine geaenderte `.user.ini` wird nicht automatisch zurueckgesetzt; zuerst die lokale Aenderung pruefen. Aktive Bot-Pruefungen muessen deaktiviert werden, bevor Turnstile-Schluessel/Zustimmung geaendert werden koennen. Die Turnstile-Integration ersetzt keine serverweite WAF oder statischen Bot-/DDoS-Schutz.

Referenzen: [AbuseIPDB CHECK](https://docs.abuseipdb.com/#check-endpoint), [Turnstile Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

## Cronjob-Sicherheitspruefung

Unter **Malware Scanner → CMS- & Cron-Pruefung** kann ein Administrator die gaengigen System- und Benutzer-Cronpfade manuell pruefen lassen. Der read-only Check sucht nach deutlichen Mustern und prueft sicher gelesene Dateien zusaetzlich mit lokalen ClamAV-Signaturen, sofern ClamAV installiert ist. Fuer den Signaturscan kopiert Guardian die begrenzten Inhalte in ein privates temporaeres Verzeichnis (maximal 4 MiB insgesamt und 45 Sekunden); der Pfad und Signaturname erscheinen im Bericht. Treffer erscheinen auch im Incident-Verlauf. Bei heuristischen Treffern werden nur Datei, Zeilennummer und Regelkennung gezeigt, nicht der Befehlstext. Guardian deaktiviert oder loescht keine Cronjobs.

Auch ClamAV ist nur ein lokaler Signaturnachweis und kein Malware-Vollscan oder Imunify-Cron-Erkennungsersatz. Ein sauberer Bericht beweist nicht, dass alle Cronjobs harmlos sind. Ungewoehnlich grosse Dateien, Symlinks und nicht lesbare Quellen werden ausgelassen; das Ergebnis markiert eine unvollstaendige Pruefung. Fehlt ClamAV, bleibt die Heuristikpruefung verfuegbar und der Signaturstatus wird als nicht ausgefuehrt angezeigt.

## Globale Malware-Ignore-Liste

Unter **Malware Scanner → Ignore List** kann ein Administrator einen geprueften SHA-256-Inhalt domainuebergreifend ignorieren. Der Dateiinhalt wird weiterhin von ClamAV gescannt und Treffer bleiben im Bericht sichtbar; Guardian unterdrueckt aber Malwarewarnung und automatische Reparatur fuer genau diesen Hash auf allen gehosteten Domains. Eine globale Ausnahme kann echte Malware auf mehreren Websites verdecken. Globale Hashes sind auf 2.000 Eintraege begrenzt und koennen einzeln entfernt werden.

## WordPress-Core-Pruefsummen

Im Verwaltungstab kann der Administrator die Core-Dateien einer gehosteten WordPress-Domain pruefen. Guardian verlangt `wp-load.php` und `wp-includes/version.php`, ruft eine root-eigene WP-CLI-Binary mit `core verify-checksums` und `--skip-plugins --skip-themes --skip-packages` auf und startet sie mit der Website-UID. Projekt-/Benutzerkonfigurationen werden durch ein isoliertes Home und Arbeitsverzeichnis umgangen. Die Netzwerkpruefung verwendet WP-CLI-Standardverhalten mit TLS-Pruefung; `--insecure` wird nicht gesetzt.

Das Core-Ergebnis meldet erkannte Dateiabweichungen mit Pfad und Regelkennung, speichert einen Bericht und erzeugt einen Incident bei Abweichungen. Dateien werden nicht geaendert. WordPress.org-Core-Pruefsummen verwenden laut WP-CLI MD5-Pruefwerte ueber HTTPS und sind kein signierter Paketnachweis.

Eine zweite Aktion prueft Plugins mit `wp plugin verify-checksums --all`. WordPress.org-Plugins mit vorhandenen Checksums werden verglichen. Plugins ohne oeffentliche Checksums (typischerweise kommerzielle/eigene Plugins) werden separat aufgefuehrt und ergeben den Status **partial**, nicht **verified**. Themes, Must-Use-Plugins, eigene Dateien und automatische Reparatur bleiben unberuecksichtigt. Die Pruefung beweist daher nicht, dass die gesamte Website frei von Malware ist. [WP-CLI-Pluginpruefung](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/)

### WordPress-Datenbankindikatoren

Die manuelle Aktion `WordPress-Datenbank pruefen` scannt `posts`, `postmeta`, `options` sowie vorhandene Kommentar-Tabellen. Sie verwendet WP-CLI `db prefix`, `db tables` und ausschliesslich begrenzte `SELECT`-Abfragen mit SQL-Identifiern aus einer festen Allowlist. Ausgefuehrt wird WP-CLI mit der Website-UID/GID, isoliertem HOME und ohne Plugins/Themes. Guardian erfasst nur Tabellenname, numerische Zeilen-ID, Spalte und feste Regelkennung; SQL-Inhalte, Zugangsdaten und Datenbankwerte werden nicht in Berichte geschrieben. Abfragen sind auf 101 Zeilen je Tabelle, 2 MiB Ausgabe und insgesamt 5 Minuten begrenzt.

Die separate Aktion `CMS-Datenbank mit ClamAV pruefen` erkennt WordPress, Joomla oder Magento im Plesk-Document-Root. WordPress nutzt `wp db export -`; Joomla/Magento lesen nur statische Werte aus `configuration.php` beziehungsweise `app/etc/env.php` und starten `mysqldump`/`mariadb-dump` als Website-UID/GID. PHP-Konfigurationen werden nie ausgefuehrt; dynamische Werte, mehrdeutige CMS-Roots und andere Datenbanktreiber werden abgelehnt. Joomla/Magento-Zugangsdaten stehen waehrend des Exports in einer kurzlebigen 0600-Clientdatei in einem privaten Temp-Verzeichnis, nie in Prozessargumenten oder Berichten. In allen Faellen fliesst der Export direkt in einen verifizierten ClamAV-Prozess. Es entsteht keine SQL-Dumpdatei. Export und Scanner sind auf 512 MiB, 5 Minuten und begrenzte Prozess-CPU beschraenkt. Fehlgeschlagener Export, Scannerfehler, Ausgabe-/Datenlimit und Timeout werden nie als sauber gewertet. Berichte enthalten nur CMS, byte-Anzahl und bis zu 100 erlaubte ClamAV-Signaturnamen, keine SQL-Werte. Es wird nichts bereinigt oder veraendert. Der Scan nutzt lokale ClamAV-Signaturen und ersetzt nicht Imunifys MDS-Signaturen; grosse Datenbanken muessen separat geprueft werden, wenn das Limit erreicht wird.

Referenzen: [WP-CLI `db export -` schreibt den Dump auf stdout](https://developer.wordpress.org/cli/commands/db/export/); [ClamAV akzeptiert `-` als Scan-Eingabe und begrenzt Dateigroesse/Scanumfang](https://docs.clamav.net/manual/Usage/Scanning.html).

Die Heuristik sucht bekannte Kombinationen aus Kodierung/Verschleierung und dynamischer Ausfuehrung. Treffer sind manuell zu untersuchende Kandidaten, keine Malware-Klassifikation; falsch-positive und falsch-negative Ergebnisse sind moeglich. Fehlende Pflichttabellen, Abfragefehler und Grenzwerte ergeben einen Teilstatus. Das ist weder Imunify Malware Database Scanner noch ClamAV-Ersatz. Es gibt keine Datenbankbereinigung, kein Backup und keinen Rollback. [WP-CLI Datenbankabfragen](https://developer.wordpress.org/cli/commands/db/query/) · [Tabellenauflistung](https://developer.wordpress.org/cli/commands/db/tables/)

## Malware-Ignore-Liste

Im Verwaltungstab kann ein Administrator den exakten SHA-256-Inhalt eines ClamAV-Funds fuer die ausgewaehlte Domain markieren. Die Datei wird bei spaeteren Vollscans und Live-Wachen weiterhin geprueft und bleibt im Bericht sichtbar; Guardian unterdrueckt nur Malwarewarnungen und automatische Baseline-Reparatur fuer genau diesen Inhalt. Ein Hash auf einer Domain wirkt nicht fuer andere Domains. Maximal 500 Eintraege je Domain und 2000 insgesamt. Nach manueller Pruefung kann der Eintrag entfernt werden. Alte Berichte werden nicht nachtraeglich umgeschrieben.

Die Ignore-Liste kann eine echte Infektion verbergen, wenn ein Administrator den Fund falsch bewertet. Sie ist keine Bereinigung und kein sauberer Baseline-Nachweis.

## Good-File-Reparatur

Die Vertrauensquelle ist eine vom Administrator als sauber freigegebene Website, **kein** signiertes Herstellerpaket. ClamAV allein kann die saubere Herkunft nicht beweisen.

1. Saubere Testwebsite aus bekannter Quelle bereitstellen und fehlerfreien Guardian-Vollscan ohne Funde ausfuehren.
2. Innerhalb einer Stunde eine Baseline erstellen und die saubere Herkunft bestaetigen.
3. Guardian speichert PHP-/Konfigurationsdateien root-privat mit SHA-256, Domain-/UID-/Document-Root-Zuordnung. Limits: 2 MiB pro Datei, 5000 Dateien, 64 MiB insgesamt, 20 aufbewahrte Baselines und mindestens 128 MiB freier Speicher. Dateien mit unpassenden Besitzern, Symlinks oder Aenderungen waehrend der Aufnahme werden abgelehnt.
4. Automatische Reparatur separat pro Domain aktivieren. Sie arbeitet **nach abgeschlossenen Vollscans**, nicht unmittelbar auf Live-Dateiwache-Ereignissen.
5. Nur passende, unveraenderte Malwarefunde mit bekanntem Baseline-Pfad werden ersetzt. Das Original bleibt in Quarantaene. Neue/unbekannte Dateien werden nicht automatisch geloescht.
6. Manuelle Reparatur und Rollback stehen beim gewaehlten Scanbericht im Verwaltungstab zur Verfuegung. Rollback verweigert inzwischen geaenderte reparierte Dateien und tauscht das Original atomar zurueck. Dadurch kann Malware erneut aktiv werden.

Nach CMS-Updates eine neue saubere Baseline erstellen. Eine neue Baseline deaktiviert vorher aktivierte automatische Reparaturen. Baselines sind durch private root-Rechte und Digests geschuetzt, nicht durch WORM-Speicher oder eine externe Signatur. Bei gleichzeitig schreibenden Websites bleiben Race-Conditions moeglich; abgelehnte Vorgaenge und erhaltene Quarantaene-Journale manuell pruefen. Ein voller Website-/Datenbank-Rollback ist nicht enthalten.

## Diagnose und Testreihenfolge in Plesk

1. ZIP installieren/aktualisieren und Guardian als direkter Administrator oeffnen. **Verwaltung → Diagnose** muss ohne Helferfehler laden.
2. Fuer eine Testdomain **Diagnose ausfuehren**. Optional HTTPS-PHP-Probe aktivieren: Guardian legt kurz eine zufaellig benannte PHP-Datei an, ruft sie mit TLS-Pruefung ab und entfernt sie im Abschlussblock. Der Bericht prueft PHP-Version, geladenes Snuffleupagus, PHP-cURL und Prepend-Anzeige. Abstuerze/harte Prozessabbrueche koennen eine Testdatei zuruecklassen; sie enthaelt keine Geheimnisse.
3. **Letztes Diagnoseergebnis als JSON herunterladen** und zur Auswertung weitergeben. Der Export enthaelt Domainnamen und Betriebsstatus, keine API-Schluessel oder vollstaendigen Konfigurationen.
4. PHP-Backup → Installation → Simulation → echte Website-Requests → Blockieren → legitime Requests/absichtlich blockierte harmlose Testfunktion → Rollback testen.
5. WAF-Vorschau → Nur protokollieren → Logs/HTTP pruefen → niedrigen Testschwellwert setzen → HTTP 429 pruefen → Deaktivieren/Rollback.
6. AbuseIPDB-Abfrage mit eigenem Key pruefen. Turnstile fuer einen passend konfigurierten Testhost aktivieren, INI-Cache abwarten, Anmeldung ohne Cookie/mit gueltiger Challenge/mit manipuliertem Cookie testen und wieder deaktivieren.
7. Baseline einer sauberen Testwebsite erstellen, eine Testdatei gezielt mit einer ClamAV-Testsignatur veraendern und Vollscan ausfuehren. Nur auf der Testdomain Reparatur, unbekannten Dateipfad und Rollback pruefen.
8. Deinstallation pruefen: Guardian deaktiviert seine aktiven Policies und Dateiwachen. Falls fremde Aenderungen eine sichere Ruecknahme verhindern, wird die Deinstallation mit Fehler abgebrochen. Backups, Quarantaene, installierte Module und Build-Benutzer bleiben fuer Wiederherstellung erhalten.

Automatisierte CI prueft bislang Python-/PHP-Logik, lokale PHP-HTTP-Requests und echte ModSecurity-HTTP-Limits in einem isolierten Apache. Echte Plesk-Handler, Dienstnamen, Include-Pfade und externe Dienste mit Kundenschluesseln bleiben Gegenstand der obigen Betreiberpruefung.
