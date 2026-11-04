# Guardian Lite 0.13.0 – Schutzverwaltung und Plesk-Praxistest

## Voraussetzungen und Reichweite

Plesk Obsidian **18.0.55 oder neuer**, Linux und Python >=3.8. Die sichere stdin-Schnittstelle von `pm_ApiCli::callSbin` wird fuer API-Schluessel verwendet. Nur direkt angemeldete Administratoren koennen Verwaltungsaktionen ausfuehren. Alle neuen aktiven Funktionen sind nach Installation aus.

## Systemkomponenten je Funktion

Es muessen nur die Komponenten fuer Funktionen installiert werden, die du verwendest. Guardian installiert keine Betriebssystempakete selbst.

| Funktion | Benoetigt |
|---|---|
| Scans, Historie, Quarantaene, Baselines/Reparatur | ClamAV `clamscan` und aktuelle Signaturen, z. B. unter Debian/Ubuntu `apt install clamav clamav-freshclam`; Signaturen mit `freshclam` aktualisieren. |
| Fail2Ban-Anzeige und IP-Aktionen | Fail2Ban (`fail2ban-client`) und mindestens ein konfiguriertes Jail. Guardian erstellt keine Jails. |
| E-Mail-Warnungen | Lokaler Sendmail-kompatibler Mailtransport oder in Plesk funktionierender Mailtransport. |
| Dateiwache | Linux `inotify` (Kernel-Schnittstelle); kein zusaetzliches PHP-Modul. |
| Plesk-Firewall-Status | Optionale Plesk-Erweiterung **Firewall**. Die Installation allein aktiviert keine Regeln. Die Erweiterung ist keine Voraussetzung fuer andere Guardian-Funktionen. |
| Plesk-Firewall-IP-Sperrliste | Plesk Firewall muss installiert und aktiv sein; Plesk-CLI `plesk ext firewall` und der dazugehoerige Dienst muessen funktionieren. `firewalld` darf laut Plesk nicht parallel betrieben werden. |
| Guardian-WAF/HTTP-Limits | Apache-ModSecurity **v2**, geladenes `mod_unique_id`, `SecDataDir` und Plesk-WAF fuer wirksames Blockieren. In Plesk ueber Installer/Komponentenverwaltung einrichten und danach Guardian-Vorschau pruefen. |
| Snuffleupagus | Pro verwaltetem Plesk-PHP-FPM-Handler das passende Entwicklerpaket, z. B. `plesk-php83-dev`, ausserdem `git`, `gcc`, `make`, `autoconf`; Handler-Version 8.0–8.5. Beispiel Debian/Ubuntu: `apt install plesk-php83-dev git gcc make autoconf`. |
| Turnstile-Bot-Challenge | PHP-cURL fuer genau den ausgewählten Plesk-PHP-Handler, HTTPS-Ausgangsverbindung und eigene Cloudflare-Site-/Secret-Keys. Kein globales `php-curl`, falls die Domain einen separaten Plesk-Handler nutzt. |
| WordPress-Core-Pruefsummen | WP-CLI als root-eigene Datei unter `/usr/local/bin/wp`, `/usr/bin/wp` oder `/bin/wp`; systemweite PHP-CLI und ausgehender HTTPS-Zugriff auf WordPress.org. Guardian installiert WP-CLI nicht. |
| AbuseIPDB | HTTPS-Ausgangsverbindung und eigener API-Key; kein Serverpaket. |

Plesk-Pakete/Handler-Komponenten koennen je nach Betriebssystem und PHP-Version abweichen. System-PHP-Entwicklungspakete ersetzen nicht die zum Plesk-Handler gehoerigen Pakete.

Automatisierte Tests ersetzen die Plesk-Praxistests nicht. Die Tests des Betreibers finden auf einem separaten Plesk-Testserver statt. Guardian fuehrt keine pauschale Aktivierung auf vorhandenen Domains durch.

## Plesk-Firewall-IP-Sperrliste

Im Angriffe-&-Schutz-Bereich zeigt Guardian eigene Deny-Regeln, die es in der Plesk-Firewall angelegt hat. Es erstellt nur manuelle eingehende Deny-Regeln ueber `plesk ext firewall --set-rule` und entfernt nur exakt passende Guardian-Regeln ueber `--remove-rules`. Andere Regeln werden weder veraendert noch geloescht. Plesk Firewall muss bereits aktiv sein; Guardian aktiviert sie nicht.

Unterstuetzt sind einzelne IPv4-/IPv6-Adressen und CIDR-Netze bis maximal IPv4 `/24` bzw. IPv6 `/64`. Loopback-, unspecified-, link-local- und Multicast-Netze sowie die aktuelle `REMOTE_ADDR` der Plesk-Admin-Verbindung werden abgelehnt. Weitergeleitete Proxy-Header werden nicht als Admin-IP verwendet. Ein Admin hinter Proxy/CDN muss nach dem ersten Plesk-Test die tatsaechlich ankommende Verbindung beruecksichtigen.

Beim Anlegen kann eine Sperre dauerhaft oder fuer 1 Stunde, 24 Stunden beziehungsweise 7 Tage angelegt werden. Die Ablaufzeit wird erst nach manueller Bestaetigung gespeichert. Der vorhandene stuendliche Plesk-Scheduler entfernt abgelaufene Guardian-Regeln; die tatsaechliche Entsperrung kann bis zu einer Stunde nach der angezeigten Zeit erfolgen. Entsperrungen nutzen Plesks `--apply`/`--confirm` Ablauf. Bei offener Admin-Aenderung oder nicht lesbarer Firewall-Regelliste aendert Guardian nichts und protokolliert den Fehler; fremde Regeln werden nie entfernt.

Nach jeder Aenderung fuehrt Plesk `--apply` aus und startet sein 60-Sekunden-Rollback. Teste zuerst in einer unabhaengigen SSH- oder Plesk-Admin-Verbindung, dass Panel und erforderliche Dienste erreichbar bleiben; bestaetige erst danach im Guardian-Panel. Ohne Bestaetigung stellt Plesk die vorherige aktive Konfiguration wieder her. Automatische IP-Reputation, Allowlisten und Provider-Firewalls sind noch nicht enthalten.

Plesk warnt vor gleichzeitig aktivem `firewalld`, weil beide Dienste dieselben Firewallregeln verwalten koennen. Guardian blockiert deshalb Aenderungen, wenn `firewalld` als aktiv erkannt wird. [Plesk Firewall: Regeln und Rollback](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-for-linux-the-plesk-firewall.72046/) · [Plesk CLI](https://support.plesk.com/hc/en-us/articles/12377519983511-How-to-manage-local-firewall-rules-using-Plesk-Firewall-in-Plesk-for-Linux)

## PHP-Handler und Snuffleupagus

Unter **Verwaltung & Diagnose** werden unterstuetzte Plesk-PHP-Handler 8.0–8.5 angezeigt. Ein Handler gilt fuer alle ihm zugeordneten Websites. Keine automatische Umschaltung von Domains auf andere Handler.

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

Schluessel im Tab **Verwaltung & Diagnose** eingeben und Uebermittlung ausdruecklich erlauben. Die private Datei `/var/lib/guardian-lite/management/config.json` hat Modus 0600; Status und Diagnose geben keine Schluessel aus. Leere Formularfelder behalten gespeicherte Werte.

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

Unter **Verwaltung & Diagnose** kann ein Administrator die gaengigen System- und Benutzer-Cronpfade manuell pruefen lassen. Der Check ist read-only und sucht nach wenigen deutlichen Mustern wie Remote-Shell-Pipes, dekodierten Shell-Payloads, PHP-Inline-Eval und Ausfuehrung aus temporaeren Verzeichnissen. Treffer erscheinen im Ergebnis und im Incident-Verlauf. Angezeigt werden nur Datei, Zeilennummer und Regelkennung; der Befehlstext wird nicht kopiert. Guardian deaktiviert oder loescht keine Cronjobs.

Das ist eine begrenzte Heuristik, kein Malware-Vollscan. Ein sauberer Bericht beweist nicht, dass alle Cronjobs harmlos sind. Ungewoehnlich grosse Dateien, Symlinks und nicht lesbare Quellen werden ausgelassen; das Ergebnis markiert eine unvollstaendige Pruefung.

## WordPress-Core-Pruefsummen

Im Verwaltungstab kann der Administrator die Core-Dateien einer gehosteten WordPress-Domain pruefen. Guardian verlangt `wp-load.php` und `wp-includes/version.php`, ruft eine root-eigene WP-CLI-Binary mit `core verify-checksums` und `--skip-plugins --skip-themes --skip-packages` auf und startet sie mit der Website-UID. Projekt-/Benutzerkonfigurationen werden durch ein isoliertes Home und Arbeitsverzeichnis umgangen. Die Netzwerkpruefung verwendet WP-CLI-Standardverhalten mit TLS-Pruefung; `--insecure` wird nicht gesetzt.

Das Core-Ergebnis meldet erkannte Dateiabweichungen mit Pfad und Regelkennung, speichert einen Bericht und erzeugt einen Incident bei Abweichungen. Dateien werden nicht geaendert. WordPress.org-Core-Pruefsummen verwenden laut WP-CLI MD5-Pruefwerte ueber HTTPS und sind kein signierter Paketnachweis.

Eine zweite Aktion prueft Plugins mit `wp plugin verify-checksums --all`. WordPress.org-Plugins mit vorhandenen Checksums werden verglichen. Plugins ohne oeffentliche Checksums (typischerweise kommerzielle/eigene Plugins) werden separat aufgefuehrt und ergeben den Status **partial**, nicht **verified**. Themes, Must-Use-Plugins, eigene Dateien und automatische Reparatur bleiben unberuecksichtigt. Die Pruefung beweist daher nicht, dass die gesamte Website frei von Malware ist. [WP-CLI-Pluginpruefung](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/)

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

1. ZIP installieren/aktualisieren und Guardian als direkter Administrator oeffnen. **Verwaltung & Diagnose** muss ohne Helferfehler laden.
2. Fuer eine Testdomain **Diagnose ausfuehren**. Optional HTTPS-PHP-Probe aktivieren: Guardian legt kurz eine zufaellig benannte PHP-Datei an, ruft sie mit TLS-Pruefung ab und entfernt sie im Abschlussblock. Der Bericht prueft PHP-Version, geladenes Snuffleupagus, PHP-cURL und Prepend-Anzeige. Abstuerze/harte Prozessabbrueche koennen eine Testdatei zuruecklassen; sie enthaelt keine Geheimnisse.
3. **Letztes Diagnoseergebnis als JSON herunterladen** und zur Auswertung weitergeben. Der Export enthaelt Domainnamen und Betriebsstatus, keine API-Schluessel oder vollstaendigen Konfigurationen.
4. PHP-Backup → Installation → Simulation → echte Website-Requests → Blockieren → legitime Requests/absichtlich blockierte harmlose Testfunktion → Rollback testen.
5. WAF-Vorschau → Nur protokollieren → Logs/HTTP pruefen → niedrigen Testschwellwert setzen → HTTP 429 pruefen → Deaktivieren/Rollback.
6. AbuseIPDB-Abfrage mit eigenem Key pruefen. Turnstile fuer einen passend konfigurierten Testhost aktivieren, INI-Cache abwarten, Anmeldung ohne Cookie/mit gueltiger Challenge/mit manipuliertem Cookie testen und wieder deaktivieren.
7. Baseline einer sauberen Testwebsite erstellen, eine Testdatei gezielt mit einer ClamAV-Testsignatur veraendern und Vollscan ausfuehren. Nur auf der Testdomain Reparatur, unbekannten Dateipfad und Rollback pruefen.
8. Deinstallation pruefen: Guardian deaktiviert seine aktiven Policies und Dateiwachen. Falls fremde Aenderungen eine sichere Ruecknahme verhindern, wird die Deinstallation mit Fehler abgebrochen. Backups, Quarantaene, installierte Module und Build-Benutzer bleiben fuer Wiederherstellung erhalten.

Automatisierte CI prueft bislang Python-/PHP-Logik, lokale PHP-HTTP-Requests und echte ModSecurity-HTTP-Limits in einem isolierten Apache. Echte Plesk-Handler, Dienstnamen, Include-Pfade und externe Dienste mit Kundenschluesseln bleiben Gegenstand der obigen Betreiberpruefung.
