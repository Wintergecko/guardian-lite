# Guardian Lite v0.17.0 – Sicherheitsmodell und Grenzen

- Root-Helfer unter Plesk `sbin`; Panelzugriff nur Administrator, POST-CSRF fuer Mutationen.
- Dateizugriffe validieren Domains, kanonische Docroots und nofollow-Pfade. Quarantaene nur bei unveraendertem SHA256/Metadaten-Fingerprint und eindeutiger regulaerer Datei. Race Conditions bei aktiv schreibenden Sites lassen sich ohne Isolation nicht vollstaendig ausschliessen.
- Kein frei konfigurierbarer Shell-Befehl, keine direkten Website-Pfade aus Form-Parametern.
- Fail2Ban: nur validierte aktive Jail-Namen und per ipaddress gepruefte IPv4/IPv6-Adressen. Die Sperre einer externen Administrator-IP bleibt moeglich; Panel bestaetigt vor der Aktion.
- Plesk Firewall: nur Plesks eigene CLI und Guardian-eigene Regeln; fremde Regeln und firewalld werden nicht umgeschrieben. Aktuelle `REMOTE_ADDR` wird bei Sperren ausgespart, breite Netze sowie loopback/link-local/multicast werden abgelehnt. Nach `--apply` sind getrennte Verbindungspruefung und explizite Bestaetigung erforderlich; sonst rollt Plesk nach 60 Sekunden zurueck.
- Scanner folgt keinen Symlinks, laeuft mit Website-UID; CPU/Log/Groessen-/Zeit-Limits. Ist nicht gleichbedeutend mit sicherer PHP-Laufzeit-Analyse.
- ClamAV-Vollscans laufen durch `flock` strikt einzeln. Eine root-private FIFO-Warteschlange nimmt bis zu 100 Scan-Auftraege an; Queue-Zugriff wird separat gesperrt, Job-Reports atomar geschrieben. Plesk-Scheduler nur Opt-in.
- Quarantaene speichert Dateien in privatem root-Verzeichnis, Restore ueberschreibt nie. Bei Crash im Status `pending` kann Restore die Dateiverschiebung rueckgaengig machen, wenn die Datei tatsaechlich in Quarantaene liegt.
- WAF-Parser speichert keine unredigierten HTTP-Requests im Dashboard, nur Regel-ID und IP aus maximal 512 KiB Audit-Log. Das Betriebssystem bewahrt sein eigenes Audit-Log unabhaengig davon auf.
- `watch_changes` ist ein begrenzter periodischer Metadatenvergleich. Separat existiert eine opt-in inotify-Dateiwache mit gezielten ClamAV-Pruefungen, ohne automatische Quarantaene oder Ausfuehrungsblockade. Verschobene Teilbaeume werden vom alten Pfad getrennt; ein verschobener Document-Root beendet den Monitor.
- Neue aktive Policies werden nur per expliziter Admin-Aktion aktiviert. Automatische Good-File-Reparatur erfordert zusaetzlich eine freigegebene Baseline und Opt-in pro Domain. Originale bleiben in Quarantaene; unbekannte Dateien werden nicht automatisch geloescht.
- Kein externer Sicherheitsaudit; fuer Produktion Code Review und Test-VPS erforderlich.

## v0.4.0 policy boundaries

Runtime-/HTTP-Flood-Schutz ist nur als Opt-in-Vorlage enthalten. Es gibt bewusst keinen privilegierten Web-Endpunkt zur Aktivierung beliebiger PHP-/Webserver-Regeln. Ein Policy-Rollout muss auf einer Testdomain erfolgen und die produktive Konfiguration sichern.

## 0.7.1 – Aktive Verwaltung

Die vorstehende v0.4.0-Beschreibung ist historisch. `guardian-manager` bietet nun feste Verwaltungsaktionen fuer vorbereitete Policies, keine freien Regeln oder Shell-Befehle. Anforderungen und Grenzen stehen in [MANAGEMENT.md](MANAGEMENT.md).

- API-Schluessel werden ueber stdin uebergeben und root-privat gespeichert. Kein Schluessel wird in Status, Jobs oder Diagnoseexport aufgenommen. Provider-URLs sind fest vorgegeben, TLS-Verifikation bleibt aktiv und Redirects werden abgelehnt.
- Snuffleupagus wird aus einem festgelegten Upstream-Commit unter einem eigenen unprivilegierten Build-Benutzer kompiliert. PHP-/FPM-Pruefungen und Recovery-Backups gehen einer Aktivierung voraus. Root darf weiterhin bewusst nativen Modulcode installieren; eine Commit-Pin ist keine unabhaengige Herstellersignatur.
- Guardian-WAF-Regeln werden nach Modul-/Include-/Syntaxpruefung installiert. Fremde Regeldateien werden nicht ueberschrieben. Die WAF darf nach wie vor keine ungeprueften Forwarded-IP-Header vertrauen.

## 0.8.0 – Malware-Ignore-Hashes

- SHA-256-Ausnahmen sind pro Domain begrenzt und root-privat gespeichert. Die Datei wird weiterhin gescannt und der Fund bleibt sichtbar. Die Ausnahme verhindert nur Malwarewarnung und automatische Baseline-Reparatur dieses exakten Inhalts.
- Bei manueller Reparatur wird auch die aktuelle Ignore-Liste geprueft, damit alte Formulare oder Scanberichte die Sperre nicht umgehen.
- Turnstile prueft Tokens serverseitig samt Hostname und Action. Ein Cookie ohne gueltige HMAC-Signatur reicht nicht aus. Ein kompromittierter Website-Benutzer kann seinen eigenen PHP-Guard umgehen; das ist keine Isolation gegen bereits erfolgreiche Codeausfuehrung.
- Baselines sind root-private, mit Digests gepruefte und vom Administrator freigegebene Kopien. Sie sind weder Hersteller-signiert noch externer WORM-Speicher. Pfad-, UID-, Fingerprint- und Nicht-Ueberschreiben-Pruefungen begrenzen Reparaturen; gleichzeitig schreibende Websites bleiben ein Race-Risiko.
- Bei Deinstallation werden Guardian-Policies rueckgenommen. Fremde zwischenzeitliche Konfigurationsaenderungen koennen die automatische Ruecknahme verhindern; dann wird abgebrochen, statt Konfigurationen ungeprueft zu ueberschreiben. Daten/Quarantaene und Module bleiben erhalten.

## 0.9.0 – Cronjob-Sicherheitspruefung

- Die Admin-Pruefung liest nur Dateien aus festen, ueblichen Cron-Pfaden. Symlinks und unregulaere Dateien werden nicht verfolgt; Dateianzahl, Dateigroesse und Gesamtvolumen sind begrenzt.
- Die heuristischen Treffer nennen Quelldatei, Zeilennummer und Regelkennung, aber keinen Cron-Befehlsinhalt. Kein Cronjob wird automatisch deaktiviert oder geloescht.
- Die Erkennungsregeln sind bewusst eng und unvollstaendig. Ein sauberer Bericht beweist nicht, dass Cronjobs frei von Malware sind.

## 0.10.0 – WordPress-Core-Pruefsummen

- Guardian ruft nur eine root-eigene WP-CLI-Binary aus festen Systempfaden mit festem Unterbefehl/Optionen auf. Die Domain wird als nicht-shell-ausgewertetes `--path`-Argument uebergeben.
- WP-CLI laeuft mit Webspace-UID/GID, begrenzter Laufzeit/Dateiausgabe, isoliertem Home, deaktiviertem Auto-Update und ohne Plugins, Themes oder Packages.
- Netzwerkverifikation bleibt auf WP-CLI/WordPress.org HTTPS mit Zertifikatspruefung angewiesen. Keine automatische Datei-Reparatur; MD5-Pruefsummen sind kein signierter Build-Nachweis.

## 0.12.0 – Plesk-Firewall-IP-Sperrliste

- Eine IP- oder begrenzte CIDR-Sperre wird nur als Guardian-eigene Plesk-Custom-Regel erstellt oder entfernt.
- Plesk muss installiert und aktiv sein. Guardian aktiviert keine Firewall und fasst keine fremden Regeln an.
- Plesks Aktivierungs-Timeout wird genutzt: nicht bestaetigte Aenderungen rollen nach 60 Sekunden zurueck.

## 0.13.0 – Zeitbegrenzte Plesk-Firewall-Sperren

- Nur feste TTL-Werte von 1h, 24h oder 7d sind zulaessig; dauerhaft bleibt explizit waehlbar.
- Ablaufdaten werden privat gespeichert und erst nach manueller Plesk-Bestaetigung aktiviert. Ein stuendlicher Scheduler entfernt nur passende Guardian-Regeln und bestaetigt deren Entsperrung.
- Bei nicht lesbarer Regelliste oder offener Aenderung erfolgt keine automatische Firewall-Aenderung. Der Scheduler kann den Ablauf bis zu einer Stunde verzoegern.

## 0.14.0 – Malware-Scan-Warteschlange

- Nur valide Plesk-Domains und feste Scan-Trigger gelangen in die Warteschlange. Job-IDs werden streng validiert; wartende Jobs werden atomar persistiert und nacheinander aus einer root-privaten Queue-Datei entnommen.
- Die Queue nimmt hoechstens 100 wartende Scans an. Ein Scheduler-Lauf reiht faellige Domains ein; das 24-Stunden-Intervall wird zwischen tatsaechlichen Scanstarts berechnet. Ein aktiver Worker behaelt den globalen `flock`; es laufen keine parallelen Vollscans.
- Scannerprozess bleibt unter Website-UID/GID, startet mit niedriger CPU-Prioritaet und bestehenden CPU-/Dateigroessenlimits. Die Warteschlange reduziert Parallelitaet, garantiert aber keine Laufzeit und setzt ClamAV nicht in einen isolierten Container.

## 0.15.0 – Speicherverwaltung

- Speicherberichte zaehlen nur regulaere Dateien und folgen keinen Symlinks; problematische Eintraege setzen den Status `incomplete`.
- Baselines liegen in root-privaten Verzeichnissen. Loeschaktionen akzeptieren nur hexadezimale IDs, pruefen Domain-/Manifest-Zuordnung und verweigern aktuell fuer automatische Reparatur ausgewaehlte Baselines.
- Backup-Loeschung prueft ID, Dateityp und SHA-256. Das in der Guardian-WAF-Konfiguration referenzierte Rollback-Backup wird abgelehnt.
- Neue Backups und Baselines werden bei voller Count-/Speicherquote abgelehnt, bevor Konfigurationsaenderungen stattfinden. Es gibt keine automatische Retention oder Hintergrundloeschung.

## 0.16.0 – Admin-Tool-Kandidaten

- Die Pruefung ist read-only und auf Adminer/TinyFileManager-Namen plus Marker begrenzt; sie meldet Kandidaten, keine Malware-Verurteilung.
- Traversal folgt keinen Symlinks und keinen Mountpoints, begrenzt Dateien/Dateisystemeintraege/Dateigroesse/Tiefe/Laufzeit und markiert erkannte Abdeckungsluecken.
- Treffer enthalten Dateipfad und SHA-256, aber keinen Quelltext. Es gibt keine automatische Quarantaene, Reparatur oder Deaktivierung dieser Kandidaten.

## 0.17.0 – WordPress-Datenbankindikatoren

- WP-CLI laeuft mit Website-UID/GID, isoliertem HOME und deaktivierten Plugins/Themes. Tabellen-/Spaltennamen stammen aus festen Allowlisten; Tabellenpraefixe werden strikt validiert.
- Ausschliesslich read-only SELECT-Abfragen, 101 Zeilen je Tabelle, 2 MiB Ausgabe und 5 Minuten Gesamtzeit. Ausgabe/Bericht enthalten keine Datenbankwerte oder Zugangsdaten.
- Numerische Zeilen-IDs koennen Website-Strukturen offenlegen und werden nur root-privat gespeichert sowie Administratoren angezeigt.
- Muster sind heuristisch; Fehlalarme und uebersehene Malware sind moeglich. Kein Imunify MDS, kein ClamAV-Ersatz und keine Datenbankaenderung.

## 0.11.0 – WordPress-Plugin-Pruefsummen

- Nur Plugins mit verfuegbaren WordPress.org-Pruefsummen gelten als geprueft. Uebersprungene Plugins werden separat benannt und als Teilstatus ausgewiesen.
- WP-CLI bleibt an root-eigene Binary-Pfade, isolierte Konfiguration, Webspace-UID und TLS-Standardpruefung gebunden. Keine automatische Aenderung oder Reparatur.
