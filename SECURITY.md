# Guardian Lite v0.9.0 – Sicherheitsmodell und Grenzen

- Root-Helfer unter Plesk `sbin`; Panelzugriff nur Administrator, POST-CSRF fuer Mutationen.
- Dateizugriffe validieren Domains, kanonische Docroots und nofollow-Pfade. Quarantaene nur bei unveraendertem SHA256/Metadaten-Fingerprint und eindeutiger regulaerer Datei. Race Conditions bei aktiv schreibenden Sites lassen sich ohne Isolation nicht vollstaendig ausschliessen.
- Kein frei konfigurierbarer Shell-Befehl, keine direkten Website-Pfade aus Form-Parametern.
- Fail2Ban: nur validierte aktive Jail-Namen und per ipaddress gepruefte IPv4/IPv6-Adressen. Die Sperre einer externen Administrator-IP bleibt moeglich; Panel bestaetigt vor der Aktion.
- Scanner folgt keinen Symlinks, laeuft mit Website-UID; CPU/Log/Groessen-/Zeit-Limits. Ist nicht gleichbedeutend mit sicherer PHP-Laufzeit-Analyse.
- Ein Scan/Quarantaene-Vorgang zur Zeit durch `flock`; Job-Reports atomar geschrieben. Plesk-Scheduler nur Opt-in.
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
