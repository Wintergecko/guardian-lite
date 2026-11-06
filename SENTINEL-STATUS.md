# Sentinel Security: Liefer- und Pruefstatus 0.28.53

Stand: 6. November 2026. Dieses Paket ist ein Entwicklungsstand der vorhandenen
Plesk-Erweiterung `guardian-lite`. Der gesamte Entwicklungsauftrag mit zwoelf
vollstaendigen Modulen ist noch nicht abgeschlossen. Eine Produktionsfreigabe
auf Ubuntu 24.04 oder Debian mit Plesk wurde in dieser Sitzung nicht nachgewiesen.

## Bestandsaufnahme und Zuordnung

[ARCHITEKTUR.md](ARCHITEKTUR.md) dokumentiert den vorgefundenen Stand 0.28.46,
die Komponenten, Vertrauensgrenzen und alle zwoelf Module mit konkreten Luecken.
Die Erweiterung nutzt weiterhin denselben Plesk-Controller, dieselbe Extension-ID,
dieselben Datenverzeichnisse sowie die vorhandenen React-/TypeScript- und
serverseitigen Ansichten. Dieses Update fuehrt keine Datenmigration durch.

## In 0.28.53 ergaenzt

- Globale Fail2Ban-Defaults fuer `MaxRetry`, `FindTime` und `BanTime` in
  `[DEFAULT]`, mit Plesk-Admin-/CSRF-Schutz, Eingabe- und
  Konfigurations-Fingerprint-Pruefung.
- Vor jeder Aenderung wird die Guardian-Override-Datei gesichert. Bestehende
  Jail-spezifische Abschnitte bleiben beim Setzen und Wiederherstellen erhalten.
- Anwenden und Wiederherstellen fuehren `fail2ban-client -t`, einen vollstaendigen
  Fail2Ban-Reload und unabhaengige Laufzeitpruefungen aus. Fehler loesen ein
  Rueckschreiben der vorherigen Konfiguration aus; ein fehlgeschlagenes
  Rollback wird explizit gemeldet.
- Die UI warnt vor dem vollstaendigen Reload und zeigt die Grenzen der
  Fail2Ban-CLI bei der Erkennung von `[DEFAULT]`-Vererbung. Der Helper prueft
  effektive Werte pro aktivem Jail, kann aber die Herkunft nicht beweisen.
- Gezielte Fail2Ban-Helper-Tests (14), UI-/Navigations-Tests (29),
  TypeScript-/Produktionsbuild und PHP-Smoke-Tests bestanden lokal. Kein
  Live-Reload, keine Installation und kein Firewall-Apply auf dem Plesk-Server.

## In 0.28.52 ergaenzt

- Der Compose-Erstellungs- und YAML-Editor markiert moegliche Klartextwerte
  anhand typischer Passwort-, Token-, Secret-, API-Key- und Credential-
  Variablennamen. Die Warnung gibt keine Werte aus und verhindert weder
  Speicherung noch Nutzung eines Secrets.
- Administratoren muessen erkannte Zugangsdaten rotieren und gespeicherte
  Compose-Backups beruecksichtigen. Docker Secrets oder root-private
  Umgebungsdateien sind vorzuziehen, sofern die Anwendung diese unterstuetzt.
- TypeScript-/Produktionsbuild und gezielte UI-/Versions-/Paketpruefungen
  bestanden. Die Warnung wurde nicht auf dem Plesk-Server installiert.

## In 0.28.51 ergaenzt

- Neuer Docker-Menuepunkt mit Serverinventar fuer bis zu 100 Container und
  Docker-Compose-Projekte. Docker/Compose werden nur gelesen, wenn die CLI,
  Daemon und Compose v2 verfuegbar sind; Guardian installiert/aktiviert Docker
  nicht.
- Container koennen gestartet, gestoppt, neu gestartet, geloggt und hinsichtlich
  CPU, RAM und Neustartregel angepasst werden. Neue Standalone-Container
  unterstuetzen ein Image, Ressourcenlimits, eine Portbindung und optionale
  benannte Volumes; Host-Verzeichnisse, Docker-Socket und privilegierte
  Optionen sind fuer diese Funktion nicht freigegeben.
- Compose-Dateien root-eigener Projekte in root-verwalteten Verzeichnissen
  lassen sich bearbeiten, mit Compose validieren, vor Aenderungen sichern und
  aus Backups wiederherstellen. Speichern startet keine Dienste; `up` ist eine
  separate bestaetigungspflichtige Aktion. Compose-YAML kann dennoch
  Hostrechte vermitteln und muss vor dem Anwenden geprueft werden.
- Container-Loeschen erfordert einen gestoppten Container und behaelt Images
  sowie Volumes. Compose-Down entfernt Container/Netze, aber keine Volumes oder
  Images. Nur von Sentinel erstellte Compose-Projekte koennen auch mit ihrer
  YAML-Datei geloescht werden; ein root-privates Backup bleibt erhalten.
- Aenderungen sind Plesk-Admin-/CSRF-geschuetzt und laufen ueber einen festen
  argumentbasierten Helper. Es gibt keinen `docker exec`-Endpunkt. Aktionen
  werden ohne Konfigurationsinhalte, Umgebungsvariablen oder Zugangsdaten in
  einem begrenzten root-privaten Docker-Audit protokolliert.
- TypeScript-/Produktionsbuild, gezielte Docker-Helper-Tests, PHP-Smokes und
  Release-Paketpruefung bestanden. Docker-Livebetrieb sowie Update/Installation
  auf dem Plesk-Server wurden nicht getestet.

## In 0.28.50 ergaenzt

- Der Port-Tab zeigt jetzt alle von Plesk gelieferten Datensaetze mit Portangaben
  read-only, einschliesslich Plesk-Standarddiensten und benutzerdefinierten
  Plesk-Regeln. Guardian-eigene Portregeln bleiben in einem separaten Abschnitt
  mit den vorhandenen Admin-/CSRF-geschuetzten Aktionen.
- Die Inventaranzeige umfasst bis zu 2000 Plesk-Regeln. Nicht darstellbare
  Datensaetze und eine unvollstaendige Liste werden explizit gemeldet.
- Plesk-Regeln ohne Namen erhalten einen sicheren Anzeigenamen; dies veraendert
  nicht die Erkennung von Guardian-eigenen Regeln.
- Die read-only Abfrage des Zielservers lieferte 25 Regeln, darunter 22 Regeln
  mit Portangaben (20 Plesk-Standarddienste und zwei benutzerdefinierte Regeln).
  Diese Beobachtung bestaetigt die Datenquelle, nicht die Installation oder
  Darstellung der neuen Version auf dem Server.

## In 0.28.50 ergaenzt

- Webschutz-Ereignisse und Guardian-Meldungen/Audit-Log werden als getrennte,
  per Tastatur bedienbare Tabs dargestellt. Die inaktive Tabelle bleibt
  verborgen; Filter und Auto-Refresh gelten fuer beide Ansichten.
- Beide Listen werden clientseitig mit 25 Eintraegen pro Seite paginiert.
  Filterwechsel setzt die Seite zurueck; Seitenzaehler und Grenzen werden
  angezeigt. Die Pagination bezieht sich auf die vom Server bereitgestellten
  Eintraege, derzeit maximal 200 WAF- und 200 Audit-Ereignisse.
- Der Audit-JSON-Export bleibt nur im Audit-Tab verfuegbar. Der Exportumfang
  folgt weiterhin dem serverseitigen Endpunkt.
- React-/TypeScript-Produktionsbuild und gezielte UI-/Navigationstests liefen
  lokal erfolgreich; ein neuer Live-Test oder eine Installation auf dem
  Plesk-Server wurde nicht ausgefuehrt.

## In 0.28.47 implementiert

### Fail2Ban-IP-Aktionen

- IPv4/IPv6 werden vor Befehlsaufrufen normalisiert und validiert.
- Eine exakte Laufzeitabfrage (`get JAIL banned IP`) muss bereits vor der
  Aenderung eine eindeutige Antwort liefern. Unbekannte Antwortformate verhindern
  die Aktion. Die auf 100 IPs begrenzte Dashboard-Anzeige dient nicht als Nachweis.
- Jail-bezogene Freigaben verwenden `plesk bin ip_ban --unban IP,JAIL`, wenn
  die Plesk-Binary vorhanden ist. Ohne Plesk wird der vorhandene Fail2Ban-Client
  genutzt. Ein fehlgeschlagener Plesk-Aufruf loest keinen zweiten Schreibversuch
  ueber einen anderen Adapter aus.
- Manuelles Sperren verwendet weiterhin `fail2ban-client set JAIL banip IP`.
  Die dokumentierte Plesk-CLI stellt keinen manuellen Sperrbefehl bereit.
- Nach einer Aenderung wird die exakte IP bis zu dreimal im Jail abgefragt.
  Fehler, unbekannte Antworten und widersprechende Zustaende ergeben keinen Erfolg.
- Anforderung, Fehler und verifizierter Abschluss erscheinen im bestehenden
  root-privaten Incident-Verlauf und dessen Export. Das ist kein neuer zentraler
  Audit-Dienst mit Akteurzuordnung oder manipulationssicherer Historie.

Ein Fehler nach dem Schreibversuch bedeutet, dass der Zustand manuell zu pruefen
ist. Das Update behauptet weder automatische Ruecknahme einer IP-Aktion noch
kernelwirksame Paketsperren allein aufgrund des Fail2Ban-Laufzeitstatus.

### Firewall-Bestaetigung

- Vor `--confirm` wird das Plesk-Regelinventar neu gelesen. Unvollstaendige oder
  unlesbare Listen verhindern die Bestaetigung.
- Bei hinzugefuegten Regeln muessen Name, exakte Quelle, Richtung, Klasse,
  Aktion und gegebenenfalls Port/Protokoll zur ausstehenden Aenderung passen.
  Doppelte Namen oder zusaetzliche Quellnetze verhindern die Bestaetigung.
- Bei geloeschten Regeln muss der Name auch aus dem Inventar verschwunden sein;
  eine vom Guardian-Parser nicht erkannte Restregel reicht nicht als Loeschnachweis.
- Nach dem Inventarabruf wird die Bestaetigungsfrist erneut geprueft. Eine zu
  spaete Antwort darf den Plesk-Rollback nicht nachtraeglich deaktivieren.
- Bei negativem Nachweis wird kein `--confirm` gesendet und die ausstehende
  Aenderung bleibt fuer Rollback oder explizite Ruecknahme erhalten.

Der Nachweis bezieht sich auf das Plesk-Regelinventar. Ein unabhaengiger
Verbindungstest in einer zweiten Sitzung ist weiter erforderlich. Die bestehenden
Plesk-Apply/Confirm-/Reset-Ablaeufe ersetzen kein vollstaendiges externes Backup.

## Lokal getestet

Umgebung: Windows, Python 3.14, vorhandene PHP-CLI und Node/npm.

- TypeScript-Typpruefung und Vite-Produktionsbuild.
- PHP-Syntax aller PHP-/PHTML-Dateien.
- Alle drei vorhandenen PHP-Smoke-Programme: Scan-Controller, Verwaltung und Updater.
- 14 neue portable Tests fuer reale Helper-Funktionen mit isolierten
  Systemgrenzen: IPv6, Plesk-Freigabe, direkter Fallback ohne Plesk,
  verzogerter Status, Fehler, unbekannte Antworten, Eingabevalidierung,
  Inventarabweichungen, unvollstaendige Listen und abgelaufene Fristen.
- Insgesamt 48 erfolgreiche portable Python-Tests einschliesslich vorhandener
  UI-Vertrags-, Versions- und ZIP-Pruefungen; keine Fehler oder uebersprungenen
  Tests in dieser gezielt ausgewaehlten Testsuite.
- Python-Syntaxpruefung der drei privilegierten Helfer und des Paketbuilders;
  `git diff --check` ohne Befund.

Die portablen Tests kompilieren die ausgewaehlten Funktionsdefinitionen aus dem
tatsaechlichen Helper, damit Windows keine Linux-Module importieren muss.
Sie ersetzen weder den vollstaendigen Helper-Import noch Linux-Systemtests.
Weitere Paket-/UI-Pruefergebnisse stehen im lokalen Testprotokoll unter
`dist/verification/`. Diese Protokolle sind nicht Bestandteil des Extensions-ZIP.

## Zusaetzlich auf dem bereitgestellten Plesk-Server getestet

Umgebung: Debian 13.7, Plesk 18.0.82, Python 3.13.5, Fail2Ban 1.1.1.
Die Tests liefen aus einer getrennten Quellcodekopie in einer transienten
systemd-Serviceumgebung: schreibgeschuetztes Serversystem, privates Netzwerk
mit ausschliesslich Loopback sowie separate `/tmp`, `/var` und `/run`.
Produktive Fail2Ban-/Datenbank-/systemd-Sockets waren in der Testumgebung
nicht erreichbar. Laufzeit, Speicher, Prozesse und CPU wurden begrenzt.

- Vollstaendige Python-Discovery: **203 Tests ausgefuehrt, 202 bestanden,
  ein Test uebersprungen, keine Fehler**. Der optionale native
  Snuffleupagus-Buildtest blieb deaktiviert.
- Die Suite umfasst echte isolierte HTTP-Tests fuer Bot-Schutz und ModSecurity,
  Linux-Dateiwache und Dateiberechtigungs-/Symlink-Pruefungen.
- Alle drei PHP-Smoke-Programme und saemtliche PHP-/PHTML-Syntaxpruefungen
  bestehen auch auf diesem Debian-System.
- Der neue Fail2Ban-Verifikator wurde zusaetzlich mit einer echten, ausschliesslich
  lesenden Abfrage am aktiven SSH-Jail erfolgreich geprueft.
- Die Livepruefung fand einen Parserfehler: Plesk liefert Standardregeln mit
  `name: null`. Diese Regeln werden nun anhand ihrer Klasse angezeigt; sie
  werden dadurch niemals zu Guardian-eigenen, bearbeitbaren Regeln.
- Nach Korrektur erkennt das Inventar alle **25 von 25** vorhandenen Regeln.
  Nicht erkannte Datensaetze markieren das Inventar als unvollstaendig und
  verhindern neue Firewall-Aenderungen sowie deren Bestaetigung.
- Ein veralteter Fail2Ban-Test wurde an die neue Laufzeitverifikation angepasst;
  ein weiterer Test verwendet jetzt einen temporaeren statt eines festen Datenpfads.
- Das echte Plesk-Firewallinventar hatte vor und nach den Tests denselben SHA-256.

Der reproduzierbare Runner liegt im Quellprojekt unter
`tools/run_isolated_server_tests.py`. Die vollstaendigen Protokolle liegen lokal
in `dist/verification/linux-tests-debian13-final.txt` und
`dist/verification/server-readonly-and-php.txt`.

## Weiterhin nicht verifiziert

- Installation/Upgrade im Plesk Extension Manager und Zustanderhalt im Livebetrieb.
- Ubuntu 24.04 und weitere Debian-/Plesk-/Fail2Ban-Versionen.
- Aktive Sperr-/Freigabeaktionen, IPv6-Paketsperren und konkrete Fail2Ban-Actions.
- Firewall-Apply, automatische Ruecknahme nach Verbindungsabbruch, Confirm und Reset
  auf dem Zielsystem sowie Wechselwirkungen mit vorhandenen Regeln.
- Produktive Plesk-WAF-/PHP-FPM-HTTP-Integration, externer Anbieterbetrieb,
  reale Mailzustellung und der native Snuffleupagus-Build.

Die installierte Erweiterung und produktiven Sicherheitskonfigurationen wurden
nicht geaendert. Es wurde kein Release veroeffentlicht. Aktive Live-Tests stehen
bis zur Klaerung der produktiven Nutzung des bereitgestellten Servers aus.

## Live-Integrationspruefung und Einschraenkung in 0.28.48

Die korrigierte Version wurde erneut in der abgeschotteten Linux-Umgebung
geprueft: **207 Tests, 206 bestanden, ein optionaler nativer Buildtest
uebersprungen**, keine Fehler. Alle drei PHP-Smokes und Syntaxpruefungen bestehen.
Das Protokoll liegt unter `dist/verification/live-048-tests.txt`.

Nach ausdruecklicher Betreiberfreigabe wurde 0.28.47 auf dem produktiven Server
installiert. Die Plesk-Einstellungen blieben unveraendert. Aktive IPv4- und
IPv6-Sperr-/Freigabetests am SSH-Jail mit reservierten Dokumentationsadressen
bestanden einschliesslich unabhaengigem Nachweis der Regeln im Paketfilter.
Beide Testsperren wurden wieder entfernt.

Der aktive Firewalltest bestand nicht: Plesk-CLI-Bestaetigungen schlugen fehl,
und native Hintergrundaktivierungen ueberschnitten sich. `--reset` nahm nur den
Datenbankentwurf zurueck. Im Fehlerpfad aktivierte Plesk zeitweise seine
Notfallkonfiguration. Die originalen Filtertabellen fuer IPv4/IPv6 einschliesslich
Fail2Ban-/Imunify-Ketten sowie die konsistente Firewall-Datenbank und das aktive
Plesk-Regelskript wurden anschliessend aus dem zuvor angelegten root-privaten
Backup wiederhergestellt. Das abschliessende Regelinventar entsprach bytegenau
dem Ausgangsbestand mit 25 Regeln.

Diese Firewall-Schreibstrecke gilt auf dem untersuchten Server als **nicht
freigegeben**. 0.28.48 wertet die root-private Datei
`/var/lib/guardian-lite/firewall-write-block.json` aus. Bei vorhandener Sperrdatei
werden saemtliche Guardian-Firewall-Aktionen vor dem ersten Plesk-Aufruf
abgewiesen. Die UI zeigt den Grund und sperrt die betroffenen Formulare.
Die echte Firewall bleibt eingeschaltet; reine Inventarabfragen und separate
Fail2Ban-Aktionen bleiben verfuegbar. Die Sperre bleibt bei Updates erhalten.
Sie darf erst nach nachgewiesen funktionierendem Apply/Confirm/Rollback entfernt
werden. Ein weiterer Test durch pauschales erneutes Apply ist keine Freigabe.

Zusaetzlich verhindert 0.28.48 eine neue Aenderung bei vorhandener nativer
Plesk-Aktivierungs-Pipe. Eine angeforderte Ruecknahme behaelt ihre ausstehende
Transaktion und wird als `rollback_requested` statt als abgeschlossen angezeigt.
Dies ist weiterhin kein unabhaengiger Nachweis einer aktiven Kernel-Ruecknahme.

## Nicht fertig implementierter Auftragsumfang

Die bestehenden Teilfunktionen bleiben erhalten. Offen bleiben insbesondere:

- sichere Filter-/Action-/Jail-Erstellung und getestete Plesk-spezifische
  Jail-Vorlagen;
- allgemeine Firewalladapter, vollstaendige Regelverwaltung und priorisierte
  systemweite Black-/Whitelist;
- kontinuierlicher Logstream und dauerhafte historische Angriffsaggregation;
- GeoIP-Laenderregeln, Ausnahmen und historische GeoIP-Auswertungen;
- allgemeine Sicherheitsprofile, wiederkehrende Angreiferregeln und Zeitplaene;
- Telegram, Discord, sichere Webhooks und konfigurierbare Benachrichtigungsregeln;
- einheitliche Konfigurationsversionierung, Export/Import und Wiederherstellung;
- vollstaendige Diagnosematrix und konsolidierte persistente Einstellungen.

## Installation und Update

1. Zuerst einen isolierten Plesk-Testserver und ein externes, wiederherstellbares
   Systembackup bereitstellen. Vorhandene Einstellungen, aktive Regeln und
   `/var/lib/guardian-lite/` sichern. Das Entwicklungs-ZIP nicht als bereits
   produktionsgeprueft behandeln.
2. Die SHA-256-Datei zusammen mit dem ZIP auf den Testserver uebertragen und dort
   mit `sha256sum -c guardian-lite-0.28.53.zip.sha256` pruefen.
3. Neuinstallation: `plesk bin extension -i /root/guardian-lite-0.28.53.zip`.
   Update: `plesk bin extension -g /root/guardian-lite-0.28.53.zip`.
4. Als direkt angemeldeter Plesk-Administrator oeffnen, Diagnose ausfuehren und
   vorhandene Routen, Einstellungen, Scans und Wiederherstellungsdaten pruefen.
5. Firewall-Apply/Confirm/Rollback ausschliesslich auf einem isolierten
   Testserver mit zweiter Verbindung und unabhaengigem Konsolenzugang pruefen.
   Auf dem untersuchten Produktivserver bleibt die Guardian-Firewall-Schreibsperre
   aktiv; dort keine Firewall-Schreibtests oder manuelle Entfernung der Sperrdatei
   durchfuehren. Ein fehlgeschlagener Test muss den unveraenderten Ausgangsbestand
   nachweislich wiederherstellen.
6. Erst nach erfolgreicher Zielsystempruefung ueber einen produktiven Einsatz
   entscheiden. Detaillierte Voraussetzungen stehen in [MANAGEMENT.md](MANAGEMENT.md)
   und [SECURITY.md](SECURITY.md).

## Technische Referenzen

- [Plesk ip_ban CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/ip_ban-ip-address-banning-fail2ban.73594/)
- [Fail2Ban-Client: offizielle Manpage](https://github.com/fail2ban/fail2ban/blob/master/man/fail2ban-client.1)
