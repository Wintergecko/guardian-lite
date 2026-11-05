# Guardian Lite v0.28.13 – Sicherheitsmodell und Grenzen

## 0.28.13 – Globale Moduldiagnose und WAF-Bedienung

- Ein gemeinsamer, standardmaessig ausgeschalteter Root-Schalter steuert Debugereignisse aus Helper-Aktionen, Verwaltungsmanager, Hintergrundauftraegen, Updater und Plesk-Firewall.
- Modulaktionen speichern nur feste Aktionsnamen, Ergebniscode und Laufzeit; keine Anfrageargumente, Datei-Inhalte oder CLI-Standardausgabe. Begrenzte Plesk-Fehlerhinweise aus dem vorhandenen Firewall-Debugpfad koennen weiterhin Werte enthalten.
- Die Logdatei bleibt root-privat, auf 256 KiB begrenzt und schreibt nichts, wenn der Schalter aus ist. Abschalten behaelt bestehende Ereignisse bis zur natuerlichen Begrenzung bei.
- WAF- und CRS-Statusanzeige aendert die Aktivierungs- und Rollback-Sicherungen nicht.

## 0.28.12 – Signaturgepruefte OWASP-CRS-Verwaltung

- Guardian laedt nur das offizielle CRS-v4-Minimalarchiv aus GitHub-Releases und prueft die OpenPGP-Signatur gegen den fest im Code gepinnten OWASP-Projektschluessel-Fingerprint. Die HTTPS-Keyquelle allein gilt nicht als Vertrauensanker.
- Archivgroesse, Dateianzahl, expandierte Groesse und Pfade sind begrenzt. Symlinks, Hardlinks, Sonderdateien, doppelte Pfade, unerwartete Dateien und veraenderte Dateien werden vor Aktivierung abgelehnt.
- Bereitstellen aktiviert keine Regeln. Aktivierung schreibt nur Guardians eigene Apache-Include-Datei, testet Syntax und Include-Aufloesung und laedt Apache erst danach neu; Fehler stellen die vorigen Bytes wieder her.
- Vorherige Guardian-Includes werden mit Digest gesichert und koennen nur bei unveraendertem aktuellen Digest zurueckgerollt werden. Aktives CRS verhindert eine Deinstallation, die Regeln zuruecklassen koennte.
- CRS-Regeln koennen legitime Anfragen blockieren. Guardian setzt keinen Plesk-WAF-Modus; Betreiber muessen eine Testdomain im Erkennungsmodus pruefen und den gewuenschten Blockmodus separat konfigurieren.

## 0.28.4 – Bewegungseinstellungen
- Kurzanimationen sind dekorativ und veraendern keine Sicherheitsaktionen oder deren Bestaetigung.
- `prefers-reduced-motion: reduce` deaktiviert Animationen und Navigationstransitionen.

## 0.28.3 – Modulnavigation
- Statische Menue-Fallbacks verbergen Untermenues ausdruecklich, solange ihr `details`-Element geschlossen ist.
- Die JavaScript-Navigation verschiebt weiterhin ausschliesslich serverseitig gerenderte Elemente anhand fester IDs; pro Ansicht wird genau ein Modulbereich eingeblendet.

## 0.28.2 – Menue-Darstellung
- Servergerenderte native Menuepunkte sind statisch und fuer alle Beschriftungen HTML-escaped.
- Die Navigation ist auch ohne JavaScript verfuegbar; ausgeblendete Inhaltsbereiche werden erst nach erfolgreicher Initialisierung verborgen.

## 0.28.0 – Menue-Neuordnung

- Die Navigation nutzt statische, HTML-escaped Beschriftungen und IDs aus dem Template; keine nutzerkontrollierten HTML-Fragmente oder dynamischen `innerHTML`-Inhalte.
- Inhaltsbereiche werden clientseitig nur in Menuepanels verschoben. Ohne JavaScript bleiben alle bereits serverseitig gerenderten Bereiche sichtbar.
- Gruppen und Untermenuepunkte verlinken nur Guardian-Funktionen. PHP-Handler-Schutz, WebShield, Reputation und CMS-Pruefungen sind entsprechend ihrem tatsaechlichen Teil-/Manuellstatus markiert.

## 0.27.1 – Diagnose-Schalter in der Schutzverwaltung

- Der Management-Tab verwendet dieselben POST-/CSRF-geschuetzten `debug-on`- und `debug-off`-Aktionen wie die Firewall-Ansicht; es gibt keine zweite unabhaengige Einstellung.
- Sichtbarer Status und Ereignisausschnitt stammen aus demselben root-privaten, begrenzten Firewall-Debugprotokoll.

## 0.27.0 – Firewall-Dashboard und Diagnose

- Fremde Plesk-Regeln werden ausschliesslich aus `plesk ext firewall --list-json` gelesen und im Panel mit HTML-Escaping angezeigt; Schreibaktionen bleiben auf Guardian-eigene Regeln begrenzt.
- Firewall-Diagnose ist standardmaessig aus und nur ueber Admin-POST mit CSRF schaltbar. Die root-private JSONL-Datei ist auf 256 KiB begrenzt und speichert keine Argumente oder Standardausgabe.
- Das Diagnoseprotokoll enthaelt Zeit, feste CLI-Schritte, Exitcode, Laufzeit, Ausgabegroesse und begrenzte Fehlerhinweise. Unbekannte/unlesbare Settings deaktivieren Logging.
- Debugdaten koennen begrenzte Fehlerdetails enthalten und sind daher nur fuer kurzzeitiges Troubleshooting vorgesehen; das Abschalten stoppt weitere Eintraege, loescht den Verlauf aber nicht.

## 0.26.0 – E-Mail-Outbox

- Outbox und Sperrdatei liegen root-eigen mit Modus 0600 unter dem Guardian-Datenverzeichnis. Eintraege enthalten nur Incident-Metadaten, nie Dateiinhalt oder API-Schluessel; Anzahl und Dateigroesse sind begrenzt.
- Transportfehler werden als Incident protokolliert und bis zu sechs Mal mit Backoff wiederholt. Nach Erschoepfung ist eine manuelle Wiederholung verfuegbar.
- Sendmail-Exit-Code null bedeutet nur lokale Annahme. Externe Mailzustellung und Bounce-Verarbeitung werden nicht bestaetigt.

## 0.25.0 – Guardian-IP-Ausnahmen

- Kommentare und Netze werden validiert; ueberschneidende Eintraege und neue Guardian-IP-/Port-Sperren innerhalb eines Ausnahme-Netzes werden abgelehnt.
- Die Ausnahme ist Guardian-intern. Sie ist keine Firewall-Allow-Regel und hebt keine bestehenden Plesk-, Betriebssystem- oder Provider-Sperren auf.
- Bestehende Guardian-Sperren muessen vor dem Eintragen manuell ueber die Guardian-Regelverwaltung entfernt werden. Eintraege sind dauerhaft bis zur manuellen Entfernung.

## 0.24.0 – Globale Malware-Ignore-Hashes

- Administratoren koennen einen SHA-256-Inhalt domainuebergreifend als ignoriert markieren. Scans laufen weiter und Funde bleiben sichtbar; Warnungen und automatische Reparatur fuer diesen Inhalt werden unterdrueckt.
- Globale Hash-Ausnahmen sind auf 2.000 Eintraege begrenzt, reversibel und im Incident-Verlauf dokumentiert. Ein Hash ist kein Sicherheitsnachweis: falsche Freigabe kann Malware auf mehreren Websites verdecken.

## 0.23.0 – Plesk-Portregeln

- Portregeln schreiben ausschliesslich eingehende Guardian-eigene Regeln ueber `plesk ext firewall`; Port-Allow ist auf eine einzelne Quell-IP begrenzt, Port-Deny auf die bestehende CIDR-Obergrenze.
- Port-Deny lehnt ein Quellnetz ab, das die aktuelle Admin-Verbindungs-IP enthaelt. Plesk-Regelauswertung kann globale Systemrichtlinien nicht zwingend ueberstimmen.
- Aenderungen erfordern Plesks 60-Sekunden-Bestaetigungsablauf und getrennten Verbindungstest. Die UI entfernt Portregeln nur per numerischer Guardian-Regel-ID. Kein automatisches Entfernen oder Aendern fremder Regeln.
- Die Deinstallation wird blockiert, solange Guardian-Port-Allow-Regeln aktiv sind; diese muessen einzeln entfernt und mit Verbindungstest bestaetigt werden.

## 0.22.0 – Cronjob-ClamAV-Signaturscan

- Cron-Dateien werden ueber feste Systempfade geoeffnet; Symlinks und unregulaere Dateien werden nicht verfolgt. Der optionale ClamAV-Scan arbeitet auf Kopien in einem privaten temporaeren Verzeichnis und aendert keine Cronjobs.
- Gesamtinhalt ist auf 4 MiB und Laufzeit auf 45 Sekunden begrenzt. Treffer bleiben manuell zu pruefende ClamAV-Signaturen, keine automatische Klassifikation oder Bereinigung.
- ClamAV fehlt: Heuristikpruefung laeuft weiter; Signaturscan meldet `unavailable`.

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

## 0.21.0 – Gestreamter CMS-Datenbankscan

- Joomla- und Magento-PHP-Konfigurationen werden ueber no-follow-Dateideskriptoren begrenzt gelesen; PHP wird nicht interpretiert.
- `mysqldump`/`mariadb-dump` werden nur als root-eigene Systembinaries akzeptiert und mit fester Argumentliste ohne Shell als Website-Benutzer ausgefuehrt.
- Passwoerter bleiben aus Argumenten, Logausgabe und Berichten; die temporaere Client-Optionsdatei wird in einem geschuetzten Verzeichnis erstellt, danach auf 0600 gesetzt und unter der Website-UID genutzt.
- Der Dump wird nie persistiert. Teilergebnis/Fehler, Timeout und Groessenlimits gelten nie als sauber; kein automatisches Datenbank-Cleanup.

## 0.20.0 – Gestreamter WordPress-Datenbankscan

- WP-CLI exportiert die Datenbank als Website-Benutzer direkt auf stdout; der Inhalt wird ohne Dumpdatei in ClamAV eingespeist. Beide Prozesse verwenden feste Argumente, leere/isolierte Umgebungen, begrenzte CPU und getrennte Prozessgruppen.
- Datenstrom ist auf 512 MiB und 5 Minuten begrenzt. Bei Ueberschreitung werden Prozesse beendet und der Befund als unvollstaendig markiert. ClamAV laeuft als Website-Benutzer und benoetigt dort lesbare lokale Signaturen.
- Prozessausgaben werden nicht roh gespeichert. Berichte enthalten nur begrenzte Dateibytes und validierte ClamAV-Signaturnamen; keine Datenbankinhalte oder Zugangsdaten.
- Der Scan ist read-only und nutzt ClamAV-Signaturen, nicht Imunifys MDS-Datenbank-Signaturen. Keine Bereinigung, Datenbank-Backup-/Rollback-Funktion oder vollstaendige Datenbankabdeckung bei ueberschrittenem Streamlimit.

## 0.19.0 – WordPress.org-Themevergleich

- Die manuelle Theme-Pruefung verwendet nur HTTPS zu `api.wordpress.org` und `downloads.wordpress.org`; Weiterleitungen auf andere Hosts werden vor dem Folgen abgelehnt.
- Theme-Archive und entpackte Eintraege haben Groessen-/Dateilimits. Absolute Pfade, Traversal, doppelte Pfade, Symlinks und verschluesselte ZIP-Eintraege werden abgelehnt.
- Lokale Theme-Dateien werden ohne Symlink-Following gelesen und waehrend der Pruefung auf Austausch/Veraenderung geprueft. Reports enthalten nur relative Pfade und feste Regeln, keinen Dateiinhalt.
- Die Quelle ist das HTTPS-Verzeichnisarchiv, kein signierter Herstellerpruefwert. Eigene und kommerzielle Themes bleiben unbewertet; Abweichungen sind manuell zu klaeren und werden nie automatisch repariert.

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

## 0.18.0 – RapidScan-Cache

- Cache-Dateien liegen root-privat. Cachetreffer verlangen exakte Dateisystem-Metadaten inklusive ctime sowie gleiche ClamAV-Binary-/Signaturidentitaet. Ein Signatur- oder Binary-Update invalidiert den gesamten Domaincache.
- Cacheverwendung setzt ein vollstaendiges, begrenztes Inventar ohne unsichere Pfade voraus. ClamAV prueft nur neue/geaenderte Pfade aus einer root-erstellten, nicht durch Website-Benutzer beschreibbaren Liste; Cache wird nachher nur fuer unveraenderte Dateien aktualisiert.
- Malwarefund-Dateien werden nicht als sauber gespeichert; Scannerwarnungen, unvollstaendige Logs oder Inventarfehler verhindern Cache-Updates. Cache-Grenzen: 16 Domains, 4 MiB je Domain, 10.000 Dateien. Sonstige Faelle verwenden den regulaeren Vollscan.
- Wie jeder inkrementelle Scanner hat dies ein Zeitfenster bei gleichzeitig geaenderten Websites; periodische Vollscans bleiben sinnvoll. Dies nutzt keine externe Hash-Reputation.

## 0.11.0 – WordPress-Plugin-Pruefsummen

- Nur Plugins mit verfuegbaren WordPress.org-Pruefsummen gelten als geprueft. Uebersprungene Plugins werden separat benannt und als Teilstatus ausgewiesen.
- WP-CLI bleibt an root-eigene Binary-Pfade, isolierte Konfiguration, Webspace-UID und TLS-Standardpruefung gebunden. Keine automatische Aenderung oder Reparatur.

## 0.28.1 – Navigation-Fallback
- Die Navigation und Sprungmarken werden im Plesk-Template ausgegeben, bevor JavaScript ausgefuehrt wird.
- JavaScript blendet nicht aktive Panels erst nach erfolgreicher Initialisierung aus.
