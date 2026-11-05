## 0.28.15 – PHP-Handler-Reload fuer dedizierte Pools

Guardian laedt nach PHP-Runtime-Aenderungen und Rollbacks nun neben dem gemeinsamen Plesk-FPM-Dienst auch alle laufenden dedizierten FPM-Pools derselben PHP-Version neu. Damit erreichen Simulation, Aktivierung und Wiederherstellung auch Websites mit eigenen PHP-FPM-Diensten.

Auf dem Testserver erfolgreich fuer PHP 8.4 geprueft: sechs dedizierte FPM-Dienste aktiv, Snuffleupagus geladen und Simulationsregel pro Domain gesetzt. shell_exec wurde im Simulationsmodus protokolliert und weiterhin ausgefuehrt. HTTP-Proben waren fuer zwei Sites moeglich; vier weitere beantworten Requests mit 403/404/502 oder werden von Anwendungs-Proxys bedient, daher ist deren Live-PHP-Aufruf nicht bestaetigt.

## 0.28.14 – Bestaetigte Aufbewahrungsbereinigung
- Ergaenzt eine Aufbewahrungsfrist mit Vorschau fuer alte PHP-/WAF-Backups und Good-File-Baselines.
- Entfernt Wiederherstellungspunkte erst nach separater Admin-Bestaetigung; die Vorschau wird vor der Bereinigung erneut gegen den aktuellen Bestand geprueft.
- Schuetzt aktive WAF-Rollbacks, ausgewaehlte und fuer Auto-Reparatur genutzte Baselines; behaelt mindestens drei neueste Sicherungen je Typ/Ziel und drei Baselines je Domain.
- Erweitert Tests und Betriebsdokumentation fuer Vorschau, Schutzregeln, Bestaetigung und veraltete Vorschauen.

## 0.28.13 – WAF-Formulare und globales Debugging
- Gruppiert WAF-Einstellungen in beschriftete Felder und klare Aktionsleisten; ersetzt leeres Roh-JSON durch einen lesbaren Regelstatus.
- Gestaltet CRS-Status, Bereitstellung, Aktivierung und Rollback als abgegrenzten Bereich mit responsiven Aktionen.
- Macht den bestehenden Diagnose-Schalter global fuer Helper-, Verwaltungs-, Hintergrund- und Updater-Aktionen; protokolliert nur feste Aktion, Ergebnis und Laufzeit.
- Zeigt denselben globalen Status samt Umschalter in Verwaltung und Firewall; Debug bleibt standardmaessig aus und die Logdatei begrenzt.

## 0.28.12 – OWASP CRS-Verwaltung
- Stellt offizielle OWASP CRS-v4-Minimal-Releases nach Downloadbegrenzung, Archivpfadpruefung und GPG-Signaturpruefung gegen einen fest gepinnten Fingerprint bereit.
- Verlangt separate Admin-Aktivierung; Apache-ModSecurity-/mod_unique_id-Erkennung, Konfigurationstest, Include-Pruefung, Reload und transaktionaler Rollback schuetzen vor fehlerhaften Includes.
- Zeigt bereitgestellte Versionen, aktive Konfiguration und Rollback im Verwaltungstab; aktive CRS-Konfiguration blockiert die Deinstallation bis zum Rollback.
- Fuegt Tests fuer manipulierte Archive/Assets, Fingerprintbindung und Konfigurationsfehler mit Wiederherstellung hinzu.

## 0.28.11 – Incident-Zeitreihe und Filter
- Erweitert die Incident-Ansicht auf bis zu 200 gespeicherte Ereignisse.
- Fuegt 24-Stunden-, 7-Tage- und 30-Tage-Filter, Kennzahlen, Ereignisverlauf sowie Suche und Schweregradfilter hinzu.
- Chart und Tabelle nutzen ausschliesslich bereits gespeicherte Incident-Metadaten; kein externer Dienst erforderlich.

## 0.28.10 – CrowdSec AppSec-Status
- Erkennt lesend CrowdSec-Dienst, AppSec-Erfassungsquelle, nur lokalen Listener, geladenes Apache-Modul, Einbindung der Bouncer-Konfiguration und aktivierte Weiterleitung.
- Zeigt Status in der Schutzverwaltung; Schluessel und Konfigurationsinhalte werden nicht ausgegeben.
- Installiert und aktiviert keine Fremdkomponenten; Hinweise zum manuellen Plesk-Test ergaenzt.
- Tests fuer lokale Listenerpruefung, Apache-Modulerkennung und Geheimnisausschluss hinzugefuegt.

## 0.28.9 – Optionale CrowdSec-Entscheidungen
- Zeigt aktive lokale CrowdSec-Entscheidungen begrenzt und validiert im Firewall-Bereich an.
- Einzelne IP-Entscheidungen vom Typ `ban` koennen manuell in Guardians bestaetigten Plesk-Firewallablauf uebernommen werden; Bereiche bleiben reine Anzeige.
- Installations-/Lizenzgrenzen dokumentiert; Guardian installiert weder CrowdSec noch einen Firewall-Bouncer und blockiert nicht automatisch.
- Tests fuer JSON-Auswertung, ungueltige Eintraege, Fehlerstatus und UI-Verknuepfung hinzugefuegt.

## 0.28.8 – Dropdowns im gesamten Modul
- Vereinheitlicht Kontrast, Schriftgroesse, Hoehe und Breite aller nativen Auswahlfelder in Hauptansicht und Verwaltung.
- Laesst Auswahlfelder in Aktionszeilen responsiv umbrechen und kuerzt lange Firewall-Aktionsnamen.
- Behebt abgeschnittene Eintraege in Fail2Ban-, Firewall-, Domain-, WAF-, Turnstile- und Reparaturauswahlfeldern.

## 0.28.7 – Kompakte Firewall-Auswahl
- Kuerzt die Fail2Ban-Aktionsnamen und setzt feste responsive Feldbreiten, damit Jail- und Aktionsauswahl nicht als abgeschnittene Punkte erscheinen.

## 0.28.6 – Sichtbare Fail2Ban-Auswahlfelder
- Verstaerkt die Kontrastregeln fuer Jail- und Aktionsauswahl mit ID-spezifischen CSS-Regeln und expliziten Feldstilen, damit Plesk-Formularregeln den ausgewaehlten Text nicht unsichtbar machen.

## 0.28.5 – Fail2Ban-Sperren und Dropdown-Lesbarkeit
- Zeigt aktuell von Fail2Ban gebannte IP-Adressen je Jail; begrenzt die sichtbare Liste und markiert fehlende oder gekuerzte Listen.
- Ermoeglicht die Freigabe einzelner IPs aus dem passenden Jail. Permanentes Sperren nutzt die Plesk-Firewall mit 60-Sekunden-Rueckfall und bestaetigungspflichtigem Verbindungstest.
- Macht die Text- und Hintergrundfarbe nativer Auswahlfelder explizit, damit Plesk-Themes die Auswahl nicht weiss auf weiss darstellen.

## 0.28.4 – Sanfte Navigationseffekte
- Modulansichten und Dropdowns erscheinen mit kurzen Einblendungen und dezenter Bewegung.
- Dropdown-Pfeile reagieren auf den Menuezustand; Menuepunkte erhalten eine kurze Hover-Bewegung.
- Betriebssystemeinstellung fuer reduzierte Bewegung deaktiviert alle neu hinzugefuegten Animationen.

## 0.28.3 – Einzelansichten und kompaktere Navigation
- Navigationspunkte zeigen jeweils nur das gewaehlte Modul; zusammengehoerige Funktionen bleiben unter Malware Scanner, Incidents, Firewall, Webschutz & PHP sowie Verwaltung gruppiert.
- Malware-Scanstart und letzter Bericht sind eigene Ansichten; umfangreiche Modulbereiche muessen nicht mehr als lange Gesamtliste durchsucht werden.
- Statische Menue-Fallbacks blenden geschlossene Untermenues ausdruecklich aus, auch wenn Plesk-Styles die Browser-Standarddarstellung ueberschreiben.
- Ausgewaehltes Modul bleibt waehrend der Sitzung erhalten; Asset-Cacheversion auf 0.28.3 aktualisiert.

## 0.28.2 – Imunify-aehnliche obere Navigation
- Navigationsbereiche in eine horizontale Kopfzeile nach dem Imunify-Dashboard-Beispiel verschoben; Unterpunkte erscheinen in Dropdowns.
- Guardian Lite Wortmarke, helle Kopfzeile, gruenes Aktivsignal und kompaktere Seitentitel eingefuehrt.
- Serverseitig gerenderte Menuepunkte bleiben ohne JavaScript als native Dropdowns und Sprunglinks nutzbar.

## 0.28.1 – Navigation auch ohne JavaScript
- Imunify-aehnliche Menueleiste wird serverseitig gerendert und bleibt bei blockiertem oder nicht geladenem JavaScript sichtbar.
- JavaScript verbessert das statische Menue, schaltet Inhaltsbereiche um und verarbeitet auch Seiten, auf denen optionale Funktionsbereiche fehlen.
- Versionierte Assets und Release-Paket auf 0.28.1 aktualisiert.

## 0.28.0 – Menue-Neuordnung nach Imunify360-Dashboard

- Ersetzt die bisherigen Sammel-Tabs durch ein Seitenmenue fuer Dashboard, Malware Scanner, Incidents, Firewall, WebShield, PHP Runtime, Reputation Management und Einstellungen.
- Verschiebt funktionierende Scan-, Historien-, Ignorierlisten-, Reparatur-, Firewall-, Fail2Ban-, WAF-, Reputation-, Runtime- und Updatebereiche in passende Menues mit Unterpunkten.
- Kennzeichnet manuelle bzw. partielle Integrationen; nicht vorhandene Imunify-Dienste wie KernelCare oder Cloud-Proactive-Defense erscheinen nicht als Guardian-Funktionen.
- Ohne JavaScript bleiben Inhalte sichtbar; alte Tab-Links werden auf passende Menues abgebildet.
- Tests fuer Menuezuordnung, Bereiche, PHP-Templates und Versionskonsistenz.

## 0.27.1 – Diagnose-Schalter in der Schutzverwaltung

- Der Firewall-Debugstatus kann zusaetzlich im Tab „Schutzverwaltung und Diagnose“ ein- und ausgeschaltet werden.
- Status und letzte Ereignisse werden dort aus derselben Einstellung wie im Firewall-Dashboard angezeigt.
- Tests fuer die zwei Admin-Schaltflaechen, CSRF-geschuetztes Controller-Routing und Management-Template.

## 0.27.0 – Plesk-Firewall-Dashboard und schaltbare Diagnose

- Plesks eingehende Erlauben-/Sperrregeln und Sperrregeln mit Zaehlern, Suche und Listenfilter anzeigen; Fremdregeln bleiben read-only.
- Guardian-eigene IP-/Portaktionen bleiben an Plesk gebunden und erfordern weiterhin den separaten Verbindungstest mit Ruecknahme.
- Firewall-Debugausgabe im Panel ein-/ausschaltbar, standardmaessig aus; root-private, auf 256 KiB begrenzte Ereignisse mit Zeit, Schritt, Exitcode und Laufzeit. Keine CLI-Argumente oder Firewall-Standardausgabe im Log.
- Greylist, Bot-Challenge, Reputation und globale Port-Policies werden als nicht durch Plesk bereitgestellt gekennzeichnet.
- Tests fuer Plesk-Regelinventar, Zaehler, sichere Debugrechte, Deaktivierung, Panel-CSRF und Such-/Filteroberflaeche.

## 0.26.0 – Mail-Warteschlange mit Wiederholungen

- Fehlgeschlagene Malware-E-Mail-Warnungen bleiben in einer root-eigenen, auf 100 Eintraege begrenzten Warteschlange erhalten.
- Plesks stuendlicher Task wiederholt Zustellungen mit wachsendem Abstand; nach sechs Fehlern wird ein Eintrag als ausgeschöpft markiert. Administratoren koennen manuell erneut versuchen.
- Panel zeigt offene und ausgeschöpfte Zustellungen sowie den letzten Transportfehler. Zustellung bleibt vom lokalen Mailtransport abhaengig und wird durch Exit-Code null nicht garantiert.
- Ereignisfehler werden im Incident-Protokoll festgehalten; Geheimnisse oder Dateiinhalte werden nicht in die Warteschlange geschrieben.
- Tests fuer Outbox-Berechtigungen/Validierung, Wiederholungen, Rueckstau, Controller-CSRF und Panelstatus.

## 0.25.0 – Guardian-IP-Ausnahmen

- Fuehrt eine kommentierte, serverweite IP-/CIDR-Ausnahmeliste fuer Guardian-eigene Firewall-IP- und Port-Sperren ein.
- Neue Guardian-Sperren, die ein Ausnahme-Netz schneiden, werden abgelehnt; ueberlappende Netze koennen nicht doppelt eingetragen werden.
- Die Ausnahmeliste aendert keine Plesk- oder Provider-Firewallregel und entfernt keine bestehenden Sperren. Vor dem Eintragen werden aktive Guardian-Sperren abgefragt.
- Aenderungen werden im Incident-Protokoll dokumentiert. Limit 200 Eintraege; IP-Netze unterliegen derselben /24-/64-Grenze wie Guardian-Sperren.
- Tests fuer Hinzufuegen, Entfernen, Kommentare, Ueberlappungen, Sperrkonflikte, CLI-Routing und Plesk-Controller.

## 0.21.0 – Joomla- und Magento-Datenbank-Streamscan

- ClamAV-Datenbankscan erkennt WordPress, Joomla oder Magento im Plesk-Document-Root.
- Joomla-configuration.php und Magento-app/etc/env.php werden als begrenzte statische Konfiguration gelesen; Guardian fuehrt PHP-Konfiguration nicht aus und lehnt dynamische Werte ab.
- Joomla/Magento-Exporte laufen ueber ein root-eigenes mysqldump/mariadb-dump als Website-Benutzer. Zugangsdaten stehen nur in einer kurzlebigen 0600-Clientdatei in einem privaten Temp-Verzeichnis und nie in Argumenten oder Berichten.
- SQL fliesst ohne Dumpdatei direkt in ClamAV. 512-MiB-/5-Minuten-Grenzen, Teilstatus bei Fehlern, begrenzte Signaturausgabe und keine Datenbankaenderungen bleiben erhalten.
- Lokale ClamAV-Signaturen ersetzen weder Imunify-MDS-Erkennung noch Datenbankbereinigung/CSV-Restore. Dynamische Konfigurationen und andere Datenbanktreiber bleiben nicht unterstuetzt.
- Regressionstests fuer statische Joomla-/Magento-Konfigurationen, dynamische PHP-Ausdruecke und private Credential-Weitergabe.

## 0.20.0 – WordPress-Datenbankscan mit ClamAV

- Optionale separate Aktion exportiert die WordPress-Datenbank ueber WP-CLI und leitet den Inhalt ohne temporaere Dumpdatei durch lokale ClamAV-Signaturen.
- Website-UID fuer Export und Scanner; feste Prozessargumente, begrenzte Laufzeit/CPU, maximale 512-MiB-Pipe, Prozessgruppen-Abbruch und begrenzte, bereinigte Trefferberichte.
- Export-/Scannerfehler und Limits koennen keinen sauberen Befund erzeugen. Keine automatische Bereinigung oder Aenderung; MDS-Signaturen werden nicht nachgebildet.
- Regressionstests sollen Clean-, Treffer-, Exportfehler- und Ueberlaufpfade mit echten isolierten Hilfsprozessen pruefen.

## 0.19.0 – WordPress.org-Themeintegritaet

- Neue manuelle Read-only-Pruefung vergleicht installierte Theme-Dateien mit dem HTTPS-Archiv derselben Version aus dem WordPress.org-Verzeichnis.
- Gepruefte Themes werden einzeln ausgewiesen; unbekannte Versionen, eigene/kommerzielle Themes und unsichere/unvollstaendige Archive erscheinen als unvollstaendig.
- Abweichungen erzeugen einen Incident, aber keine Datei wird veraendert. ZIP-/Dateigroessen, Anzahl, Pfade und HTTPS-Redirect-Ziele sind begrenzt/geprueft.
- Regressionstests fuer exakten Treffer, geaenderte Datei, Pfad-Traversal und nicht verfuegbare Theme-Version.

## 0.18.0 – Lokaler signaturgebundener RapidScan

- Lokaler Cache ueberspringt unveraenderte saubere Dateien nur bei gleichem ClamAV-Binary und unveraenderten lokalen Signaturdateien.
- Geaenderte/neue Dateien werden ueber eine sichere ClamAV-Dateiliste geprueft; Malwarefunde werden nie als sauber gecacht.
- Bei unvollstaendigem Inventar, Scannerwarnungen oder unsicherem Stand faellt Guardian auf Vollscan zurueck. Cache ist auf 16 Domains und 4 MiB je Domain begrenzt und in der Speicheranzeige enthalten.

## 0.17.0 – WordPress-Datenbankindikatoren

- Neue manuelle, read-only WordPress-Datenbankpruefung mit festen SELECT-Abfragen und begrenzter Laufzeit/Ausgabe.
- Berichte enthalten nur Tabellen-/Spaltennamen, numerische Zeilen-IDs und Regelkennungen; Treffer erzeugen Incidents.
- Heuristikstatus und Grenzen erklaeren, dass dies weder MDS noch vollstaendige Malware-Erkennung oder Bereinigung ist.

## 0.16.0 – Erkennung von Admin-Tools

- Domain-Scans erkennen in begrenztem Umfang Adminer- und TinyFileManager-Dateien anhand von Name und Quelltextmerkmalen.
- Kandidaten erscheinen separat als Admin-Tools zur manuellen Pruefung, nicht als Malware-Treffer; Guardian aendert oder loescht sie nicht.
- Symlinks und andere Dateisysteme werden nicht verfolgt. Scanzeit, Dateianzahl, Dateigroesse und Anzahl der Meldungen sind begrenzt; unvollstaendige Pruefungen werden gekennzeichnet.
- Tests fuer Treffer, harmlose Dateinamen, Symlink-Ausschluss und Grenzen.

## 0.15.0 – Speicheranzeige und manuelle Aufbewahrung

- Verwaltung zeigt Guardian-Speicher pro Bereich und freien Speicher des Datentraegers an.
- Baselines sind auf 512 MiB gesamt, 64 MiB und 5000 Dateien je Snapshot sowie 20 Verzeichnisse begrenzt; unvollstaendige Snapshots werden bei Fehlern entfernt.
- PHP-/WAF-Backups sind auf 256 MiB und 200 Eintraege begrenzt. Vollstaendige Bestandsbackups werden im Panel aufgelistet.
- Administratoren koennen unbenutzte Baselines und Backups nach Bestaetigung dauerhaft entfernen. Auto-Reparatur-Baselines und das aktive WAF-Rollback-Backup sind geschuetzt.
- Regressionstests pruefen Speicherverbrauch, Quota-Blockade und Loeschschutz.

## 0.14.0 – Malware-Scan-Warteschlange und Laststeuerung

- Manuelle und geplante Domain-Scans werden in einer root-privaten FIFO-Warteschlange mit maximal 100 wartenden Auftraegen serialisiert.
- Der stundenweise Plesk-Task reiht alle faelligen Domains ein; je Domain bleiben mindestens 24 Stunden zwischen tatsaechlichen Scanstarts. Ein Worker startet automatisch den naechsten Auftrag.
- Die Oberflaeche zeigt wartende Domains und Ausloeser an. Vollscans laufen weiterhin einzeln und mit niedriger CPU-Prioritaet; kein paralleler Scan-Sturm.
- Fehlerfaelle fuer FIFO-Dispatch, volle Warteschlange, Deduplizierung und Warteschlangenstatus abgesichert.

## 0.13.0 – Zeitbegrenzte Plesk-Firewall-Sperren

- Guardian-Firewall-Regeln koennen dauerhaft oder fuer 1 Stunde, 24 Stunden beziehungsweise 7 Tage gesetzt werden.
- Ablaufzeiten werden erst nach erfolgreicher Plesk-Bestaetigung gespeichert; der stündliche Plesk-Scheduler nimmt nur Guardian-eigene Regeln zurueck.
- Automatische Entsperrung nutzt Plesks Apply/Confirm-Rollback und protokolliert Fehler; maximal zehn abgelaufene Regeln werden pro Lauf bearbeitet.
- Dashboard zeigt Ablaufzeiten; der stuendliche Scheduler verarbeitet bis zu zehn Ablaufe pro Lauf und protokolliert groessere Rueckstaende.
- Regressionstests fuer TTL-Validierung, Ablaufmetadaten, sichere Entsperrung und Panel-Weitergabe.

## 0.12.0 – Plesk-Firewall-IP-Sperrliste

- Manuelle IP-/CIDR-Deny-Regeln ausschliesslich ueber die installierte Plesk-Firewall-CLI.
- Admin-Verbindungs-IP wird vor Sperren abgeglichen; IPv4-Netze breiter als /24, IPv6 breiter als /64 sowie lokale/reservierte Netze werden abgelehnt.
- Jede Aenderung nutzt Plesks 60-Sekunden-Rollback und bleibt unbestaetigt, bis ein separater Verbindungstest bestaetigt wurde.
- Fremde Plesk-Regeln werden nicht bearbeitet; Firewall-Aktivierung und automatische Reputation bleiben aus.
- Tests fuer Regelisolation, Lockout-Schutz, CIDR-Grenzen, Rollback/Bestaetigung und CSRF-geschuetzten Panel-Aufruf.

## 0.11.0 – WordPress.org-Pluginpruefsummen

- Manuelle WP-CLI-Pruefung fuer installierte Plugins mit verfuegbaren WordPress.org-Pruefsummen.
- Kommerzielle/eigene Plugins ohne oeffentliche Pruefsummen werden als nicht geprueft aufgelistet; der Status bleibt teilweise statt sauber.
- Treffer laufen als Website-UID, werden getrennt vom Core-Bericht gespeichert und veraendern keine Dateien.
- Regressionstests fuer Plugin-Abweichungen, ausgelassene kommerzielle Plugins, sicheren Aufruf und Statuskennzeichnung.

## 0.10.0 – WordPress-Core-Pruefsummen

- Neue manuelle Pruefung vergleicht WordPress-Core-Dateien ueber WP-CLI mit WordPress.org-Pruefsummen.
- WP-CLI laeuft mit festen Argumenten und Umgebungsvariablen als Website-UID, ohne Plugins/Themes/Packages und ohne unsicheren TLS-Fallback.
- Treffer werden begrenzt im Panel/Incident-Log gezeigt. Kein automatisches Reparieren; Plugins, Themes und eigene Dateien bleiben ausserhalb dieser Core-Pruefung.
- Regressionstests fuer saubere und abweichende Core-Dateien, sichere Ausgabe und unveraenderte Website-Dateien.

## 0.9.1 – Plattformunabhaengige Release-Pakete

- Der ZIP-Build normalisiert jetzt auch eingebettete Markdown-Dateien in Unterordnern auf LF, damit Windows- und Linux-Builds dieselben Paketdateiinhalte enthalten.
- Regressionstest fuer die Zeilenenden im Security-Dokument.

## 0.9.0 – Cronjob-Sicherheitspruefung

- Neue read-only Admin-Pruefung ueblicher System- und Benutzer-Cronpfade auf ausgewaehlte verdächtige Befehlsmuster.
- Ergebnis zeigt nur Quelle, Zeile, Regel und Schweregrad; Cronjob-Inhalte werden nicht exportiert und nichts wird automatisch geaendert oder geloescht.
- Gepruefte Grenzen (Anzahl/Groesse), ausgelassene Quellen und heuristischer Charakter werden im Ergebnis ausgewiesen; Funde gehen in den Incident-Verlauf.
- Regressionstest fuer Erkennung, Symlink-Ausschluss und Unveraendertheit der Cron-Dateien.

## 0.8.0 – Malware-Ignore-Liste und Imunify360-Abgleich

- Plesk-Admin kann exakte Datei-SHA-256-Funde je Domain administrativ ignorieren und wieder freigeben. Treffer bleiben sichtbar/gescannt; Warnung und automatische Baseline-Reparatur werden fuer diesen Inhalt unterdrueckt.
- Ignore-Liste hat Domain-/Gesamtlimits, Audit-Vorfaelle und Schutz fuer manuelle/automatische Reparatur gegen veraltete Berichte.
- Vollscan, Live-Wache, Scanbericht und Historie zeigen die Ausnahmen getrennt an.
- Imunify360-Paritaetsabgleich mit Produktgrenzen und priorisiertem Plesk-Implementierungsplan ergaenzt.

## 0.7.1 – Abhaengigkeiten und Firewall-Status

- Plesk-Firewall-Erkennung prueft die aktuellen sowie bisherigen systemd-Service-Namen und unterscheidet installierte Erweiterung von aktivierten Regeln.
- Funktionsbezogene Betriebssystem- und Plesk-Komponenten dokumentiert; unnoetige globale Paketinstallation vermeiden.

## 0.7.0 – Opt-in-Schutzverwaltung und Diagnose

- Neuer Tab Verwaltung & Diagnose mit CSRF-geschuetzten festen Aktionen; Plesk >=18.0.55 wegen sicherer stdin-Uebergabe erforderlich.
- Snuffleupagus 0.14.0 aus festem Upstream-Commit als eigener Build-Benutzer installieren; Simulation/Aktivierung mit PHP-Probe, FPM-Konfigurationspruefung, Backup und Rollback.
- Guardian-ModSecurity-Regeln mit Vorschau, IP-Limit, Erkennungs-/Sperrmodus, Include-/Syntaxpruefung, Apache-Reload und Rollback; Domain-WAF-Modus via Plesk CLI.
- AbuseIPDB: ausdrueckliche Zustimmung, oeffentliche IPs, feste HTTPS-API, Schema-Pruefung und Stunden-Cache.
- Turnstile fuer PHP-Anmeldepfade via .user.ini: serverseitige Tokenvalidierung, signierte Clearance-Cookies, Ruecknahme mit Aenderungspruefung.
- Admin-freigegebene Good-File-Baselines; opt-in automatische Reparatur passender Vollscan-Funde, Originale in Quarantaene und kontrollierter Rollback. Kein Hersteller-Abgleich.
- Diagnose-JSON und optional kurzlebige HTTPS-PHP-Probe fuer Plesk-Praxistests.
- Neue isolierte Management-, PHP-HTTP- und echte Apache/ModSecurity-HTTP-Tests. Echte Plesk-Integrationstests fuehrt der Betreiber separat durch.

## 0.6.4 – Zuverlaessige Scanplanung und Verzeichniswechsel

- Geplante Scans ermitteln den letzten Lauf aus allen aufbewahrten Berichten; die Anzeigegrenze von 30 Berichten beeinflusst den 24-Stunden-Abstand nicht mehr.
- Live-Dateiwache entfernt Watches verschobener/geloeschter Teilbaeume und erfasst hineingeschobene Verzeichnisse unter ihrem neuen Pfad. Bei verschobenem/geloeschtem Document-Root wird der Monitor beendet.
- Regressionstests fuer viele neuere manuelle Scans sowie heraus- und hineinverschobene verschachtelte Verzeichnisse.
- Funktionsliste und Dokumentation auf den aktuellen Implementierungsstand gebracht.
- Plesk-End-to-End-Pruefung erfolgt separat auf dem Testserver; keine automatische Aktivierung zusaetzlicher Schutzregeln.

## 0.6.3 – Plesk-Document-Root-Resolver und automatische Release-Veröffentlichung

- Scanner, geplante Scans, Dateiwache und Quarantaene verwenden den zu jeder Domain in der Plesk-Hosting-Datenbank gespeicherten Document-Root statt `/var/www/vhosts/<domain>/httpdocs`.
- Zusatzdomains in gemeinsamen Abonnements und individuell konfigurierte Document-Roots werden unterstuetzt.
- Sicherheitspruefung: Kanonischer Pfad muss unter dem zugeordneten Plesk-Webspace liegen, ausserhalb liegende Symlinks sowie root-eigene Ziele werden abgelehnt.
- Plesk-Domainliste zeigt nur Domains mit Website-Hosting; der letzte manuelle Scan-Zielname bleibt bei der Rueckmeldung erhalten.
- Neue Tests fuer Zusatzdomains, Webspace-Isolation und Plesk-Datenbankantworten.
- Diese Version wird per freigegebenem GitHub-Release-Workflow nach bestandenen Tests veroeffentlicht.

## 0.6.2 – Domainauswahl und Scanplanung in Plesk

- Alle Formularaktionen benutzen die offizielle Plesk-URL via pm_Context::getActionUrl.
- Erzwungene kontrastreiche Auswahlfeld-Farben, unabhaengig von Plesk-Skins; ausgewaehlte Domain wird zusaetzlich als Text angezeigt.
- Opt-in-Planungsaktionen zeigen Erfolg oder Fehler direkt im Malware-Tab, auch nach einem Redirect.
- Der Malware-Tab bleibt nach Scan-/Planungsaktionen geoeffnet.
- Scanplanung validiert die Antwort des privilegierten Helfers, bevor Erfolg angezeigt wird.
- Tests fuer Plesk-Formular-URLs, Domainanzeige, Statusfeedback und Version.
- Keine automatisch aktivierten Scans, WAF- oder PHP-Schutzregeln. Kein echter VPS-End-to-End-Test.

## 0.6.1 – Update-Pruefung zeigt zuverlaessig Rueckmeldung

- Update-Formular nutzt offizielle Plesk-Action-URLs.
- Nach dem POST bleibt der Updates-Tab ueber URL-Fragment aktiv.
- Letzter Pruefstatus und GitHub-Fehler werden in Plesk sichtbar gespeichert.
- Pruefresultat ist maximal 30 Minuten lang zur Installationsbestaetigung gueltig.
- Der Button zeigt unmittelbar nach dem Absenden eine Statusmeldung.
- Keine stillen automatischen Updates; Installation weiterhin nur mit Admin-Bestaetigung.

## 0.6.0 – Opt-in-Echtzeit-Dateiwache und Incident-Zentrale

- Linux-inotify Echtzeitueberwachung pro freigegebener Plesk-Domain (max. 5 Domains / 450 Verzeichnisse je Domain), standardmaessig AUS.
- Neue/geaenderte PHP-Dateien: optionale ClamAV-Einzeldateipruefung als Website-UID, ohne automatische Dateiveraenderungen.
- Root-private Incident-Protokollierung mit begrenzter Groesse und JSON-Export aus Plesk (nur Administrator).
- Opt-in E-Mail-Warnungen fuer ClamAV-Malwareereignisse ueber lokalen Mail-Transport; Versand gedrosselt und Testfunktion.
- Neue Plesk-Registerkarte „Incidents“ mit Echtzeitmonitor, Protokoll und E-Mail-Konfiguration.
- Dry-run-nahe PHP-Handler-Konfigurationssicherung plus SHA-geschuetzter manueller Rollback-CLI-Helfer; keine Aktivierung auf Live-Websites.
- Beispiel eines stufenweisen ModSecurity-Botlimits (zunaechst nur Monitoring, keine automatische Sperre).
- GitHub CI mit Python 3.11 bis 3.13 und Ubuntu 22.04/24.04; echte Plesk-Multidistributions-Integrationstests stehen aus.
- Keine vollautomatische Malware-Reparatur, Snuffleupagus-Aktivierung, Bot-Challenges oder Cloud-Reputation ohne produktiv getestete Voraussetzungen.

## 0.5.2 – Updater-Button immer sichtbar

- Das Guardian-Repository Wintergecko/guardian-lite wird automatisch als Default verwendet, wenn noch keine Repository-Einstellung gespeichert ist.
- Die Schaltflaeche zum Pruefen auf neue Versionen ist im Updates-Tab immer sichtbar und kann ohne vorheriges Speichern benutzt werden.
- Manuell gespeicherte vertrauenswuerdige Repositories bleiben erhalten.
- Versionsnummern und Tests aktualisiert. Keine automatische Installation oder Aenderung aktiver Schutzregeln.

## 0.5.1 – GitHub-Updater Release-Pipeline repariert

- GitHub Actions testet die root-gebundenen Helper-Funktionen mit Root-Rechten auf isolierten Runnern.
- Python-3.11-kompatibles Path-Mocking im PHP-Runtime-Test.
- Release-Workflow baut erst nach bestandenen Tests eine installierbare ZIP-Datei mit SHA-256.
- Keine automatischen Änderungen am Schutzstatus, WAF, PHP oder Firewall.

## 0.5.0 – Uebersichtliche Plesk-Tabs und Feature-Liste

- Fuenf Bereiche: Uebersicht, Malware & Dateien, Angriffe & Schutz, Updates, Feature-Liste.
- Tastaturbedienbare Tabs mit ARIA-Rollen, Hash-Links und Wiederherstellung des letzten Tabs.
- Alle vorhandenen Formulare und POST-Aktionen bleiben bestehen.
- Ohne JavaScript bleiben alle Abschnitte sichtbar.
- Feature-Liste unterscheidet implementierte, manuell vorbereitete und offene Funktionen.
- Die Laufzeit-/Bot-Policies werden weiterhin nicht automatisch aktiviert.

## 0.4.1

- Updater-Repository-Feld akzeptiert nun owner/repo oder vollständige GitHub-URL.
- Prüfung, ob die Repository-Einstellung gespeichert wurde.
- Hinweis: Private GitHub-Releases sind noch nicht mit dem Updater nutzbar.

# 0.4.0 – PHP-Runtime-/HTTP-Bot-Integration (Opt-in)

- Konservative Anzeige von Plesk-PHP-Konfigurationen und WAF-Log-Bereitschaft.
- Snuffleupagus- und ModSecurity-Regelvorlagen mit Test-/Rollback-Hinweisen; standardmaessig deaktiviert.
- Keine automatischen produktiven Firewall-, NGINX-, PHP- oder WAF-Aenderungen.

# Changelog

## 0.3.0 – 2026-11-04

- Opt-in-Scanplanung ueber Plesk-Scheduler; stündliche Faelligkeitspruefung und Schutz vor parallelen Scans.
- Root-private Scan-Historie mit Einzelberichten und Rotation aelterer sauberer Berichte.
- Admin-bestaetigte Quarantaene und Wiederherstellung mit Fingerprint-, Pfad- und Nicht-Ueberschreiben-Pruefungen.
- Lesende WAF-Ereignisuebersicht aus dem Plesk-ModSecurity-Audit-Log.
- Manuelle Fail2Ban-IP-Sperre und Entsperre mit Validierung.
- Periodische Metadaten-Dateiaenderungspruefung fuer Websites mit aktivierter Planung.
- Erweiterte Tests, Datenschutz- und Sicherheitsdokumentation.
- GitHub-Release-Updater mit manueller Installation, ZIP-Verifikation und Release-Build-Workflow.

## 0.1.0

- Erstes Admin-Dashboard fuer Fail2Ban/ModSecurity/Firewall, manueller ClamAV-On-Demand-Scan.
## 0.22.0 – ClamAV-Pruefung fuer Cron-Dateien

- Read-only Cronjob-Audit ergaenzt die bestehenden Heuristiken optional um lokale ClamAV-Signaturen.
- Nur sicher gelesene, regulaere Cron-Dateien werden in ein privates temporaeres Verzeichnis kopiert; 4-MiB-/45-Sekunden-Grenzen, keine Bereinigung und kein Aendern der Cronjobs.
- Treffer werden mit urspruenglichem Pfad und bereinigtem Signaturnamen protokolliert; fehlendes ClamAV oder Fehler werden separat ausgewiesen.
- Imunify360-Cron-Erkennung kann andere proprietaere Regeln verwenden; ClamAV-Treffer sind keine vollstaendige Cron-Malware-Bewertung.
- Tests pruefen Trefferzuordnung und unveraenderte Quell-Dateien.

## 0.23.0 – Plesk-Portregeln fuer ausgewaehlte Quell-IPs

- Guardian kann einzelne TCP-/UDP-Ports fuer genau eine Quell-IP erlauben oder fuer ein begrenztes Quellnetz sperren.
- Jede Aenderung nutzt Plesks eigene CLI, 60-Sekunden-Rollback und explizite Bestaetigung nach getrenntem Verbindungstest.
- Die UI zeigt nur Guardian-eigene Regeln; Portfreigaben lassen sich ausschliesslich per gelisteter numerischer Regel-ID entfernen. Fremde Plesk-Regeln werden nicht veraendert.
- Globale Port-Policies, globale IP-Allowlisten, Greylisting, Provider-Firewalls und zeitbegrenzte Portregeln bleiben offen. Eine Allow-Regel kann globale Plesk- oder Provider-Sperren nicht ueberstimmen.
- Tests decken CLI-Argumente, Port-/Quellvalidierung, Admin-IP-Schutz, Listenfilterung, Loeschen eigener Regeln und Controller-Routing ab.

## 0.24.0 – Globale Malware-Ignore-Hashes

- Ergaenzt eine domainuebergreifende SHA-256-Ausnahmeliste neben den bestehenden domainbezogenen Ausnahmen.
- Ausgenommene Inhalte werden weiterhin gescannt und sichtbar berichtet; Malwarewarnungen und automatische Reparaturen werden fuer exakt diesen Inhalt unterdrueckt.
- UI zeigt den Geltungsbereich, erlaubt gezieltes Hinzufuegen/Entfernen und warnt vor domainuebergreifender Wirkung; Grenze 2.000 globale Eintraege.
- Tests pruefen Wirkung auf unterschiedliche Domains, sichtbare Treffer, Reparatursperre, Ruecknahme und Controller-Routing.

