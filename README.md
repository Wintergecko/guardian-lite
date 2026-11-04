# Guardian Lite v0.7.0 – Plesk Security (Linux)

Ein **experimenteller Open-Source-Baukasten** fuer Plesk Obsidian 18.x auf Linux mit Root-Zugriff. Keine offizielle Plesk-/Imunify360-Software, kein Ersatz fuer professionell getestete Malware-Abwehr. **Installation nur zuerst auf Test-VPS / Snapshot.** Fuer die aktuelle Version sind Python >=3.8 und eine Plesk-Umgebung mit Extension-API erforderlich.

## Aktueller Stand 0.7.0

Opt-in-Live-Dateiwache (inotify), Incident-Protokoll, JSON-Export und E-Mail-Warnungen sind implementiert. Die periodische Metadatenpruefung bleibt als separate Funktion erhalten. Plesk-Integration und Mailzustellung werden auf einem separaten Testserver geprueft.

## Was umgesetzt ist

| Funktion | Stand |
|---|---|
| Admin-Dashboard, WAF-Modus, Firewall-, ClamAV- und Fail2Ban-Status | implementiert, nur beobachtend |
| Malware-Scan pro gehosteter Plesk-Domain mit ClamAV als Website-UID | implementiert, manuell |
| Automatische Scans | implementiert, opt-in pro Domain, stuendliche Faelligkeitspruefung, maximal ein Scan pro Scheduler-Lauf, mind. 24h Abstand pro Domain |
| Scan-Berichte/History | 30 zuletzt geaenderte Berichte angezeigt, bis 200 aktive oder bis 90 Tage aufbewahrt; Quarantaene-Berichte laenger |
| Quarantaene / Wiederherstellung | **nur manuell**, Move nach Fingerprint-Kontrolle; Restore verweigert Ueberschreiben; keine automatische Malware-Reparatur |
| Metadaten-Dateiueberwachung | zeitversetzte Stichprobe fuer PHP-/Config-Dateien auf opt-in Domains (bis 1500 Dateien pro Lauf), **kein Echtzeit-Schutz** |
| WAF-Ereignisse | letzte 512 KiB `/var/log/modsec_audit.log` auf Regeln/IPs reduziert; keine HTTP-Bodies |
| IP sperren / entsperren | manuell ueber aktives Fail2Ban-Jail; keine automatische Bedrohungsbewertung |

**Nicht enthalten:** ClamAV-On-Access, Hersteller-signierte CMS-Reparaturpakete, Netzwerk-DDoS-Schutz, SQL-Datenbank-Scans, Push-Benachrichtigungen und Bearbeitung fremder WAF-Regeln. Alle neuen aktiven Schutzfunktionen sind standardmaessig aus. Details und Grenzen von 0.7.0 stehen in [MANAGEMENT.md](MANAGEMENT.md).

## Vorbedingungen

- Vollstaendigen VPS-Snapshot und externe Backups anlegen, SSH-Zugang pruefen.
- Testdomain mit Document-Root innerhalb ihres Plesk-Webspaces verwenden. Zusatzdomains und eigene Document-Roots werden aus der Plesk-Datenbank ermittelt. Websites mit root-eigenem Document-Root werden nicht gescannt.
- Plesk 18.0.55 oder neuer (Obsidian) + Linux, Python >=3.8, PHP fuer Plesk.
- ClamAV samt aktueller Datenbank installieren; z.B. unter Debian/Ubuntu:

  ```bash
  apt update
  apt install clamav clamav-freshclam
  ```

- Fail2Ban/WAF bei Bedarf in Plesk aktivieren. Guardian erstellt **keine** WAF-Regeln, Firewall-Policies oder Fail2Ban-Jails. Imunify360 kann mit bestimmten Fail2Ban-Integrationen kollidieren; Guardian und Imunify360 nicht ungeregelt parallel betreiben.
- Fuer kleine VPS auf RAM/CPU achten. Jeder Scan kann bis zu 60 Minuten dauern, maximal 25 MB Einzeldatei / 150 MB Archivscan-Kontext. Dateilimits koennen Funde uebersehen.

## Installation / Upgrade

Paket auf den Server kopieren; vor dem Einspielen Inhalt und Quellcode pruefen. Als **root**:

```bash
# Neuinstallation
plesk bin extension -i /root/guardian-lite-0.7.0.zip

# Upgrade einer vorhandenen guardian-lite 0.1.0 vom lokalen ZIP
plesk bin extension -g /root/guardian-lite-0.7.0.zip

# Version/Status ansehen
plesk bin extension -l | grep guardian-lite
```

Plesk-Dokumentation: [Extension-CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/extension-extensions.71031/). `-g` ist der dokumentierte Upgrade-Befehl fuer ein **ZIP** (nicht `--upgrade guardian-lite`, das normalerweise den Katalog abfragt).

**Nach Installation:** in Plesk als echter Administrator `Erweiterungen → Meine Erweiterungen → Guardian Lite` oeffnen. Der Plesk-Scheduler registriert automatisch eine stuendliche Guardian-Aufgabe. Diese tut **nichts**, solange du nicht pro Domain `Automatische Scans → Aktivieren` anklickst. Im Panel unter `Tools & Einstellungen → Geplante Aufgaben` verifizieren, dass die Guardian-Aufgabe vorhanden ist.

Bei Update von v0.1.0 bleiben Legacy-Scandateien unter `/var/lib/guardian-lite/` als Altbericht erhalten. Neue Scans verwenden das Verzeichnis `jobs/`.

## Bedienung

1. Eine kleine Testdomain manuell scannen und anschliessend den Bericht aufrufen.
2. Falls gewuenscht, automatische Scans fuer einzelne Domains aktivieren. Scheduler prueft stuendlich; aus Lastgruenden nur **ein neuer Scan pro Lauf** (bei vielen Domains verzoegert). Kein Scan, wenn ein anderer laeuft.
3. Erst nach Pruefung einer ClamAV-Fundmeldung die Schaltflaeche **Quarantaene** nutzen. Der Vorgang verschiebt die Datei physisch in `/var/lib/guardian-lite/quarantine/` und kann deine Website stoeren! Vorher Backup.
4. Per **Wiederherstellen** wird die Datei nur zurueckgegeben, wenn am Originalpfad **keine** Datei existiert. Zurueckgespielte Malware kann wieder ausgefuehrt werden.
5. Fail2Ban-IP-Sperren nur nach Pruefung vornehmen. Eigene Administrator-IP nicht sperren.
6. WAF-Ereignisse sind **keine** vollstaendige Echtzeit-Analyse, nur ein begrenzter Log-Ausschnitt.

## Berechtigungen und Datenablage

- Admin-Sitzung + CSRF-Token fuer jede schreibende Aktion; kein Shell- oder Dateipfadfeld in der Weboberflaeche.
- Privilegierter Helper nur feste Verben und streng validierte Argumente; Scan unter Website-UID, keine Root-Scans.
- Serverzustand, Berichte, Dateimonitor und Quarantaene liegen root-eigen unter `/var/lib/guardian-lite/` mit 0700-Verzeichnissen / 0600-JSON-Dateien. Diese Daten werden beim Deinstallieren **nicht** geloescht, um eine Wiederherstellung zu ermoeglichen.
- Quarantaene verwendet Rename im gleichen Dateisystem; bei unterschiedlichen Mounts wird der Move abgelehnt. Originale werden nicht heimlich geloescht. In der schmalen Race-Condition bei parallel geaenderten Website-Dateien kann manuelle Nacharbeit erforderlich sein. Keine Garantien fuer Live-Systeme.
- Filewatch erfasst Metadaten, keine Dateiinhalte. Die Metadaten-Stichprobe ist begrenzt und kann Aenderungen uebersehen. Scan-Ereignisse enthalten Dateipfade; WAF-Anzeige IP-Adressen. Auf Datenschutz und Zugriffsrechte achten.
- Berichte ohne aktive Quarantaene werden nach mehr als 90 Tagen oder bei >200 Berichten nach und nach entfernt. Berichte mit Quarantaene-Dateien bleiben zur Wiederherstellung erhalten.

## Tests und Diagnose

```bash
unzip -l guardian-lite-0.7.0.zip
php -l plib/controllers/IndexController.php
php -l plib/views/scripts/index/index.phtml
python3 -m unittest discover -s tests -v
```

Die Tests laufen offline ohne Plesk. **Keine End-to-End-Installation auf einem realen Plesk-Server getestet.** Vor Produktion muessen Installer, Plesk-Scheduler, Rechte von sbin, Fail2Ban-Integration, Dokumentwurzeln und WAF-Pfade auf deiner spezifischen OS-/Plesk-Version geprueft werden.

## Verweise

- [Plesk Extensions-Aufbau](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-extensions-basics/extension-structure.71076/)
- [Plesk Scheduler](https://docs.plesk.com/en-US/obsidian/extensions-guide/plesk-features-available-for-extensions/scheduling-tasks.71094/)
- [Plesk ModSecurity Log](https://docs.plesk.com/en-US/obsidian/administrator-guide/server-administration/web-application-firewall-modsecurity.73383/)
- [ClamAV Scans](https://docs.clamav.net/manual/Usage/Scanning.html)

## Lizenz

MIT (Guardian Lite); Drittsoftware unter eigenen Lizenzen. Diese Extension enthaelt keine proprietaeren Imunify360-Bestandteile.

## GitHub-Releases und Plesk-Updater (v0.4.0)

Die Erweiterung enthaelt den Bereich **GitHub-Updater**. In Plesk als Administrator unter `Erweiterungen → Guardian Lite` das oeffentliche GitHub-Repository im Format `owner/repo` eintragen. Die Versionserkennung nutzt die offizielle GitHub-API `releases/latest`. Nur stabile Releases mit Asset `guardian-lite-X.Y.Z.zip` und einem von GitHub gelieferten SHA-256-Digest werden akzeptiert. Update-Installation erfolgt ausschliesslich nach manuellem Admin-Klick mit CSRF-Pruefung, ZIP-Strukturvalidierung und Digest-Vergleich.

**GitHub Release erstellen:** Code auf den Standardbranch hochladen, dann Tag `v0.4.0` pushen. GitHub Actions (`.github/workflows/release.yml`) fuehrt die Offline-Tests aus, baut das ZIP und veroeffentlicht es als GitHub Release. Repository muss GitHub Actions mit Schreibberechtigung fuer Inhalte erlauben. Der Updater verwendet ausschliesslich oeffentliche GitHub-Releases; private Repositories funktionieren damit nicht.

**Sicherheit:** SHA-256 von GitHub ist keine unabhaengige Signatur. Nur ein vertrauenswuerdiges eigenes Repository eintragen und fremde Codeaenderungen vor Freigabe auditieren. Plesk arbeitet beim Upgrade mit Root-Rechten. Vor produktiver Nutzung und vor jedem Update Snapshot und Backups pruefen. Kein unbeaufsichtigtes Auto-Update.

## Neu in v0.4.0: PHP-Runtime und HTTP-Flood-Regeln

- Dashboard zeigt read-only PHP-INI-Inspektion der installierten Plesk-PHP-Handler und ModSecurity-Log-Verfuegbarkeit; dies ist **kein Funktions- oder Abwehrnachweis**.
- Im Source-Paket `security/php-runtime/guardian.rules`: optionale Snuffleupagus-PHP-Runtime-Regeln.
- Im Source-Paket `security/http-guard/guardian-modsecurity.conf`: optionale HTTP-Limit-Vorlage fuer ModSecurity v2.
- **Nicht automatisch aktiv**: siehe `security/README.md`. Keine pauschalen Aenderungen an laufenden FPM-/NGINX-/WAF-Konfigurationen.
- Eine umfangreiche DDoS-Abwehr benoetigt einen vorgeschalteten Provider/CDN-Schutz.


## Oberflaeche seit 0.5.0

Die Administratoroberflaeche verwendet ohne externe JavaScript-Bibliotheken fuenf Tabs:
Uebersicht, Malware & Dateien, Angriffe & Schutz, Updates und Feature-Liste.
Der aktuelle Tab bleibt nach Formularaktionen in derselben Browser-Sitzung erhalten; Links mit
`#guardian-tab-updates` oeffnen den Updater direkt. Ohne JavaScript bleiben alle Bereiche sichtbar.
Das Feature-Backlog ist bewusst keine Zusage eines vollstaendigen Imunify360-Ersatzes.


### Updater-Repository (ab v0.5.2)

Ohne gespeicherte Einstellung wird `Wintergecko/guardian-lite` als Voreinstellung verwendet. Unter Updates ist „Auf neue Version pruefen“ immer sichtbar. Die Extension liest nur GitHub-Releases und installiert Updates erst nach einem ausdruecklichen Admin-Klick. Ein geeignetes veroeffentlichtes Release muss das ZIP-Asset samt GitHub SHA-256-Digest enthalten.


## 0.6.0 – Echtzeit-Dateiwache und Incidents (Beta)

**Voraussetzung:** Linux mit `inotify`, Plesk Extension als direkter Administrator und
ClamAV fuer Live-Einzeldatei-Scans. Auf der Registerkarte **Incidents** muss die
Ueberwachung pro Domain explizit aktiviert werden. Standardmaessig ist sie aus.
Maximal fuenf Domains und 450 Verzeichnisse je Domain werden ueberwacht.
Bei einem inotify-Queue-Overflow oder wenn Limits erreicht sind, gelten
Ergebnisse als unvollstaendig; dann einen manuellen Vollscan durchfuehren.
Der Plesk-Stundentask startet ausgefallene aktivierte Beobachter erneut,
was eine moegliche Luecke bis zum naechsten Stundenlauf bedeutet.
Monitor-Aus/Einschalten veraendert keine Website-Dateien.

Bei einer erkannten Aenderung wird nur Ereignis-Metadatenprotokoll gespeichert.
Die ClamAV-Einzeldateipruefung erfolgt nur fuer kleine, sichere Dateien unter
der Website-UID, soweit ClamAV vorhanden ist. Verdaechtige Dateien werden
**nicht automatisch** geloescht, repariert oder in Quarantaene verschoben.
Fuer manuelle Quarantaene wird weiter ein abgeschlossener Vollscan benoetigt.

Incidents werden root-privat unter `/var/lib/guardian-lite/incidents.jsonl`
(maximal 2 MB und eine rotierte Vorgaengerversion) gespeichert. Nur Administratoren
koennen die letzten 200 Ereignisse als JSON herunterladen. Das ist kein
externes SIEM und keine kryptografisch unveraenderbare Ereigniskette.

E-Mail-Benachrichtigungen sind standardmaessig aus und benoetigen einen
lokalen sendmail-kompatiblen Mail-Transport. Bei Malwareereignissen versucht
Guardian eine Mail zu senden; das garantiert keine Zustellung. Bei gleichem
Ereignistyp/Domain wird maximal alle 15 Minuten benachrichtigt, global
hoechstens alle 60 Sekunden. Eine Testfunktion steht zur Verfuegung.

### PHP-Handler-Backup und manueller Rollback

Keine produktive Aktivierung von Snuffleupagus erfolgt durch Guardian Lite.
Vor manueller PHP-Handler-Konfigurationsaenderung kann der Admin ein
root-privates Backup anlegen:

```bash
sudo python3 security/php-runtime/handler_rollback.py backup 8.3
```

Bei einem Rollback muss der aktuelle SHA-256-Wert der PHP-Konfiguration bekannt
sein, damit zwischenzeitliche Aenderungen nicht ungefragt ueberschrieben werden:

```bash
sudo sha256sum /opt/plesk/php/8.3/etc/php.ini
sudo python3 security/php-runtime/handler_rollback.py rollback 8.3 8-3-<backup-id>.ini <aktueller-sha256>
```

Danach PHP-FPM/Dienste kontrolliert neu starten und Websites testen.
Diese CLI ist **nicht** mit der Plesk-GUI verbunden. Keine automatischen
Server- oder PHP-Dienst-Neustarts.

### Nicht fertig / benoetigt VPS-Test

- **Automatische Malware-Reparatur:** benoetigt verifizierte, unveraenderbare
  Good-File-Backups je CMS und sicheres Rollback. Bis dahin bewusst nicht aktiv.
- **PHP-Laufzeitschutz:** Snuffleupagus muss je Handler installiert, aktiviert
  und unter echten Requests getestet werden. Eine php.ini-Aenderung kann
  produktive Sites zerstoeren.
- **Aktive Bot-Challenges / adaptives Blockieren / Cloud-Reputation:**
  brauchen stabile Reverse-Proxy-/WAF-Integration, Reputationsanbieter,
  Datenschutzeinwilligung und Lasttests. Eine zusaetzliche ModSecurity-Regelvorlage
  liegt unter `security/http-guard/`, bleibt aber deaktiviert.
- **Plesk-Integrationstests:** Der CI-Testlauf prueft Python-/PHP-Syntax und
  Unittests auf Ubuntu 22.04/24.04 mit Python 3.11/3.12/3.13. Das ist KEIN
  Test auf Debian-, AlmaLinux- oder Ubuntu-VPS mit installiertem Plesk.


### Update-Pruefung sichtbar (ab v0.6.1)

Die Update-Formulare verwenden die offiziellen Plesk-Action-URLs. Nach dem Klick
landet man wieder im Tab **Updates**. Erfolg, bereits aktuelle Version und
Fehler der GitHub-Abfrage werden direkt in diesem Tab angezeigt. Der letzte
Pruefstatus ist ueber ein Neuladen der Seite hinweg gespeichert. Ein zuvor
erfolgreich geprueftes Release ist maximal 30 Minuten lang zur Installation
freigegeben; die Update-Engine prueft das Release beim Start nochmals.

Bei Verbindungsschwierigkeiten wird die Fehlermeldung der privilegierten
Updater-Engine angezeigt. Es wird **nicht** automatisch installiert.


### Plesk Domainauswahl/Scanplanung (v0.6.2)

Alle Formulare verwenden nun `pm_Context::getActionUrl`. Im Tab Malware & Dateien wird nach
Klick auf Aktivieren/Deaktivieren die Serverantwort (Erfolg oder Fehler) direkt angezeigt.
Wenn das Aktivieren fehlschlaegt, den Text im rot markierten Statusfeld und die Plesk-Logs pruefen.
Die Domainauswahl besitzt ein kontrastreiches natives Select und eine zusaetzliche Textausgabe.
Ein gruenes Erfolgssignal bestaetigt die Rueckgabe von `guardian-helper`, nicht die
Ausfuehrung des geplanten Scans. Der geplante Scan erfordert weiterhin den Plesk-Scheduler.


### Plesk-Document-Roots (ab 0.6.3)

Der privilegierte Scanner liest fuer jede gehostete Domain den konfigurierten `hosting.www_root` sowie `sys_users.home` aus der lokalen Plesk-Datenbank (`plesk db -Ne`). Das unterstuetzt Zusatzdomains und geaenderte Document-Roots innerhalb einer Subscription. Es gibt keinen Fallback auf erratene Pfade. Vor dem Scan werden der kanonische Pfad, die Webspace-Grenze und ein nicht-root-Eigentuemer geprueft. Domain-Eingaben werden strikt validiert, die CLI wird ohne Shell aufgerufen. Auf Servern ohne lesbare Plesk-Hosting-Daten wird der Scan mit Fehlermeldung abgebrochen.


### Korrekturen in 0.6.4

- Die Scanplanung prueft alle aufbewahrten Berichte statt nur der 30 sichtbaren Eintraege. Viele manuelle Scans verkuerzen dadurch nicht mehr den 24-Stunden-Abstand geplanter Scans.
- Bei verschobenen oder geloeschten Verzeichnissen entfernt die Live-Dateiwache die Watches des gesamten alten Teilbaums. Hineinverschobene Verzeichnisse werden unter ihrem neuen Pfad ueberwacht. Wird der Document-Root selbst verschoben oder geloescht, beendet sich der Monitor; der Scheduler kann ihn nach Wiederherstellung neu starten.
- Feature-Liste und aktuelle Voraussetzungen wurden berichtigt.

## Neue Schutzverwaltung ab 0.7.0

Der Tab **Verwaltung & Diagnose** bietet PHP-Handler-Backup und Rollback, Snuffleupagus-Build/Simulation/Aktivierung, Guardian-WAF-Regeln und Botlimits, AbuseIPDB-Reputationsabfragen, Turnstile fuer PHP-Anmeldepfade sowie opt-in Good-File-Reparatur. Der privilegierte Manager akzeptiert feste Aktionen als begrenztes JSON ueber stdin. API-Schluessel werden root-privat gespeichert und weder in Prozessargumenten noch in Status/Diagnose ausgegeben.

Die frueheren Versionsabschnitte dokumentieren den historischen Stand. Fuer aktuelle Aktivierung, Grenzen und Praxistests gilt [MANAGEMENT.md](MANAGEMENT.md).
