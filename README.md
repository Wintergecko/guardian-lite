# Guardian Lite v0.4.0 – Plesk Security (Linux)

Ein **experimenteller Open-Source-Baukasten** fuer Plesk Obsidian 18.x auf Linux mit Root-Zugriff. Keine offizielle Plesk-/Imunify360-Software, kein Ersatz fuer professionell getestete Malware-Abwehr. **Installation nur zuerst auf Test-VPS / Snapshot.** Fuer die aktuelle Version sind Python >=3.8 und eine Plesk-Umgebung mit Extension-API erforderlich.

## Was umgesetzt ist

| Funktion | Stand |
|---|---|
| Admin-Dashboard, WAF-Modus, Firewall-, ClamAV- und Fail2Ban-Status | implementiert, nur beobachtend |
| Malware-Scan pro Plesk-Standard-Domain mit ClamAV als Website-UID | implementiert, manuell |
| Automatische Scans | implementiert, opt-in pro Domain, stuendliche Faelligkeitspruefung, maximal ein Scan pro Scheduler-Lauf, mind. 24h Abstand pro Domain |
| Scan-Berichte/History | 30 zuletzt geaenderte Berichte angezeigt, bis 200 aktive oder bis 90 Tage aufbewahrt; Quarantaene-Berichte laenger |
| Quarantaene / Wiederherstellung | **nur manuell**, Move nach Fingerprint-Kontrolle; Restore verweigert Ueberschreiben; keine automatische Malware-Reparatur |
| Metadaten-Dateiueberwachung | zeitversetzte Stichprobe fuer PHP-/Config-Dateien auf opt-in Domains (bis 1500 Dateien pro Lauf), **kein Echtzeit-Schutz** |
| WAF-Ereignisse | letzte 512 KiB `/var/log/modsec_audit.log` auf Regeln/IPs reduziert; keine HTTP-Bodies |
| IP sperren / entsperren | manuell ueber aktives Fail2Ban-Jail; keine automatische Bedrohungsbewertung |

**Nicht integriert/automatisch aktiviert:** proaktive PHP-Laufzeitueberwachung (Snuffleupagus-Policy nur als Opt-in-Vorlage), ClamAV-On-Access, automatisierte Schadcode-Bereinigung, Bad-Bot-JavaScript-Challenges, DDoS-Schutz auf Netzwerkebene, IP-Reputation-/Cloud-Feeds, WAF-Regelbearbeitung, SQL-Datenbank-Scans, E-Mail-/Push-Benachrichtigungen, vollstaendige Benutzer-/Vhost-Unterstuetzung bei Custom-Document-Roots. ClamAV und ModSecurity muessen separat konfiguriert sein.

## Vorbedingungen

- Vollstaendigen VPS-Snapshot und externe Backups anlegen, SSH-Zugang pruefen.
- Testdomain mit **Standard-Docroot** `/var/www/vhosts/DOMAIN/httpdocs` verwenden. Custom Docroots werden bewusst abgelehnt. Websites mit root-eigenem Document-Root werden nicht gescannt.
- Plesk 18 (Obsidian) + Linux, Python >=3.8, PHP fuer Plesk.
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
plesk bin extension -i /root/guardian-lite-0.4.0.zip

# Upgrade einer vorhandenen guardian-lite 0.1.0 vom lokalen ZIP
plesk bin extension -g /root/guardian-lite-0.4.0.zip

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
unzip -l guardian-lite-0.4.0.zip
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


## Hinweis zum privaten GitHub-Repository

Dieses Repository ist privat. Der eingebaute GitHub-Updater arbeitet derzeit nur mit **oeffentlichen** GitHub-Releases ohne Authentifizierung. Auf diesem privaten Repository wird er keine Updates finden. Bitte kein persoenliches Zugriffstoken in die Extension eintragen. Fuer private Releases ist ein separater sicherer Authentifizierungs- und Signaturmechanismus erforderlich.
