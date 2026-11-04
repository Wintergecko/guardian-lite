# Guardian Lite 0.4 Policy-Integrationen (Opt-in)

**Standard: deaktiviert.** Das Dashboard zeigt nur Hinweise und statische PHP-Konfigurations-Indikatoren an. Es behauptet nicht, dass Requests bereits geschuetzt sind. Keine automatischen Webserver-/PHP-Config-Aenderungen.

## PHP-Laufzeitabwehr

`php-runtime/guardian.rules` ist eine Starter-Policy fuer das **separat installierte** PHP-Modul [Snuffleupagus](https://snuffleupagus.readthedocs.io/). Das Modul kann zur Laufzeit PHP-Funktionsaufrufe sperren; Guardian liefert keine eigene PHP-Engine. Die Regeln koennen WordPress-/Shop-/Backup-Plugins beeintraechtigen. Vor Einsatz: betroffenen Plesk-PHP-Handler pro Domain ermitteln, eine mit exakt diesem PHP-Build kompatible Snuffleupagus-Version installieren, im Handler-INI `extension=snuffleupagus.so` und `sp.configuration_file=/.../guardian.rules` aktivieren und nach einem erfolgreichen Test PHP-FPM neu laden. Auch `extension_dir` und der Handler-Pfad muessen stimmen. Auf Testdomain legitime Requests und absichtlich blockierte Funktionen separat pruefen. Anschliessend Plesk-PHP-Einstellungen und FPM-Logs kontrollieren. **Nicht global alle PHP-Handler auf einmal aendern.** Rollback: zwei INI-Zeilen auskommentieren, FPM-Handler neu laden. Snuffleupagus `simulation()` kann zum Vorabtest einzelner Regeln genutzt werden.

Wichtig: Sicherheitsmodule auf dem Plesk-PHP-Handler des Websites laufen, nicht automatisch auf dem System-PHP oder Plesk-Control-Panel-PHP. Pruefen, dass die verwendete Version von Snuffleupagus sicher gepatcht ist.

## HTTP-Bot-/Flood-Schutz

`http-guard/guardian-modsecurity.conf` enthaelt eine **optionale Beispielregel**, die HTTP-Anfragen pro Quell-IP in einem 60-Sekunden-Fenster auf 120 begrenzen soll. Sie ist nicht global aktiviert und setzt korrekt initialisierte IP-Collections und eine passende `SecDataDir`-Konfiguration voraus. Ob die Integration zum Plesk-ModSecurity-Regelsatz moeglich ist, muss pro Plesk-Installation geprueft werden. Starte mit einem Test-Vhost, ModSecurity Audit-Logging und Tests hinter dem verwendeten Proxy/CDN. IP-Adressen duerfen nur aus vertrauenswuerdigen Real-IP-Headern uebernommen werden. ACHTUNG: Cloudflare-IPs, NAT-Nutzer und API-/Cron-Jobs teilen eventuell eine IP und koennen geblockt werden. Die Blockrate und Bedingungen sind nur Ausgangswerte; False Positives zuerst im DetectionOnly-Modus pruefen. ModSecurity mit fehlender Collection-Persistenz bietet kein verlaessliches Limit.

**Kein volumetrischer DDoS-Schutz:** Ueberlastungen der Netzwerkleitung lassen sich nur vorgelagert beim Provider/CDN filtern. Laut Plesk Support ist `limit_req` beim Plesk-NGINX nicht voraussetzbar; NGINX-Konfigurationsaenderungen sind daher kein Teil der automatischen Installation.

## Aktivierung / Sicherheit

Beide Policys erfordern eine bewusste, getestete manuelle Aktivierung und Rollback-Plan. Das Paket installiert ausschliesslich die Dateien unter der Extension, nicht unter `/etc` oder `/opt/plesk/php`. Keine root-berechtigte Eingabe von freien Regelausdruecken ueber die Weboberflaeche.
