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
