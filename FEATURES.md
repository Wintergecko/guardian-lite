# Weitere Features nach 0.18.0

Der umfassende Vergleich mit Imunify360 steht in [IMUNIFY360_PARITY.md](IMUNIFY360_PARITY.md). Ergaenzend zu den dortigen Funktionsluecken bleiben folgende eigenstaendige Guardian-Verbesserungen offen:

Diese Punkte sind Vorschlaege aus der Code- und Ablaufpruefung, keine bereits implementierten Funktionen.

| Prioritaet | Feature | Nutzen / konkrete Luecke |
|---|---|---|
| Hoch | Hersteller-Pruefsummen weiterer CMS | WordPress-Core und WordPress.org-Plugins geprueft; Joomla/Magento-Herstellerquellen und sichere, signierte Good-File-Pakete fehlen. Keine automatische Reparatur aus Pruefergebnissen |
| Hoch | Signaturbasierter Datenbankscanner | WordPress hat einen begrenzten read-only SQL-Heuristikscan; Hersteller-/Malware-Signaturen sowie Joomla/Magento fehlen, Bereinigung/Backup/Rollback ist offen |
| Hoch | Firewall-Allowlist und Notfall-Freischaltung | Plesk-Firewall-Deny-Regeln und begrenzte TTLs sind vorhanden; explizite priorisierte Admin-/Monitoring-Ausnahmen fehlen |
| Hoch | Baseline-/Backup-Aufbewahrung und Speicheranzeige | Globale Speicheranzeige und manuelle Loeschung vorhanden; Quota pro Domain, Aufbewahrungsregeln, Backups ausserhalb der verwalteten PHP-/WAF-Metadaten und Reparaturquellenanzeige fehlen |
| Hoch | Cronjob-Regelausbau und Verifikation | Aktueller read-only Heuristikcheck deckt nur gaengige Muster und feste Cron-Pfade ab; Malware-Signaturen und Distributionen-Faelle fehlen |
| Hoch | Echte Plesk-Testmatrix | Reproduzierbare VPS-Tests mit installierten Plesk-Versionen, Debian/Ubuntu/AlmaLinux und mehreren PHP-Handlern; aktuell nicht automatisiert nachgewiesen |
| Hoch | Transaktionale Service-Rollouts | Aenderungen mit vorher/nachher Diff, FPM-/WAF-Gesundheitsprobe und zeitgesteuerter Ruecknahme, falls ein Betreiber den Rollout nicht bestaetigt |
| Mittel | PHP-/FPM-Zuordnung pro Domain | Vor einer Handler-Aktivierung alle betroffenen Domains anzeigen und gezielte Handler-/TuxCare-Unterstuetzung ergaenzen |
| Mittel | Erweiterte Bot-Pfadprofile | Pro CMS vordefinierte Login-/API-Pfade, explizite Ausnahmen, keine frei eingebbaren PHP-/Shell-Fragmente |
| Mittel | Reputationsbewertung mit nachvollziehbarer Freigabe | WAF-/Fail2Ban-Ereignisse mit AbuseIPDB-Ergebnissen verknuepfen; Allowlist und Freigabe vor Sperren, statt pauschalem automatischem Blockieren |
| Mittel | Alert-Warteschlange | Versandfehler speichern, kontrolliert erneut versuchen und Zustellungsstatus im Panel zeigen; bisher nur Uebergabe an lokalen Mailtransport |
| Mittel | Zentraler Audit-Verlauf | Konfigurationsaenderungen mit Backup-ID, Akteur, vorher/nachher Hash und optionalem externem Append-only-Ziel dokumentieren |
| Mittel | Dateiwache fuer groessere Installationen | Watch-Budget je Domain, nachvollziehbare Abdeckung, robuste Wiederaufnahme nach Overflow und kuerzere Healthchecks |
| Niedrig | Benachrichtigungen/Webhooks | Ereignisse in vorhandene Betriebswerkzeuge integrieren; Geheimnisse und Zielhosts strikt begrenzen |
| Niedrig | Admin-Tool-Erkennung ausbauen | Aktuell begrenzte Namens-/Markerpruefung fuer Adminer und TinyFileManager; kuratierte, gepruefte Markerlisten und weitere Admin-Werkzeuge fehlen |

Lokaler signaturgebundener RapidScan-Cache ist umgesetzt. Naechster grosser Malware-Paritaetsschritt ist ein signaturbasierter CMS-Datenbankscanner mit sicheren, getesteten Backups und Rollback; ein proprietaerer AI-Bolit-Nachbau ist nicht vorgesehen. Cloud-Hash-Reputation benoetigt eine eigene Datenschutz-/Anbieterfreigabe. Eine Firewall-Allowlist benoetigt zuerst Plesk-Regelprioritaetstests, damit Freigaben Deny-Regeln sicher uebersteuern.

Technische Grundlage fuer Hersteller-Pruefsummen: [WP-CLI core verify-checksums](https://developer.wordpress.org/cli/commands/core/verify-checksums/) vergleicht WordPress-Core-Dateien mit WordPress.org-Pruefsummen, ohne WordPress dafuer zu laden. Premium-Erweiterungen und angepasste Dateien benoetigen eigene Vertrauensquellen.
