# Weitere Features nach 0.11.0

Der umfassende Vergleich mit Imunify360 steht in [IMUNIFY360_PARITY.md](IMUNIFY360_PARITY.md). Ergaenzend zu den dortigen Funktionsluecken bleiben folgende eigenstaendige Guardian-Verbesserungen offen:

Diese Punkte sind Vorschlaege aus der Code- und Ablaufpruefung, keine bereits implementierten Funktionen.

| Prioritaet | Feature | Nutzen / konkrete Luecke |
|---|---|---|
| Hoch | Weitere CMS-Pruefsummen | WordPress-Core und WordPress.org-Plugins geprueft; Joomla/Magento-Herstellerquellen und sichere, signierte Good-File-Pakete fehlen. Keine automatische Reparatur aus Pruefergebnissen |
| Hoch | Granulare Allowlist und Notfall-Freischaltung | Eigene Admin-IP, Monitoring, XML-RPC/API-Clients und legitime Bots bei WAF/Turnstile gezielt ausnehmen; Schutz vor Selbstaussperrung |
| Hoch | Baseline-/Backup-Aufbewahrung und Speicheranzeige | Alte/incomplete Snapshots sicher per GUI entfernen, Quota pro Domain, freien Speicher und benoetigte Reparaturquellen anzeigen |
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

Fuer die naechste Runde sind Hersteller-Pruefsummen, Allowlist/Notfallzugang und Snapshot-Verwaltung am wertvollsten. Sie verbessern Vertrauen und Bedienbarkeit der nun vorhandenen aktiven Funktionen.

Technische Grundlage fuer Hersteller-Pruefsummen: [WP-CLI core verify-checksums](https://developer.wordpress.org/cli/commands/core/verify-checksums/) vergleicht WordPress-Core-Dateien mit WordPress.org-Pruefsummen, ohne WordPress dafuer zu laden. Premium-Erweiterungen und angepasste Dateien benoetigen eigene Vertrauensquellen.
