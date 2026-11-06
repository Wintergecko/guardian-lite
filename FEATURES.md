# Weitere Features nach 0.28.33

Der umfassende Funktionsvergleich steht in [FUNKTIONSUEBERSICHT.md](FUNKTIONSUEBERSICHT.md). Ergaenzend zu den dortigen Funktionsluecken bleiben folgende eigenstaendige Guardian-Verbesserungen offen:

Diese Punkte sind Vorschlaege aus der Code- und Ablaufpruefung, keine bereits implementierten Funktionen.

| Prioritaet | Feature | Nutzen / konkrete Luecke |
|---|---|---|
| Hoch | Hersteller-Pruefsummen weiterer CMS | WordPress-Core, WordPress.org-Plugins und passende Theme-Archive geprueft; Joomla/Magento-Herstellerquellen und signierte Good-File-Pakete fehlen. Keine automatische Reparatur aus Pruefergebnissen |
| Hoch | CMS-Datenbankreinigung mit sicherem Backup und Rollback | Read-only ClamAV-Streams fuer WordPress/Joomla/Magento; Herstellersignaturen, Datenbankbereinigung, Backup und Rollback fehlen |
| Hoch | Plesk-weite priorisierte Allowlist und Greylist | Guardian-IP-Ausnahmen verhindern nur kuenftige Guardian-Sperren; sie schalten keine Firewall frei. Eine echte Whitelist-Prioritaet und Greylist brauchen einen dokumentierten Plesk-Mechanismus und Integrationstests gegen Systemrichtlinien |
| Hoch | Baseline-/Backup-Aufbewahrung und Speicheranzeige | Speicheranzeige und manuelle Aufbewahrungsvorschau mit bestaetigter Einmal-Bereinigung umgesetzt. Quota pro Domain, Backups ausserhalb der verwalteten PHP-/WAF-Metadaten und Reparaturquellenanzeige fehlen |
| Hoch | Cronjob-Regelausbau und Verifikation | Read-only Heuristiken plus optionale lokale ClamAV-Signaturen sind umgesetzt; breitere Distributionenabdeckung und Tests auf echten Plesk-Distributionen fehlen |
| Hoch | Echte Plesk-Testmatrix | Reproduzierbare VPS-Tests mit installierten Plesk-Versionen, Debian/Ubuntu/AlmaLinux und mehreren PHP-Handlern; aktuell nicht automatisiert nachgewiesen |
| Hoch | Transaktionale Service-Rollouts | Aenderungen mit vorher/nachher Diff, FPM-/WAF-Gesundheitsprobe und zeitgesteuerter Ruecknahme, falls ein Betreiber den Rollout nicht bestaetigt |
| Mittel | PHP-/FPM-Zuordnung pro Domain | Vor einer Handler-Aktivierung alle betroffenen Domains anzeigen und gezielte Handler-/TuxCare-Unterstuetzung ergaenzen |
| Mittel | Erweiterte Bot-Pfadprofile | Pro CMS vordefinierte Login-/API-Pfade, explizite Ausnahmen, keine frei eingebbaren PHP-/Shell-Fragmente |
| Mittel | Reputationsbewertung mit nachvollziehbarer Freigabe | WAF-/Fail2Ban-Ereignisse mit AbuseIPDB-Ergebnissen verknuepfen; Allowlist und Freigabe vor Sperren, statt pauschalem automatischem Blockieren |
| Mittel | Konfigurierbare Warnereignisse und sichere Webhooks | E-Mail-Outbox mit Wiederholungen ist umgesetzt; Ereignisfilter, feste authentifizierte Webhook-Ziele und Zustellstatus ausserhalb des lokalen Mailtransports fehlen |
| Mittel | Zentraler Audit-Verlauf | Konfigurationsaenderungen mit Backup-ID, Akteur, vorher/nachher Hash und optionalem externem Append-only-Ziel dokumentieren |
| Mittel | Dateiwache fuer groessere Installationen | Watch-Budget je Domain, nachvollziehbare Abdeckung, robuste Wiederaufnahme nach Overflow und kuerzere Healthchecks |
| Niedrig | Benachrichtigungen/Webhooks | Ereignisse in vorhandene Betriebswerkzeuge integrieren; Geheimnisse und Zielhosts strikt begrenzen |
| Niedrig | Admin-Tool-Erkennung ausbauen | Aktuell begrenzte Namens-/Markerpruefung fuer Adminer und TinyFileManager; kuratierte, gepruefte Markerlisten und weitere Admin-Werkzeuge fehlen |

Lokaler signaturgebundener RapidScan-Cache, gestreamte ClamAV-Datenbankscans fuer WordPress/Joomla/Magento und ein lokaler Cron-Datei-Signaturscan sind umgesetzt. Die Datenbank- und Cron-Scans veraendern keine Inhalte. Sichere Datenbank-Backups und Rollback vor einer kuenftigen Bereinigung fehlen. Ein proprietaerer AI-Bolit-Nachbau ist nicht vorgesehen. Cloud-Hash-Reputation benoetigt eine eigene Datenschutz-/Anbieterfreigabe. Eine Firewall-Allowlist benoetigt zuerst Plesk-Regelprioritaetstests, damit Freigaben Deny-Regeln sicher uebersteuern.

Technische Grundlage fuer Hersteller-Pruefsummen: [WP-CLI core verify-checksums](https://developer.wordpress.org/cli/commands/core/verify-checksums/) vergleicht WordPress-Core-Dateien mit WordPress.org-Pruefsummen, ohne WordPress dafuer zu laden. Der [WordPress.org Theme API](https://developer.wordpress.org/reference/functions/themes_api/) liefert Versionsinformationen und Download-Archive; Guardian vergleicht die passende Theme-Version und kennzeichnet sie ausdruecklich als nicht signierten Nachweis. Premium-Erweiterungen und angepasste Dateien benoetigen eigene Vertrauensquellen.
