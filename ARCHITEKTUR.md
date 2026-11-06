# Sentinel Security – Architektur und Bestandsaufnahme

Stand: Version 0.28.46. Dieses Dokument beschreibt die vorhandene Erweiterung, keine Soll-Implementierung. Die Funktionsangaben sind auf Quellcode, Tests und die dokumentierten Systemvoraussetzungen begrenzt.

## Architektur

Die Erweiterung bleibt unter der Plesk-Extension-ID `guardian-lite`. Sie verwendet Plesks PHP-Extension-Controller als Authentifizierungs-, CSRF- und Integrationsschicht. Ein separater FastAPI-Dienst ist nicht erforderlich und wird nicht eingesetzt.

```text
Plesk Obsidian (Administrator)
  └─ plib/views/scripts/index/*.phtml
       ├─ bestehende serverseitig gerenderte Module und POST-Formulare
       └─ React-/TypeScript-Shell und Modulansichten
            └─ htdocs/sentinel/sentinel.js + sentinel.css
                 └─ Plesk-Controller (plib/controllers/IndexController.php)
                      ├─ guardian-helper: feste privilegierte Aktionen
                      └─ guardian-manager: Verwaltungsoperationen, JSON über stdin
                           └─ lokale Plesk-/Linux-Dienste und private Zustandsdaten
```

### Komponenten und Vertrauensgrenzen

| Komponente | Aufgabe | Sicherheitsgrenze |
|---|---|---|
| `plib/controllers/IndexController.php` | Plesk-Ansichten, Statusabfragen und Schreibaktionen | Admin-Zugriff, direkte nicht-impersonierte Sitzung, POST und CSRF für Schreibaktionen; Eingabeprüfung vor Aufruf der Helfer |
| `plib/views/scripts/index/` | Serverseitige Modulansichten und Formulare | Escaping für ausgegebene Daten; Aktionen bleiben an Plesk-Controller gebunden |
| `htdocs/js/guardian-tabs.js` | Plesk-Menüintegration und Umschalten zwischen vorhandenen Modulen | Verschiebt vorhandene Inhalte in Modul-Panels; ersetzt deren Controller nicht |
| `ui/src/` | React-/TypeScript-Navigation, Dashboard und migrierte Modulansichten | Nutzt Plesk-gerenderte Statusdaten und geschützte Plesk-Endpunkte; kein privilegierter Browserzugriff |
| `sbin/guardian-helper` | Systemstatus, Scans, Firewall-/Fail2Ban-Aktionen und weitere privilegierte Funktionen | Feste Aktionen, geprüfte Argumente, begrenzte Prozesse und private Datenverzeichnisse; keine frei wählbaren Shell-Befehle |
| `sbin/guardian-manager` | Verwaltungsfunktionen wie WAF-, PHP-, Backup-, Baseline- und Integrationsverwaltung | Feste Operationsnamen; vertrauliche JSON-Eingaben über stdin statt Prozessargumente; begrenzte Dateiziele und Wiederherstellungspunkte |
| `security/` | Verwaltete Regel- und Konfigurationsvorlagen | Aktivierung über explizite, geprüfte Abläufe; Backup, Konfigurationstest und Rollback je nach Modul |
| `tests/` | Python-, PHP-Smoke-, UI-Vertrags-, Paket- und HTTP-Integrationstests | Linux-CI ergänzt lokale Tests; echte Plesk-/Provider-/Mailzustellung benötigt weiterhin einen separaten Plesk-Testserver |

### Datenfluss und Betrieb

- Die UI ist kein eigenständiger API-Server. Serverdaten werden durch den Plesk-Controller geladen und für React bereitgestellt; andere Ansichten bleiben serverseitig gerendert.
- Privilegierte Aktionen laufen über Plesks `pm_ApiCli::callSbin`. Der Helper akzeptiert festgelegte Aktionen statt frei übergebener Befehle oder Pfade. Der Manager erhält JSON über stdin.
- Zustandsdaten, Schlüssel, Berichte, Incidents und Wiederherstellungspunkte werden lokal in geschützten Verzeichnissen unter `/var/lib/guardian-lite/` gehalten. Die jeweilige Funktion kann zusätzliche Systemvoraussetzungen haben.
- Firewall- und Fail2Ban-Konfigurationen werden nicht pauschal ersetzt. Die vorhandenen Schreibpfade verwenden eigene Regeln/Overrides, Vorabprüfung, Sicherung und Verifikation, soweit das betreffende Modul dies unterstützt.
- Die Oberfläche und das Plesk-ZIP werden aus `ui/` gebaut; die auslieferbaren Browserdateien liegen unter `htdocs/sentinel/`. Python-/PHP-Helfer sind Teil desselben Extensionspakets.
- Installation und Aktualisierung erfolgen manuell über Plesk CLI durch den Betreiber. Ein Release oder CI-Erfolg installiert nichts auf dem Plesk-Server.

## Abgleich mit den zwölf angeforderten Modulen

„Teilweise“ bedeutet, dass es eine echte Funktion gibt, aber nicht der vollständige im Auftrag beschriebene Umfang. Nicht vorhandene Funktionen werden nicht als verfügbar dargestellt.

| # | Angefordertes Modul | Stand 0.28.46 | Verifiziert vorhandener Umfang | Wesentliche Lücken |
|---|---|---|---|---|
| 1 | Security Dashboard | Teilweise | Reale Fail2Ban-, Firewall-, Ereignis- und WAF-Statusdaten; Schutzkennzahlen und IP-Karte, wenn lokale Datenbank und Abhängigkeit vorhanden sind | Dauerhafte, umfassende Statistikhistorie und zusätzliche Datenquellen |
| 2 | Fail2Ban Manager | Teilweise | Status, aktive Jails, begrenzte Jail-Parameter, manuelles Sperren/Freigeben; eigene Override-Datei, Backup, Konfigurationstest, Laufzeitprüfung und Rollback | Verwaltung globaler Fail2Ban-Einstellungen, Erstellen von Jails/Filtern/Aktionen und getestete Plesk-spezifische Jail-Vorlagen |
| 3 | Firewall Manager | Teilweise | Plesk-Regelinventar, Guardian-IP-Regeln/Schutz-Ausnahmen und ausgewählte quell-IP-bezogene Portregeln; Vorschau, Admin-Bestätigung, Rollback und Verifikation für unterstützte Schreibpfade | Vollständige Richtung-/Netz-/Protokollverwaltung über alle Adapter, globale Policies und priorisierte Allowlist/Greylist |
| 4 | IP Block Manager | Teilweise | IPv4/IPv6-Sperren, begrenzte Netze, zeitlich begrenzte Guardian-Regeln, Ausnahmen und Massenaktionen in bestehenden Abläufen | Einheitliche Black-/Whitelist mit systemweiter Priorität, umfassendere Historie und adapterübergreifende Regeln |
| 5 | Security Event Viewer | Teilweise | WAF-/Incident-Daten, Filter, jüngste Ereignisse und JSON-Export; lokale E-Mail-Warnungen für Malwareereignisse | Konfigurierbare Ereignisregeln, umfassender Live-Log-Stream und persistente, unbegrenzte Ereignishistorie |
| 6 | Attack Analytics | Teilweise | Begrenzte 24h-/7d-/30d-Auswertungen über vorhandene Incidents und WAF-Ereignisse | Dauerhafte Aggregation, feinere Zeitreihen, angreifer-/dienstbezogene Langzeitanalysen und Export historischer Kennzahlen |
| 7 | GeoIP Security | Teilweise | Lokale IP-Länderauflösung und Karte für begrenzte aktive/aktuelle Sperr-IP-Daten bei installierter DB-IP-Lite-Datei und `python3-maxminddb` | Länderregeln, GeoIP-Statistiken über Zeit, Ausnahmen und belastbare Verifikation regionaler Firewall-Regelpriorität |
| 8 | Automation Engine | Teilweise | Geplante/serielle Scans, Dateiwache und ausdrücklich aktivierbare Baseline-Reparatur; begrenzte Regelabläufe | Sicherheitsprofile, wiederkehrende Angreiferregeln, allgemeine Zeitpläne und nachvollziehbare Freigabe-/Abschaltmechanismen |
| 9 | Notification Center | Teilweise | Gedrosselte Malware-E-Mail-Outbox mit begrenzten Wiederholungen und manuellem Retry | Telegram, Discord, sichere Webhooks, Ereignisfilter, Test-/Zustellstatus und konfigurierbare Regeln |
| 10 | Backup Manager | Teilweise | Begrenzte PHP-/WAF-/Fail2Ban-Backups, Baselines, Speicheranzeige, Aufbewahrungsvorschau und ausgewählte Rollbacks | Einheitliche Konfigurationsversionierung, Export/Import, umfassendere sichere Wiederherstellung und automatische Aufbewahrungsregeln |
| 11 | System Diagnostics | Teilweise | Sanitisiertes Diagnose-JSON, Dienst-/Abhängigkeitsstatus und optionale kurzlebige HTTPS-PHP-Probe | Vollständige Berechtigungs- und Backendadapter-Testmatrix über unterstützte Plesk-/OS-Varianten |
| 12 | Settings | Teilweise | Hell-/Dunkelmodus, lokale UI-Sprache, ausgewählte Service-Schlüssel, Speicher-/Wartungs- und Update-Ansichten | Persistente Administrationssprache, umfassendere Integrations-/Sicherheits-/Datenhaltungsoptionen und konsolidierte Erweiterungskonfiguration |

Die Funktionsgrenzen, Abhängigkeiten und Risiken der bestehenden Module sind zusätzlich in [README.md](README.md), [MANAGEMENT.md](MANAGEMENT.md), [SECURITY.md](SECURITY.md) und [FUNKTIONSUEBERSICHT.md](FUNKTIONSUEBERSICHT.md) beschrieben.

## Umsetzungskriterien für die nächsten Module

Jede Erweiterung muss in die vorhandene Plesk-Schicht integriert werden und mindestens folgende Kriterien erfüllen:

1. Funktionsumfang und Betriebssystem-/Plesk-Abhängigkeiten werden vor der Aktion geprüft und im UI als verfügbar, nicht verfügbar oder teilweise verfügbar ausgewiesen.
2. Schreibende Aktionen verwenden direkte Plesk-Admin-Berechtigung, POST und CSRF; Browsercode erhält keine privilegierten Zugangsdaten.
3. Der privilegierte Helfer erhält nur feste Operationen und validierte, begrenzte Werte. Kein vom Benutzer erzeugter Shell-Befehl, Dateipfad oder unbegrenzter Prozess.
4. Kritische Änderungen benötigen, wo anwendbar, eine Vorschau, ein root-geschütztes Backup, Bestätigung, unabhängige Zustandsprüfung und einen überprüfbaren Rollback.
5. Fehler und Rollback-Fehler werden sichtbar als Fehler ausgegeben. Ein fehlender Dienst oder Datenfeed darf nicht als erfolgreicher Schutz erscheinen.
6. Jede Funktion erhält Tests für Eingabegrenzen, Fehlerpfade und Schutz der bestehenden Konfiguration sowie eine Dokumentation ihrer Verfügbarkeit und Grenzen.

Der konkrete Funktionsabgleich und die priorisierten offenen Arbeiten stehen in [FEATURES.md](FEATURES.md). Implementierte Funktionalität wird erst nach gezielten Tests und dem Release-CI als ausgeliefert behandelt.
