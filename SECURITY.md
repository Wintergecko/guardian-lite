# Guardian Lite v0.6.4 – Sicherheitsmodell und Grenzen

- Root-Helfer unter Plesk `sbin`; Panelzugriff nur Administrator, POST-CSRF fuer Mutationen.
- Dateizugriffe validieren Domains, kanonische Docroots und nofollow-Pfade. Quarantaene nur bei unveraendertem SHA256/Metadaten-Fingerprint und eindeutiger regulaerer Datei. Race Conditions bei aktiv schreibenden Sites lassen sich ohne Isolation nicht vollstaendig ausschliessen.
- Kein frei konfigurierbarer Shell-Befehl, keine direkten Website-Pfade aus Form-Parametern.
- Fail2Ban: nur validierte aktive Jail-Namen und per ipaddress gepruefte IPv4/IPv6-Adressen. Die Sperre einer externen Administrator-IP bleibt moeglich; Panel bestaetigt vor der Aktion.
- Scanner folgt keinen Symlinks, laeuft mit Website-UID; CPU/Log/Groessen-/Zeit-Limits. Ist nicht gleichbedeutend mit sicherer PHP-Laufzeit-Analyse.
- Ein Scan/Quarantaene-Vorgang zur Zeit durch `flock`; Job-Reports atomar geschrieben. Plesk-Scheduler nur Opt-in.
- Quarantaene speichert Dateien in privatem root-Verzeichnis, Restore ueberschreibt nie. Bei Crash im Status `pending` kann Restore die Dateiverschiebung rueckgaengig machen, wenn die Datei tatsaechlich in Quarantaene liegt.
- WAF-Parser speichert keine unredigierten HTTP-Requests im Dashboard, nur Regel-ID und IP aus maximal 512 KiB Audit-Log. Das Betriebssystem bewahrt sein eigenes Audit-Log unabhaengig davon auf.
- `watch_changes` ist ein begrenzter periodischer Metadatenvergleich. Separat existiert eine opt-in inotify-Dateiwache mit gezielten ClamAV-Pruefungen, ohne automatische Quarantaene oder Ausfuehrungsblockade. Verschobene Teilbaeume werden vom alten Pfad getrennt; ein verschobener Document-Root beendet den Monitor.
- Keine automatischen Firewall-Policy-Aenderungen, keine automatische Quarantaene und keine automatische Malware-Bereinigung.
- Kein externer Sicherheitsaudit; fuer Produktion Code Review und Test-VPS erforderlich.

## v0.4.0 policy boundaries

Runtime-/HTTP-Flood-Schutz ist nur als Opt-in-Vorlage enthalten. Es gibt bewusst keinen privilegierten Web-Endpunkt zur Aktivierung beliebiger PHP-/Webserver-Regeln. Ein Policy-Rollout muss auf einer Testdomain erfolgen und die produktive Konfiguration sichern.
