# LogWarden

Selbstgehostetes, SIEM-ähnliches Werkzeug zur Sammlung, Normalisierung, Suche
und Alarmierung von Security-Logs aus einer gemischten Windows-/Fortinet-
Infrastruktur. Kein Agent auf den Zielsystemen.

**Stand:** Fundament und FortiGate-Syslog-Ingestion sind fertig und getestet.
Siehe [Roadmap](#roadmap).

---

## Architekturentscheidungen

### PostgreSQL 16+ als einziger Datenspeicher

| Anforderung | Umsetzung |
|---|---|
| Hohes Event-Volumen | Tages-Partitionen auf `events.ts`; Retention = `DROP TABLE` statt Delete-Storm |
| Zeitraum-Suche | Partition-Pruning; Queries fassen nur die betroffenen Tage an |
| Volltext | Natives `tsvector`/GIN — der Index existiert nur auf den letzten N Tagen |
| Feld-Suche | `inet`-Typ für echte Subnetz-Queries, `jsonb` + GIN für quellenspezifische Felder |
| Quellenübergreifende Korrelation | Joins und Window-Functions: „VPN-Login, dann AD-Fehlschlag" ist *eine* Query |
| Konfiguration und Alerts | Transaktional, im selben System |

OpenSearch wurde verworfen, weil es keine Joins kennt (Korrelationsregeln würden
zu Applikationslogik) und weil Konfiguration plus Alert-Status ohnehin eine
zweite, relationale Datenbank erfordert hätten.

### Frontend ohne Build-Step

Server-gerenderte PHP-Templates, ein Stylesheet mit CSS-Custom-Properties und
eine Datei progressiv verbesserndes JavaScript. Kein npm, kein Bundler, keine
Web-Fonts von fremden Servern. Diagramme sind handgeschriebenes Inline-SVG und
funktionieren auch mit deaktiviertem JavaScript.

### Rule-Engine

Regeln sind Plugins: eine Datei in `src/Rules/Builtin/`, eine Zeile in `rules`.
Die Datenbank speichert einen Schlüssel, keinen Klassennamen — ein
`new $row['rule_class']` würde aus Schreibzugriff auf eine Konfigurationstabelle
beliebige Objekterzeugung machen.

Ein offener Alert ist pro Entität eindeutig. Eine anhaltende Lage lässt den
bestehenden Alert wachsen, statt die Liste mit fast identischen Kopien zu
füllen; `cooldown_s` steuert nur die Wiederbenachrichtigung. Geschlossen wird
nie automatisch. Details in [docs/rules.md](docs/rules.md).

### Corporate Identity

Unter *Verwaltung → Corporate Identity* lassen sich Produktname, Logos,
Primär-/Navigations-/Akzentfarbe, Schriftfamilie, Eckenform, Dichte und
Standard-Modus einstellen. Daraus wird `/theme.css` generiert, das die
Brand-Tokens des Design-Systems überschreibt.

Zwei Dinge sind bewusst **nicht** anpassbar:

* **Schweregrad-Farben von Alerts** — sie kodieren Bedeutung.
* **Farbskala der Diagramme** — als Satz auf Farbfehlsichtigkeit geprüft.

Die Lesbarkeit wird nicht dem Zufall überlassen: Aus der gewählten Markenfarbe
berechnet LogWarden nach WCAG die Schriftfarbe für Buttons und dunkelt die Farbe
für Fließtext ab, bis sie 4,5:1 erreicht. Die Einstellungsseite zeigt die
Kontrastwerte an.

---

## Installation

```bash
# 1. Abhängigkeiten (Debian/Ubuntu)
apt install php8.4-cli php8.4-fpm php8.4-pgsql php8.4-curl php8.4-mbstring \
            php8.4-xml postgresql-16 nginx
# php8.4-ldap wird zusätzlich gebraucht, sobald die Anmeldung aktiv ist

# 2. Datenbank
sudo -u postgres createuser --pwprompt logwarden
sudo -u postgres createdb --owner=logwarden logwarden

# 3. Konfiguration
cp config/config.php.dist config/config.php
$EDITOR config/config.php

# 4. Schlüssel für verschlüsselte Credentials
bin/logwarden-keygen          # legt config/secret.key mit Modus 0600 an

# 5. Schema und Partitionen
bin/logwarden-migrate
bin/logwarden-maintenance

# 6. Dienste
cp deploy/systemd/* /etc/systemd/system/
systemctl enable --now logwarden-syslogd logwarden-rules.timer \
                       logwarden-maintenance.timer logwarden-spool-replay.timer
```

`composer install` ist optional — ohne Composer greift ein eingebauter
PSR-4-Autoloader, sodass ein einfaches Kopieren des Verzeichnisses genügt.

### Weboberfläche lokal ansehen

```bash
bin/logwarden-serve 8080      # bindet ausschließlich an 127.0.0.1
```

Die Oberfläche startet nur mit `web.auth_mode = 'none'`, solange der
LDAP-Login nicht gebaut ist — sie verweigert den Dienst sonst, damit niemand
versehentlich ein unauthentifiziertes SIEM ins Netz stellt.

---

## FortiGate anbinden

Auf der FortiGate:

```
config log syslogd setting
    set status enable
    set server "10.0.0.50"
    set port 514
    set mode udp          # oder: reliable (TCP) bzw. udp mit enc-algorithm für TLS
    set format default    # 'cef' wird ebenfalls unterstützt
end
```

In `config/config.php` unbedingt `syslog.allow_from` auf die FortiGate-Adressen
setzen. UDP-Syslog ist nicht authentifiziert und die Absenderadresse trivial
fälschbar; wer mehr braucht, nutzt TCP/TLS mit Client-Zertifikaten
(`syslog.tls.ca_file`).

### Ohne FortiGate testen

```bash
# Ein einzelnes Event per UDP
logger -n 127.0.0.1 -P 5514 -d \
  'date=2026-09-15 time=10:01:15 devname="FGT-60F-HQ" logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" remip=198.51.100.44 user="CORP\asmith"'

# Die mitgelieferten Fixtures per netcat
grep -v '^#' tests/fixtures/fortigate-native.log | nc -q1 127.0.0.1 5514
```

Welche Events erkannt und welche verworfen werden, steht in
`src/Ingest/Fortigate/FortigateNormalizer.php`: gespeichert werden VPN
(`logid 0101…`) und Authentifizierung (`logid 0102…`), Traffic- und UTM-Logs
werden verworfen.

---

## Struktur

```
bin/          CLI-Entrypoints (Daemons und Jobs)
config/       Konfiguration und Master-Key (gitignored)
db/           Migrationen und Seed-Daten
src/
  Core/       Config, Db, Logger
  Security/   SecretBox (libsodium)
  Event/      Event-DTO, Batch-Writer, Normalizer-Contract
  Ingest/     Syslog/, Fortigate/, Winrm/, Dhcp/
  Rules/      Regel-Interface, Registry, Engine und eingebaute Regeln
  Alerting/   Alert-Persistenz und Abfragen
  Notify/     Teams-Webhook
  Search/     Query-Bau und Dashboard-Aggregate
  Web/        Router, Controller, Branding, Farbmathematik, Charts
public/       Einziger DocumentRoot
templates/    PHP-Templates
deploy/       systemd-Units, nginx-Beispiel, Windows-Hinweise
tests/        Unit-Tests und FortiGate-Fixtures
```

## Regeln prüfen

```bash
bin/logwarden-rules --list       # was auf der Platte gefunden wurde
bin/logwarden-rules --dry-run    # auswerten, ohne zu schreiben
bin/logwarden-rules --rule=failed_login_burst
```

## Tests

```bash
php tests/run.php

# Datenbanktests (Reconnect-Verhalten) gegen eine Wegwerf-Datenbank
LW_TEST_DSN='host=/var/run/postgresql;dbname=logwarden_test;user=logwarden;password=…' \
  php tests/run.php
```

## Roadmap

| Schritt | Status |
|---|---|
| Fundament, Schema, Partitionierung | fertig |
| FortiGate-Syslog-Ingestion (UDP/TCP/TLS, CEF + key=value) | fertig |
| Design-System und Corporate Identity | fertig |
| Dashboard | fertig |
| Rule-Engine und die drei Startregeln | fertig |
| Alert-Übersicht und Detailansicht | fertig |
| Such- und Filteransicht, Event-Detailansicht | offen |
| Teams-Benachrichtigung | offen |
| WinRM-Pull für AD | offen |
| DHCP-CSV-Import | offen |
| DNS: Audit-Kanal, danach optional Analytic-Verdichtung ([Strategie](docs/dns.md)) | offen |
| LDAP-Anmeldung und Rollenmodell | offen |

### Zwei bekannte Fallstricke

**DNS** zerfällt in zwei sehr unterschiedliche Dinge. Der Audit-Kanal
(Zonen- und Record-Änderungen) ist standardmäßig aktiv, winzig und im Alltag
direkt nützlich — er kommt zuerst. Der Analytic-Kanal schreibt eine Zeile pro
Abfrage, auf einem produktiven DC 2.000–10.000 Events/s, und wird ausschließlich
verdichtet auf dem DC selbst erfasst, nicht roh. Die Begründung und die
konkreten Filter stehen in [docs/dns.md](docs/dns.md).

**WinRM in reinem PHP** ist WS-Management-SOAP über HTTPS, machbar mit
`ext-curl` und `CURLAUTH_NTLM`. Kerberos setzt ein curl mit GSSAPI-Support
voraus, das nicht überall vorhanden ist. Plan B ist WEF-Push auf einen
Windows-Collector, dessen `ForwardedEvents` LogWarden ausliest.
