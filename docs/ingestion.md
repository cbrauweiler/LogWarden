# Ingestion

## Gemeinsamer Weg

```
Rohzeile → NormalizerInterface::normalize() → Event → EventWriter → PostgreSQL
                                                          ↓ bei DB-Ausfall
                                                      var/spool/*.ndjson
```

Jedes Ingestion-Modul implementiert `LogWarden\Event\NormalizerInterface`:

```php
interface NormalizerInterface
{
    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array;
    public function supports(string $raw, array $context = []): bool;
}
```

`normalize()` gibt eine Liste zurück, nicht ein einzelnes Event: Eine Rohzeile
kann zu mehreren Events werden — oder zu keinem, wenn der Normalizer sie
bewusst verwirft.

## Batching und Spooling

`EventWriter` puffert Events und schreibt sie als ein Multi-Row-INSERT mit
`ON CONFLICT DO NOTHING`. Ein INSERT pro Event würde den Listener bei wenigen
hundert Events/s deckeln.

Ist die Datenbank nicht erreichbar, landet der Batch als NDJSON in `var/spool/`
(erst unter `.partial`, dann umbenannt, damit der Replay nie eine halb
geschriebene Datei liest). `logwarden-spool-replay` spielt sie zurück; ein
Datenbank-Neustart kostet dadurch Latenz statt UDP-Datagramme.

Bricht nur die Verbindung weg, während der Server weiterläuft, verbindet sich
`Db` transparent neu und der Batch geht gar nicht erst in den Spool.

> `PDO::inTransaction()` meldet bei einer toten pgsql-Verbindung `true` (libpq
> liefert `PQTRANS_UNKNOWN`). `Db` führt den Transaktionsstatus deshalb selbst —
> sonst wäre der Reconnect genau dann deaktiviert, wenn er gebraucht wird.
> Siehe `tests/Unit/DbReconnectTest.php`.

## FortiGate-Syslog

`bin/logwarden-syslogd`, ein Prozess mit `stream_select`-Schleife über
UDP-, TCP- und TLS-Listener.

### Framing

RFC 6587 erlaubt auf TCP zwei Verfahren, FortiOS nutzt je nach Konfiguration
beide, also werden beide unterstützt:

* **Octet-Counting** — `123 <189>date=…`
* **Zeilenende** — durch `\n` getrennt

Der Puffer setzt Frames über TCP-Segmentgrenzen hinweg zusammen.

### TLS

Der Handshake läuft nicht-blockierend aus der Leseschleife heraus
(`stream_socket_enable_crypto` liefert `0`, solange Daten fehlen). Ein Client,
der mitten im Handshake stehen bleibt, blockiert damit nicht die Ingestion aller
anderen. Ist `syslog.tls.ca_file` gesetzt, werden Client-Zertifikate verlangt —
erst damit ist Syslog wirklich authentifiziert.

### Erkannte Formate

| Format | Erkennung |
|---|---|
| FortiOS key=value | `devname=`, `logid=` bzw. `date=` + `devid=` |
| CEF | `CEF:` im Payload und Vendor `Fortinet` |

Beide werden auf dieselbe flache Feldliste abgebildet; Klassifikation und
Feldzugriff sind danach identisch.

### Klassifikation

| Signal | Ergebnis |
|---|---|
| `logid` beginnt mit `0101` | `fortigate_vpn` |
| `logid` beginnt mit `0102` | `fortigate_auth` |
| `subtype = vpn` | `fortigate_vpn` |
| `subtype` ∈ {`user`, `auth`} | `fortigate_auth` |
| `action` enthält `tunnel`/`ssl-login` | `fortigate_vpn` |
| `action` enthält `auth`/`login`/`logout` | `fortigate_auth` |
| sonst | verworfen |

Traffic- und UTM-Logs werden verworfen. Sie würden den Speicher dominieren,
ohne einer der Regeln zu dienen.

### Zeitstempel

Reihenfolge der Auswertung:

1. `eventtime` / `FTNTFGTeventtime` / `rt` — die Einheit wird aus der
   Ziffernzahl abgeleitet, weil FortiOS sie zwischen Releases geändert hat
   (Sekunden bis 6.0, Nanosekunden ab 6.2)
2. `date` + `time` + `tz`
3. Zeitstempel des Syslog-Headers
4. Empfangszeit

### Benutzernamen

`CORP\asmith`, `asmith@corp.local` und `asmith` werden alle zu `asmith` —
sonst würde derselbe Mensch in AD und FortiGate als zwei Konten erscheinen und
die quellenübergreifenden Regeln liefen ins Leere. Die Originalform bleibt in
`details.user_raw` erhalten.

## Betrieb

```bash
systemctl status logwarden-syslogd
journalctl -u logwarden-syslogd -f
```

Der Daemon protokolliert minütlich Durchsatz und Writer-Statistik:

```
INFO [syslogd] Throughput {"received":23,"normalized":21,"skipped":2,
                           "rejected":0,"malformed":0,"eps":0.4,"clients":0,
                           "writer":{"written":12,"duplicates":9,"spooled":0}}
```

| Feld | Bedeutung |
|---|---|
| `skipped` | Erkannt, aber keine gespeicherte Kategorie (z. B. Traffic-Logs) |
| `rejected` | Absender nicht in `syslog.allow_from` |
| `malformed` | Normalizer-Fehler oder überlange Frames |
| `duplicates` | Vom `dedup_key` abgefangene Wiederholungen |
| `spooled` | Bei DB-Ausfall auf Platte geschrieben |
