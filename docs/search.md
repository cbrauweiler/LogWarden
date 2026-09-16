# Suche

## Zwei Regeln, die alles bestimmen

**Jede Abfrage ist zeitlich begrenzt.** Ohne Zeitgrenze kann PostgreSQL keine
Partitionen ausschließen und liest jeden Tag von der Platte. Die Vorgabe sind
24 Stunden; ein Suchformular ohne Zeitraum gibt es nicht.

**Geblättert wird per Keyset, nicht per OFFSET.** Seite 200 einer
OFFSET-Abfrage liest die 20.000 Zeilen davor noch einmal — genau in dem
Moment, in dem jemand tief in einer Untersuchung steckt und am wenigsten
warten will. Stattdessen vergleicht die Abfrage gegen den Primärschlüssel:

```sql
WHERE (ts, id) < (:cursor_ts, :cursor_id)
ORDER BY ts DESC, id DESC
```

Gemessen an 500.000 Events über 30 Tage: Seite 1 braucht 4,1 ms, Seite 144
braucht 4,3 ms.

## Filter

Alle Filter sind kombinierbar und werden mit UND verknüpft.

| Feld | Verhalten |
|---|---|
| Volltext | Wortweise über `raw_message`. Anführungszeichen für Phrasen, Minus schließt aus. |
| Konto | Exakt, oder mit `*` als Präfix-Platzhalter (`svc-*`). Domäne ist bereits abgeschnitten. |
| IP oder Netz | Einzeladresse oder CIDR (`10.0.0.0/8`), wahlweise nur Quelle, nur Ziel oder beides. |
| System | Exakt oder mit `*`. |
| Event-Typ | Exakt oder mit `*` (`4625`, `ssl-login-*`). |
| Ergebnis | success / fail / info |
| Quelle | Mehrfachauswahl über die Quelltypen |
| Zeitraum | Voreinstellungen oder benutzerdefiniert, immer UTC |

`%` und `_` bleiben literal — nur `*` ist ein Platzhalter. Wer nach einem
Kontonamen mit Prozentzeichen sucht, findet ihn.

Eine verdrehte benutzerdefinierte Zeitspanne wird getauscht statt leer
zurückzugeben: das ist ein Tippfehler, kein Suchergebnis.

Eine ungültige IP-Eingabe wird gemeldet und der Filter ignoriert. Durchgereicht
würde sie auf PostgreSQLs `inet`-Cast treffen und als Serverfehler erscheinen —
für einen Tippfehler.

## Die Suche ist ein Link

Jeder Filter steht in der Query-String. Eine Suche lässt sich in ein Ticket
oder einen Chat einfügen, und die nächste Person sieht genau dieselbe Ansicht.
Aus demselben Grund sind auf der Detailansicht Konto, IPs, System und Event-Typ
verlinkt: der übliche nächste Schritt ist „zeig mir alles von diesem Konto".

## Trefferzahl und Verteilung

Beide sind gedeckelt, und zwar aus demselben Grund: ein exaktes Aggregat über
alle Treffer ist linear im Datenvolumen.

* Ab 10.000 Treffern wird nicht weiter gezählt, die Anzeige lautet `10.000+`.
* Die Quellenverteilung wird dann über die 10.000 neuesten Treffer berechnet
  und beschriftet das auch.

Ohne diese Grenze kostete die Verteilung über 30 Tage bei 500.000 Events
158 ms — und wäre bei dem Volumen eines Jahres unbenutzbar. Mit Grenze: 8 ms.

## Volltext und der Index

Der GIN-Index auf `search_tsv` existiert nur auf den letzten
`retention_policies.fts_days` Partitionen, weil er 30–40 % zusätzlichen
Speicher kostet. Reicht der gewählte Zeitraum weiter zurück, liest die Suche
die älteren Tage vollständig. Die Oberfläche sagt das vorher, statt die Abfrage
stillschweigend dreißig Sekunden laufen zu lassen.

Die Volltextsuche ist **wortbasiert**, keine Teilstringsuche: `kennwort` findet
„Kennwort falsch", `ennwor` findet nichts. Für Teilstrings sind die Feldfilter
mit `*` da.

## CSV-Export

Der Export übernimmt die aktuellen Filter, blättert intern weiter und hält
dadurch den Speicher flach — er puffert nie den gesamten Treffersatz.
Obergrenze 50.000 Zeilen.

Semikolon als Trennzeichen und ein UTF-8-BOM voran, weil diese Dateien
üblicherweise in Excel landen und dort sonst als Latin-1 interpretiert werden.
Zeilenumbrüche in `raw_message` werden zu Leerzeichen, damit ein Event eine
Zeile bleibt.

## Indizes

| Filter | Genutzter Index |
|---|---|
| Zeitraum | Partition-Pruning + Primärschlüssel `(ts, id)` |
| Konto | `events_user_ts_idx (username_norm, ts DESC)` |
| Quell-IP | `events_srcip_ts_idx (src_ip, ts DESC)` |
| Ziel-IP | `events_dstip_ts_idx (dst_ip, ts DESC)` |
| Quelle + Event-Typ | `events_type_ts_idx (source_type, event_type, ts DESC)` |
| System | `events_host_ts_idx (source_host, ts DESC)` |
| Nur Fehlschläge | `events_fail_ts_idx (ts DESC) WHERE result = 'fail'` |
| Volltext | `events_YYYYMMDD_tsv_idx` (nur auf jungen Partitionen) |

> Der Index auf `dst_ip` kam erst mit Migration 0004 dazu. Ohne ihn verband die
> Suche über beide IP-Felder eine indizierte mit einer nicht indizierten Spalte;
> der Planer ließ daraufhin beide Indizes fallen und las alle Partitionen
> sequenziell — 55 ms für vier Treffer, und linear wachsend. Mit Index: 4,5 ms.

## Gemessen

500.000 Events über 30 Tage, 349 MB, eine einzelne PostgreSQL-Instanz:

| Abfrage | Seite | Anzahl | Verteilung |
|---|---|---|---|
| 24 Stunden, ohne Filter | 8 ms | 2 ms | 10 ms |
| 30 Tage, ohne Filter | 12 ms | 3 ms | 8 ms |
| Konto exakt | 3 ms | 28 ms | 57 ms |
| Einzel-IP über beide Felder | 5 ms | 3 ms | 3 ms |
| Netz /16 | 4 ms | 8 ms | 20 ms |
| Volltext | 3 ms | 4 ms | 8 ms |
| Konto + Ergebnis + Quelle | 4 ms | 78 ms | 88 ms |

Die Zahlen stammen aus einer Testinstanz ohne getrennte Platten und ohne
Tuning. Sie sagen nichts über euer Volumen, aber sie zeigen, dass nichts
linear im Gesamtbestand wächst — und genau darum geht es.
