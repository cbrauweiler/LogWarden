# Datenmodell

Zielsystem: PostgreSQL 16+, Datenbank-Zeitzone `UTC`.

## Übersicht

| Tabelle | Zweck |
|---|---|
| `events` | Normalisierte Events, tagesweise partitioniert |
| `ingest_sources` | Konfiguration je Quelle inkl. Bookmark und Fehlerstatus |
| `secrets` | libsodium-verschlüsselte Credentials und Webhook-URLs |
| `rules`, `alerts`, `alert_events` | Rule-Engine und ausgelöste Alerts |
| `notification_channels`, `rule_channels`, `notification_log` | Teams-Benachrichtigung |
| `users`, `ldap_role_map`, `sessions`, `audit_log` | Anmeldung, Rollen, Nachvollziehbarkeit |
| `branding`, `branding_assets` | Corporate Identity |
| `retention_policies` | Aufbewahrungsdauer je Quelltyp |

## `events`

Das gemeinsame Schema aller Quellen. Der Partitionsschlüssel ist `ts`, der
Primärschlüssel entsprechend `(ts, id)` — PostgreSQL verlangt den
Partitionsschlüssel im PK. Praktische Folge: Detail-Links tragen beide Werte,
sonst müsste ein Lookup jede Partition anfassen.

| Spalte | Typ | Anmerkung |
|---|---|---|
| `ts` | `timestamptz` | Event-Zeit der Quelle |
| `ingested_at` | `timestamptz` | Zustellzeit; die Differenz zeigt Uhr-Drift |
| `source_type` | `source_type_t` | `ad`, `dns`, `dhcp`, `fortigate_vpn`, `fortigate_auth` |
| `source_host` | `text` | Meldendes System |
| `event_type` | `text` | `4625`, `tunnel-up`, `ssl-login-fail` … |
| `username` | `text` | Domäne abgeschnitten, damit Quellen korrelieren |
| `username_norm` | `text` | Generiert: `lower(username)` |
| `src_ip`, `dst_ip` | `inet` | Echte Subnetz-Queries möglich |
| `result` | `event_result_t` | `success`, `fail`, `info` |
| `raw_message` | `text` | Originalzeile |
| `details` | `jsonb` | Quellenspezifische Felder, GIN-indiziert |
| `dedup_key` | `text` | Macht Replays idempotent |
| `search_tsv` | `tsvector` | Generiert aus `raw_message` |

### Warum `details jsonb` statt separater Detail-Tabellen

Ein Join gegen eine partitionierte Tabelle über `event_id` allein kann nicht
prunen — jede Detail-Abfrage würde sämtliche Partitionen anfassen. Zudem
blockiert ein Fremdschlüssel auf `events` das `DROP` alter Partitionen und damit
das gesamte Retention-Konzept. `details` auf derselben Zeile hält den Schreibweg
bei einem INSERT und bleibt per GIN indiziert:

```sql
SELECT * FROM events
 WHERE ts >= now() - interval '24 hours'
   AND details @> '{"tunneltype":"ssl-tunnel"}';
```

### Partitionen

```sql
SELECT lw_create_event_partition('2026-09-16');  -- legt events_20260916 an
SELECT lw_drop_event_partition('2026-03-01');    -- entfernt eine Partition
```

`events_default` fängt Events ab, für die noch keine Partition existiert. Läuft
`logwarden-maintenance` verspätet, holt die Anlegefunktion diese Zeilen unter
Beibehaltung ihrer `id` aus der Default-Partition zurück.

### Indizes

Auf der Elterntabelle angelegt und damit auf allen Partitionen vorhanden:

```
(username_norm, ts DESC) WHERE username IS NOT NULL
(src_ip,        ts DESC) WHERE src_ip IS NOT NULL
(source_type, event_type, ts DESC)
(source_host,   ts DESC)
(ts DESC)                WHERE result = 'fail'
GIN (details jsonb_path_ops)
```

Der GIN-Volltext-Index auf `search_tsv` wird bewusst **nicht** global angelegt.
Er kostet 30–40 % zusätzlichen Speicher und Schreibaufwand, deshalb legt
`logwarden-maintenance` ihn nur auf den letzten `retention_policies.fts_days`
Partitionen an und entfernt ihn danach wieder — jeweils `CONCURRENTLY`, damit
die Ingestion weiterläuft.

## Retention

`retention_policies` hält je Quelltyp `keep_days` und `fts_days`.

Da eine Partition Events aller Quelltypen enthält, darf sie erst fallen, wenn
sie älter als die großzügigste Policy ist. Zeilen, die ihre eigene Policy in
einer noch lebenden Partition überschreiten, werden quelltypweise gelöscht.

| Quelltyp | Vorgabe `keep_days` | `fts_days` |
|---|---|---|
| `ad` | 365 | 30 |
| `dns` | 21 | 7 |
| `dhcp` | 90 | 14 |
| `fortigate_vpn` | 180 | 30 |
| `fortigate_auth` | 180 | 30 |

## Alerts

`alerts.evidence` enthält einen Snapshot der auslösenden Daten. `alert_events`
verweist absichtlich **ohne** Fremdschlüssel auf `(event_ts, event_id)`: ein FK
in eine partitionierte Tabelle würde das Löschen alter Partitionen blockieren.
Ein Alert bleibt dadurch lesbar, auch wenn seine Quell-Events längst
ausgelaufen sind.

## Beispiel: quellenübergreifende Korrelation

Regel 3 („erfolgreicher VPN-Login, kurz darauf AD-Anmeldefehler"):

```sql
SELECT v.username,
       v.ts                        AS vpn_login,
       host(v.src_ip)              AS vpn_von,
       count(*)                    AS ad_fehlschlaege,
       min(f.ts)                   AS erster_fehlschlag
  FROM events v
  JOIN events f
    ON f.username_norm = v.username_norm
   AND f.source_type   = 'ad'
   AND f.result        = 'fail'
   AND f.ts >  v.ts
   AND f.ts <= v.ts + interval '10 minutes'
 WHERE v.source_type = 'fortigate_vpn'
   AND v.result      = 'success'
   AND v.ts >= now() - interval '24 hours'
 GROUP BY v.username, v.ts, v.src_ip
HAVING count(*) >= 3;
```

Genau diese Ausdrucksfähigkeit war der Grund für PostgreSQL: In einer
Suchmaschine ohne Joins wäre das Applikationslogik mit mehreren Roundtrips.
