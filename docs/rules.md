# Rule-Engine

## Ablauf

`bin/logwarden-rules` läuft minütlich per Timer. Pro aktiver Regel:

1. Fenster bestimmen: `[now − lag_seconds − window_minutes, now − lag_seconds]`
2. `evaluate()` der Regel aufrufen
3. Je Fund einen Alert anlegen **oder** den offenen Alert derselben Entität fortschreiben
4. `last_run_at`, `last_cursor_ts` und `last_duration_ms` schreiben

Eine fehlgeschlagene Regel stoppt die anderen nicht — eine kaputte Erkennung
ist schlecht, eine stillstehende Erkennungskette ist schlimmer. Der Fehler
landet in `rules.last_error` und der Prozess endet mit Exit-Code 1, damit der
Timer im `systemctl status` rot wird.

### Warum `lag_seconds`

Events treffen verzögert ein: Syslog braucht Netzlaufzeit, ein WinRM-Pull läuft
im Intervall. Würde die Auswertung bis `now()` reichen, beurteilte sie ein
Fenster, das sich noch füllt. Die Vorgabe von 60 Sekunden passt zu UDP-Syslog;
für eine Quelle, die nur alle fünf Minuten gepollt wird, gehört der Wert höher.

### Verpasste Läufe

Regeln werten ein gleitendes Fenster aus, keinen Cursor. Ein ausgefallener Lauf
kostet Aktualität, keine Abdeckung: Der nächste Lauf sieht dieselben Events, so
lange die Lücke kleiner als `window_minutes` ist.

## Alert-Lebenszyklus

Eine Regel mit Zehn-Minuten-Fenster, minütlich ausgewertet, würde für einen
Vorfall zehn fast identische Alerts erzeugen. Eine Alert-Liste, die niemand
liest, ist schlechter als keine.

Deshalb: **Ein offener Alert ist pro Entität eindeutig** (Unique-Index auf
`dedup_key` für `status = 'new'`). Eine anhaltende Lage aktualisiert den
bestehenden Alert.

| Feld | Bedeutung |
|---|---|
| `event_count` | Anzahl im *aktuellen* Fenster |
| `evidence.peak_count` | Höchststand über alle Auswertungen |
| `evidence.evaluations` | Wie oft die Lage bestätigt wurde |
| `last_seen_at` | Letzte Bestätigung |
| `severity` | Höchster je erreichter Wert |

**Alerts werden nie automatisch geschlossen.** Ein Burst, der endet, weil der
Angreifer drin ist, sieht genauso aus wie einer, der endet, weil jemand
aufgegeben hat. Die Unterscheidung ist Menschenarbeit.

Nach dem Quittieren erzeugt dieselbe Lage wieder einen neuen Alert — der
Unique-Index greift nur für `status = 'new'`.

`cooldown_s` steuert ausschließlich die **Wieder**benachrichtigung, nicht die
Alert-Erzeugung. Ein Vorfall über eine Stunde erzeugt einen Alert und, bei 900
Sekunden Cooldown, vier Meldungen statt sechzig.

## Eingebaute Regeln

### `failed_login_burst`

X fehlgeschlagene Anmeldungen eines Kontos in Y Minuten, **quellenübergreifend
gezählt**. Drei Fehlversuche am VPN und drei gegen den Domain Controller sind
sechs Versuche auf ein Konto — jede Quelle für sich bleibt aber unter einer
sinnvollen Schwelle. Das funktioniert nur, weil die Normalizer `CORP\asmith`,
`asmith@corp.local` und `asmith` auf dasselbe Principal reduzieren.

```json
{
  "threshold": 5,
  "sources": {
    "ad":             ["4625", "4771", "4776"],
    "fortigate_auth": [],
    "fortigate_vpn":  ["ssl-login-fail", "login-fail", "auth-logon-failed"]
  },
  "ignore_users": ["krbtgt", "svc-*"]
}
```

Leere Event-Typ-Liste heißt „alle fehlgeschlagenen Events dieser Quelle".
`ignore_users` versteht Shell-Muster. Mehr als eine beteiligte Quelle hebt den
Schweregrad auf 5.

### `account_lockout`

AD-Event 4740. Der Lockout selbst ist eine Zeile und sagt fast nichts — die
Frage ist, *was* gesperrt hat und *von wo*. Der Alert bringt deshalb die
vorausgegangenen Fehlversuche aller Quellen mit, nach Herkunft gruppiert. Das
beantwortet es meist direkt: ein altes Passwort auf einem Telefon, ein
Dienstkonto mit veralteten Zugangsdaten, oder ein echter Versuch von außen.

```json
{ "event_types": ["4740"], "evidence_lookback_minutes": 60, "ignore_users": [] }
```

Der Rückblick reicht bewusst weiter zurück als das Regelfenster: Der Lockout ist
das Symptom, die Versuche liegen davor.

Findet die Regel keine vorausgegangenen Fehlversuche, sagt sie das ausdrücklich
— dann liefen die Versuche über eine Quelle, die LogWarden noch nicht erfasst.
Diese Lücke ist der eigentliche Befund.

### `vpn_then_ad_fail`

Erfolgreicher VPN-Login, kurz darauf fehlgeschlagene AD-Anmeldungen desselben
Kontos. Die Form, auf die das zielt: Jemand kommt mit Zugangsdaten ins Netz, die
am Perimeter funktionieren, und scheitert dann am Active Directory.

```json
{ "correlation_minutes": 10, "min_failures": 3, "ad_event_types": ["4625", "4771", "4776"] }
```

Ehrlicherweise auch in die andere Richtung anfällig: Ein Notebook mit einem
veralteten zwischengespeicherten Passwort tut bei jeder Einwahl exakt dasselbe.
Erst laufen lassen, dann `min_failures` an die Umgebung anpassen.

Der `dedup_key` enthält den Zeitstempel des VPN-Logins, nicht nur das Konto —
eine zweite Einwahl später am Tag ist ein eigener Vorfall.

## Eigene Regel schreiben

Eine Datei in `src/Rules/Builtin/`, eine Zeile in `rules`. Kein Core-Code.

```php
final class ImpossibleTravel implements RuleInterface
{
    public static function key(): string   { return 'impossible_travel'; }
    public static function title(): string { return 'Unmögliche Ortswechsel'; }
    public static function description(): string { return '…'; }

    public static function defaultParams(): array
    {
        return ['min_km_per_hour' => 900];
    }

    public function evaluate(RuleContext $context, array $params): array
    {
        $rows = $context->db()->fetchAll(
            'SELECT … FROM events WHERE ts >= ?::timestamptz AND ts < ?::timestamptz AND …',
            [$context->windowStart(), $context->windowEnd()],
        );

        return array_map(fn (array $row) => new AlertCandidate(
            dedupKey:   'impossible_travel:' . $row['username'],
            title:      '…',
            summary:    '…',
            eventCount: (int) $row['n'],
            entityUser: $row['username'],
            evidence:   ['…' => '…'],
            eventRefs:  [[$row['ts'], (int) $row['id']]],
        ), $rows);
    }
}
```

Dann:

```sql
INSERT INTO rules (name, rule_key, severity, window_minutes, cooldown_s, params)
VALUES ('Unmögliche Ortswechsel', 'impossible_travel', 4, 60, 900, '{}'::jsonb);
```

`bin/logwarden-rules --list` zeigt, was auf der Platte gefunden wurde,
`--dry-run` wertet aus, ohne zu schreiben, `--rule=KEY` beschränkt auf eine
Regel.

### Regeln, an die man sich halten sollte

**Immer mit `windowStart()`/`windowEnd()` eingrenzen.** Eine unbegrenzte Query
auf `events` hebelt das Partition-Pruning aus und liest jeden Tag von der
Platte.

**Der `dedup_key` identifiziert die Lage, nicht das Vorkommnis.** Zwei
Auswertungen desselben laufenden Problems müssen denselben Schlüssel liefern,
sonst wächst der Alert nicht, sondern vermehrt sich.

**`evidence` muss für sich stehen.** Nach Ablauf der Aufbewahrung sind die
Quell-Events weg; was dann noch erklärt, was passiert ist, steht in diesem
Snapshot.

**Der Regelschlüssel ist dauerhaft.** Er steht in `rules.rule_key`; ein
Umbenennen verwaist bestehende Zeilen.

## Sicherheitshinweis

Die Datenbank speichert einen Schlüssel, keinen Klassennamen. `RuleRegistry`
findet die Klassen auf der Platte und ordnet sie über ihr eigenes `key()` zu.
Ein `new $row['rule_class']` würde aus Schreibzugriff auf eine
Konfigurationstabelle beliebige Objekterzeugung machen.
