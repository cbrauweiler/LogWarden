# Benachrichtigungen

## Ablauf

`bin/logwarden-notify` läuft minütlich per Timer, getrennt von der
Rule-Engine. Eine Teams-Störung darf die Erkennung weder verlangsamen noch
zum Scheitern bringen, und ein Zustellversuch darf keine Regeln neu auswerten.

```
offener Alert  ──► passende Kanäle ──► Zustellprüfung ──► Adaptive Card ──► Teams
                    (Zuordnung +         (Cooldown /
                     Mindest-Schweregrad)  Backoff)
```

## Zustellprüfung

Die Entscheidung fällt je **Paar aus Alert und Kanal**, nicht je Alert. Ein
unerreichbarer Kanal darf die anderen nicht blockieren, und ein Wiederholversuch
an den kaputten darf nicht erneut an die funktionierenden senden.

| Letzter Eintrag im Zustellprotokoll | Entscheidung |
|---|---|
| keiner | senden |
| erfolgreich | erst nach `rules.cooldown_s` erneut |
| fehlgeschlagen, wiederholbar | nach Backoff: 60 s, 120 s, 300 s, 900 s, 1800 s |
| fehlgeschlagen, 5 Versuche erreicht | aufgeben |
| fehlgeschlagen, nicht wiederholbar | sofort aufgeben |

**Wiederholbar** sind Netzwerkfehler und die Status 5xx, 408 und 429. Ein
4xx bedeutet, dass Teams genau diese Anfrage abgelehnt hat — fünf Versuche
darauf zu verbrennen verzögert nur die Alerts dahinter. Solche Fehlschläge
werden direkt mit der höchsten Versuchsnummer protokolliert, damit die
Backoff-Logik sie nicht weiterzählt.

## Karten-Format

Adaptive Card Version 1.4 in der Message-Hülle, die beide Teams-Endpunkt-
Generationen akzeptieren:

```json
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "contentUrl": null,
    "content": { "type": "AdaptiveCard", "version": "1.4", "body": [ … ] }
  }]
}
```

Die Karte enthält Titel und Zusammenfassung, ein FactSet mit Regel, Konto,
Quell-IP, System, Event-Anzahl, Höchststand und Quellenverteilung, die
Herkunftsliste (die ersten vier Adressen) und — sofern `web.base_url` gesetzt
ist — einen Knopf, der den Alert in LogWarden öffnet.

### Was Teams von der Corporate Identity übernimmt

Nur den Produktnamen. Adaptive Cards folgen dem Teams-Design des Empfängers;
eigene Farbwerte lassen sich nicht setzen. Der Schweregrad nutzt deshalb die
semantischen Schlüsselwörter der Karte (`attention`, `warning`, `accent`), die
im Hell- wie im Dunkelmodus lesbar bleiben — was ohnehin die bessere Wahl ist.
Farbe steht nie allein: Das Wort („Kritisch", „Hoch", …) steht daneben.

Ein Logo ließe sich nur über eine URL einbinden, die Microsofts Server
erreichen können. Bei einer internen Installation ist das nicht gegeben, deshalb
trägt die Karte keines.

## Einrichtung

### In Teams

1. Zielkanal öffnen → **…** → **Workflows**
2. Vorlage *„Post to a channel when a webhook request is received"*
3. Erzeugte HTTP-POST-URL kopieren

Die klassischen Office-365-Connectors (`*.webhook.office.com`) funktionieren
weiterhin und werden unterstützt, sind von Microsoft aber abgekündigt.

### In LogWarden

Unter **Verwaltung → Benachrichtigungen**: Kanal anlegen, Webhook-URL
hinterlegen, **Test** drücken, dann in der Zuordnungstabelle ankreuzen, welche
Regel an welchen Kanal meldet.

Alternativ über die Kommandozeile, was die URL aus der Shell-Historie und aus
`ps` heraushält:

```bash
echo 'https://prod-01.westeurope.logic.azure.com/workflows/…' \
  | bin/logwarden-notify --set-webhook='SOC-Teams'

bin/logwarden-notify --test=1
bin/logwarden-notify --list-channels
bin/logwarden-notify --dry-run
```

### Zwei Filter, die zusammenwirken

Ein Alert erreicht einen Kanal nur, wenn **beides** zutrifft:

* Die Regel ist dem Kanal zugeordnet (`rule_channels`)
* Der Schweregrad des Alerts erreicht `notification_channels.min_severity`

Damit lässt sich ein Kanal für alles einrichten und ein zweiter nur für
Kritisches — dieselben Regeln, unterschiedliche Empfänger.

Alerts ohne passenden Kanal werden als `unrouted` gezählt und protokolliert.
„Es kommen keine Teams-Nachrichten an" liegt fast immer daran und wäre sonst
unsichtbar.

## Sicherheit

**Die Webhook-URL ist das Zugangsgeheimnis.** Wer sie hat, kann in den Kanal
schreiben. Sie wird deshalb mit libsodium verschlüsselt in `secrets` abgelegt,
nie im Klartext protokolliert und in der Oberfläche nie wieder angezeigt — nur
der Referenzname. Beim Löschen eines Kanals wird sie mitgelöscht.

**SSRF-Schutz.** Die URL ist administrativ gesetzt und dieser Prozess erreicht
das gesamte interne Netz. Ohne Prüfung wäre LogWarden ein Anfrage-Proxy
hinein. Deshalb:

* nur `https`
* der Hostname wird aufgelöst, und private oder reservierte Zieladressen werden
  abgelehnt — auch wenn ein interner Name darauf zeigt
* keine Weiterleitungen, damit die Nutzlast nicht woanders landet
* TLS-Zertifikatsprüfung ist aktiv und nicht abschaltbar

Für einen internen Relay lässt sich `notify.allow_private_targets` setzen. Das
ist bewusst eine Konfigurationsentscheidung und keine Voreinstellung.

**Ausgehender Proxy:** `notify.proxy`.

## Betrieb

```bash
systemctl status logwarden-notify.timer
journalctl -u logwarden-notify -f
```

Kanalstatus steht in `notification_channels` (`sent_total`, `failed_total`,
`last_success_at`, `last_error`) und wird in der Oberfläche angezeigt, damit
ein stillschweigend kaputt gegangener Webhook auffällt, bevor ein Vorfall davon
abhängt.

Das vollständige Zustellprotokoll liegt in `notification_log`, je Versuch eine
Zeile mit Status, Dauer und Nutzlastgröße.
