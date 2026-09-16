# DNS-Logs: was sich lohnt und was nicht

Windows-DNS liefert drei Log-Quellen, die im Alltag völlig unterschiedlich viel
wert sind. Sie werden gern in einen Topf geworfen — genau das macht DNS zum
teuersten und nutzlosesten Teil vieler SIEM-Installationen.

| Quelle | Kanal | Volumen | Relevanz |
|---|---|---|---|
| **Audit** | `Microsoft-Windows-DNSServer/Audit` | winzig (Dutzende/Tag) | **hoch** |
| **Server-Eventlog** | `DNS Server` | winzig | mittel |
| **Analytic** | `Microsoft-Windows-DNSServer/Analytical` | gewaltig (2.000–10.000/s) | gering pro Zeile |

## 1. Audit-Kanal — die Antwort auf „gibt es relevante DNS-Logs?"

Ja, und zwar diesen. Der Audit-Kanal protokolliert **Änderungen**, nicht
Abfragen: wer hat eine Zone angelegt, einen Record gelöscht, die
Zonentransfer-Einstellungen geändert, dynamische Updates umkonfiguriert.

Drei Eigenschaften machen ihn zum klaren ersten Schritt:

* **Seit Server 2012 R2 standardmäßig aktiv.** Nichts einzuschalten, keine
  Performance-Diskussion, die Daten liegen schon da.
* **Winzig.** Ein DNS-Server, an dem nicht gerade gearbeitet wird, schreibt an
  manchen Tagen nichts.
* **Jede Zeile ist ein Vorgang, den jemand ausgelöst hat.** Kein Rauschen.

Was man damit tatsächlich beantwortet:

* Wer hat den A-Record des Fileservers geändert — und wann genau begannen die
  Störungsmeldungen?
* Wurde eine Zone gelöscht oder angehalten?
* Hat jemand Zonentransfers für einen neuen Host freigeschaltet?
* Wurde „unsichere dynamische Updates" eingeschaltet?
* Sind Records verschwunden, die per Scavenging nicht hätten wegfallen dürfen?

Das sind Änderungsnachweise. Sie erklären Ausfälle im Nachhinein und decken
Manipulationen auf — und beides braucht man im Betrieb regelmäßig.

Ereigniskategorien im Kanal:

| Kategorie | Bedeutung |
|---|---|
| Zone angelegt / gelöscht / angehalten / fortgesetzt | strukturelle Änderungen |
| Record angelegt / gelöscht (statisch und dynamisch) | die häufigsten Vorgänge |
| RRSet bzw. Knoten gelöscht | größere Löschungen |
| Zonentransfer-Einstellungen geändert | sicherheitsrelevant |
| Dynamic-Update-Einstellungen geändert | sicherheitsrelevant |
| Scavenging-Einstellungen geändert | erklärt verschwundene Records |
| Forwarder / Root-Hints geändert | Umleitung der Auflösung |

> **Die exakten Event-IDs ziehen wir beim ersten Pull aus dem Kanal**, statt sie
> hier zu raten — sie unterscheiden sich zwischen Server-Versionen. Auf einem
> DC listet das folgende Kommando, was tatsächlich vorkommt:
>
> ```powershell
> Get-WinEvent -LogName 'Microsoft-Windows-DNSServer/Audit' -MaxEvents 5000 |
>   Group-Object Id |
>   Select-Object Count, Name, @{n='Beispiel';e={$_.Group[0].Message.Split("`n")[0]}} |
>   Sort-Object Count -Descending
> ```
>
> Die Liste kommt anschließend in `ingest_sources.config` — sie ist Konfiguration,
> kein Code.

## 2. Server-Eventlog

Dienst gestartet/gestoppt, Zone konnte nicht geladen werden, AD-Integration
gestört, Forwarder nicht erreichbar. Ebenfalls winzig, gehört mitgenommen.
Beantwortet „warum löst seit heute früh nichts mehr auf".

## 3. Analytic-Kanal — der Teil, der wehtut

Eine Zeile pro DNS-Abfrage. Auf einem produktiven DC sind das leicht 2.000 bis
10.000 Events pro Sekunde und damit **mehr als AD, DHCP und FortiGate zusammen
um etwa Faktor 100**.

Drei praktische Hürden dazu:

* **WEF kann Analytic-Kanäle nicht weiterleiten.** Es geht nur ETW bzw.
  `Get-WinEvent` auf der `.etl`-Datei.
* **Der Kanal ist standardmäßig aus** und muss bewusst eingeschaltet werden.
* **Das Lesen kostet auf dem DC selbst Leistung** — nicht dramatisch, aber es
  ist nicht gratis.

### Was einzelne Abfragen trotzdem wert sein können

Nicht die Abfragen selbst, sondern Muster darin:

| Muster | Worauf es hindeutet |
|---|---|
| NXDOMAIN-Häufung bei einem Client | DGA-Malware sucht ihren C2-Server |
| Ungewöhnlich lange Labels, hohe Zeichen-Entropie | DNS-Tunneling (Datenabfluss) |
| Auffälliges Volumen an TXT- oder NULL-Records | DNS-Tunneling |
| Clients, die externe Resolver direkt befragen | Umgehung der Richtlinie |
| AXFR/IXFR von unerwarteten Adressen | Aufklärung |

**Keines dieser Muster erkennt man an einer einzelnen Zeile.** Alle sind
Aggregate über einen Client und ein Zeitfenster. Das ist der entscheidende
Punkt: Wenn die Erkenntnis ohnehin nur aus der Verdichtung entsteht, gibt es
keinen Grund, die Rohdaten überhaupt zu speichern.

## Empfehlung

### Verdichten, wo die Daten entstehen

Nicht 10.000 Events pro Sekunde über das Netz schieben, um 99,9 % davon
wegzuwerfen. Die Aggregation gehört in die PowerShell-Abfrage, die der
WinRM-Collector ohnehin absetzt — über das Netz geht nur das Ergebnis.

Der `dns_analytic`-Collector setzt also sinngemäß ab:

```powershell
# läuft AUF dem DC, liefert nur die Verdichtung zurück
Get-WinEvent -LogName 'Microsoft-Windows-DNSServer/Analytical' -Oldest |
  Where-Object TimeCreated -ge $since |
  ForEach-Object { <# Client, QNAME, QTYPE, RCODE herausziehen #> } |
  Group-Object Client, Bucket |
  Where-Object {
      $_.NXDomainAnteil -gt 0.4 -or        # DGA-Verdacht
      $_.MaxLabelLaenge -gt 50   -or       # Tunneling-Verdacht
      $_.TxtAnteil      -gt 0.2
  }
```

Aus 800 Millionen Zeilen pro Tag werden so einige Dutzend. Diese wenigen Zeilen
passen problemlos ins bestehende Event-Schema: `source_type = 'dns'`,
`event_type = 'dns-anomaly'`, die Kennzahlen in `details`.

### Zwei Stufen

| Stufe | Inhalt | Volumen/Tag | Vorgabe |
|---|---|---|---|
| **1** | Audit + Server-Eventlog | Dutzende | **an** |
| **2** | Analytic, nur Anomalie-Verdichtungen | Dutzende bis Hunderte | optional |

Die vollständige Abfrage-Historie ist **keine** vorgesehene Stufe. Wer sie
wirklich braucht — etwa aus Compliance-Gründen — nimmt dafür ein System, das
für dieses Volumen gebaut ist, und lässt LogWarden die Verdichtung machen.

### Der billigere Weg über die FortiGate

Falls der DNS-Verkehr ohnehin über die FortiGate läuft, liefert deren
DNS-Filter-Profil die interessanten Fälle bereits als UTM-Events per Syslog:
geblockte Domains, Botnet-C2-Kategorien, Kategorie-Verstöße. Kein DC-Eingriff,
kein Analytic-Kanal, keine Verdichtung nötig — und die Ingestion-Strecke dafür
steht schon.

Der Unterschied: Die FortiGate sieht die IP des Clients, der DNS-Server sieht
sie auch. Was beiden fehlt, ist der **Prozess**, der gefragt hat. Den liefert
nur Sysmon Event 22 auf dem Endgerät — und das wäre ein Agent, den du
ausgeschlossen hast. Die Lücke ist damit bewusst in Kauf genommen, nicht
übersehen.

## Vorgeschlagene Reihenfolge

1. **Audit-Kanal** über den WinRM-Collector (identischer Codeweg wie AD) —
   sofort nützlich, praktisch gratis.
2. **Server-Eventlog** mitnehmen — dieselbe Abfrage, anderer Kanal.
3. **FortiGate-DNS-Filter** einschalten, falls vorhanden — kommt über die
   bestehende Syslog-Strecke herein.
4. **Analytic-Verdichtung** nur, wenn nach Schritt 1–3 noch eine konkrete Frage
   offen ist. Dann gemeinsam festlegen, welche.

Punkt 4 ist bewusst das Ende und nicht der Anfang. Der übliche Fehler ist,
mit dem Firehose anzufangen, an den Kosten zu scheitern und DNS anschließend
ganz sein zu lassen — inklusive des Audit-Kanals, der die Arbeit gemacht hätte.
