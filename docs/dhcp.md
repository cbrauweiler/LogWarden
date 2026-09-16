# DHCP-Audit-Log

Der Windows-DHCP-Server schreibt kein Ereignisprotokoll, sondern CSV-Dateien
ins Dateisystem: eine je Wochentag, wöchentlich überschrieben. LogWarden holt
sie über dieselbe WinRM-Strecke wie die Ereigniskanäle ab — kein Agent, keine
Freigabe.

## Wofür das gut ist

Einzeln beantwortet „Lease erneuert" nichts. Was den Kanal wertvoll macht, ist
**Zuordnung**: Drei Wochen später sagt ein FortiGate-Log, dass 10.20.30.44
etwas getan hat, und das Einzige, was dann noch sagen kann, *welche Maschine
das war*, ist die Lease.

```
[10] Adresse vergeben 10.20.30.44 an WS-ASMITH.corp.local (A0-B1-C2-D3-E4-F5)
```

Die Adresse landet in `src_ip` — dort, wo eine Suche nach einer Adresse
hinschaut —, Hostname und MAC in `details`. Der Herstellerpräfix der MAC steht
separat in `details.mac_oui`, weil „alle Leases dieses Herstellers" eine Frage
ist, die man bei der Suche nach einem Fremdgerät stellt.

Der zweite, kleinere Teil ist sicherheitsrelevant im engeren Sinn: die
Ereignisse 50–64 zeigen, ob ein **nicht autorisierter DHCP-Server** im Netz
Adressen verteilt.

## Einrichten

Auf dem DHCP-Server muss die Protokollierung aktiv sein — sie ist es
standardmäßig:

```powershell
Get-DhcpServerAuditLog          # Enable, Path, MaxMBFileSize
Set-DhcpServerAuditLog -Enable $true
```

Das Sammelkonto braucht neben dem WinRM-Zugang Lesezugriff auf das
Protokollverzeichnis (Vorgabe `C:\Windows\System32\dhcp`):

```powershell
$acl = Get-Acl 'C:\Windows\System32\dhcp'
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'CORP\svc-logwarden', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl 'C:\Windows\System32\dhcp' $acl
```

Danach in *Verwaltung → Quellen* als Quellenart **DHCP-Audit-Log** anlegen.
Angegeben wird das **Verzeichnis**, nicht eine Datei.

## Drei Eigenheiten der Datei

Alle drei werden auf der Windows-Seite behandelt, weil dort die Antworten
liegen.

**Die Dateinamen sind lokalisiert.** Der Server legt eine Datei je Wochentag an
und benennt sie mit dem kurzen Tagesnamen *seiner eigenen Sprache*:
`DhcpSrvLog-Mon.log` auf Englisch, `DhcpSrvLog-Mo.log` auf Deutsch. Den Namen
zu berechnen funktioniert im Labor und scheitert in halb Europa — deshalb wird
das Verzeichnis durchgesehen und nach Änderungszeit ausgewählt.

**Die Datumsangaben sind es auch, und mehrdeutig.** `05/06/26` ist je nach
Installation der 5. Juni oder der 6. Mai. Der Server kennt seine eigene Kultur
und löst jede Zeile deshalb dort zu einem ISO-Zeitstempel auf. Nur beim
Import einer von Hand kopierten Datei wird geraten — und der mehrdeutige Fall
dann **verworfen** statt auf den falschen Tag gelegt: ein falsches Datum in
einem Sicherheitsprotokoll ist schlimmer als eine fehlende Zeile, weil nichts
daran falsch aussieht.

**Die Datei ist ANSI, nicht UTF-8.** Ein Hostname mit Umlaut käme sonst als
anderes Byte an, als PostgreSQL gleich darauf als UTF-8 zugesichert bekommt.

Dazu eine vierte, die auf der PHP-Seite sitzt: **die Spaltenzahl hat sich
zwischen Windows-Versionen geändert** — Server 2008 schrieb elf Spalten, 2016
und später neunzehn. Deshalb schickt das Skript die Kopfzeile der Datei mit,
und die Spaltennamen kommen von dort statt aus einer festen Liste.

## Was gesammelt wird

Die Event-IDs sind hier **nicht geraten**: Der DHCP-Server schreibt seine
eigene Liste in den Kopf jeder Datei, die er anlegt. Was ein konkreter Server
dokumentiert, zeigt:

```bash
bin/logwarden-winrm --header='DHCP01 Audit'
```

Standardmäßig an: Leases (10, 11, 12), Konflikte und Verweigerungen (13, 15),
erschöpfter Adresspool (14), fehlgeschlagene DNS-Aktualisierungen (31, 34, 35)
und die gesamte Autorisierungsgruppe (50–64).

**10 und 11 sind der Großteil des Volumens** — eine Zeile je Client je Lease
und Erneuerung — und trotzdem vorausgewählt, weil sie die Zuordnung sind,
also der Grund, DHCP überhaupt zu sammeln. Sie sind das Erste, was man
abschaltet, wenn das Volumen drückt.

Eine unbekannte ID wird gespeichert, nicht verworfen, und behält die
Beschreibung, die der Server selbst in die Zeile geschrieben hat.

## Betrieb

```bash
bin/logwarden-winrm --list
bin/logwarden-winrm --test='DHCP01 Audit'     # Erreichbarkeit und Konto
bin/logwarden-winrm --header='DHCP01 Audit'   # Event-IDs laut Server
bin/logwarden-winrm --dry-run
```

Der Abruf nutzt dasselbe Zeitfenster und dasselbe Lesezeichen wie die
Ereigniskanäle. Ein Deduplizierungsschlüssel aus Host, Sekunde und Zeileninhalt
macht überlappende Fenster kostenlos — die Datei hat keine Datensatz-ID.

Zwei byteweise identische Zeilen innerhalb derselben Sekunde fallen dabei zu
einem Event zusammen. Das ist der Preis dafür, ein Fenster gefahrlos zweimal
lesen zu können, und in dieser Richtung der bessere Handel.

## Was hier nicht geprüft werden konnte

Der gesamte Weg ist gegen das Mock in `tests/support/winrm-mock.php` geprüft,
das die Logdatei ausliefert und die Zeitfenster-Filterung nachstellt.

**Nicht** geprüft ist der Kontakt mit einem echten Windows-DHCP-Server: die
Lokalisierung der Dateinamen, die ANSI-Codepage und das Datumsformat sind
genau die Stellen, an denen sich eine deutsche Installation anders verhält —
und genau die, die hier nur aus der Dokumentation stammen. Der erste Lauf mit
`--header` und `--dry-run` gehört deshalb in die Einführung eingeplant.
