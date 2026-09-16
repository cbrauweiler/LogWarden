# WinRM-Collector: Windows-Logs ohne Agent

LogWarden holt Windows-Ereignisprotokolle per WinRM ab. Auf den Zielsystemen
wird nichts installiert — WinRM ist ab Windows Server 2012 vorhanden und auf
Serverbetriebssystemen standardmäßig aktiv.

---

## Warum Remote-Kommando und nicht WS-Management-Enumeration

WS-Management kann Ereignisprotokolle auch direkt aufzählen. Das käme mit
weniger Rechten aus, und trotzdem setzt LogWarden ein PowerShell-Kommando ab.
Der Grund steht in [docs/dns.md](dns.md): Der Analytic-Kanal des DNS-Servers
liefert 2.000–10.000 Zeilen pro Sekunde, und die einzige sinnvolle Antwort
darauf ist, **auf dem Domain Controller zu verdichten** und nur das Ergebnis
über das Netz zu schicken. Eine Enumeration kann filtern, aber nicht
aggregieren. Ein Codeweg für alle vier geplanten Quellen — AD-Sicherheit,
DNS-Audit, DNS-Server-Eventlog und die DNS-Verdichtung — ist die
Entscheidung wert.

Der Preis ist, dass das Sammelkonto Remote-Shell-Zugriff braucht. Der
Abschnitt [Rechte eng ziehen](#rechte-eng-ziehen) holt das wieder ein.

---

## Windows einrichten

### 1. WinRM mit HTTPS

```powershell
# Prüfen, was da ist
winrm enumerate winrm/config/listener
```

Ist kein HTTPS-Listener vorhanden, **nicht** einfach `winrm quickconfig -transport:https`
verwenden: das erzeugt ein selbstsigniertes Zertifikat, und ein
selbstsigniertes Zertifikat, das niemand prüft, macht jeden Rechner auf dem Weg
zum möglichen Empfänger der Anmeldedaten eines Domänenkontos.

Der saubere Weg ist ein Zertifikat der eigenen CA:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$env:COMPUTERNAME.$env:USERDNSDOMAIN" } |
        Select-Object -First 1

New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
         -CertificateThumbPrint $cert.Thumbprint -Force

New-NetFirewallRule -DisplayName 'WinRM HTTPS (LogWarden)' -Direction Inbound `
                    -Protocol TCP -LocalPort 5986 -Action Allow `
                    -RemoteAddress 10.0.0.50    # nur der LogWarden-Host
```

Die Einschränkung auf die LogWarden-Adresse ist kein Schmuck: WinRM ist ein
Fernausführungsdienst, und er soll genau einen Gesprächspartner haben.

### 2. Sammelkonto

Ein eigenes Dienstkonto, kein Administrator:

```powershell
New-ADUser -Name 'svc-logwarden' -SamAccountName 'svc-logwarden' `
           -AccountPassword (Read-Host -AsSecureString 'Passwort') `
           -Enabled $true -PasswordNeverExpires $true `
           -Description 'LogWarden Log-Abholung (nur lesend)'
```

Drei Berechtigungen, jede mit einem eigenen Grund:

```powershell
# a) Darf sich überhaupt per WinRM anmelden
Add-LocalGroupMember -Group 'Remote Management Users' -Member 'CORP\svc-logwarden'

# b) Darf Ereignisprotokolle lesen
Add-LocalGroupMember -Group 'Event Log Readers' -Member 'CORP\svc-logwarden'

# c) Darf die WinRM-Konfiguration ansprechen
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI
```

> **Der Security-Kanal ist ein Sonderfall.** „Event Log Readers" genügt auf
> vielen Systemen nicht, weil der Kanal eine eigene SDDL trägt. Falls der Test
> mit „Zugriff verweigert" auf Schritt 2 endet:
>
> ```powershell
> # Vorhandene SDDL sichern, bevor irgendetwas geändert wird
> $sddl = (Get-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security').Sddl
> $sddl | Out-File C:\security-channel-sddl.bak
>
> # Die SID von "Event Log Readers" ist überall S-1-5-32-573
> wevtutil gl Security                       # zeigt die aktuelle channelAccess
> wevtutil sl Security /ca:"<alte SDDL>(A;;0x1;;;S-1-5-32-573)"
> ```
>
> `0x1` ist Lesezugriff. Mehr wird nicht gebraucht und mehr soll das Konto auch
> nicht haben.

Anmeldung des Kontos **außer** per Netzwerk ausschließen — es soll sich an
keiner Konsole und an keinem Terminalserver anmelden können. Das geht per
Gruppenrichtlinie über „Anmelden über Remotedesktopdienste verweigern" und
„Lokal anmelden verweigern".

### 3. Überwachungsrichtlinien

Ohne aktivierte Überwachung schreibt Windows die interessanten Ereignisse gar
nicht erst. Auf dem DC per GPO (Default Domain Controllers Policy →
*Erweiterte Überwachungsrichtlinienkonfiguration*):

| Unterkategorie | Einstellung | Liefert |
|---|---|---|
| Anmeldung | Erfolg und Fehler | 4624, 4625 |
| Kontosperrung | Erfolg und Fehler | 4740 |
| Kerberos-Authentifizierungsdienst | Erfolg und Fehler | 4768, 4771 |
| Anmeldeinformationsüberprüfung | Erfolg und Fehler | 4776 |
| Benutzerkontenverwaltung | Erfolg | 4720–4781 |
| Sicherheitsgruppenverwaltung | Erfolg | 4727–4758 |
| Sonderanmeldung | Erfolg | 4672 |
| Andere Anmeldeereignisse | Erfolg und Fehler | 4648 |

**Nicht** einschalten, solange keine konkrete Frage daran hängt:
*Kerberos-Diensticketvorgänge* (4769) und *Verzeichnisdienstzugriff* (5136).
Beide sind um Größenordnungen umfangreicher als alles andere zusammen.

Die Größe des Security-Kanals muss dazu passen — Vorgabe sind 20 MB, das sind
auf einem DC wenige Stunden:

```powershell
wevtutil sl Security /ms:1073741824    # 1 GB
```

Der Kanal ist der Puffer, aus dem LogWarden liest. Ist er zu klein, überholen
neue Ereignisse die alten, bevor der Collector sie geholt hat — und *das* wäre
eine Lücke, die niemand bemerkt.

---

## Rechte eng ziehen

Remote-Shell-Zugriff auf einen Domain Controller ist mehr, als zum Log-Lesen
nötig wäre. Ein JEA-Endpunkt (Just Enough Administration) schneidet das auf
genau ein Kommando zurück:

`deploy/windows/logwarden-jea.psrc` und `logwarden-jea.pssc` liegen bei. Kurz:

```powershell
New-Item -Path 'C:\Program Files\WindowsPowerShell\Modules\LogWardenJEA\RoleCapabilities' -ItemType Directory -Force
Copy-Item logwarden-jea.psrc 'C:\Program Files\WindowsPowerShell\Modules\LogWardenJEA\RoleCapabilities\LogWarden.psrc'
Register-PSSessionConfiguration -Name 'LogWarden' -Path .\logwarden-jea.pssc -Force
```

Das Sammelkonto läuft dann unter einem virtuellen Konto, das ausschließlich
`Get-WinEvent` ausführen darf — mehr steht in der Rollenbeschreibung nicht
drin. Ein kompromittiertes LogWarden kann damit Logs lesen und sonst nichts.

> **Einschränkung, die man kennen sollte:** LogWarden spricht derzeit den
> Standard-Endpunkt `.../shell/cmd` an. Für JEA muss die Quelle auf den
> benannten Endpunkt zeigen; das ist als `endpoint`-Einstellung vorgesehen,
> aber noch nicht implementiert. Bis dahin ist JEA vorbereitet, nicht aktiv.

---

## Quelle in LogWarden anlegen

*Verwaltung → Quellen*. Eine Quelle ist **ein Host und ein Kanal** — Security
und der DNS-Audit-Kanal führen getrennte Lesezeichen und werden getrennt
ein- und ausgeschaltet.

| Feld | Bedeutung |
|---|---|
| Host | FQDN des DCs, ohne Schema und ohne Pfad |
| Konto | bei NTLM als `DOMÄNE\benutzer` |
| Kanal | `Security`, `Microsoft-Windows-DNSServer/Audit`, … |
| Abrufintervall | wie oft der Timer diese Quelle anfasst (Vorgabe 300 s) |
| Fenstergröße | wie viel Zeit **ein** Abruf umfasst (Vorgabe 900 s) |
| Max. Events je Fenster | Obergrenze, ab der das Fenster halbiert wird |
| Vorlaufzeit | wie weit der allererste Lauf zurückgeht |

Danach **Test** drücken. Der Test prüft drei Dinge getrennt, weil „geht nicht"
drei verschiedene Ursachen mit drei verschiedenen Lösungen hat:

1. Ist überhaupt ein WinRM-Listener erreichbar (Port, Firewall, TLS)?
2. Werden die Anmeldedaten angenommen (Konto, Passwort, Verfahren)?
3. Darf das Konto den Kanal lesen (Gruppen, Kanal-SDDL)?

---

## Wie der Abruf funktioniert

### Zeitfenster statt Event-Anzahl

Naheliegend wäre „gib mir die nächsten 5.000 Events nach meinem Lesezeichen".
Auf Windows ist das **falsch, und zwar unauffällig falsch**: `Get-WinEvent`
liefert die *neuesten* zuerst, `-MaxEvents 5000` wählt also die neuesten 5.000
Treffer aus. Ein Collector mit 10.000 Events Rückstand bekäme die neuesten
5.000, setzte sein Lesezeichen ans Ende davon — und holte die 5.000 dazwischen
**nie**. Die Lücke würde nirgends als Fehler auftauchen.

LogWarden fragt deshalb immer einen *Zeitraum* ab. Das Ergebnis ist entweder
nachweislich vollständig (weniger Treffer als die Obergrenze) oder das Fenster
wird halbiert und erneut versucht. Erst wenn auch das kleinste Fenster
überläuft, meldet der Lauf `partial` — mit dem Hinweis, welche Einstellung
das behebt.

### Aufholen

Ein Lauf arbeitet bis zu `max_windows_per_run` Fenster ab (Vorgabe 12) oder bis
sein Zeitbudget erschöpft ist (Vorgabe 240 s). Ohne das käme ein Collector mit
einem Wochenende Rückstand bei 15-Minuten-Fenstern und Fünf-Minuten-Timer auf
zwei Tage Aufholzeit — und meldete dabei jeden Lauf als Erfolg.

### Doppelte Events

Der Deduplizierungsschlüssel ist `Host + Kanal + EventRecordID`. Die
EventRecordID vergibt der Kanal und verwendet sie nicht wieder, solange das
Protokoll existiert. Überlappende Fenster sind damit gratis: derselbe Datensatz
erzeugt denselben Schlüssel, der Insert läuft ins Leere. Deshalb **darf** der
Collector überlappen, statt Uhren vertrauen zu müssen.

Ein `wevtutil cl Security` setzt die Zähler zurück. Das ist Ereignis 1102 und
wird gesammelt — genau dafür steht es in der Vorgabeauswahl.

---

## DNS-Kanäle

Derselbe Collector, andere Kanäle — und ein eigener Normalizer, weil fast
nichts übertragbar ist: DNS-Audit-Events haben keine Anmeldeart, keinen
NTSTATUS und keine SID eines Zielkontos. Sie haben eine Zone, einen Knoten,
einen Record-Typ und einen Wert. Durch den AD-Normalizer gejagt ergaben sie
„Ereignis 542" ohne Benutzer — technisch gespeichert, praktisch wertlos.

| Kanal | Quelltyp | Inhalt |
|---|---|---|
| `Microsoft-Windows-DNSServer/Audit` | `dns` | Zonen- und Record-Änderungen |
| `DNS Server` | `dns` | Dienstzustand, Ladefehler, verweigerte Transfers |

Zwei Unterschiede zum Sicherheitsprotokoll, beide bewusst:

* **Keine Auswahl heißt alles sammeln.** Der Audit-Kanal schreibt an ruhigen
  Tagen nichts; die Vorgabe „lieber zu viel" ist hier richtig.
* **Unbekannte IDs werden gespeichert, nicht verworfen.** Das Gegenteil des
  Cisco-Plugins — dort bedeutet ein unbekannter Meldungstyp eine Flut, hier
  eine seltene Änderung.

> Die Nummern in `DnsEventCatalog.php` stammen aus Microsofts Dokumentation und
> sind **gegen keinen echten DNS-Server geprüft**. Was ein konkreter Server
> schreibt, zeigt:
>
> ```bash
> bin/logwarden-winrm --discover='DC01 DNS-Audit'
> ```
>
> Es zählt pro ID, zeigt je ein Beispiel und die vorhandenen Feldnamen und
> markiert, was der Katalog nicht kennt.

## Was gesammelt wird

Die Auswahl ist eine Volumenentscheidung, keine Übersetzungstabelle. Auf einem
DC dominieren wenige IDs den Kanal, die kaum eine Frage beantworten, während
die wertvollsten Ereignisse ein paar Mal pro Woche vorkommen. „Alles" kostet
das Hundertfache an Speicher für ein *schlechteres* Signal, weil die
brauchbaren Zeilen untergehen.

Standardmäßig **an**: An- und Abmeldefehler (4625, 4771, 4776), erfolgreiche
Anmeldungen (4624), Sonderrechte (4672), die gesamte Konto- und
Gruppenverwaltung (4720–4781), Richtlinienänderungen und das Löschen des
Protokolls (1102).

Standardmäßig **aus**, mit Begründung in der Oberfläche: 4769
(Diensttickets, auf einem DC leicht 80 % des Kanals), 4634/4647 (Abmeldungen),
4800/4801 (Bildschirmsperre), 5136/5137/5141 (Verzeichniszugriff).

Ebenfalls standardmäßig verworfen: **Maschinenkonten** (`RECHNER$`) und
**Systemkonten** (`SYSTEM`, `ANONYMOUS LOGON`). Sie stellen die Mehrheit des
Kanals, und mit ihnen wäre jede „Top-Konten"-Ansicht eine Liste von Computern.

### Die Klartextzeile

LogWarden schreibt `raw_message` selbst:

```
[4625] Anmeldung fehlgeschlagen pweber von 10.20.30.77 (Netzwerk) — Falsches Passwort
[4740] Konto gesperrt pweber — ausgelöst von WS-PWEBER
[4728] Mitglied zu globaler Gruppe hinzugefügt Peter Weber in "Domänen-Admins" durch Administrator
```

Windows' eigener Meldungstext zu 4624 ist rund 1,5 KB, davon etwa 1,2 KB immer
gleicher Erklärtext über Anmeldearten. Gespeichert stünde dieser Aufsatz
hunderttausendfach im Volltextindex, und jede Suche nach einem häufigen Wort
träfe jede Anmeldung, die je stattgefunden hat. Die selbst gebaute Zeile trägt
dieselben Fakten, ist deutsch unabhängig von der Sprache des DCs, und passt in
eine Zeile. Wer den Originaltext braucht, schaltet ihn je Quelle ein; er landet
dann in `details.win_message`.

### Drei Fallstricke in den Feldern

* **4625 trägt den Grund in `SubStatus`, nicht in `Status`.** `Status` ist bei
  fast jedem 4625 `0xC000006D` („Anmeldung fehlgeschlagen"). Wer nur das liest,
  sieht jeden Fehlschlag gleich — dabei ist der Unterschied zwischen „falsches
  Passwort" und „Konto existiert nicht" genau das, was einen Kollegen nach dem
  Urlaub von jemandem unterscheidet, der Kontonamen durchprobiert.
* **4740 missbraucht `TargetDomainName` für den auslösenden Rechner.** Dort
  steht `WS-PWEBER`, nicht `CORP`. LogWarden legt das als
  `details.lockout_source` ab — es ist die nützlichste Einzelinformation des
  Ereignisses, weil dort das veraltete Passwort liegt.
* **Gruppenereignisse führen die Gruppe in `TargetUserName`.** Das betroffene
  Konto steht in `MemberName`, als DN. LogWarden ordnet das Ereignis dem
  *Mitglied* zu, nicht der Gruppe. Weil ein DN einen Anzeigenamen enthält
  („Peter Weber") und keinen Anmeldenamen, verbindet sich das nicht automatisch
  mit 4624 derselben Person; `details.member_sid` ist die Kennung, die es tut.

---

## Betrieb

```bash
bin/logwarden-winrm --list                    # Zustand aller Quellen
bin/logwarden-winrm --test='DC01 Sicherheit'  # Erreichbarkeit und Kanalzugriff
bin/logwarden-winrm --dry-run                 # abrufen, nichts schreiben
bin/logwarden-winrm --source='DC01 Sicherheit' --force
bin/logwarden-winrm --reset='DC01 Sicherheit' # Lesezeichen zurücksetzen
bin/logwarden-winrm --discover='DC01 DNS-Audit'  # welche IDs enthält der Kanal?
```

```
systemctl status logwarden-winrm.timer
journalctl -u logwarden-winrm -f
```

Die Lauf-Historie steht in `ingest_runs` und in der Oberfläche unter
„Letzte Läufe". Sie existiert, weil „es sammelt nicht mehr" eine Frage nach den
letzten Versuchen ist, und die einzelne Spalte `last_error` sich immer nur an
einen davon erinnert.

| Status | Bedeutung |
|---|---|
| `ok` | Fenster vollständig abgeholt |
| `empty` | Fenster vollständig, enthielt nichts |
| `partial` | Fenster lief über, ein Teil fehlt — Meldung nennt die Abhilfe |
| `error` | Abruf fehlgeschlagen; **das Lesezeichen bleibt stehen** |

Dass ein fehlgeschlagener Lauf das Lesezeichen nicht bewegt, ist der Grund,
warum eine Störung Verzögerung kostet und keine Daten.

---

## Häufige Fehlerbilder

| Meldung | Ursache und Abhilfe |
|---|---|
| `HTTP 401` | Konto, Passwort oder Verfahren. Bei NTLM muss der Name `DOMÄNE\benutzer` oder `benutzer@domäne` lauten. |
| `nicht erreichbar` | Kein Listener oder Firewall. `winrm enumerate winrm/config/listener` auf dem Host. |
| `TLS-Zertifikat nicht überprüfbar` | Selbstsigniertes Zertifikat aus `winrm quickconfig`. CA-Zertifikat in `winrm.ca_file` hinterlegen — oder besser ein Zertifikat der eigenen CA ausstellen. |
| `Zugriff verweigert` (Schritt 2) | Konto fehlt in „Remote Management Users". |
| `Zugriff verweigert` (Kanal) | Security-Kanal-SDDL, siehe oben. |
| `QuotaLimit` | `MaxConcurrentOperationsPerUser` bzw. `MaxShellsPerUser` erschöpft. Abrufintervall erhöhen oder Grenze anheben. |
| `partial` | Das kleinste Fenster enthält mehr als `max_events`. Entweder die Obergrenze anheben oder die Event-ID-Auswahl enger fassen. |

---

## Was hier nicht getestet werden konnte

Der Protokollpfad ist gegen ein Mock-Endpunkt (`tests/support/winrm-mock.php`)
geprüft, das die MS-WSMV-Shell-Konversation wirklich spricht: Envelope-Aufbau,
NTLM-Dreiwegehandshake, Verbindungswiederverwendung, Wiederaufnahme nach
Operation-Timeout, das Zusammensetzen mehrteiliger Base64-Ströme über
Multibyte-Grenzen hinweg, Fault-Behandlung und das Aufräumen der Shell.

**Nicht** geprüft ist das Zusammenspiel mit einem echten Domain Controller:
NTLM gegen eine echte Domäne, Kerberos, die Kanal-SDDL, die genauen
Fehlertexte lokalisierter Windows-Versionen. Dafür fehlt in dieser Umgebung
ein Windows-System. Der erste Test gegen einen echten DC gehört deshalb in die
Einführung eingeplant, nicht übersprungen — `--test` und `--dry-run` sind
genau dafür da.
