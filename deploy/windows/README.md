# Windows-Seite

| Datei | Zweck |
|---|---|
| `logwarden-jea.psrc` | JEA-Rollenbeschreibung: erlaubt nur `Get-WinEvent` |
| `logwarden-jea.pssc` | JEA-Sitzungskonfiguration, läuft unter virtuellem Konto |

Die vollständige Einrichtung — HTTPS-Listener, Sammelkonto, Kanalrechte,
Überwachungsrichtlinien und die Größe des Security-Kanals — steht in
[docs/winrm.md](../../docs/winrm.md).

**`CORP\svc-logwarden` in `logwarden-jea.pssc` vor dem Registrieren durch den
eigenen Domänennamen ersetzen.**

> JEA ist vorbereitet, aber noch nicht nutzbar: LogWarden spricht derzeit den
> Standard-Endpunkt an und kann noch nicht auf einen benannten
> Sitzungsendpunkt zeigen. Die Dateien liegen bei, damit die Rechte-Frage
> beim Rollout schon beantwortet ist.
