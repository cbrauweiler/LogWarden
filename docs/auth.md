# Anmeldung und Berechtigungen

## Zwei Verfahren nebeneinander

| Verfahren | Wofür |
|---|---|
| **Active Directory** | Der Normalfall. Anmeldung mit dem Windows-Konto, Berechtigungsstufe aus der Gruppenmitgliedschaft. |
| **Lokales Konto** | Der Weg zurück, wenn der Domain Controller ausgefallen ist — also für genau die Störung, die man mit diesem System untersuchen würde. |

Beide sind immer aktiv. Die Provider werden der Reihe nach gefragt; der erste,
der die Zugangsdaten bestätigt, gewinnt.

> **Voraussetzung:** `php8.4-ldap`. Ohne die Extension funktionieren nur lokale
> Konten — die Anmeldeseite sagt das dann auch.

## Erste Inbetriebnahme

Eine frische Installation hat keine Konten und damit keine Möglichkeit, sich
anzumelden, um welche anzulegen. Das erste Konto kommt deshalb von der
Kommandozeile:

```bash
bin/logwarden-user --create=admin --role=admin --display="IT-Security"
bin/logwarden-user --list
```

Das Passwort wird abgefragt, nicht als Argument übergeben: Argumente landen in
der Shell-Historie und in `ps`.

Danach die Gruppen zuordnen — entweder in der Oberfläche unter
**Verwaltung → Benutzer** oder per CLI:

```bash
bin/logwarden-user --map-group=SOC-Admins    --role=admin
bin/logwarden-user --map-group=SOC-Analysten --role=analyst
bin/logwarden-user --map-user=pruefer        --role=readonly
```

## Berechtigungsstufen

Drei Stufen, jede ein Superset der darunterliegenden.

| | Dashboard, Suche, Export | Alerts quittieren | Regeln bearbeiten | Quellen, Benachrichtigungen, CI, Benutzer |
|---|---|---|---|---|
| **Nur lesend** | ✅ | ❌ | ❌ | ❌ |
| **Analyst** | ✅ | ✅ | nur einsehen und testen | ❌ |
| **Administrator** | ✅ | ✅ | ✅ | ✅ |

Die Stufen sind fest. Einzelne Rechte lassen sich nicht zusammenklicken — ein
Rechtemodell, das jede Kombination erlaubt, ist eines, bei dem nach zwei Jahren
niemand mehr sagen kann, wer was darf.

Das eigene Profil zeigt die Stufe, die Herleitung und Punkt für Punkt, was sie
abdeckt und was nicht.

## Zuordnung

Ein Eintrag adressiert entweder eine **AD-Gruppe** oder ein **einzelnes Konto**.
Beides wird gebraucht: Gruppen für das Team, ein Einzelkonto für den einen
externen Prüfer, der keine neue AD-Gruppe rechtfertigt — und auf eine zu warten
ist der Grund, warum Leute anfangen, Logins zu teilen.

**Gruppen werden über den kurzen Namen oder den vollständigen DN erkannt.**
`SOC-Admins` und `CN=SOC-Admins,OU=Groups,DC=corp,DC=local` treffen beide.
Administratoren denken in Gruppennamen, und einen DN von Hand abzutippen ist
der zuverlässigste Weg, eine Zuordnung stillschweigend ins Leere laufen zu
lassen.

**Bei mehreren Treffern gewinnt die höhere Priorität, bei gleicher Priorität
die stärkere Stufe.** Wer in `SOC-Analysten` und `SOC-Admins` ist, ist
Administrator. Eine bewusst höher gesetzte Priorität kehrt das um — so lässt
sich eine Gruppe gezielt herabstufen, ohne die anderen Einträge anzufassen.

**Ohne passende Zuordnung wird die Anmeldung abgelehnt**, auch bei korrektem
Passwort. Ein neues AD-Konto soll nicht dadurch Zugang bekommen, dass es
existiert. Die Meldung sagt das ausdrücklich, statt eine leere Oberfläche zu
zeigen, die niemand erklären kann.

**Eine manuell gesetzte Stufe überschreibt die Zuordnung dauerhaft**
(`role_source = 'manual'`). So lässt sich eine Einzelfallentscheidung treffen,
ohne das Active Directory anzufassen — die nächste Anmeldung setzt sie nicht
zurück.

## Sitzungen

Sitzungen liegen in der Datenbank, nicht in PHPs eigener Sitzungsverwaltung.
Der Grund ist praktisch: Ein Administrator muss die Sitzung eines Benutzers
beenden können, und mit PHP-Sessions hieße das, eine Datei auf demjenigen
Knoten zu suchen, der ihn zufällig bedient hat. Hier ist es ein `DELETE`.

* Das Cookie trägt ein Zufallstoken; gespeichert wird nur dessen SHA-256. Ein
  Datenbank-Abzug gibt damit keine gültigen Sitzungen preis.
* Zwei Laufzeiten: die **Leerlaufzeit** (Vorgabe 1 Stunde) verlängert sich bei
  jedem Zugriff, die **absolute** (Vorgabe 8 Stunden) nie. Eine gestohlene
  Sitzung lässt sich dadurch nicht beliebig am Leben halten.
* Der CSRF-Token hängt an derselben Zeile — eine beendete Sitzung nimmt ihn mit.
* Ein deaktiviertes Konto verliert seine Sitzungen sofort, nicht beim nächsten
  Ablauf.
* Das eigene Profil listet alle aktiven Sitzungen mit Adresse, Browser und
  Zeitpunkt und lässt jede einzeln beenden.

## Passwörter

Nur für lokale Konten. Bei Verzeichniskonten liegt das Passwort im Active
Directory und wird auch dort geändert — eine Änderung hier würde eine zweite,
abweichende Wahrheit erzeugen.

* **Argon2id**, kein bcrypt.
* **Mindestens 12 Zeichen.** Länge statt Zusammensetzungsregeln: eine lange
  Wortfolge schlägt eine kurze Zeichenkette mit angehängter Ziffer, und
  Zusammensetzungsregeln produzieren vor allem `Sommer2026!`.
* Naheliegende Bestandteile, der eigene Benutzername und Passwörter aus zu
  wenigen verschiedenen Zeichen werden abgelehnt.
* Nach einer Änderung werden **alle anderen Sitzungen beendet**. Wurde das
  Passwort geändert, weil es abgeflossen sein könnte, wäre alles andere sinnlos.
* Von einem Administrator angelegte Konten müssen das Passwort bei der ersten
  Anmeldung ändern; bis dahin ist jede andere Seite gesperrt.

## Schutzmechanismen

**Sperre nach 8 Fehlversuchen** für 15 Minuten. Danach wird auch das richtige
Passwort abgelehnt.

**Ein Verzeichnisausfall zählt nicht gegen die Sperre.** Ist der Domain
Controller nicht erreichbar, sieht ein AD-Konto wie ein falsches Passwort aus —
und mitzuzählen würde die Leute aus genau dem System aussperren, mit dem sie den
Ausfall untersuchen. Einen Providerausfall kann ein Angreifer nicht auslösen,
also ist das kein Weg hinein.

**Ratenbegrenzung pro Adresse:** 30 Fehlversuche in 10 Minuten, unabhängig
davon, welche Konten sie betreffen. Das bremst das Durchprobieren vieler Konten
mit einem Passwort, was eine Kontosperre allein nicht tut.

**Eine Meldung für alle Fehlerfälle.** „Konto unbekannt" von „Passwort falsch"
zu unterscheiden macht aus einem Rätselraten zwei einfachere. Auch die
Antwortzeit ist angeglichen: bei einem unbekannten lokalen Konto wird gegen
einen echten Argon2id-Hash geprüft, damit das frühe Zurückkehren nicht messbar
wird.

**Das letzte Administratorkonto** kann sich nicht selbst herabstufen,
deaktivieren oder löschen. Sonst endet es in einem Support-Fall, der mit
Handarbeit in der Datenbank aufhört.

**Leeres Passwort erreicht das Verzeichnis nie.** Ein Bind mit DN und leerem
Passwort ist ein *unauthenticated bind* (RFC 4513 §5.1.2). Server sollen ihn
ablehnen, nicht alle tun es — und ein Verzeichnis, das ihn annimmt, würde jedes
existierende Konto jedem bestätigen, der das Feld leer lässt.

**Benutzernamen mit Filter-Metazeichen** werden abgewiesen, bevor eine
LDAP-Abfrage daraus wird.

## Was protokolliert wird

`login_attempts` hält jeden Versuch mit Zeitpunkt, Adresse, Verfahren, Ergebnis
und Grund — auch für Konten, die es nicht gibt. Das eigene Profil zeigt die
letzten fünfzehn: ein Versuch, den man selbst nicht kennt, gehört gemeldet.

`audit_log` hält die Änderungen: Anmeldungen, Rollenänderungen,
Passwortänderungen, beendete Sitzungen, angelegte und gelöschte Konten und
Zuordnungen.

## Kommandozeile

```bash
bin/logwarden-user --list
bin/logwarden-user --create=NAME --role=admin|analyst|readonly
bin/logwarden-user --passwd=NAME
bin/logwarden-user --user=NAME --role=analyst
bin/logwarden-user --unlock=NAME
bin/logwarden-user --enable=NAME | --disable=NAME
bin/logwarden-user --map-group=GRUPPE --role=ROLLE [--priority=N]
bin/logwarden-user --map-user=NAME   --role=ROLLE [--priority=N]
```

## Konfiguration

```php
'web' => [
    'auth_mode'        => 'ldap',   // 'ldap' oder 'local'
    'session_ttl'      => 8 * 3600, // absolut, verlängert sich nie
    'session_idle_ttl' => 3600,     // Leerlauf, verlängert sich bei Zugriff
    'default_role'     => '',       // leer = Anmeldung ohne Zuordnung ablehnen
],

'ldap' => [
    'hosts'           => ['ldaps://dc01.corp.local', 'ldaps://dc02.corp.local'],
    'base_dn'         => 'DC=corp,DC=local',
    'bind_format'     => '%s@corp.local',      // AD nimmt den UPN
    'login_attribute' => 'sAMAccountName',
    'start_tls'       => false,                 // bei ldap:// auf Port 389
    'tls_verify'      => true,
    'nested_groups'   => false,                 // AD-Matching-Rule für verschachtelte Gruppen
],
```
