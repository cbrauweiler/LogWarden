# Cisco-ASA-Plugin

Nimmt Syslog von Cisco ASA und Firepower Threat Defense entgegen.

## ASA konfigurieren

```
logging enable
logging timestamp
logging host inside 10.0.0.50
logging trap informational
logging device-id hostname
```

`logging timestamp` nicht vergessen: ohne sie sendet die ASA keinen
Zeitstempel, und LogWarden muss auf die Empfangszeit ausweichen.
`logging device-id hostname` sorgt dafür, dass mehrere Appliances
unterscheidbar bleiben.

`syslog.allow_from` in `config/config.php` auf die ASA-Adressen setzen.

## Was gesammelt wird

Erkannt wird an der Meldungsnummer in `%ASA-<schwere>-<nummer>:`. Alles, was
nicht im Katalog steht, wird verworfen — eine ASA am Perimeter sendet sonst
eine Zeile pro TCP-Verbindung (302013/302014), und die beantwortet keine Frage.

**VPN** (`cisco_asa_vpn`, Rolle `vpn`): 113039, 113019, 722022, 722023, 722051,
716001, 716002, 716039, 713119, 713120, 713904

**Authentifizierung** (`cisco_asa_auth`, Rolle `auth`): 113004, 113005, 113006,
113012, 113015, 113021, 605004, 605005, 611101, 611102, 109005, 109006,
109025, 315011

Die vollständige Liste mit Beschriftungen steht in `AsaMessageCatalog.php`.

## Drei Feldstile

Cisco verwendet je nach Subsystem unterschiedliche Formate, teils zwei in einer
Zeile. Alle drei werden explizit geparst, nicht über einen hoffnungsvollen
regulären Ausdruck:

```
Group <SSL-VPN> User <asmith> IP <203.0.113.5>
Group = SSL-VPN, Username = asmith, IP = 203.0.113.5
reason = Invalid password : server = 10.0.0.10 : user = pweber : user IP = 203.0.113.9
```

Dazu `for user "admin"` in den Verwaltungsmeldungen und `Uname: asmith` in
611101/611102.

> Der Benutzername im dritten Stil läuft bis zum nächsten ` : `, nicht bis zum
> nächsten Leerzeichen — sonst bräche „van der Berg" nach „van" ab.

## Testen

```bash
bin/logwarden-plugins --test=cisco-asa
grep -v '^#' fixtures/cisco-asa.log | nc -q1 127.0.0.1 5514
```
