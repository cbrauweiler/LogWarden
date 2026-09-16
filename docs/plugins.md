# Quellen als Plugins

Windows-Logs sind fest eingebaut. Alles andere — FortiGate, Cisco ASA, was
noch kommt — ist ein Plugin: ein Verzeichnis unter `plugins/`, das man
hineinkopiert und wieder löscht. Es gibt nichts zu registrieren, keine
Migration, keinen Schalter in der Datenbank.

```
plugins/
  fortigate/
    plugin.json              Manifest
    FortigatePlugin.php      implementiert PluginInterface
    FortigateNormalizer.php
    CefParser.php
    FortigateKvParser.php
    fixtures/                Beispielzeilen für --test
    README.md
```

## Warum Windows nicht auch ein Plugin ist

Die Windows-Quellen teilen sich den WinRM-Collector, sie sind der Grund, warum
das Werkzeug in einer Windows-Umgebung existiert, und eine Plugin-Grenze
zwischen AD, DNS und DHCP wäre eine Grenze, die nie jemand überquert. Sie
stehen deshalb in `src/Ingest/Windows/` und ihre Quelltypen in
`SourceType::CORE`.

## Das Manifest

```json
{
    "key": "cisco-asa",
    "name": "Cisco ASA / Firepower Threat Defense",
    "vendor": "Cisco",
    "version": "1.0.0",
    "description": "VPN- und Authentifizierungsmeldungen per Syslog.",
    "namespace": "LogWarden\\Plugin\\CiscoAsa",
    "class": "CiscoAsaPlugin",
    "docs": "README.md"
}
```

Zwei Regeln werden hart geprüft:

* **`key` muss dem Verzeichnisnamen entsprechen.** Das Verzeichnis ist, was
  geladen wird; der Schlüssel ist, was in der Datenbank steht. Laufen sie
  auseinander, ist „welches Plugin hat dieses Event geschrieben" nicht mehr
  beantwortbar.
* **`namespace` muss unter `LogWarden\Plugin\` liegen.** Sonst könnte ein
  Plugin beim Laden Klassen des Kerns überschreiben.

## Die Klasse

```php
final class CiscoAsaPlugin implements PluginInterface
{
    public static function key(): string { return 'cisco-asa'; }

    public static function transports(): array { return ['syslog']; }

    public static function sourceTypes(): array
    {
        return [
            new SourceTypeDefinition(
                key:         'cisco_asa_vpn',
                label:       'Cisco ASA VPN',
                keepDays:    180,
                ftsDays:     30,
                color:       '--series-6',
                description: 'AnyConnect-, WebVPN- und IPsec-Sitzungen',
                role:        SourceTypeDefinition::ROLE_VPN,
            ),
        ];
    }

    public function normalizers(): array { return [new CiscoAsaNormalizer()]; }
}
```

### Was ein Plugin *nicht* darf

Es öffnet keine Sockets, stellt keine Datenbankabfragen, registriert keine
Routen und bekommt die Konfiguration nicht zu sehen. Der Transport ist Sache
von LogWarden; das Plugin sieht einen Rohdatensatz und sagt, was er bedeutet.
Damit kann ein fremdes Plugin wenig mehr anrichten, als falsche Events zu
erzeugen — und genau deshalb hat `PluginInterface` keinen Zugriff auf `Db`
oder `Config`.

## Die Rolle ist wichtiger als der Hersteller

Jeder Quelltyp trägt eine **Rolle**: `vpn`, `auth`, `directory`, `dns`,
`dhcp`, `firewall`, `endpoint`, `other`.

Das ist nicht Kosmetik, sondern der Grund, warum sich ein Plugin lohnt. Die
Korrelationsregel „VPN-Login, danach Anmeldefehler im Verzeichnis" fragt:

```sql
AND v.source_type IN (SELECT key FROM source_types WHERE role = 'vpn')
```

statt `AND v.source_type = 'fortigate_vpn'`. Wer das Cisco-Plugin installiert,
ist damit sofort in jeder bestehenden Regel dabei. Stünde dort ein
Herstellername, müsste man beim Hinzufügen jedes Herstellers jede Regel
anfassen — und dann kauft das Plugin-System nichts ein.

Genau das ist beim Bau des zweiten Plugins aufgefallen: Mit nur einem Plugin
sieht ein fest verdrahtetes `'fortigate_vpn'` völlig in Ordnung aus.

## Farben

`SourceTypeDefinition::PALETTE` hat acht Stufen, als Satz auf
Farbfehlsichtigkeit geprüft. Ein Plugin wählt eine davon; wer keine wählt,
bekommt eine stabil aus dem Schlüssel abgeleitete. Die Tests stellen sicher,
dass sich keine zwei Quelltypen eine Farbe teilen — sie stehen in jedem
Diagramm nebeneinander.

## Quelltypen und die Datenbank

Die Deklaration im Code ist maßgeblich. `source_types` ist ein Spiegel, damit
SQL Label, Farbe und Rolle mitjoinen kann:

```bash
bin/logwarden-plugins --sync --dry-run   # zeigen, was sich ändern würde
bin/logwarden-plugins --sync
```

Zwei Feinheiten:

* **`keep_days` und `fts_days` werden beim Sync nie überschrieben.** Sie sind
  der Teil der Zeile, der dem Administrator gehört; ein Plugin-Update darf
  eine bewusst gewählte Aufbewahrung nicht stillschweigend zurücksetzen.
* **Ein entferntes Plugin hinterlässt seine Zeile als `orphaned`.** Die Events
  bleiben durchsuchbar und beschriftet; nur neue kommen keine mehr dazu. Die
  Quellenseite weist darauf hin, wenn ein verwaister Typ noch Daten trägt.

Der Kern gewinnt bei einer Kollision: Ein Plugin kann `ad` nicht umdefinieren
und damit nicht die Aufbewahrung des Sicherheitsprotokolls der Domain
Controller ändern.

## Ein Plugin schreiben

1. Verzeichnis unter `plugins/` anlegen, `plugin.json` schreiben.
2. Klasse mit `PluginInterface` anlegen.
3. Normalizer schreiben — `supports()` und `normalize()`, wie in
   [docs/ingestion.md](ingestion.md) beschrieben.
4. Beispielzeilen nach `fixtures/` legen.
5. Prüfen:

```bash
bin/logwarden-plugins --list
bin/logwarden-plugins --test=cisco-asa
bin/logwarden-plugins --sync
systemctl restart logwarden-syslogd
```

`--test` schickt jede Fixture-Zeile durch die Normalizer und zeigt, was daraus
wird und was verworfen wurde.

### Zwei Dinge, die man dabei falsch macht

**`supports()` zu großzügig.** Auf einem gemeinsamen Syslog-Listener bekommt
jedes Plugin jede Nachricht angeboten, der erste Treffer gewinnt. Ein
Normalizer, der alles beansprucht, verschluckt die Daten der anderen. Die
Testsuite prüft für jedes mitgelieferte Plugin, dass es beliebigen Text
ablehnt.

**Zu viel mitnehmen.** Eine ASA sendet hunderte Meldungstypen, und 302013/302014
allein sind eine Zeile pro TCP-Verbindung. Das Cisco-Plugin verwirft deshalb
alles, was nicht in seinem Katalog steht — anders als der Windows-Collector,
bei dem schon auf dem Host gefiltert wird. Welche Regel gilt, hängt davon ab,
wo gefiltert werden kann; beides bewusst zu entscheiden ist der Punkt.

## Mitgelieferte Plugins

| Plugin | Quelltypen | Rollen | Transport |
|---|---|---|---|
| [`fortigate`](../plugins/fortigate/README.md) | `fortigate_vpn`, `fortigate_auth` | vpn, auth | syslog |
| [`cisco-asa`](../plugins/cisco-asa/README.md) | `cisco_asa_vpn`, `cisco_asa_auth` | vpn, auth | syslog |

Beide hören auf demselben Listener; welcher eine Zeile bekommt, entscheidet
`supports()`.
