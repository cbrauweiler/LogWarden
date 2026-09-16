# FortiGate-Plugin

Nimmt FortiOS-Syslog entgegen, im nativen `key=value`-Format und in CEF.

## FortiGate konfigurieren

```
config log syslogd setting
    set status enable
    set server "10.0.0.50"
    set port 514
    set mode udp          # oder: reliable (TCP) bzw. udp mit enc-algorithm für TLS
    set format default    # 'cef' wird ebenfalls unterstützt
end
```

`syslog.allow_from` in `config/config.php` unbedingt auf die FortiGate-Adressen
setzen. UDP-Syslog ist nicht authentifiziert und die Absenderadresse trivial
fälschbar.

## Was gespeichert wird

| Signal | Quelltyp |
|---|---|
| `logid` beginnt mit `0101` | `fortigate_vpn` |
| `logid` beginnt mit `0102` | `fortigate_auth` |
| `subtype = vpn` | `fortigate_vpn` |
| `subtype` ∈ {`user`, `auth`} | `fortigate_auth` |
| `action` enthält `tunnel`/`ssl-login` | `fortigate_vpn` |
| `action` enthält `auth`/`login`/`logout` | `fortigate_auth` |
| sonst | verworfen |

Traffic- und UTM-Logs werden verworfen. Sie würden den Speicher dominieren,
ohne einer der Regeln zu dienen.

## Ohne FortiGate testen

```bash
grep -v '^#' fixtures/fortigate-native.log | nc -q1 127.0.0.1 5514
```
