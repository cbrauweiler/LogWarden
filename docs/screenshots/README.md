# Screenshots

Aufgenommen mit den Demo-Daten aus `bin/logwarden-seed-demo` — keine echten
Konten, keine echten Adressen. Die Namen sind erfunden, die IP-Bereiche stammen
aus RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), die für
Dokumentation reserviert sind.

Nachstellen:

```bash
bin/logwarden-seed-demo --yes
bin/logwarden-rules
```

| Datei | Ansicht |
|---|---|
| `dashboard.png` / `dashboard-dark.png` | Dashboard, hell und dunkel |
| `search.png` / `search-dark.png` | Such- und Filteransicht |
| `alerts.png` | Alert-Übersicht |
| `alert-detail.png` | Alert mit Beweiskette |
| `sources.png` | Verwaltung → Quellen (WinRM) |
| `users.png` | Verwaltung → Benutzer und Berechtigungen |
| `branding.png` | Verwaltung → Corporate Identity |
| `login.png` / `login-dark.png` | Anmeldung |

Die Darstellung zeigt die Werkseinstellung des Design-Systems. Produktname,
Farben, Logo, Schrift, Eckenform und Dichte sind unter *Corporate Identity*
einstellbar.
