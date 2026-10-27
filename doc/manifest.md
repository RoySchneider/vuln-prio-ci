# `manifest.py` – Stand des Informationspakets

Dieses Skript erhebt keine externen Daten. Es beschreibt, welchen Stand die bezogenen Quellen im
Cache-Verzeichnis haben, und hält das in `bundle-manifest.json` fest.

## Wozu

Der CI-Befehl prüft am Manifest das Höchstalter des Pakets (`ci/freshness.py`). Das Manifest wird erst
geschrieben, nachdem alle Quellen erfolgreich bezogen wurden.

## `describe(cache_dir)`

Liest den Stand jeder Quelle aus dem Cache-Verzeichnis. Ist ein Eintrag leer (`None`), wurde die Quelle
noch nicht bezogen.

| Schlüssel | Herkunft | Inhalt |
| --- | --- | --- |
| `epss` | jüngster EPSS-Snapshot in `reference.sqlite` | Bezugsdatum, Modellversion, Bezugszeitpunkt, Zeilenzahl |
| `exploitdb` | jüngster Exploit-DB-Snapshot | Commit, Commit-Zeitpunkt, Bezugszeitpunkt, Referenzen |
| `metasploit` | jüngster Metasploit-Snapshot | wie Exploit-DB |
| `nvd` | Abgleichstand in `reference.sqlite` | `synced_until`, Bezugszeitpunkt, Vollbezug, Zeilenzahl |
| `kev` | Datei `kev-dump.json` | Änderungszeit der Datei als Bezugszeitpunkt, Zahl der Einträge, jüngstes `dateAdded` |

Existiert `reference.sqlite` nicht, bleiben EPSS, Exploit-DB, Metasploit und NVD leer. Ist
`kev-dump.json` unlesbar, wird sie als leere Liste gewertet.

## `write(cache_dir, created_at=None)`

Schreibt `bundle-manifest.json` ins Cache-Verzeichnis:

```json
{
  "created_at": "2026-10-23T06:00:00+00:00",
  "sources": { "epss": {…}, "exploitdb": {…}, "metasploit": {…}, "nvd": {…}, "kev": {…} }
}
```

`created_at` ist der Erstellungszeitpunkt des Pakets (Standard: jetzt, UTC).

## `read(cache_dir)`

Liest das Manifest. Fehlt die Datei oder ist sie kein gültiges JSON, liefert die Funktion `None`.
