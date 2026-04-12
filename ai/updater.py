# ai/updater.py
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# Aggiornamento automatico della blacklist eBPF
# da feed di threat intelligence esterni.
# Automatic update of the eBPF blacklist
# from external threat intelligence feeds.
#
# Uso / Usage:
#   pip install requests
#   sudo python3 updater.py

import ipaddress
import subprocess
import socket
import time
import json
import sqlite3
import requests
from datetime import datetime, timedelta

# ──────────────────────────────────────────────
# Configurazione / Configuration
# ──────────────────────────────────────────────

# Percorso del file che contiene gli URL dei feed.
# Path to the file containing feed URLs.
# Formato / Format: url|peso|nome
FEEDS_FILE = "feeds.txt"

# Score minimo per bloccare un IP.
# Minimum score to block an IP.
# Nota: con MIN_SCORE=3 un singolo feed di peso 3
# è sufficiente. Per richiedere conferma da più fonti
# aumentare a 5 o aggiungere MIN_SOURCES.
# Note: with MIN_SCORE=3 a single feed of weight 3
# is sufficient. To require multi-source confirmation
# increase to 5 or add MIN_SOURCES.
MIN_SCORE = 3

# Numero minimo di fonti che devono segnalare un IP
# prima di bloccarlo — conferma multipla.
# Minimum number of sources that must report an IP
# before blocking it — multi-source confirmation.
MIN_SOURCES = 1

# Ore dopo cui un IP bloccato viene rimosso
# se non compare più in nessun feed.
# Hours after which a blocked IP is removed
# if it no longer appears in any feed.
TTL_HOURS = 48

# Intervallo di aggiornamento in secondi.
# Update interval in seconds.
UPDATE_INTERVAL = 3600  # 1 ora / 1 hour

# Percorso del database SQLite.
# Path to the SQLite database.
DB_PATH = "sentinel.db"

# Timeout in secondi per i comandi bpftool.
# Timeout in seconds for bpftool commands.
BPFTOOL_TIMEOUT = 10

# Pausa in secondi tra il download di un feed e il successivo.
# Pause in seconds between downloading feeds.
FEED_DELAY = 1


# ──────────────────────────────────────────────
# Lettura feed da file / Reading feeds from file
# ──────────────────────────────────────────────

def load_feeds(filepath: str) -> list:
    """
    Legge la lista dei feed dal file di configurazione.
    Reading the list of feeds from the configuration file.

    Formato / Format: url|peso|nome
    Righe vuote e commenti (#) vengono ignorati.
    Empty lines and comments (#) are ignored.

    Quando in futuro si userà un database, questa
    funzione verrà sostituita da una query SQL
    mantenendo identica l'interfaccia verso il resto
    del codice.
    When a database is used in the future, this
    function will be replaced by a SQL query
    keeping the same interface toward the rest
    of the code.
    """
    feeds = []
    try:
        with open(filepath, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()

                # Salta righe vuote e commenti
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                parts = line.split("|")
                if len(parts) != 3:
                    print(f"[updater] Riga {lineno} ignorata "
                          f"(formato errato / wrong format): {line}")
                    continue

                url = parts[0].strip()
                name = parts[2].strip()
                try:
                    weight = int(parts[1].strip())
                except ValueError:
                    print(f"[updater] Riga {lineno}: peso non valido "
                          f"'{parts[1].strip()}', uso 1 / using 1")
                    weight = 1

                feeds.append((name, url, weight))

    except FileNotFoundError:
        print(f"[updater] File {filepath} non trovato / not found.")
    except Exception as e:
        print(f"[updater] Errore lettura {filepath}: {e}")

    return feeds


# ──────────────────────────────────────────────
# Database SQLite
# ──────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    """
    Inizializza il database SQLite.
    Initializes the SQLite database.

    Nota sullo scoring / Note on scoring:
    score e sources vengono resettati a ogni ciclo.
    Rappresentano lo stato CORRENTE del ciclo,
    non uno storico cumulativo.
    first_seen e last_seen sono invece persistenti.
    score and sources are reset each cycle.
    They represent the CURRENT state of the cycle,
    not a cumulative history.
    first_seen and last_seen are persistent.
    """
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip           TEXT PRIMARY KEY,
            score        INTEGER DEFAULT 0,
            sources      TEXT DEFAULT '',
            source_count INTEGER DEFAULT 0,
            first_seen   TEXT,
            last_seen    TEXT,
            blocked      INTEGER DEFAULT 0
        )
    """)

    # Indici per velocizzare le query più frequenti.
    # Indexes to speed up the most frequent queries.
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_blocked_score
        ON ip_scores(blocked, score)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_last_seen
        ON ip_scores(last_seen)
    """)

    conn.commit()
    return conn


def update_score(conn: sqlite3.Connection,
                 ip: str, source: str, weight: int):
    """
    Aggiorna lo score corrente di un IP nel database.
    Updates the current score of an IP in the database.

    Se la fonte è già presente per questo ciclo
    non aggiunge il peso due volte.
    If the source is already present for this cycle
    the weight is not added twice.
    """
    now = datetime.utcnow().isoformat()
    row = conn.execute(
        "SELECT score, sources, source_count FROM ip_scores WHERE ip = ?",
        (ip,)
    ).fetchone()

    if row is None:
        # Primo avvistamento / First detection
        conn.execute(
            """INSERT INTO ip_scores
               (ip, score, sources, source_count, first_seen, last_seen, blocked)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ip, weight, source, 1, now, now, 0)
        )
    else:
        score, sources, source_count = row
        sources_list = sources.split(",") if sources else []
        if source not in sources_list:
            sources_list.append(source)
            score += weight
            source_count += 1
        conn.execute(
            """UPDATE ip_scores
               SET score=?, sources=?, source_count=?, last_seen=?
               WHERE ip=?""",
            (score, ",".join(sources_list), source_count, now, ip)
        )


def get_ips_to_block(conn: sqlite3.Connection) -> list:
    """
    Restituisce gli IP con score e numero di fonti
    sufficienti, non ancora bloccati.
    Returns IPs with sufficient score and source count,
    not yet blocked.

    Un IP viene bloccato solo se soddisfa ENTRAMBE
    le condizioni: score >= MIN_SCORE E
    source_count >= MIN_SOURCES.
    An IP is blocked only if it meets BOTH conditions:
    score >= MIN_SCORE AND source_count >= MIN_SOURCES.
    """
    rows = conn.execute(
        """SELECT ip FROM ip_scores
           WHERE score >= ?
           AND source_count >= ?
           AND blocked = 0""",
        (MIN_SCORE, MIN_SOURCES)
    ).fetchall()
    return [r[0] for r in rows]


def get_ips_to_expire(conn: sqlite3.Connection) -> list:
    """
    Restituisce gli IP bloccati non aggiornati da
    più di TTL_HOURS — candidati alla rimozione.
    Returns blocked IPs not updated for more than
    TTL_HOURS — candidates for removal.

    Un IP resta bloccato per TTL_HOURS dall'ultima
    osservazione nei feed, non solo finché supera
    la soglia corrente.
    An IP stays blocked for TTL_HOURS from its last
    observation in feeds, not just while it exceeds
    the current threshold.
    """
    cutoff = (
        datetime.utcnow() - timedelta(hours=TTL_HOURS)
    ).isoformat()
    rows = conn.execute(
        """SELECT ip FROM ip_scores
           WHERE last_seen < ? AND blocked = 1""",
        (cutoff,)
    ).fetchall()
    return [r[0] for r in rows]


# ──────────────────────────────────────────────
# Gestione mappa eBPF / eBPF map management
# ──────────────────────────────────────────────

def get_map_id(map_name: str) -> int:
    """
    Trova l'ID della mappa eBPF tramite bpftool.
    Finds the eBPF map ID using bpftool.
    """
    try:
        result = subprocess.run(
            ["bpftool", "map", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=BPFTOOL_TIMEOUT  # FIX 1: timeout aggiunto / added
        )
        # FIX 2: log stderr se bpftool fallisce / log stderr if bpftool fails
        if result.returncode != 0:
            print(f"[updater] bpftool fallito / failed: "
                  f"{result.stderr.strip()}")
            return -1
        maps = json.loads(result.stdout)
        for m in maps:
            if m.get("name") == map_name:
                return m["id"]
    except subprocess.TimeoutExpired:
        print("[updater] bpftool timeout — processo bloccato / stuck process")
    except Exception as e:
        print(f"[updater] Errore bpftool: {e}")
    return -1


def ip_to_hex(ip: str) -> list:
    """
    Converte un IP in lista di byte per bpftool.
    Converts an IP to a byte list for bpftool.
    Esempio / Example: 8.8.8.8 → [08, 08, 08, 08]
    """
    return list(socket.inet_aton(ip))


def map_add(map_id: int, ip: str) -> bool:
    """
    Aggiunge un IP alla mappa eBPF.
    Adds an IP to the eBPF map.
    """
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        r = subprocess.run(
            ["bpftool", "map", "update",
             "id", str(map_id),
             "key", "hex"] + key_hex.split() +
            ["value", "hex", "01", "00", "00", "00"],
            capture_output=True,
            text=True,
            timeout=BPFTOOL_TIMEOUT  # FIX 1: timeout aggiunto / added
        )
        # FIX 2: log stderr in caso di errore / log stderr on error
        if r.returncode != 0:
            print(f"[updater] map_add fallito per / failed for "
                  f"{ip}: {r.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[updater] map_add timeout per / for {ip}")
        return False
    except Exception as e:
        print(f"[updater] Eccezione map_add {ip}: {e}")
        return False


def map_remove(map_id: int, ip: str) -> bool:
    """
    Rimuove un IP dalla mappa eBPF.
    Removes an IP from the eBPF map.
    """
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        r = subprocess.run(
            ["bpftool", "map", "delete",
             "id", str(map_id),
             "key", "hex"] + key_hex.split(),
            capture_output=True,
            text=True,
            timeout=BPFTOOL_TIMEOUT  # FIX 1: timeout aggiunto / added
        )
        # FIX 2: log stderr in caso di errore / log stderr on error
        if r.returncode != 0:
            print(f"[updater] map_remove fallito per / failed for "
                  f"{ip}: {r.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[updater] map_remove timeout per / for {ip}")
        return False
    except Exception as e:
        print(f"[updater] Eccezione map_remove {ip}: {e}")
        return False


# ──────────────────────────────────────────────
# Download feed / Feed download
# ──────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """
    Verifica che la stringa sia un IPv4 valido.
    Verifies that the string is a valid IPv4 address.

    FIX 4: usa ipaddress invece di validazione custom.
    FIX 4: uses ipaddress instead of custom validation.
    Nota: il progetto supporta solo IPv4 per ora.
    Note: the project supports IPv4 only for now.
    """
    try:
        return isinstance(
            ipaddress.ip_address(ip),
            ipaddress.IPv4Address
        )
    except ValueError:
        return False


def extract_ip(line: str):
    """
    Estrae un IP da una riga di testo.
    Extracts an IP from a text line.

    FIX 4: parser robusto che gestisce / robust parser handling:
    - commenti (#) inline / inline comments
    - separatori multipli (spazio, virgola, tab, ;)
    - notazione CIDR (/24)
    - campi extra dopo l'IP
    Restituisce None se la riga non contiene un IP valido.
    Returns None if the line contains no valid IP.
    """
    line = line.strip()

    # Salta righe vuote e commenti
    # Skip empty lines and comments
    if not line or line.startswith("#"):
        return None

    # Rimuove commenti inline (es. "1.2.3.4 # commento")
    # Remove inline comments (e.g. "1.2.3.4 # comment")
    line = line.split("#", 1)[0].strip()
    if not line:
        return None

    # Normalizza separatori multipli in spazio
    # Normalize multiple separators to space
    line = line.replace(",", " ").replace(";", " ").replace("\t", " ")

    # Prende il primo token
    # Takes the first token
    token = line.split()[0] if line.split() else ""
    if not token:
        return None

    # Rimuove notazione CIDR
    # Remove CIDR notation
    ip = token.split("/")[0]

    return ip if is_valid_ip(ip) else None


def fetch_feed(url: str) -> list:
    """
    Scarica un feed e restituisce IP validi.
    Downloads a feed and returns valid IPs.
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        ips = []
        for line in response.text.splitlines():
            ip = extract_ip(line)
            if ip:
                ips.append(ip)
        return ips
    except requests.exceptions.Timeout:
        print(f"[updater] Timeout download: {url}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[updater] Errore download {url}: {e}")
        return []


# ──────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────

def main():
    print("[updater] ebpf-sentinel — threat intelligence engine")
    print(f"[updater] Database: {DB_PATH}")
    print(f"[updater] Score minimo / Minimum score: {MIN_SCORE}")
    print(f"[updater] Fonti minime / Minimum sources: {MIN_SOURCES}")
    print(f"[updater] TTL: {TTL_HOURS} ore / hours")
    print(f"[updater] Intervallo / Interval: "
          f"{UPDATE_INTERVAL // 60} min\n")

    # Inizializza database / Initialize database
    conn = init_db()

    # FIX 3: gestione Ctrl+C e chiusura DB
    # FIX 3: Ctrl+C handling and DB close
    try:
        while True:
            # Verifica che sentinel sia in esecuzione
            # Check that sentinel is running
            map_id = get_map_id("ip_blacklist")
            if map_id == -1:
                print("[updater] ATTENZIONE / WARNING: "
                      "mappa ip_blacklist non trovata.")
                print("[updater] Verifica che sentinel sia in esecuzione.")
                print("[updater] Make sure sentinel is running.")
                time.sleep(30)
                continue

            print(f"[updater] Mappa trovata — ID: {map_id}")
            print(f"[updater] Ciclo: "
                  f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

            # Carica feed dal file / Load feeds from file
            feeds = load_feeds(FEEDS_FILE)
            if not feeds:
                print(f"[updater] Nessun feed in {FEEDS_FILE}.")
                time.sleep(UPDATE_INTERVAL)
                continue

            print(f"[updater] Feed caricati / Loaded: {len(feeds)}")

            # Reset score corrente per questo ciclo.
            # Nota: first_seen, last_seen e blocked
            # rimangono invariati.
            # Reset current score for this cycle.
            # Note: first_seen, last_seen and blocked
            # remain unchanged.
            conn.execute(
                "UPDATE ip_scores SET score = 0, "
                "sources = '', source_count = 0"
            )
            conn.commit()

            # Scarica tutti i feed e calcola gli score
            # Download all feeds and calculate scores
            for name, url, weight in feeds:
                print(f"[updater] Feed: {name} "
                      f"(peso/weight: {weight})")
                ips = fetch_feed(url)
                print(f"[updater] → {len(ips)} IP trovati / found")
                for ip in ips:
                    update_score(conn, ip, name, weight)
                conn.commit()

                # Pausa tra feed / Pause between feeds
                time.sleep(FEED_DELAY)

            # Blocca nuovi IP / Block new IPs
            da_bloccare = get_ips_to_block(conn)
            print(f"\n[updater] Da bloccare / To block: "
                  f"{len(da_bloccare)}")

            bloccati = 0
            for ip in da_bloccare:
                if map_add(map_id, ip):
                    conn.execute(
                        "UPDATE ip_scores SET blocked=1 WHERE ip=?",
                        (ip,)
                    )
                    bloccati += 1
            conn.commit()
            print(f"[updater] Bloccati / Blocked: {bloccati}")

            # Rimuove IP scaduti / Remove expired IPs
            da_rimuovere = get_ips_to_expire(conn)
            print(f"[updater] Scaduti / Expired: {len(da_rimuovere)}")

            rimossi = 0
            for ip in da_rimuovere:
                if map_remove(map_id, ip):
                    conn.execute(
                        "DELETE FROM ip_scores WHERE ip=?", (ip,)
                    )
                    rimossi += 1
            conn.commit()
            print(f"[updater] Rimossi / Removed: {rimossi}")

            print(f"\n[updater] Completato. Prossimo / Next: "
                  f"{UPDATE_INTERVAL // 60} min.\n")

            time.sleep(UPDATE_INTERVAL)

    except KeyboardInterrupt:
        # FIX 3: uscita pulita / clean exit
        print("\n[updater] Interrotto dall'utente / "
              "Interrupted by user.")
    finally:
        # FIX 3: chiude sempre il DB / always closes the DB
        conn.close()
        print("[updater] Database chiuso / Database closed.")


if __name__ == "__main__":
    main()