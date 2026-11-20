LOXONE STATE READER
==================
Konzolový nástroj pro načtení aktuálních stavů bloku Loxone podle názvu.
UUID automaticky vyhledá ve struktuře Miniserveru. Čte také stavy
podřízených bloků, například týdenní rozvrh pokojového regulátoru.
Nemění nastavení ani výstupy Miniserveru.

POŽADAVKY
Python 3.10+, přístup k Miniserveru a uživatel s oprávněním zobrazit blok.

INSTALACE
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt

POUŽITÍ
  .venv/bin/python read_uuids.py --host HOST --user UZIVATEL --block "Topení obývák"

HOST nahraď IP adresou Miniserveru a UZIVATEL svým účtem. Název bloku zadej tak, jak je
uveden ve vizualizaci; velikost písmen nerozhoduje. Heslo zadáš skrytě
v terminálu. Pro názvy s mezerami použij uvozovky.

Pokud má více bloků stejný název, doplň místnost:
  .venv/bin/python read_uuids.py --host HOST --user UZIVATEL --block "Topení" --room "Obývák"

Při nejednoznačném názvu skript zobrazí shody a skončí bez výběru.
Pokud se názvy opakují i ve stejné místnosti, použij jedinečný název bloku.

VOLBY
  --host ADRESA     IP adresa nebo hostname Miniserveru (povinný)
  --tls             zapne šifrované WSS spojení
  --port CISLO      vlastní port, jinak 80 nebo 443 při --tls
  --block NAZEV      název bloku (povinný)
  --room MISTNOST    místnost pro upřesnění výběru
  --timeout 30      doba čekání na stavy v sekundách
  --client-id UUID  volitelná stabilní identita klienta ve formátu Loxone
  --help            nápověda

VÝSTUP
Standardní výstup obsahuje JSON s názvem bloku, místností a seznamem
stavů. Každý stav má název, cestu k bloku, automaticky nalezené UUID,
typ a hodnotu. Podporovány jsou čísla, texty a rozvrhy. Chybějící stavy
mají type="missing" a value=null; jejich UUID obsahuje také seznam missing.

Rozvrhy obsahují původní hodnoty z API, včetně číselně zakódovaných
pevných teplot. Skript čte počáteční stavy; nejde o nepřetržitý monitoring
ani atomický snímek všech hodnot. Tabulky počasí nejsou podporované.

Uložení výsledku do souboru:
  .venv/bin/python read_uuids.py --host HOST --user UZIVATEL --block "Topení" > output.json

Návratové kódy: 0 úspěch, 1 chyba, 2 chybějící stavy/neplatné argumenty,
130 přerušení. Chybové zprávy se vypisují na stderr.

PŘIPOJENÍ
Pro TLS přidej --tls a použij adresu odpovídající důvěryhodnému certifikátu.
WebSocket URL a cestu /ws/rfc6455 sestaví nástroj automaticky.
Ověřování certifikátu zůstává zapnuté. Nešifrované ws:// používej pouze
v důvěryhodné místní síti. Token ani heslo se neukládají a nevypisují.

Autentizace používá getkey2 a getjwt (oprávnění Web, krátkodobý JWT),
SHA1/SHA256 podle odpovědi serveru. Po přihlášení se načte LoxAPP3.json
a zapne odběr binárních stavů. Starší firmware vyžadující aplikační
RSA/AES šifrování příkazů není podporován.

TESTY
  .venv/bin/python -m unittest -v
Testy probíhají offline s umělými daty.
