"""Standalone read-only Loxone state reader. See README.txt for usage."""
import argparse
import getpass
import json
import math
import re
import struct
import time
import sys

import websocket
import hashlib
import hmac
import uuid
from urllib.parse import quote
import ipaddress

UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{16}$')


def send_command(ws, command):
    ws.send(command)

    deadline = time.monotonic() + 10
    original_timeout = ws.gettimeout()
    try:
        return _receive_response(ws, command, deadline)
    finally:
        ws.settimeout(original_timeout)


def _receive_response(ws, command, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise websocket.WebSocketTimeoutException("Vypršel čas čekání na odpověď.")
        ws.settimeout(remaining)
        response = ws.recv()
        if response == "" or response == b"":
            raise RuntimeError("Miniserver ukončil spojení.")

        # Přeskočení binárních zpráv
        if isinstance(response, bytes):
            continue

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue
        ll = data.get("LL", {})
        if not isinstance(ll, dict):
            continue

        control = ll.get("control", "").lstrip("/")

        # Odpovědi mohou normalizovat jdev/ na dev/.
        if control.removeprefix("j") == command.lstrip("/").removeprefix("j"):
            return ll

        # Zachycení autentizačních chyb
        if control == "Auth":
            return ll


# ==========================================
# AUTENTIZACE
# ==========================================

def create_auth_hash(username, password, key, salt, algorithm):
    """Postup dle Communicating with the Miniserver, Acquiring tokens."""
    algorithms = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256}
    if algorithm.upper() not in algorithms:
        raise RuntimeError(f"Nepodporovaný algoritmus: {algorithm}")
    digest = algorithms[algorithm.upper()]
    password_hash = digest(f"{password}:{salt}".encode("utf-8")).hexdigest().upper()
    return hmac.new(
        bytes.fromhex(key),
        f"{username}:{password_hash}".encode("utf-8"),
        digest,
    ).hexdigest()


def require_success(response, operation):
    code = str(response.get("code", response.get("Code")))
    if code != "200":
        hint = ""
        if code == "401":
            hint = " Ověřte přihlašovací údaje a oprávnění uživatele."
        elif code == "400" and operation == "getjwt":
            hint = (" Ověřte verzi firmware a požadavek na šifrování příkazů; "
                    "klient nepodporuje aplikační RSA/AES šifrování příkazů.")
        # Odpověď ani příkaz nevypisujeme: mohou obsahovat token nebo hash.
        raise RuntimeError(f"{operation} selhalo (API {code}).{hint}")
    return response.get("value")


def authenticate(ws, username, password, client_uuid):
    user = quote(username, safe='')
    value = require_success(send_command(ws, f'jdev/sys/getkey2/{user}'), 'getkey2')
    if isinstance(value, str):
        value = json.loads(value)
    auth_hash = create_auth_hash(username, password, value['key'], value['salt'], value['hashAlg'])
    # Web permission (2): short-lived JWT. Acquiring it authenticates this socket.
    result = require_success(send_command(ws, f'jdev/sys/getjwt/{auth_hash}/{user}/2/{client_uuid}/python-state-reader'), 'getjwt')
    if isinstance(result, str):
        result = json.loads(result)
    if not isinstance(result, dict) or not result.get('token'):
        raise RuntimeError('V odpovědi getjwt chybí token.')


def decode_text_states(payload):
    result = {}
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 36:
            raise RuntimeError("Neúplná hlavička textového stavu.")
        first, second, third = struct.unpack_from("<IHH", payload, offset)
        key = f"{first:08x}-{second:04x}-{third:04x}-{payload[offset+8:offset+16].hex()}"
        size, = struct.unpack_from("<I", payload, offset + 32)
        end = offset + 36 + size
        padded_end = end + (-size % 4)
        if padded_end > len(payload):
            raise RuntimeError("Neúplný textový stav.")
        result[key] = payload[offset + 36:end].decode("utf-8")
        offset = padded_end
    return result


def decode_daytimers(payload):
    """Dekóduje celou tabulku typu 4; zachovává i zvláštní provozní režimy."""
    result = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 28:
            raise RuntimeError("Neúplná hlavička stavu Daytimer.")
        first, second, third = struct.unpack_from("<IHH", payload, offset)
        state_uuid = f"{first:08x}-{second:04x}-{third:04x}-{payload[offset+8:offset+16].hex()}"
        default, count = struct.unpack_from("<di", payload, offset + 16)
        offset += 28
        if count < 0 or count > (len(payload) - offset) // 24:
            raise RuntimeError("Neplatný počet položek rozvrhu nebo neúplná data.")
        if not math.isfinite(default):
            raise RuntimeError("Neplatná výchozí hodnota rozvrhu.")
        entries = []
        for _ in range(count):
            mode, start, end, activate, value = struct.unpack_from("<iiiid", payload, offset)
            offset += 24
            if not math.isfinite(value):
                raise RuntimeError("Neplatná hodnota položky rozvrhu.")
            entries.append({"mode": mode, "from": start, "to": end,
                            "needActivate": activate, "value": value})
        result.append({"uuid": state_uuid, "defaultValue": default, "entries": entries})
    return result


def state_uuid(raw):
    a, b, c = struct.unpack_from('<IHH', raw)
    return f'{a:08x}-{b:04x}-{c:04x}-{raw[8:16].hex()}'


def decode_states(kind, payload):
    if kind == 2:
        if not isinstance(payload, bytes) or len(payload) % 24:
            raise RuntimeError('Neplatná tabulka číselných stavů.')
        result = {}
        for offset in range(0, len(payload), 24):
            value, = struct.unpack_from('<d', payload, offset + 16)
            if not math.isfinite(value):
                raise RuntimeError('Neplatná číselná hodnota.')
            result[state_uuid(payload[offset:offset + 16])] = {'type': 'number', 'value': value}
        return result
    if kind == 3:
        return {key: {'type': 'text', 'value': value}
                for key, value in decode_text_states(payload).items()}
    if kind == 4:
        return {state['uuid']: {'type': 'daytimer', 'value': {
                    'defaultValue': state['defaultValue'], 'entries': state['entries']}}
                for state in decode_daytimers(payload)}
    return {}


def read_states(ws, uuids, timeout=30):
    """Odebere počáteční stavy a vrátí nalezené hodnoty. Chybějící UUID neodhaduje."""
    wanted = set(uuids)
    found = {}
    acknowledged = False
    pending = None
    command = 'jdev/sps/enablebinstatusupdate'
    ws.send(command)
    deadline = time.monotonic() + timeout
    previous_timeout = ws.gettimeout()
    try:
        while not (acknowledged and wanted <= found.keys()):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ws.settimeout(remaining)
            try:
                message = ws.recv()
            except websocket.WebSocketTimeoutException:
                break
            if message == '' or message == b'':
                raise RuntimeError('Miniserver ukončil spojení.')
            if pending is None:
                if isinstance(message, bytes):
                    if len(message) != 8 or message[0] != 3:
                        raise RuntimeError('Neplatná hlavička zprávy.')
                    _, kind, flags, _, size = struct.unpack('<BBBBI', message)
                    if kind == 5:
                        raise RuntimeError('Miniserver je mimo provoz.')
                    if flags & 1 or kind == 6 or size == 0:
                        continue
                    if size > 64 * 1024 * 1024:
                        raise RuntimeError('Příliš velká zpráva.')
                    pending = kind, size
                    continue
                kind = 0
            else:
                kind, size = pending
                pending = None
                raw_size = len(message.encode('utf-8')) if isinstance(message, str) else len(message)
                if raw_size != size:
                    raise RuntimeError('Nesouhlasí délka zprávy.')
            if kind == 0:
                try:
                    data = json.loads(message)
                except (ValueError, UnicodeDecodeError):
                    continue
                ll = data.get('LL', {}) if isinstance(data, dict) else {}
                if not isinstance(ll, dict):
                    continue
                control = str(ll.get('control', '')).lstrip('/')
                if control == 'Auth' or control.removeprefix('j') == command.removeprefix('j'):
                    require_success(ll, 'odběr stavů')
                    acknowledged = True
            elif kind in (2, 3, 4):
                if not isinstance(message, bytes):
                    raise RuntimeError('Stavová tabulka není binární.')
                for key, value in decode_states(kind, message).items():
                    if key in wanted:
                        found[key] = value
        if not acknowledged:
            raise RuntimeError('Miniserver nepotvrdil odběr stavů.')
        return found
    finally:
        ws.settimeout(previous_timeout)


def read_structure(ws, timeout=30):
    ws.send('data/LoxAPP3.json')
    deadline = time.monotonic() + timeout
    previous = ws.gettimeout()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Vypršel čas načítání struktury.')
            ws.settimeout(remaining)
            message = ws.recv()
            if message == '' or message == b'':
                raise RuntimeError('Spojení ukončeno při načítání struktury.')
            if isinstance(message, bytes):
                continue
            data = json.loads(message)
            if isinstance(data, dict) and 'LL' in data:
                data = require_success(data['LL'], 'LoxAPP3.json')
                if isinstance(data, str):
                    data = json.loads(data)
            if isinstance(data, dict) and isinstance(data.get('controls'), dict):
                return data
    finally:
        ws.settimeout(previous)


def find_block(structure, name, room=None):
    matches = []
    rooms = structure.get('rooms', {})
    def visit(controls, inherited_room=None, path=()):
        for key, control in controls.items():
            if not isinstance(control, dict):
                continue
            room_id = control.get('room') or inherited_room
            room_name = rooms.get(room_id, {}).get('name', '')
            current_path = path + (control.get('name', key),)
            if str(control.get('name', '')).casefold() == name.casefold() and (room is None or room_name.casefold() == room.casefold()):
                matches.append((control, room_name, current_path))
            visit(control.get('subControls', {}), room_id, current_path)
    visit(structure['controls'])
    if not matches:
        raise RuntimeError(f'Blok „{name}“ nebyl nalezen. Ověřte název a oprávnění uživatele.')
    if len(matches) > 1:
        locations = '; '.join(f"{' / '.join(path)} (místnost: {r or 'neuvedena'})" for _, r, path in matches)
        raise RuntimeError(f'Název bloku není jednoznačný: {locations}. Upřesněte --room nebo použijte jedinečný název bloku.')
    control, room_name, path = matches[0]
    bindings = []
    def collect(block, block_path):
        for state, state_id in block.get('states', {}).items():
            if isinstance(state_id, str) and UUID_PATTERN.fullmatch(state_id.lower()):
                bindings.append({'block': ' / '.join(block_path), 'state': state, 'uuid': state_id.lower()})
        for key, child in block.get('subControls', {}).items():
            if isinstance(child, dict):
                collect(child, block_path + (child.get('name', key),))
    collect(control, path)
    if not bindings:
        raise RuntimeError('Vybraný blok ani jeho podřízené bloky nemají čitelné UUID stavů.')
    return {'name': control.get('name'), 'type': control.get('type'), 'room': room_name}, bindings


def connection_url(host, tls=False, port=None):
    if not host or host != host.strip() or any(c in host for c in '/@?#'):
        raise ValueError('Zadejte pouze IP adresu nebo hostname, bez protokolu a cesty.')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host)
        authority = f'[{address}]' if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('Neplatná adresa. Port zadávejte samostatně pomocí --port.') from None
        authority = host
    if port is not None:
        if not 1 <= port <= 65535:
            raise ValueError('Port musí být mezi 1 a 65535.')
        authority += f':{port}'
    return f"{'wss' if tls else 'ws'}://{authority}/ws/rfc6455"


def main():
    parser = argparse.ArgumentParser(description='Načtení stavů Loxone podle názvu bloku.')
    parser.add_argument('--block', required=True, help='Přesný název bloku (bez rozlišení velikosti písmen)')
    parser.add_argument('--room', help='Název místnosti pro rozlišení stejně pojmenovaných bloků')
    parser.add_argument('--timeout', type=float, default=30, help='Čekání na počáteční stavy v sekundách (výchozí 30)')
    parser.add_argument('--host', required=True, help='IP adresa nebo hostname Miniserveru')
    parser.add_argument('--tls', action='store_true', help='Šifrované WSS spojení')
    parser.add_argument('--port', type=int, help='Vlastní port (jinak 80 nebo 443 pro TLS)')
    parser.add_argument('--user', required=True, help='Uživatel Miniserveru')
    parser.add_argument('--client-id', help='Volitelné stabilní UUID klienta ve formátu Loxone')
    args = parser.parse_args()
    try:
        url = connection_url(args.host, args.tls, args.port)
    except ValueError as error:
        parser.error(str(error))
    client_hex = uuid.uuid4().hex
    client_id = args.client_id or f'{client_hex[:8]}-{client_hex[8:12]}-{client_hex[12:16]}-{client_hex[16:]}'
    if not UUID_PATTERN.fullmatch(client_id):
        parser.error('Neplatné --client-id.')
    if not args.block.strip():
        parser.error('--block nesmí být prázdný.')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout musí být kladné konečné číslo.')
    ws = None
    try:
        password = getpass.getpass('Heslo Loxone: ')
        ws = websocket.create_connection(url, timeout=10)
        authenticate(ws, args.user, password, client_id)
        structure = read_structure(ws, args.timeout)
        block, bindings = find_block(structure, args.block, args.room)
        uuids = list(dict.fromkeys(binding['uuid'] for binding in bindings))
        values = read_states(ws, uuids, args.timeout)
        missing = [u for u in uuids if u not in values]
        print(json.dumps({'block': block, 'states': [{**binding, **values.get(binding['uuid'], {'type': 'missing', 'value': None})} for binding in bindings], 'missing': missing}, ensure_ascii=False, indent=2, allow_nan=False))
        if missing:
            print('Některé stavy nepřišly. Ověřte UUID stavu, oprávnění a dostupnost ve vizualizaci.', file=sys.stderr)
            return 2
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # WebSocket chyby mohou obsahovat citlivé údaje; vypisujeme pouze jejich typ.
        print('Chyba: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        return 1
    finally:
        if ws is not None:
            ws.close()


if __name__ == '__main__':
    sys.exit(main())
