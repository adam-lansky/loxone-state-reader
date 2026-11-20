import hashlib
import hmac
import json
import struct
import unittest
from unittest.mock import Mock, patch
import read_uuids as reader

UUID = '00000001-0002-0003-0405060708090a0b'  # Synthetic test fixture.
RAW = struct.pack('<IHH',1,2,3)+bytes(range(4,12))
def frame(kind,payload):
    size=len(payload.encode()) if isinstance(payload,str) else len(payload)
    return [struct.pack('<BBBBI',3,kind,0,0,size),payload]

class ReaderTests(unittest.TestCase):
    def test_hashes(self):
        for name in ('SHA1','SHA256'):
            digest=getattr(hashlib,name.lower())
            hashed=digest(b'example:salt').hexdigest().upper()
            expected=hmac.new(bytes.fromhex('0102'),('user:'+hashed).encode(),digest).hexdigest()
            self.assertEqual(reader.create_auth_hash('user','example','0102','salt',name),expected)
    def test_auth(self):
        with patch.object(reader,'send_command',side_effect=[{'Code':200,'value':{'key':'0102','salt':'salt','hashAlg':'SHA1'}},{'Code':200,'value':{'token':'fake'}}]) as send:
            reader.authenticate(Mock(),'user','example',UUID)
        self.assertEqual(send.call_args_list[0].args[1],'jdev/sys/getkey2/user')
        self.assertTrue(send.call_args_list[1].args[1].endswith('/user/2/'+UUID+'/python-state-reader'))
        self.assertEqual(send.call_count,2)
    def test_decode(self):
        self.assertEqual(reader.decode_states(2,RAW+struct.pack('<d',21.5))[UUID]['value'],21.5)
        text='Čas'.encode()
        data=RAW+bytes(16)+struct.pack('<I',len(text))+text+bytes(-len(text)%4)
        self.assertEqual(reader.decode_states(3,data)[UUID]['value'],'Čas')
        data=RAW+struct.pack('<di',0,1)+struct.pack('<iiiid',3,480,600,0,1)
        self.assertEqual(reader.decode_states(4,data)[UUID]['value']['entries'][0]['from'],480)
    def test_subscribe(self):
        ack=json.dumps({'LL':{'control':'dev/sps/enablebinstatusupdate','Code':200}})
        ws=Mock();ws.gettimeout.return_value=10
        ws.recv.side_effect=frame(2,RAW+struct.pack('<d',21.5))+frame(0,ack)
        self.assertEqual(reader.read_states(ws,[UUID])[UUID]['value'],21.5)
        ws.send.assert_called_once_with('jdev/sps/enablebinstatusupdate')
        ws.settimeout.assert_called_with(10)
    def test_invalid(self):
        for kind,data in [(2,b'bad'),(4,RAW+struct.pack('<di',0,-1)),(3,RAW)]:
            with self.assertRaises(RuntimeError):reader.decode_states(kind,data)
    def test_redaction(self):
        with self.assertRaises(RuntimeError) as caught:
            reader.require_success({'Code':401,'value':'private-token'},'getjwt')
        self.assertNotIn('private-token',str(caught.exception))

if __name__=='__main__':unittest.main()

class DiscoveryTests(unittest.TestCase):
    def structure(self):
        return {'rooms': {'r': {'name': 'Obývák'}}, 'controls': {'a': {'name': 'Topení', 'room': 'r', 'type':'IRoomControllerV2', 'states':{'temperature':UUID}, 'subControls':{'b':{'name':'Rozvrh','states':{'entries':UUID}}}}}}
    def test_lookup_and_subcontrol(self):
        block,bindings=reader.find_block(self.structure(),'topení','obývák')
        self.assertEqual(block['name'],'Topení')
        self.assertEqual(len(bindings),2)
        self.assertEqual(bindings[1]['block'],'Topení / Rozvrh')
    def test_ambiguous_and_missing(self):
        data=self.structure()
        data['controls']['duplicate']={'name':'Topení','states':{'value':UUID}}
        with self.assertRaisesRegex(RuntimeError,'jednoznačný'):reader.find_block(data,'Topení')
        self.assertEqual(reader.find_block(data,'Topení','Obývák')[0]['room'],'Obývák')
        with self.assertRaisesRegex(RuntimeError,'nebyl nalezen'):reader.find_block(data,'Unknown')
    def test_structure_download(self):
        ws=Mock();ws.gettimeout.return_value=10
        ws.recv.side_effect=frame(0,json.dumps(self.structure()))
        self.assertEqual(reader.read_structure(ws),self.structure())
        ws.send.assert_called_once_with('data/LoxAPP3.json')
    def test_host(self):
        self.assertEqual(reader.connection_url('192.0.2.10'),'ws://192.0.2.10/ws/rfc6455')
        self.assertEqual(reader.connection_url('miniserver.example',True,8443),'wss://miniserver.example:8443/ws/rfc6455')
        self.assertEqual(reader.connection_url('::1'),'ws://[::1]/ws/rfc6455')
        for host in ('http://example','user@example','example/path','example:80',' example'):
            with self.assertRaises(ValueError):reader.connection_url(host)
