import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install-chat-client.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as bundle:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = '../../outside'
            bundle.addfile(member, io.BytesIO(data) if member.isfile() else None)
    return output.getvalue()


class InstallClientTests(unittest.TestCase):
    def test_rejects_escape_links_and_duplicate_entries(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('assets/link', tarfile.SYMTYPE), ('assets/device', tarfile.CHRTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'bundle.tar.gz').write_bytes(archive([(name,b'private',kind)]))
                with self.assertRaises(ValueError):
                    installer.extract(root/'bundle.tar.gz', root/'web')
                self.assertFalse((root/'escape').exists())

    def test_checks_digest_before_publishing_and_installs_atomically(self):
        payload = archive([('index.html',b'<html></html>',tarfile.REGTYPE),
                           ('assets',b'',tarfile.DIRTYPE),('assets/app.js',b'export{}',tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {'protocol_version':1,'web':{
                'url':'https://github.com/MagnetosphereLabs/VortexChat/releases/download/vortex-v0.1.0/vortex-chat-web.tar.gz',
                'sha256':'0'*64}}
            lock = root/'lock.json'
            lock.write_text(json.dumps(manifest))
            class Opener:
                def open(self, url, timeout):
                    return io.BytesIO(payload)
            with patch.object(installer.urllib.request,'build_opener',return_value=Opener()):
                with self.assertRaises(ValueError):
                    installer.install(lock,root/'web')
                self.assertFalse((root/'web').exists())
                manifest['web']['sha256']=hashlib.sha256(payload).hexdigest()
                lock.write_text(json.dumps(manifest))
                installer.install(lock,root/'web')
                self.assertEqual((root/'web/assets/app.js').read_bytes(),b'export{}')
                self.assertEqual((root/'web').stat().st_mode&0o777,0o755)
                installer.install(lock,root/'web')
                manifest['web']['sha256']='1'*64
                lock.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    installer.install(lock,root/'web')
                self.assertEqual((root/'web/index.html').read_text(),'<html></html>')

    def test_rejects_http_redirect(self):
        with self.assertRaises(ValueError):
            installer.HTTPSRedirect().redirect_request(None,None,302,'',{},'http://example.com/file')


if __name__ == '__main__':
    unittest.main()
