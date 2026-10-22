#!/usr/bin/env python3
"""Install the web archive pinned by this Node release, without running its contents."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

MAX_ARCHIVE = 512 * 1024**2
MAX_EXTRACTED = 2 * 1024**3


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.username or parsed.password:
            raise ValueError('The client download attempted an insecure redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def extract(archive, destination):
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) > 25000 or sum(m.size for m in members) > MAX_EXTRACTED:
            raise ValueError('The client archive exceeds its extraction limit')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or '\\' in member.name:
                raise ValueError('Invalid client archive path')
            if not member.isdir() and not member.isfile():
                raise ValueError('Links and special files are forbidden in the web client')
            if str(path) == '.':
                if not member.isdir():
                    raise ValueError('Invalid archive root')
                continue
            if path in seen:
                raise ValueError('Duplicate client archive entry')
            seen.add(path)
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, 1024**2)
                target.chmod(0o644)
        if not (destination / 'index.html').is_file() or not (destination / 'assets').is_dir():
            raise ValueError('The release archive is missing the web application')


def install(manifest_path, destination):
    manifest = json.loads(Path(manifest_path).read_text())
    client = manifest['web']
    digest, url = client['sha256'], client['url']
    if manifest['protocol_version'] != 1 or not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('Unsupported or invalid pinned web client manifest')
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/VortexChat/releases/download/[A-Za-z0-9_.-]+/vortex-chat-web\.tar\.gz', url):
        raise ValueError('The web client must be a pinned VortexChat GitHub release')
    destination = Path(destination)
    if destination.exists():
        if (destination / 'vortex-client-lock.json').read_text() != json.dumps(manifest, sort_keys=True):
            raise ValueError('A different client already exists in this immutable Node release')
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='chat-install-', dir=destination.parent) as temporary:
        temporary = Path(temporary)
        archive = temporary / 'client.tar.gz'
        checksum, size = hashlib.sha256(), 0
        opener = urllib.request.build_opener(HTTPSRedirect())
        with opener.open(url, timeout=60) as response, archive.open('xb') as output:
            while chunk := response.read(1024**2):
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise ValueError('The client download exceeds its size limit')
                checksum.update(chunk)
                output.write(chunk)
        if checksum.hexdigest() != digest:
            raise ValueError('The downloaded web client does not match its pinned checksum')
        staging = temporary / 'web'
        staging.mkdir(mode=0o755)
        extract(archive, staging)
        marker = staging / 'vortex-client-lock.json'
        marker.write_text(json.dumps(manifest, sort_keys=True))
        marker.chmod(0o644)
        for directory, _, _ in os.walk(staging):
            Path(directory).chmod(0o755)
        staging.rename(destination)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: install-chat-client.py CLIENTS_LOCK DESTINATION')
    install(*sys.argv[1:])
