"""PackGuard behavior-graph schema: 6 semantic classes + per-language API mapping.

Semantics of the 6 classes (schema version 1.0.0):

- FILE_IO      : create/read/write/delete of files and paths on the host FS.
- NETWORK      : outbound/inbound network I/O (HTTP clients, raw sockets, DNS-ish
                 connectors, FTP/Telnet clients).
- PROCESS      : spawning or controlling other processes / shell command execution.
- CRYPTO       : hashing, ciphers, key derivation, random bytes, and encoders that
                 malicious packages routinely abuse for obfuscation (base64, zlib).
- DYNAMIC_CODE : dynamic code construction/execution (eval/exec/compile, VM modules,
                 unsafe deserialization such as pickle.loads / marshal).
- DATA_ACCESS  : structured data stores (SQL/NoSQL clients, keyring) and sensitive
                 host-state reads (os.environ / process.env).

Matching rules (deterministic, disclosed):
- For a call `f(...)`, the callee text is matched against the longest dotted pattern
  for the language (e.g. "os.system", "child_process.execSync"); if no dotted pattern
  matches, the bare last identifier is matched against the bare-name table.
- Attribute reads (non-call) are matched only for the explicit ATTRIBUTE_PATTERNS
  (e.g. "os.environ", "process.env").
- Bare-name tables are deliberately coarse for dynamic/aliased module use; this is
  disclosed as a known precision limitation (see docs/packguard_prereg.md).

Any unmapped call is ignored by the extractor (it does not become a graph node).
The mapping tables below are the single source of truth and are versioned via
SCHEMA_VERSION; changing them requires bumping the version.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

SCHEMA_VERSION = "1.1.0"  # 1.1.0: round-8 file-selection fix (BUG-2); mapping tables unchanged

BEHAVIOR_CLASSES: Tuple[str, ...] = (
    "FILE_IO",
    "NETWORK",
    "PROCESS",
    "CRYPTO",
    "DYNAMIC_CODE",
    "DATA_ACCESS",
)

_CLASS_SET = frozenset(BEHAVIOR_CLASSES)


def _check(table: Dict[str, str]) -> Dict[str, str]:
    bad = {k: v for k, v in table.items() if v not in _CLASS_SET}
    if bad:
        raise ValueError(f"mapping references unknown class: {bad}")
    return dict(table)


# ---------------------------------------------------------------------------
# Python mapping
# ---------------------------------------------------------------------------
PYTHON_DOTTED: Dict[str, str] = _check({
    # FILE_IO
    "io.open": "FILE_IO",
    "os.remove": "FILE_IO",
    "os.removedirs": "FILE_IO",
    "os.rename": "FILE_IO",
    "os.renames": "FILE_IO",
    "os.chmod": "FILE_IO",
    "os.chown": "FILE_IO",
    "os.listdir": "FILE_IO",
    "os.makedirs": "FILE_IO",
    "os.mkdir": "FILE_IO",
    "os.scandir": "FILE_IO",
    "os.walk": "FILE_IO",
    "os.link": "FILE_IO",
    "os.symlink": "FILE_IO",
    "shutil.copy": "FILE_IO",
    "shutil.copy2": "FILE_IO",
    "shutil.copytree": "FILE_IO",
    "shutil.move": "FILE_IO",
    "shutil.rmtree": "FILE_IO",
    "shutil.unpack_archive": "FILE_IO",
    "pathlib.Path.read_text": "FILE_IO",
    "pathlib.Path.write_text": "FILE_IO",
    "pathlib.Path.unlink": "FILE_IO",
    "gzip.open": "FILE_IO",
    "zipfile.ZipFile": "FILE_IO",
    "tarfile.open": "FILE_IO",
    # NETWORK
    "socket.socket": "NETWORK",
    "socket.create_connection": "NETWORK",
    "socket.getaddrinfo": "NETWORK",
    "requests.get": "NETWORK",
    "requests.post": "NETWORK",
    "requests.put": "NETWORK",
    "requests.head": "NETWORK",
    "requests.request": "NETWORK",
    "requests.Session": "NETWORK",
    "httpx.get": "NETWORK",
    "httpx.post": "NETWORK",
    "httpx.Client": "NETWORK",
    "urllib.request.urlopen": "NETWORK",
    "urllib.request.urlretrieve": "NETWORK",
    "urllib2.urlopen": "NETWORK",
    "http.client.HTTPConnection": "NETWORK",
    "http.client.HTTPSConnection": "NETWORK",
    "ftplib.FTP": "NETWORK",
    "telnetlib.Telnet": "NETWORK",
    "smtplib.SMTP": "NETWORK",
    "xmlrpc.client.ServerProxy": "NETWORK",
    # PROCESS
    "os.system": "PROCESS",
    "os.popen": "PROCESS",
    "os.execv": "PROCESS",
    "os.execve": "PROCESS",
    "os.execvp": "PROCESS",
    "os.execvpe": "PROCESS",
    "os.execl": "PROCESS",
    "os.execle": "PROCESS",
    "os.execlp": "PROCESS",
    "os.execlpe": "PROCESS",
    "os.spawnv": "PROCESS",
    "os.spawnve": "PROCESS",
    "os.posix_spawn": "PROCESS",
    "subprocess.run": "PROCESS",
    "subprocess.call": "PROCESS",
    "subprocess.check_call": "PROCESS",
    "subprocess.check_output": "PROCESS",
    "subprocess.Popen": "PROCESS",
    "subprocess.getoutput": "PROCESS",
    "subprocess.getstatusoutput": "PROCESS",
    "pty.spawn": "PROCESS",
    "commands.getoutput": "PROCESS",
    # CRYPTO
    "hashlib.md5": "CRYPTO",
    "hashlib.sha1": "CRYPTO",
    "hashlib.sha256": "CRYPTO",
    "hashlib.sha512": "CRYPTO",
    "hashlib.new": "CRYPTO",
    "hmac.new": "CRYPTO",
    "hmac.digest": "CRYPTO",
    "base64.b64encode": "CRYPTO",
    "base64.b64decode": "CRYPTO",
    "base64.b32decode": "CRYPTO",
    "base64.urlsafe_b64decode": "CRYPTO",
    "codecs.decode": "CRYPTO",
    "binascii.unhexlify": "CRYPTO",
    "binascii.a2b_base64": "CRYPTO",
    "zlib.decompress": "CRYPTO",
    "zlib.compress": "CRYPTO",
    "gzip.decompress": "CRYPTO",
    "Crypto.Cipher.AES.new": "CRYPTO",
    "Cryptodome.Cipher.AES.new": "CRYPTO",
    "cryptography.fernet.Fernet": "CRYPTO",
    "secrets.token_hex": "CRYPTO",
    # DYNAMIC_CODE
    "builtins.eval": "DYNAMIC_CODE",
    "builtins.exec": "DYNAMIC_CODE",
    "importlib.import_module": "DYNAMIC_CODE",
    "importlib.__import__": "DYNAMIC_CODE",
    "marshal.loads": "DYNAMIC_CODE",
    "pickle.loads": "DYNAMIC_CODE",
    "pickle.load": "DYNAMIC_CODE",
    "cPickle.loads": "DYNAMIC_CODE",
    "dill.loads": "DYNAMIC_CODE",
    "yaml.load": "DYNAMIC_CODE",
    "yaml.unsafe_load": "DYNAMIC_CODE",
    # DATA_ACCESS
    "sqlite3.connect": "DATA_ACCESS",
    "pymysql.connect": "DATA_ACCESS",
    "MySQLdb.connect": "DATA_ACCESS",
    "psycopg2.connect": "DATA_ACCESS",
    "pymongo.MongoClient": "DATA_ACCESS",
    "redis.StrictRedis": "DATA_ACCESS",
    "redis.Redis": "DATA_ACCESS",
    "keyring.get_password": "DATA_ACCESS",
    "keyring.set_password": "DATA_ACCESS",
    "shelve.open": "DATA_ACCESS",
    "dbm.open": "DATA_ACCESS",
    "configparser.ConfigParser.read": "DATA_ACCESS",
})

PYTHON_BARE: Dict[str, str] = _check({
    "open": "FILE_IO",
    "file": "FILE_IO",
    "input": "FILE_IO",
    "socket": "NETWORK",
    "eval": "DYNAMIC_CODE",
    "exec": "DYNAMIC_CODE",
    "compile": "DYNAMIC_CODE",
    "__import__": "DYNAMIC_CODE",
    "globals": "DYNAMIC_CODE",
})

PYTHON_ATTR: Dict[str, str] = _check({
    "os.environ": "DATA_ACCESS",
})

# ---------------------------------------------------------------------------
# JavaScript mapping (npm)
# ---------------------------------------------------------------------------
JS_DOTTED: Dict[str, str] = _check({
    # FILE_IO
    "fs.readFile": "FILE_IO",
    "fs.readFileSync": "FILE_IO",
    "fs.writeFile": "FILE_IO",
    "fs.writeFileSync": "FILE_IO",
    "fs.appendFile": "FILE_IO",
    "fs.appendFileSync": "FILE_IO",
    "fs.unlink": "FILE_IO",
    "fs.unlinkSync": "FILE_IO",
    "fs.mkdir": "FILE_IO",
    "fs.mkdirSync": "FILE_IO",
    "fs.readdir": "FILE_IO",
    "fs.readdirSync": "FILE_IO",
    "fs.rmdir": "FILE_IO",
    "fs.rmdirSync": "FILE_IO",
    "fs.rmSync": "FILE_IO",
    "fs.stat": "FILE_IO",
    "fs.statSync": "FILE_IO",
    "fs.createReadStream": "FILE_IO",
    "fs.createWriteStream": "FILE_IO",
    "fs.open": "FILE_IO",
    "fs.openSync": "FILE_IO",
    "fs.chmod": "FILE_IO",
    "fs.chmodSync": "FILE_IO",
    "fs.rename": "FILE_IO",
    "fs.renameSync": "FILE_IO",
    "fs.copyFile": "FILE_IO",
    "fs.copyFileSync": "FILE_IO",
    "fs.promises.readFile": "FILE_IO",
    "fs.promises.writeFile": "FILE_IO",
    "fs.promises.readdir": "FILE_IO",
    "fs.promises.unlink": "FILE_IO",
    "fse.copy": "FILE_IO",
    "fs-extra.copy": "FILE_IO",
    # NETWORK
    "http.request": "NETWORK",
    "http.get": "NETWORK",
    "https.request": "NETWORK",
    "https.get": "NETWORK",
    "net.connect": "NETWORK",
    "net.createConnection": "NETWORK",
    "net.Socket": "NETWORK",
    "tls.connect": "NETWORK",
    "dgram.createSocket": "NETWORK",
    "axios.get": "NETWORK",
    "axios.post": "NETWORK",
    "axios.request": "NETWORK",
    "axios.create": "NETWORK",
    "got.get": "NETWORK",
    "got.post": "NETWORK",
    "request.get": "NETWORK",
    "request.post": "NETWORK",
    "superagent.get": "NETWORK",
    "superagent.post": "NETWORK",
    "node-fetch.get": "NETWORK",
    "undici.request": "NETWORK",
    "dns.lookup": "NETWORK",
    "dns.resolve": "NETWORK",
    # PROCESS
    "child_process.exec": "PROCESS",
    "child_process.execSync": "PROCESS",
    "child_process.execFile": "PROCESS",
    "child_process.execFileSync": "PROCESS",
    "child_process.spawn": "PROCESS",
    "child_process.spawnSync": "PROCESS",
    "child_process.fork": "PROCESS",
    "process.kill": "PROCESS",
    "process.exit": "PROCESS",
    "cross-spawn.sync": "PROCESS",
    "execa.command": "PROCESS",
    # CRYPTO
    "crypto.createHash": "CRYPTO",
    "crypto.createHmac": "CRYPTO",
    "crypto.createCipher": "CRYPTO",
    "crypto.createCipheriv": "CRYPTO",
    "crypto.createDecipheriv": "CRYPTO",
    "crypto.randomBytes": "CRYPTO",
    "crypto.randomUUID": "CRYPTO",
    "crypto.pbkdf2Sync": "CRYPTO",
    "crypto.scryptSync": "CRYPTO",
    "crypto.publicEncrypt": "CRYPTO",
    "crypto.privateDecrypt": "CRYPTO",
    "Buffer.from": "CRYPTO",
    "zlib.inflateSync": "CRYPTO",
    "zlib.deflateSync": "CRYPTO",
    "zlib.gunzipSync": "CRYPTO",
    # DYNAMIC_CODE
    "vm.runInNewContext": "DYNAMIC_CODE",
    "vm.runInThisContext": "DYNAMIC_CODE",
    "vm.runInContext": "DYNAMIC_CODE",
    "vm.compileFunction": "DYNAMIC_CODE",
    "Function.constructor": "DYNAMIC_CODE",
    # DATA_ACCESS
    "mongoose.connect": "DATA_ACCESS",
    "mongodb.connect": "DATA_ACCESS",
    "mongodb.MongoClient.connect": "DATA_ACCESS",
    "mysql.createConnection": "DATA_ACCESS",
    "mysql.createPool": "DATA_ACCESS",
    "pg.Client": "DATA_ACCESS",
    "pg.Pool": "DATA_ACCESS",
    "sqlite3.Database": "DATA_ACCESS",
    "keytar.getPassword": "DATA_ACCESS",
    "nodeMachineId.machineIdSync": "DATA_ACCESS",
    "process.cwd": "DATA_ACCESS",
})

JS_BARE: Dict[str, str] = _check({
    "fetch": "NETWORK",
    "XMLHttpRequest": "NETWORK",
    "WebSocket": "NETWORK",
    "readFileSync": "FILE_IO",
    "writeFileSync": "FILE_IO",
    "appendFileSync": "FILE_IO",
    "unlinkSync": "FILE_IO",
    "mkdirSync": "FILE_IO",
    "readdirSync": "FILE_IO",
    "readFile": "FILE_IO",
    "writeFile": "FILE_IO",
    "createReadStream": "FILE_IO",
    "createWriteStream": "FILE_IO",
    "openSync": "FILE_IO",
    "exec": "PROCESS",
    "execSync": "PROCESS",
    "spawn": "PROCESS",
    "spawnSync": "PROCESS",
    "execFile": "PROCESS",
    "eval": "DYNAMIC_CODE",
    "Function": "DYNAMIC_CODE",
    "require": "DYNAMIC_CODE",
    "createHash": "CRYPTO",
    "randomBytes": "CRYPTO",
    "pbkdf2Sync": "CRYPTO",
    "createCipheriv": "CRYPTO",
    "createDecipheriv": "CRYPTO",
})

JS_ATTR: Dict[str, str] = _check({
    "process.env": "DATA_ACCESS",
    "globalThis.process.env": "DATA_ACCESS",
})

# require('fs') style import targets that mark a module as "sensitive" even if the
# call sites are aliased; used for the import_edges side-channel in graphs.py.
JS_IMPORT_MODULES: Dict[str, str] = _check({
    "fs": "FILE_IO",
    "fs/promises": "FILE_IO",
    "fs-extra": "FILE_IO",
    "http": "NETWORK",
    "https": "NETWORK",
    "net": "NETWORK",
    "tls": "NETWORK",
    "dgram": "NETWORK",
    "dns": "NETWORK",
    "axios": "NETWORK",
    "got": "NETWORK",
    "request": "NETWORK",
    "node-fetch": "NETWORK",
    "child_process": "PROCESS",
    "cross-spawn": "PROCESS",
    "execa": "PROCESS",
    "crypto": "CRYPTO",
    "zlib": "CRYPTO",
    "vm": "DYNAMIC_CODE",
    "mongoose": "DATA_ACCESS",
    "mongodb": "DATA_ACCESS",
    "mysql": "DATA_ACCESS",
    "pg": "DATA_ACCESS",
    "sqlite3": "DATA_ACCESS",
    "keytar": "DATA_ACCESS",
})

PYTHON_IMPORT_MODULES: Dict[str, str] = _check({
    "socket": "NETWORK",
    "requests": "NETWORK",
    "httpx": "NETWORK",
    "urllib": "NETWORK",
    "urllib2": "NETWORK",
    "urllib.request": "NETWORK",
    "ftplib": "NETWORK",
    "telnetlib": "NETWORK",
    "smtplib": "NETWORK",
    "subprocess": "PROCESS",
    "pty": "PROCESS",
    "hashlib": "CRYPTO",
    "hmac": "CRYPTO",
    "base64": "CRYPTO",
    "binascii": "CRYPTO",
    "zlib": "CRYPTO",
    "gzip": "CRYPTO",
    "codecs": "CRYPTO",
    "Crypto": "CRYPTO",
    "Cryptodome": "CRYPTO",
    "cryptography": "CRYPTO",
    "marshal": "DYNAMIC_CODE",
    "pickle": "DYNAMIC_CODE",
    "cPickle": "DYNAMIC_CODE",
    "dill": "DYNAMIC_CODE",
    "importlib": "DYNAMIC_CODE",
    "sqlite3": "DATA_ACCESS",
    "pymongo": "DATA_ACCESS",
    "pymysql": "DATA_ACCESS",
    "MySQLdb": "DATA_ACCESS",
    "psycopg2": "DATA_ACCESS",
    "redis": "DATA_ACCESS",
    "keyring": "DATA_ACCESS",
})


def mapping_for(language: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Return (dotted, bare, attr) mapping tables for a language.

    Raises ValueError for unsupported languages so callers fail loudly.
    """
    if language == "python":
        return PYTHON_DOTTED, PYTHON_BARE, PYTHON_ATTR
    if language == "javascript":
        return JS_DOTTED, JS_BARE, JS_ATTR
    raise ValueError(f"unsupported language: {language!r}")


def import_module_class(language: str, module: str) -> str | None:
    """Class implied by importing `module`, or None if unlisted."""
    table = PYTHON_IMPORT_MODULES if language == "python" else JS_IMPORT_MODULES
    return table.get(module)


def schema_json() -> dict:
    """Machine-readable schema document (versioned) describing graph + features."""
    from packguard.features import FEATURE_NAMES  # local import: avoid cycle

    return {
        "schema_version": SCHEMA_VERSION,
        "behavior_classes": list(BEHAVIOR_CLASSES),
        "languages": ["javascript", "python"],
        "node": {"id": "int", "cls": "one of behavior_classes", "api": "matched pattern string"},
        "edge": {"src": "int", "dst": "int", "kind": "seq|data"},
        "graph_level_features": list(FEATURE_NAMES),
        "entry_kinds": ["lib", "setup", "postinstall"],
        "matching_rules": {
            "dotted_priority": "longest dotted pattern wins",
            "bare_fallback": True,
            "attribute_patterns": sorted(set(PYTHON_ATTR) | set(JS_ATTR)),
            "unmapped_calls": "ignored (not nodes)",
        },
    }
