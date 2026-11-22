# Login and capture approach as in https://github.com/arn-c0de/fritzdump
import asyncio
import hashlib
import logging
import re
from collections.abc import AsyncIterator
from urllib.parse import quote, urlencode

import aiohttp
from yarl import URL

log = logging.getLogger(__name__)

LOGIN_TIMEOUT = aiohttp.ClientTimeout(total=15)
# The inverter sends a keep-alive every ~2 minutes, so 10 minutes of silence means the stream is dead.
CAPTURE_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=600)


class FritzBoxError(Exception):
    pass


class FritzBoxAuthError(FritzBoxError):
    pass


def challenge_response(challenge: str, password: str) -> str:
    if challenge.startswith("2$"):
        _, iter1, salt1, iter2, salt2 = challenge.split("$")
        h1 = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt1), int(iter1))
        h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(salt2), int(iter2))
        return salt2 + "$" + h2.hex()
    md5 = hashlib.md5((challenge + "-" + password).encode("utf-16le")).hexdigest()
    return challenge + "-" + md5


def _xml_value(xml: str, tag: str) -> str:
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), xml)
    if not m:
        raise FritzBoxError("Unexpected login response from FRITZ!Box (no <%s>)" % tag)
    return m.group(1)


class FritzBox:
    def __init__(self, session: aiohttp.ClientSession, host: str, user: str, password: str):
        self._session = session
        self._base = host.rstrip("/") if host.startswith("http") else "http://" + host
        self._user = user
        self._password = password
        self._sid: str | None = None

    def _url(self, path: str, query: dict) -> URL:
        # Spaces must be %20: with '+' the FRITZ!Box closes the capture stream immediately.
        return URL(self._base + path + "?" + urlencode(query, quote_via=quote), encoded=True)

    async def _get_text(self, path: str, query: dict) -> str:
        async with self._session.get(self._url(path, query), timeout=LOGIN_TIMEOUT) as resp:
            resp.raise_for_status()
            return await resp.text()

    async def login(self) -> None:
        xml = await self._get_text("/login_sid.lua", {"version": 2})
        block_time = int(_xml_value(xml, "BlockTime"))
        if block_time:
            log.warning("FRITZ!Box blocks logins for %d s, waiting", block_time)
            await asyncio.sleep(block_time)
            xml = await self._get_text("/login_sid.lua", {"version": 2})
        response = challenge_response(_xml_value(xml, "Challenge"), self._password)
        xml = await self._get_text("/login_sid.lua", {"version": 2, "username": self._user, "response": response})
        sid = _xml_value(xml, "SID")
        if set(sid) == {"0"}:
            raise FritzBoxAuthError("FRITZ!Box login failed: wrong user or password")
        self._sid = sid

    async def capture(self, iface: str, bpf: str) -> AsyncIterator[bytes]:
        query = {"ifaceorminor": iface, "snaplen": 1600, "filter": bpf, "capture": "Start", "sid": self._sid}
        async with self._session.get(self._url("/cgi-bin/capture_notimeout", query),
                                     timeout=CAPTURE_TIMEOUT) as resp:
            if resp.status != 200:
                raise FritzBoxError("Capture request failed with HTTP %d" % resp.status)
            async for chunk in resp.content.iter_any():
                yield chunk

    async def stop(self, iface: str) -> None:
        if not self._sid:
            return
        query = {"ifaceorminor": iface, "capture": "Stop", "sid": self._sid}
        try:
            async with self._session.get(self._url("/cgi-bin/capture_notimeout", query),
                                         timeout=aiohttp.ClientTimeout(total=5)) as resp:
                await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.debug("Stopping capture failed: %s", e)
