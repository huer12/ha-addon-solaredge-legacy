import logging
import re
import xml.etree.ElementTree as ET

import aiohttp

log = logging.getLogger(__name__)

HOSTFILTER = "urn:dslforum-org:service:X_AVM-DE_HostFilter:1"
TIMEOUT = aiohttp.ClientTimeout(total=15)


class Tr064Error(Exception):
    pass


def soap_envelope(action: str, service: str, args: dict) -> str:
    body = "".join("<%s>%s</%s>" % (k, v, k) for k, v in args.items())
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>') % (action, service, body, action)


def find_control_url(description_xml: bytes, service_type: str) -> str | None:
    for svc in ET.fromstring(description_xml).iter():
        if svc.tag.endswith("service"):
            st = next((c.text for c in svc if c.tag.endswith("serviceType")), "")
            if st == service_type:
                return next((c.text for c in svc if c.tag.endswith("controlURL")), None)
    return None


class HostFilter:
    """FRITZ!Box TR-064 X_AVM-DE_HostFilter: block/unblock internet access of one LAN device."""

    def __init__(self, session: aiohttp.ClientSession, host: str, port: int = 49000):
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
        self._base = "http://%s:%d" % (host, port)
        self._session = session
        self._control_url: str | None = None

    async def _control(self) -> str:
        if not self._control_url:
            async with self._session.get(self._base + "/tr64desc.xml", timeout=TIMEOUT) as resp:
                resp.raise_for_status()
                url = find_control_url(await resp.read(), HOSTFILTER)
            if not url:
                raise Tr064Error("FRITZ!Box offers no X_AVM-DE_HostFilter service (FRITZ!OS too old?)")
            self._control_url = url
        return self._base + self._control_url

    async def _call(self, action: str, **args) -> dict:
        headers = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (HOSTFILTER, action)}
        async with self._session.post(await self._control(), data=soap_envelope(action, HOSTFILTER, args),
                                      headers=headers, timeout=TIMEOUT) as resp:
            text = await resp.text()
            if resp.status != 200:
                if resp.status == 401:
                    raise Tr064Error("TR-064 %s: not authorized. Enable 'Zugriff für Anwendungen zulassen' "
                                     "and give the user the 'FRITZ!Box settings' permission" % action)
                code = re.search(r"<errorCode>(\d+)</errorCode>", text)
                desc = re.search(r"<errorDescription>(.*?)</errorDescription>", text)
                raise Tr064Error("TR-064 %s failed: HTTP %d %s %s" % (
                    action, resp.status, code.group(1) if code else "", desc.group(1) if desc else ""))
        return dict(re.findall(r"<(New\w+)>(.*?)</New\w+>", text))

    async def set_blocked(self, ip: str, blocked: bool) -> None:
        await self._call("DisallowWANAccessByIP", NewIPv4Address=ip, NewDisallow=1 if blocked else 0)

    async def is_blocked(self, ip: str) -> bool:
        return (await self._call("GetWANAccessByIP", NewIPv4Address=ip)).get("NewDisallow") == "1"


def tr064_session(user: str, password: str) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(middlewares=(aiohttp.DigestAuthMiddleware(user, password),))
