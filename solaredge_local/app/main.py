import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
from pathlib import Path

import aiohttp
import aiomqtt

from . import __version__
from . import discovery as d
from .config import ConfigError, Options, load_mqtt_settings, load_options, parse_inverter_key
from .fritzbox import FritzBox, FritzBoxAuthError, FritzBoxError
from .mqtt import Publisher
from .pcap import PcapStreamParser
from .reconnect import ForcedReconnect, ReconnectTrigger
from .solaredge import Decoder, split_messages
from .tcp import TcpReassembler
from .tr064 import HostFilter, tr064_session

log = logging.getLogger("solaredge_local")

BACKOFF_MIN_S = 5
BACKOFF_MAX_S = 300
AUTH_BACKOFF_S = 900


def stream_handler(decoder: Decoder):
    def on_stream(buf: bytearray) -> None:
        for hdr, payload in split_messages(buf):
            try:
                decoder.handle(hdr, payload)
            except Exception:
                log.exception("Failed to decode message 0x%04x", hdr[3])
    return on_stream


async def capture_loop(opts: Options, decoder: Decoder, publisher: Publisher) -> None:
    bpf = "host %s" % opts.inverter_ip
    backoff = BACKOFF_MIN_S
    last_error = None
    async with aiohttp.ClientSession() as session:
        fb = FritzBox(session, opts.fritzbox_host, opts.fritzbox_user, opts.fritzbox_password)
        try:
            while True:
                parser = PcapStreamParser()
                try:
                    await fb.login()
                    # A capture left running by a previous container blocks a new one.
                    await fb.stop(opts.capture_interface)
                    tcp = TcpReassembler(stream_handler(decoder))
                    async for chunk in fb.capture(opts.capture_interface, bpf):
                        if parser.received_bytes == 0:
                            log.info("Capturing %s on FRITZ!Box %s (%s)", bpf, opts.fritzbox_host,
                                     opts.capture_interface)
                            publisher.set_capture_state("connected")
                            backoff, last_error = BACKOFF_MIN_S, None
                        for frame in parser.feed(chunk):
                            tcp.packet(frame)
                        await publisher.flush()
                    if parser.received_bytes == 0:
                        raise FritzBoxError("FRITZ!Box closed the capture without data (wrong capture interface, "
                                            "user lacks the 'FRITZ!Box settings' permission, or capture busy)")
                    raise FritzBoxError("Capture stream ended")
                except FritzBoxAuthError as e:
                    error, delay = str(e), AUTH_BACKOFF_S
                except (FritzBoxError, aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as e:
                    error, delay = "%s: %s" % (type(e).__name__, e), backoff
                    backoff = min(backoff * 2, BACKOFF_MAX_S)
                except Exception as e:
                    log.exception("Unexpected capture error")
                    error, delay = "%s: %s" % (type(e).__name__, e), backoff
                    backoff = min(backoff * 2, BACKOFF_MAX_S)
                if error != last_error:
                    log.warning("%s - retrying in %d s", error, delay)
                    last_error = error
                else:
                    log.debug("%s - retrying in %d s", error, delay)
                publisher.set_capture_state("disconnected")
                await publisher.flush()
                await asyncio.sleep(delay)
        finally:
            await asyncio.shield(fb.stop(opts.capture_interface))


async def mqtt_loop(publisher: Publisher) -> None:
    backoff = BACKOFF_MIN_S
    last_error = None
    while True:
        try:
            settings = await load_mqtt_settings()
            async with aiomqtt.Client(
                hostname=settings.host, port=settings.port,
                username=settings.username, password=settings.password,
                identifier="solaredge_local",
                will=aiomqtt.Will(d.STATUS_TOPIC, "offline", qos=1, retain=True),
            ) as client:
                log.info("Connected to MQTT broker %s:%d", settings.host, settings.port)
                backoff, last_error = BACKOFF_MIN_S, None
                await client.subscribe(d.DISCOVERY_PREFIX + "/status")
                await publisher.attach(client)
                try:
                    async for message in client.messages:
                        if message.payload == b"online":
                            log.info("Home Assistant restarted, republishing discovery")
                            await publisher.attach(client)
                finally:
                    publisher.detach()
                    with contextlib.suppress(aiomqtt.MqttError):
                        await asyncio.shield(client.publish(d.STATUS_TOPIC, "offline", qos=1, retain=True))
        except (aiomqtt.MqttError, ConfigError, aiohttp.ClientError) as e:
            if str(e) != last_error:
                log.warning("MQTT: %s - retrying in %d s", e, backoff)
                last_error = str(e)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX_S)


async def run_live(opts: Options, data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    session_key_file = data_dir / "se_session_key.bin"
    publisher = Publisher(__version__, opts.optimizer_details, data_dir / "device_info.json")
    trigger = ReconnectTrigger()

    def on_key_state(valid: bool) -> None:
        publisher.set_session_key_valid(valid)
        if valid:
            trigger.key_valid()

    saved_key = session_key_file.read_bytes() if session_key_file.exists() else None
    decoder = Decoder(opts.inverter_key, publisher.handle_telemetry, session_key_file.write_bytes,
                      on_key_state, saved_key, on_undecryptable=trigger.undecryptable_traffic)
    async with contextlib.AsyncExitStack() as stack, asyncio.TaskGroup() as tg:
        tg.create_task(mqtt_loop(publisher))
        tg.create_task(capture_loop(opts, decoder, publisher))
        if opts.force_reconnect:
            session = await stack.enter_async_context(tr064_session(opts.fritzbox_user, opts.fritzbox_password))
            reconnect = ForcedReconnect(HostFilter(session, opts.fritzbox_host), opts.inverter_ip, trigger,
                                        data_dir / "inverter_blocked")
            tg.create_task(reconnect.run())


def run_replay(capture_file: Path, key: bytes, details: bool) -> None:
    def print_telemetry(t: dict) -> None:
        if t["kind"] == "inverter_3ph":
            print("INVERTER", t["id"], json.dumps(d.inverter_state(t)))
        elif t["kind"] == "optimizer":
            print("OPTIMIZER", t["id"], json.dumps(d.optimizer_state(t, details)))
        else:
            print(t["kind"].upper(), json.dumps(t))

    decoder = Decoder(key, print_telemetry)
    tcp = TcpReassembler(stream_handler(decoder))
    parser = PcapStreamParser()
    with capture_file.open("rb") as f:
        while chunk := f.read(65536):
            for frame in parser.feed(chunk):
                tcp.packet(frame)


def main() -> None:
    ap = argparse.ArgumentParser(description="SolarEdge Local – FRITZ!Box capture to MQTT")
    ap.add_argument("--options", type=Path, default=Path("/data/options.json"))
    ap.add_argument("--data-dir", type=Path, default=Path("/data"))
    ap.add_argument("--replay", type=Path, help="decode a saved capture file and print it (key from SE_KEY)")
    args = ap.parse_args()

    if args.replay:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
        run_replay(args.replay, parse_inverter_key(os.environ.get("SE_KEY", "")), details=True)
        return

    try:
        opts = load_options(args.options)
    except ConfigError as e:
        logging.basicConfig(format="%(levelname)s %(message)s")
        log.error("Configuration error: %s", e)
        sys.exit(1)
    logging.basicConfig(level=opts.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("SolarEdge Local %s starting", __version__)
    asyncio.run(_run_until_signal(opts, args.data_dir),
                loop_factory=asyncio.SelectorEventLoop if sys.platform == "win32" else None)


async def _run_until_signal(opts: Options, data_dir: Path) -> None:
    task = asyncio.current_task()
    if sys.platform != "win32":
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        await run_live(opts, data_dir)
    except asyncio.CancelledError:
        log.info("Stopped")


if __name__ == "__main__":
    main()
