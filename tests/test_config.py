import pytest

from app.config import ConfigError, parse_options
from app.fritzbox import challenge_response

VALID = {
    "fritzbox_user": "solar-capture",
    "fritzbox_password": "secret",
    "inverter_ip": "192.168.178.50",
    "inverter_key": "00112233445566778899aabbccddeeff",
}


def test_defaults_are_applied():
    opts = parse_options(VALID)

    assert opts.fritzbox_host == "fritz.box"
    assert opts.capture_interface == "1-lan"
    assert opts.inverter_key == bytes.fromhex(VALID["inverter_key"])
    assert opts.optimizer_details is False


def test_key_with_separators_is_accepted():
    opts = parse_options({**VALID, "inverter_key": "00:11:22:33 44:55:66:77-8899AABBCCDDEEFF"})

    assert len(opts.inverter_key) == 16


@pytest.mark.parametrize("override, message", [
    ({"fritzbox_password": ""}, "fritzbox_password"),
    ({"inverter_ip": None}, "inverter_ip"),
    ({"inverter_ip": "192.168.178.300"}, "IPv4"),
    ({"inverter_key": "abc"}, "32 hex"),
    ({"inverter_key": "zz112233445566778899aabbccddeeff"}, "32 hex"),
])
def test_invalid_options_are_rejected(override, message):
    with pytest.raises(ConfigError, match=message):
        parse_options({**VALID, **override})


def test_pbkdf2_challenge_response_format():
    response = challenge_response("2$10$5A1711$2000$5A1722", "1example!")

    salt2, digest = response.split("$")
    assert salt2 == "5A1722"
    assert len(digest) == 64
