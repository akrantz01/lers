import logging
from os import environ, listdir
from pathlib import Path
import signal
import time

import josepy
import requests
from acme.client import ClientNetwork, ClientV2
from acme.messages import Directory, NewRegistration
from josepy import JWK, JWASignature, JWKEC, JWKRSA

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

DIRECTORY = environ.get("DIRECTORY", "https://10.30.50.2:14000/dir")
ACCOUNTS = Path(environ.get("ACCOUNTS", "testdata/accounts"))


def wait_for_acme_server():
    """
    Wait for the directory URL to respond
    """
    while True:
        try:
            response = requests.get(DIRECTORY, verify=False)
            if response.status_code == 200:
                return
        except requests.exceptions.ConnectionError as e:
            print(e)
            pass

        time.sleep(0.1)


def alg_for_key(key: JWK) -> JWASignature:
    if isinstance(key, JWKRSA):
        return josepy.RS256
    elif isinstance(key, JWKEC):
        curve = key.fields_to_partial_json()["crv"]
        if curve == "P-256":
            return josepy.ES256
        elif curve == "P-384":
            return josepy.ES384
        elif curve == "P-521":
            return josepy.ES512

    raise ValueError(f"unsupported key type: {key.typ!r}")


def new_client(account) -> ClientV2:
    with (ACCOUNTS / account).open("rb") as file:
        key = JWK.load(file.read(), password=None)

    net = ClientNetwork(key, user_agent="lers/seeder", verify_ssl=False, alg=alg_for_key(key))
    directory = Directory.from_json(net.get(DIRECTORY).json())
    return ClientV2(directory, net)


if __name__ == "__main__":
    # Die on SIGINT
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    accounts = listdir(ACCOUNTS)

    wait_for_acme_server()
    for a in accounts:
        client = new_client(a)
        acc = client.new_account(NewRegistration.from_data(email="test@user.com", terms_of_service_agreed=True))
        print(acc)
