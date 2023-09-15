#!/usr/bin/python3
import argparse
import json
import os
import re
import requests
import shutil
import sys
from typing import Dict, Optional, List
from logging import getLogger, basicConfig, DEBUG

basicConfig(level=DEBUG)
logger = getLogger(__name__)

CERTS = ("/etc/cb/certs/carbonblack-alliance-client.crt",
         "/etc/cb/certs/carbonblack-alliance-client.key")

EXPORT_FEEDS = ['abusech', 'Bit9AdvancedThreats', 'alienvault',
                'CbCommunity', 'Bit9EarlyAccess', 'Bit9SuspiciousIndicators', 'Bit9EndpointVisibility',
                'fbthreatexchange', 'CbKnownIOCs', 'sans', 'mdl', 'ThreatConnect', 'tor', 'attackframework']

DEFAULT_SERVER = "127.0.0.1"
DEFAULT_PORT = 443
FEED_API_URL_FMT = "https://{edr_server}:{edr_port}/api/v1/feed"

NO_PROXY = {
        "http": None,
        "https": None,
        }

# noinspection PyBroadException
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


def get_api_token() -> str:
    import psycopg2
    conn = psycopg2.connect("dbname=cb port=5002")
    cur = conn.cursor()
    cur.execute("select auth_token from cb_user where global_admin is true order by id limit 1;")
    token = cur.fetchone()[0]
    token = re.sub("^'|'$", "", token)
    return token


def get_feed(headers: Dict, name: str, server: str = DEFAULT_SERVER,
             port: int = DEFAULT_PORT) -> Optional[Dict]:
    feeds = requests.get(FEED_API_URL_FMT.format(edr_server=server, edr_port=port), headers=headers,
                                verify=False, proxies=NO_PROXY)
    feeds.raise_for_status()
    for feed in feeds.json():
        if feed['name'].lower() == name.lower():
            return feed
    return None


def import_feeds(folder: str, headers: Dict, server: str = DEFAULT_SERVER,
                 port: int = DEFAULT_PORT) -> int:
    logger.info(f'Importing Threat Intelligence feeds from {folder}')

    errors = 0

    for root, sub_dirs, files in os.walk(folder):
        for temp_file in files:
            if temp_file.endswith('.json'):
                filepath = os.path.join(root, temp_file)
                logger.debug(f'filepath = {filepath}')

                feed_url = f"file://{filepath}"
                data = {'feed_url': feed_url,
                        'validate_server_cert': False,
                        'manually_added': True}

                file_json = json.loads(open(filepath).read())
                feed_name = file_json['feedinfo']['name']
                feed = get_feed(headers, feed_name, port=port)
                if feed is not None:
                    feed_id = feed.pop('id')
                    # CB-39336: cbfeed_airgap import of existing feeds fails when ValidateApiPayloadSchema enabled
                    feed = {k: v for k, v in feed.items() if v is not None}
                    logger.info(f"Feed {feed_name} already exists, attempting update")
                    feed.update({"feed_url": feed_url, "manually_added": True})
                    feed_update = requests.put(
                        f"{FEED_API_URL_FMT.format(edr_server=server, edr_port=port)}/{feed_id}",
                        data=json.dumps(feed), headers=headers, verify=False, proxies=NO_PROXY)
                    if feed_update.status_code == 200:
                        logger.info(f"Updated {feed_name}")
                    else:
                        logger.error(f"Failed to update {feed_name} (error {feed_update.status_code})")
                        errors += 1
                else:
                    feed_update = requests.post(FEED_API_URL_FMT.format(edr_server=server, edr_port=port),
                                                data=json.dumps(data),
                                                headers=headers, verify=False, proxies=NO_PROXY)
                    if feed_update.status_code == 200:
                        logger.info(f"Added feed {feed_name}")
                    else:
                        logger.error(f"Failed to add feed {feed_name}: {feed_update.status_code}")
                        errors += 1
    return errors


def export_feeds(folder: str, headers: Dict, server: str = DEFAULT_SERVER,
                 port: int = DEFAULT_PORT) -> int:
    export_path = os.path.join(folder, "feeds")
    logger.info(f'Exporting Threat Intelligence Feeds to {export_path}')

    try:
        os.makedirs(export_path)
    except OSError:
        pass  # probably due to folder already existing

    feeds = requests.get(FEED_API_URL_FMT.format(edr_server=server, edr_port=port),
                         headers=headers, verify=False, proxies=NO_PROXY)
    feeds.raise_for_status()

    errors = 0

    for feed in feeds.json():
        feed_url = feed.get('feed_url', None)
        feed_name = str(feed.get('name', ""))
        logger.info(f"Checking feed {feed_name} at {feed_url}")
        if feed_url and feed_url.startswith('http'):
            if feed_name not in EXPORT_FEEDS:
                logger.info(f"{feed_name} is not an exportable feed")
                continue
            try:
                response = requests.get(url=feed_url, cert=CERTS)
                response.raise_for_status()

                fn = os.path.join(export_path, feed_name + ".json")
                f = open(fn, "w+")
                try:
                    logger.info(f"Exporting feed {feed_name} to {fn}")
                    f.write(json.dumps(response.json()))
                except Exception as e:
                    logger.error(f'Error writing to {feed_name}: {e}')
                    errors += 1
            except Exception as e:
                logger.error(f'Could not export feed {feed_name}: {e}')
                errors += 1
        else:
            logger.info(f"Invalid feed URL: {feed_url}")

    return errors


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VMware Carbon Black EDR Airgap Feeds import/export utility")

    parser.add_argument("-s", "--server", action="store", dest="edr_server", default=DEFAULT_SERVER,
                        help=f"EDR server (default: {DEFAULT_SERVER})")

    parser.add_argument("-p", "--port", action="store", dest="edr_port", default=DEFAULT_PORT,
                        help=f"EDR port (default: {DEFAULT_PORT})")

    commands = parser.add_subparsers(help="Commands", dest="command")

    default_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feeds")

    import_command = commands.add_parser("import", help="Import feeds from disk")
    import_command.add_argument("-f", "--folder", help="Folder to import", default=default_folder, required=False)

    export_command = commands.add_parser("export", help="Export feeds to disk")
    export_command.add_argument("-f", "--folder", help="Folder to export to", default=None, required=True)

    return parser


def main(argv: List) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(args=argv)
    mode = args.command

    if hasattr(args, "folder"):
        folder = args.folder
    else:
        # use location of script
        folder = os.path.dirname(os.path.abspath(__file__))

    try:
        headers = {'X-Auth-Token': get_api_token()}
    except psycopg2.OperationalError as e:
        print(e)
        return 1

    errors = 0
    if mode == 'import':
        errors = import_feeds(args.folder, headers, server=args.edr_server, port=args.edr_port)
    else:
        errors = export_feeds(args.folder, headers, server=args.edr_server, port=args.edr_port)

    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
