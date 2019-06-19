#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import codecs
import os
import signal
import sys
from pathlib import Path

import psycopg2
from psycopg2._json import Json
from psycopg2._psycopg import OperationalError
from psycopg2.extensions import connection
from sanic import Sanic
from sanic import request as sanic_request
from sanic import response as sanic_response
from sanic.exceptions import NotFound, MethodNotSupported
from sanic.response import text
from systemd._daemon import booted, notify

__author__ = 'Paweł Krawczyk'

INSERT = """
WITH ins_ua AS (
    INSERT INTO reporting_api_useragent (user_agent)
    VALUES (%(ua)s)
    ON CONFLICT (user_agent) DO UPDATE
    SET user_agent = %(ua)s
    RETURNING id AS ua_id
), ins_tag AS (
    INSERT INTO reporting_api_tag (tag)
    VALUES (%(tag)s)
    ON CONFLICT (tag) DO UPDATE
    SET tag = %(tag)s
    RETURNING id AS t_id
)
INSERT INTO reporting_api_report (data, date, ip, user_agent_id, tag_id)
    SELECT
        %(data)s::json,
        NOW(),
        %(ip)s,
        ua_id, 
        (SELECT t_id FROM ins_tag)
    FROM ins_ua;
"""

HEADERS = {
    "X-Robots-Tag": "noindex,nofollow,noarchive",
    "Content-Security-Policy": "default-src 'none'"
}


def connect(app: Sanic) -> connection:
    return psycopg2.connect(
        dbname=app.config.DB_NAME,
        host=app.config.DB_HOST,
        port=app.config.DB_PORT,
        user=app.config.DB_USER,
        password=app.config.DB_PASS
    )


# creates application object and also imports environment variables with SANIC_ prefix
app = Sanic('reporter')

# For testing set SNAP_COMMON=.
# Under Snapd, SNAP_COMMON=/var/snap/reporter/common
# https://docs.snapcraft.io/environment-variables/7983
try:
    # we use SNAP_COMMON because the service is running as root
    # so the config file needs to be placed in root-owned directory anyway
    # there are plans for snapd to create user accounts for services but not implemented as of 2019
    app.config.from_pyfile(Path(os.environ.get('SNAP_COMMON')) / "settings.py")
except FileNotFoundError as e:
    print(e)
    if booted():
        notify(f"STATUS={e}")
        notify(f"STOPPING=1")
    sys.exit(1)

try:
    database = connect(app)
except OperationalError as e:
    print(e)
    if booted():
        notify(f"STATUS={e}")
        notify(f"STOPPING=1")
    sys.exit(1)


# noinspection PyCompatibility
@app.exception((NotFound, MethodNotSupported))
async def not_found(request: sanic_request, exception) -> sanic_response:
    return text('Not found', status=404, headers=HEADERS)


# noinspection PyCompatibility
@app.route('/robots.txt', methods=['GET', 'HEAD'])
async def robots(request: sanic_request) -> sanic_response:
    return text('User-agent: *\nDisallow: /', headers=HEADERS)


# noinspection PyCompatibility,PyUnresolvedReferences
@app.route('/<tag:[a-z0-9-]{,20}>', methods=('GET', 'POST'))
async def report(request: sanic_request, tag: str) -> sanic_response:
    global database, app

    # obtain client IP, either directly or from proxy header
    client_ip = request.ip
    if request.headers.get('X-Real-Ip'):
        client_ip = request.headers.get('X-Real-Ip')

    if tag in ('magick', 'xxe', 'xss'):
        data = {'headers': dict(request.headers)}
        data['type'] = tag
        ct = request.headers.get('Content-Type')
        if ct and 'charset' in ct:
            charset = ct.split('=')[1]
        else:
            charset = 'utf-8'
        if request.method == 'POST':
            data['body'] = codecs.decode(request.body, charset, 'replace')
        else:
            data['body'] = request.args
    else:
        # the actual report contents
        data = request.json

    # reject empty reports
    if not data:
        return text('No report', status=400)

    # reject unsupported report types
    if not all((
            type(data) is dict,
            any((
                    data.get('type') in ('magick', 'xxe', 'xss'),
                    # https://w3c.github.io/reporting/
                    data.get('type') in ('deprecation', 'intervention', 'crash'),
                    # https://www.w3.org/TR/network-error-logging-1/
                    data.get('type') == 'network-error',
                    # https://wicg.github.io/feature-policy/
                    data.get('type') == 'feature-policy-violation',
                    # https://w3c.github.io/webappsec-csp/
                    data.get('csp-report'),
                    # https://tools.ietf.org/html/rfc7469#section-3
                    data.get('validated-certificate-chain'),
                    # https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-07#section-3
                    data.get('expect-ct-report'),
            )),
    )):
        return text('Unsupported report', status=400)

    # ignored reports
    if data.get('csp-report') and any((
            data.get('csp-report').get('blocked-uri') == 'chrome-extension',
            data.get('csp-report').get('source-file') == 'about',)):
        return text('', status=204)

    params = {
        'data': Json(data),
        'tag': tag,
        'ip': client_ip,
        'ua': request.headers.get('User-Agent'),
    }

    try:
        cursor = database.cursor()
    except psycopg2.InterfaceError:
        database = connect(app)
        cursor = database.cursor()

    if app.config.DEBUG:
        print(cursor.mogrify(INSERT, params))

    cursor.execute(INSERT, params)
    database.commit()

    return text('', status=204)


def shutdown(signum: int, frame) -> None:
    """
    Properly notify systemd about termination
    """
    message = f'Received signal {signum}, shutting down'
    print(message)
    if booted():
        notify(f'STATUS={message}')
        notify(f"STOPPING=1")
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    if booted():
        notify("READY=1")
    app.run(host=app.config.LISTEN, port=app.config.PORT)


if __name__ == "__main__":
    main()
