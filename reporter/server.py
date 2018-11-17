#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2
from psycopg2._json import Json
from sanic import Sanic
from sanic import request as sanic_request
from sanic import response as sanic_response
from sanic.response import text

__author__ = 'Paweł Krawczyk'

# also import environment variables with SANIC_ prefix
app = Sanic()

database = psycopg2.connect(
    dbname=app.config.DB_NAME,
    host=app.config.DB_HOST,
    port=app.config.DB_PORT,
    user=app.config.DB_USER,
    password=app.config.DB_PASS
)

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


# noinspection PyCompatibility,PyUnresolvedReferences
@app.route('/<tag:[a-z0-9-]{,20}>', methods=['POST'])
async def report(request: sanic_request, tag: str) -> sanic_response:
    cursor = database.cursor()

    # obtain client IP, either directly or from proxy header
    client_ip = request.ip
    if request.headers.get('X-Real-Ip'):
        client_ip = request.headers.get('X-Real-Ip')

    # the actual report contents
    data = request.json

    # input validation
    if not data:
        return text('No report', status=400)

    if not all((
            type(data) is dict,
            any((
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

    params = {
        'data': Json(data),
        'tag': tag,
        'ip': client_ip,
        'ua': request.headers.get('User-Agent'),
    }

    if app.config.DEBUG == 'yes':
        print(params)
        print(cursor.mogrify(INSERT, params))

    cursor.execute(INSERT, params)
    database.commit()

    return text('', status=204)


if __name__ == "__main__":
    app.run(host=app.config.LISTEN, port=app.config.PORT)
