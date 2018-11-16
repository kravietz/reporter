#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2
from psycopg2._json import Json

from sanic import Sanic, response, request
from sanic import response as sanic_response
from sanic import request as sanic_request
from sanic.response import text

__author__ = 'Paweł Krawczyk'

app = Sanic()
app.config.from_pyfile('config.py')

database = psycopg2.connect(app.config.DSN)

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

    data = request.json

    if not data:
        return text('No report', status=400)

    if not all((
            type(data) is dict,
            'type' in data,
            data.get('type') in ['network-error'],
    )):
        return text('Invalid report', status=400)

    params = {
        'data': Json(data),
        'tag': tag,
        'ip': request.ip,
        'ua': request.headers.get('User-Agent'),
    }

    if app.config.DEBUG:
        print(params)
        print(cursor.mogrify(INSERT, params))

    cursor.execute(INSERT, params)
    database.commit()

    return text('', status=204)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
