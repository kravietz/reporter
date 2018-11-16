#!/usr/bin/env pytest
import json
import random

from .server import app

# https://w3c.github.io/network-error-logging/#examples
NEL = {
  "age": random.randint(1, 1000),
  "type": "network-error",
  "url": "https://www.example.com/",
  "body": {
    "sampling_fraction": 0.5,
    "referrer": "http://example.com/",
    "server_ip": "123.122.121.120",
    "protocol": "h2",
    "method": "GET",
    "request_headers": {},
    "response_headers": {},
    "status_code": 200,
    "elapsed_time": 823,
    "phase": "application",
    "type": "http.protocol.error"
  }
}


def test_nel_returns_204():
    request, response = app.test_client.post('/aaa', data=json.dumps(NEL))
    assert response.status == 204

def test_invalid_tag_returns_404():
    request, response = app.test_client.post('/x-1-2@', data=json.dumps(NEL))
    assert response.status == 404

def test_invalid_returns_400():
    request, response = app.test_client.post('/aaa')
    assert response.status == 400
