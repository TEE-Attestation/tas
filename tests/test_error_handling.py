#
# TEE Attestation Service - Tests for Error Handling
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import pytest
from flask import Flask, jsonify
from werkzeug.exceptions import BadRequest, Forbidden, HTTPException, Unauthorized

from tas.error_handlers import register_error_handlers


@pytest.fixture()
def app():
    """Create a test Flask app using the actual error handler from tas."""
    test_app = Flask(__name__)
    test_app.config["TESTING"] = True

    # Register the real error handler from tas/error_handlers.py
    register_error_handlers(test_app)

    # Route that works normally
    @test_app.route("/ok")
    def ok():
        return jsonify({"status": "ok"}), 200

    # Route that raises a generic (non-HTTP) exception
    @test_app.route("/server-error")
    def server_error():
        raise RuntimeError("something broke internally")

    # Route that raises a 400 Bad Request
    @test_app.route("/bad-request")
    def bad_request():
        raise BadRequest("Missing required field")

    # Route that raises a 401 Unauthorized
    @test_app.route("/unauthorized")
    def unauthorized():
        raise Unauthorized("Invalid credentials")

    # Route that raises a 403 Forbidden
    @test_app.route("/forbidden")
    def forbidden():
        raise Forbidden("Access denied")

    # Route that raises an HTTPException with description=None
    @test_app.route("/no-description")
    def no_description():
        exc = HTTPException()
        exc.code = 422
        exc.description = None
        raise exc

    return test_app


@pytest.fixture()
def client(app):
    return app.test_client()


class TestHTTPExceptionHandling:
    """Verify that HTTPException subclasses return their correct status codes."""

    def test_not_found_returns_404(self, client):
        resp = client.get("/nonexistent-route")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data

    def test_bad_request_returns_400(self, client):
        resp = client.get("/bad-request")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "Missing required field"

    def test_unauthorized_returns_401(self, client):
        resp = client.get("/unauthorized")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == "Invalid credentials"

    def test_forbidden_returns_403(self, client):
        resp = client.get("/forbidden")
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["error"] == "Access denied"

    def test_method_not_allowed_returns_405(self, client):
        resp = client.post("/ok")
        assert resp.status_code == 405
        data = resp.get_json()
        assert "error" in data

    def test_http_exception_with_none_description(self, client):
        resp = client.get("/no-description")
        assert resp.status_code == 422
        data = resp.get_json()
        assert data["error"] == "Request error"

    def test_http_exception_response_is_json(self, client):
        resp = client.get("/nonexistent-route")
        assert resp.content_type == "application/json"


class TestGenericExceptionHandling:
    """Verify that non-HTTP exceptions return 500 with a generic message."""

    def test_runtime_error_returns_500(self, client):
        resp = client.get("/server-error")
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["error"] == "Internal server error"

    def test_server_error_does_not_leak_details(self, client):
        resp = client.get("/server-error")
        data = resp.get_json()
        assert "something broke" not in data["error"]
        assert "RuntimeError" not in data["error"]

    def test_server_error_response_is_json(self, client):
        resp = client.get("/server-error")
        assert resp.content_type == "application/json"


class TestNormalRoutes:
    """Sanity check: normal routes still work as expected."""

    def test_ok_route_returns_200(self, client):
        resp = client.get("/ok")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}
