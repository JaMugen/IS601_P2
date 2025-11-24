import pytest
from datetime import timedelta
from fastapi import HTTPException

from app.auth import jwt as jwt_module
from app.schemas.token import TokenType


def test_create_token_encode_failure(monkeypatch):
    """Simulate jwt.encode raising an exception so create_token raises HTTPException (500)."""
    def raise_exc(*args, **kwargs):
        raise Exception("encode failed")

    monkeypatch.setattr(jwt_module, "jwt", jwt_module.jwt)
    monkeypatch.setattr(jwt_module.jwt, "encode", raise_exc)

    with pytest.raises(HTTPException) as excinfo:
        jwt_module.create_token("user-err", TokenType.ACCESS)

    assert excinfo.value.status_code == 500
    assert "Could not create token" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_decode_token_invalid_type():
    # create a refresh token and try to decode as access -> Invalid token type
    token = jwt_module.create_token("u1", TokenType.REFRESH, expires_delta=timedelta(days=1))
    with pytest.raises(HTTPException) as excinfo:
        await jwt_module.decode_token(token, TokenType.ACCESS)
    assert excinfo.value.status_code == 401
    assert "Could not validate credentials" in excinfo.value.detail


@pytest.mark.asyncio
async def test_decode_token_expired():
    token = jwt_module.create_token("u2", TokenType.ACCESS, expires_delta=timedelta(seconds=-1))
    with pytest.raises(HTTPException) as excinfo:
        await jwt_module.decode_token(token, TokenType.ACCESS)
    assert excinfo.value.status_code == 401
    assert "expired" in str(excinfo.value.detail).lower()


@pytest.mark.asyncio
async def test_decode_token_malformed():
    # malformed token should raise JWTError -> HTTPException
    bad = "not.a.jwt"
    with pytest.raises(HTTPException) as excinfo:
        await jwt_module.decode_token(bad, TokenType.ACCESS)
    assert excinfo.value.status_code == 401
    assert "Could not validate credentials" in excinfo.value.detail


@pytest.mark.asyncio
async def test_decode_token_blacklisted(monkeypatch):
    token = jwt_module.create_token("u3", TokenType.ACCESS, expires_delta=timedelta(minutes=5))

    async def fake_blacklisted(jti: str) -> bool:
        return True

    monkeypatch.setattr(jwt_module, "is_blacklisted", fake_blacklisted)

    with pytest.raises(HTTPException) as excinfo:
        await jwt_module.decode_token(token, TokenType.ACCESS)

    assert excinfo.value.status_code == 401
    assert "revoked" in str(excinfo.value.detail).lower()


@pytest.mark.asyncio
async def test_get_current_user_decode_raises(monkeypatch):
    """When decode_token raises an exception, get_current_user should
    catch it and re-raise an HTTPException with status 401 and the
    original error message included in the detail.
    """

    async def fake_decode(token, token_type, verify_exp=True):
        raise Exception("decode failure")

    monkeypatch.setattr(jwt_module, "decode_token", fake_decode)

    with pytest.raises(HTTPException) as excinfo:
        await jwt_module.get_current_user("any-token", db=None)

    assert excinfo.value.status_code == 401
    assert "decode failure" in str(excinfo.value.detail)