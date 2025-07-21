import os

import jwt
from fastapi import Request
from jwt import PyJWKClient

from litellm.proxy._types import UserAPIKeyAuth

CORP_ISSUER = os.getenv("CORP_SSO_ISSUER", "https://sso-corp.luizalabs.com/realms/corp")
MAGALU_ISSUER = os.getenv("ID_MAGALU_ISSUER", "https://autoseg-idp.luizalabs.com/")
CORP_JWKS_URL = os.getenv(
    "CORP_SSO_JWKS_URL", "https://sso-corp.luizalabs.com/realms/corp/protocol/openid-connect/certs"
)
MAGALU_JWKS_URL = os.getenv(
    "ID_MAGALU_JWKS_URL", "https://autoseg-idp.luizalabs.com/oauth/discovery/keys"
)
MASTER_KEY = os.getenv("MASTER_API_KEY")


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    print("=" * 100)
    print(request.headers)
    print(request.body)
    print("=" * 100)
    try:

        if not api_key:
            raise Exception("API key não fornecida")

        if MASTER_KEY and api_key == MASTER_KEY:
            return UserAPIKeyAuth(api_key=api_key, user_id="default_user_id")

        unverified_payload = jwt.decode(api_key, options={"verify_signature": False})
        issuer = unverified_payload.get("iss")
        if not issuer:
            raise Exception("Token JWT sem emissor (iss)")

        if issuer == CORP_ISSUER:
            jwks_url = CORP_JWKS_URL
        elif issuer == MAGALU_ISSUER:
            jwks_url = MAGALU_JWKS_URL
        else:
            raise Exception("Emissor do token não reconhecido")

        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(api_key)

        payload = jwt.decode(
            api_key,
            key=signing_key.key,
            algorithms=[
                "RS256",
                "RS512",
                "HS256",
            ],
            options={"verify_aud": False},
            issuer=issuer,
        )

        sub = payload.get("sub")
        if not sub:
            raise Exception("Token JWT sem 'sub' no payload")
        return UserAPIKeyAuth(api_key=api_key, user_id="default_user_id")
    except jwt.InvalidSignatureError as e:
        raise Exception("Assinatura do token inválida") from e
    except jwt.ExpiredSignatureError as e:
        raise Exception("Token expirado") from e
    except jwt.DecodeError as e:
        raise Exception("Erro ao decodificar o token JWT") from e
    except jwt.InvalidTokenError as e:
        raise Exception("Token JWT inválido") from e
    except Exception as e:
        raise Exception(f"Erro desconhecido durante autenticação: {str(e)}") from e
