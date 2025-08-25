from typing import cast

from fastapi import Request
from litellm._logging import verbose_proxy_logger
from litellm.proxy._types import LiteLLMRoutes, LitellmUserRoles, UserAPIKeyAuth
from litellm.proxy.auth.auth_checks import common_checks
from litellm.proxy.auth.auth_utils import get_request_route, route_in_additonal_public_routes
from litellm.proxy.auth.handle_jwt import JWTAuthManager
from litellm.proxy.auth.user_api_key_auth import get_global_proxy_spend
from litellm.proxy.common_utils.http_parsing_utils import _read_request_body


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    from litellm.proxy.proxy_server import (
        general_settings,
        jwt_handler,
        litellm_proxy_admin_name,
        llm_router,
        prisma_client,
        proxy_logging_obj,
        user_api_key_cache,
    )

    route: str = get_request_route(request=request)

    if (
        route in LiteLLMRoutes.public_routes.value  # type: ignore
        or route_in_additonal_public_routes(current_route=route)
    ):
        return UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER_VIEW_ONLY)

    user_from_kong = request.headers.get("x-consumer-username")
    if user_from_kong and user_from_kong != "anonymous-user":
        return UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER_VIEW_ONLY)

    request_data = await _read_request_body(request=request)
    is_jwt = jwt_handler.is_jwt(token=api_key)
    verbose_proxy_logger.debug("is_jwt: %s", is_jwt)
    if is_jwt:
        result = await JWTAuthManager.auth_builder(
            request_data=request_data,
            general_settings=general_settings,
            api_key=api_key,
            jwt_handler=jwt_handler,
            route=route,
            prisma_client=prisma_client,
            user_api_key_cache=user_api_key_cache,
            proxy_logging_obj=proxy_logging_obj,
            parent_otel_span=None,
        )

        is_proxy_admin = result["is_proxy_admin"]
        team_id = result["team_id"]
        team_object = result["team_object"]
        user_id = result["user_id"]
        user_object = result["user_object"]
        end_user_id = result["end_user_id"]
        end_user_object = result["end_user_object"]
        org_id = result["org_id"]
        token = result["token"]

        global_proxy_spend = await get_global_proxy_spend(
            litellm_proxy_admin_name=litellm_proxy_admin_name,
            user_api_key_cache=user_api_key_cache,
            prisma_client=prisma_client,
            token=token,
            proxy_logging_obj=proxy_logging_obj,
        )

        if is_proxy_admin:
            return UserAPIKeyAuth(
                user_role=LitellmUserRoles.PROXY_ADMIN,
                parent_otel_span=None,
            )

        valid_token = UserAPIKeyAuth(
            api_key=user_id,
            team_id=team_id,
            team_tpm_limit=(team_object.tpm_limit if team_object is not None else None),
            team_rpm_limit=(team_object.rpm_limit if team_object is not None else None),
            team_models=team_object.models if team_object is not None else [],
            user_role=(
                LitellmUserRoles(user_object.user_role)
                if user_object is not None and user_object.user_role is not None
                else LitellmUserRoles.INTERNAL_USER
            ),
            user_id=user_id,
            org_id=org_id,
            parent_otel_span=None,
            end_user_id=end_user_id,
        )
        # run through common checks
        _ = await common_checks(
            request=request,
            request_body=request_data,
            team_object=team_object,
            user_object=user_object,
            end_user_object=end_user_object,
            general_settings=general_settings,
            global_proxy_spend=global_proxy_spend,
            route=route,
            llm_router=llm_router,
            proxy_logging_obj=proxy_logging_obj,
            valid_token=valid_token,
        )
        # return UserAPIKeyAuth object
        return cast(UserAPIKeyAuth, valid_token)
