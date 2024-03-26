from httpx import AsyncClient
from fastapi import status
from app.main import app


async def test_secure_endpoint_status_code(
    client: AsyncClient,
    default_user_headers: dict[str, str],
) -> None:
    response = await client.get(
        app.url_path_for("secure_endpoint"),
        headers=default_user_headers,
    )

    assert response.status_code == status.HTTP_200_OK


async def test_secure_endpoint_response(
    client: AsyncClient,
    default_user_headers: dict[str, str],
) -> None:
    response = await client.get(
        app.url_path_for("secure_endpoint"),
        headers=default_user_headers,
    )

    assert response.json() == {"message": "Acesso autorizado"}
