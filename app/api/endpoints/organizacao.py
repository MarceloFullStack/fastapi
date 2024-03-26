from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.models import User

router = APIRouter()


@router.get('/secure-endpoint')
async def secure_endpoint(
    current_user: User = Depends(deps.get_current_user),
    session: AsyncSession = Depends(deps.get_session),
) -> dict:
    # Se esta linha for alcançada, significa que a autenticação foi bem-sucedida
    return {'message': 'Acesso autorizado'}
