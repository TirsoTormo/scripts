import os
import sys
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Ensure the root folder is added to python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.core.database import db_manager
from app.models.orm import Base
from app.core.config import settings

# Force using in-memory database for tests
settings.DB_FILE = ":memory:"

@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_test_db():
    """Sets up an isolated, clean in-memory SQLite database for each test run."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    test_sessionmaker = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    
    # Override engine on the db_manager singleton
    db_manager.engine = test_engine
    db_manager.async_session = test_sessionmaker
    
    # Create all schemas
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    yield
    
    await test_engine.dispose()

from httpx import AsyncClient, ASGITransport

@pytest_asyncio.fixture(scope="function")
async def client():
    """Provides an async HTTP client for integration test execution."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
