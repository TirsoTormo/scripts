import os
import yaml
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.core.config import settings
from app.services.router_engine import router_engine
from app.api.auth import require_admin, require_viewer

logger = logging.getLogger("webhook-gateway.admin.config")

router = APIRouter()

class RulesUpdateRequest(BaseModel):
    rules_yaml: str

@router.get("/api/rules", dependencies=[require_viewer])
async def get_rules_content():
    """Reads current rules.yaml contents from the server filesystem."""
    try:
        with open("rules.yaml", "r", encoding="utf-8") as f:
            return {"rules_yaml": f.read()}
    except Exception as e:
        return {"rules_yaml": "", "error": str(e)}

@router.post("/api/rules", dependencies=[require_admin])
async def update_rules_content(payload: RulesUpdateRequest):
    """Validates syntax and overwrites rules.yaml on the server, hot-reloading rules in-memory."""
    try:
        # Pre-validate YAML syntax to protect the server engine from crashes
        yaml.safe_load(payload.rules_yaml)
        
        with open("rules.yaml", "w", encoding="utf-8") as f:
            f.write(payload.rules_yaml)
            
        router_engine.load_rules()
        return {"status": "success", "message": "Routing rules updated and hot-reloaded successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML Syntax: {str(e)}")

@router.get("/api/config", dependencies=[require_viewer])
async def get_env_config():
    """Parses active .env settings variables for the admin panel input fields."""
    config_values = {}
    
    # 1. Parse from local .env if it exists
    if os.path.exists(".env"):
        try:
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        parts = line.split("=", 1)
                        config_values[parts[0].strip()] = parts[1].strip()
        except Exception as e:
            logger.error(f"Failed to read .env file: {e}")

    # 2. Add fallback or in-memory settings defaults if missing
    for key in settings.model_fields.keys():
        if key not in config_values:
            val = getattr(settings, key)
            config_values[key] = str(val) if val is not None else ""
            
    return config_values

@router.post("/api/config", dependencies=[require_admin])
async def update_env_config(payload: dict):
    """Saves updated .env variables to the file system and hot-reboots properties in-memory."""
    # 1. Update settings in-memory
    for key, val in payload.items():
        if key in settings.model_fields:
            field_type = settings.model_fields[key].annotation
            try:
                if val == "" or val is None:
                    setattr(settings, key, None)
                elif field_type == int or field_type == Optional[int]:
                    setattr(settings, key, int(val))
                elif field_type == bool or field_type == Optional[bool]:
                    setattr(settings, key, str(val).lower() in ("true", "1", "yes"))
                else:
                    setattr(settings, key, str(val))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid field type for key '{key}': {str(e)}")

    # 2. Persist updated variables back to physical .env
    try:
        with open(".env", "w", encoding="utf-8") as f:
            f.write("# ======================================================================\n")
            f.write("# WEBHOOK GATEWAY - AUTOMATICALLY UPDATED VIA CONTROL BOARD\n")
            f.write("# ======================================================================\n\n")
            for key, val in payload.items():
                if val is not None:
                    f.write(f"{key}={val}\n")
        return {"status": "success", "message": "Configurations saved and system settings hot-rebooted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save .env file: {str(e)}")
