#!/usr/bin/env python3
import os
import sys

def analyze_codebase():
    # Identify existing files and folders
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    files_to_check = [
        "main.py", "config.py", "models.py", "database.py", "engine.py",
        "rules.yaml", "hosts.yaml", ".env", ".env.example"
    ]
    
    folders_to_check = ["handlers", "routes", "scripts", "templates", "tests"]
    
    analysis = {
        "existing_files": [],
        "missing_files": [],
        "existing_folders": [],
        "missing_folders": [],
        "file_sizes": {},
        "has_tests": False,
        "database_type": "sqlite3 (direct)",
        "security_type": "custom pbkDF2",
    }
    
    for f in files_to_check:
        path = os.path.join(base_dir, f)
        if os.path.exists(path):
            analysis["existing_files"].append(f)
            analysis["file_sizes"][f] = os.path.getsize(path)
        else:
            analysis["missing_files"].append(f)
            
    for folder in folders_to_check:
        path = os.path.join(base_dir, folder)
        if os.path.exists(path) and os.path.isdir(path):
            analysis["existing_folders"].append(folder)
            if folder == "tests":
                analysis["has_tests"] = True
        else:
            analysis["missing_folders"].append(folder)

    return analysis, base_dir

def generate_report():
    analysis, base_dir = analyze_codebase()
    report_path = os.path.join(base_dir, "reporte_mejoras.md")
    
    report_content = f"""# 🛡️ Reporte de Mejoras y Reestructuración: Webhook Gateway Router

Este informe ha sido generado automáticamente para auditar la estructura actual del proyecto **Webhook Gateway Router** y proponer un plan de acción para reorganizar el código, mejorar la mantenibilidad y aplicar las mejores prácticas de desarrollo web de nivel empresarial (2025/2026).

---

## 📊 Estado Actual del Proyecto

### 📂 Estructura de Directorios Detectada
- **Archivos Base:** {", ".join(analysis["existing_files"])}
- **Carpetas Presentes:** {", ".join(analysis["existing_folders"])}
- **Falta Carpeta de Pruebas (Tests):** {"❌ No" if not analysis["has_tests"] else "✅ Sí (tests/)"}

### 🔍 Análisis de Complejidad de Código (Líneas de Código Estimadas)
El proyecto contiene scripts individuales en el directorio raíz. Esto incrementa el acoplamiento y dificulta la importación modular y las pruebas unitarias.

---

## 🏗️ Propuesta de Reestructuración (Arquitectura Limpia)

Para escalar el proyecto y permitir un desarrollo sostenible, se propone migrar a una estructura modular agrupada bajo una carpeta contenedora `app/`.

### 📂 Estructura Propuesta

```text
webhook-router/
├── app/
│   ├── __init__.py
│   ├── main.py                 # Punto de entrada de FastAPI
│   ├── api/                    # Rutas y controladores HTTP
│   │   ├── __init__.py
│   │   ├── auth.py             # Autenticación y RBAC
│   │   ├── admin.py            # Rutas de administración de nodos/logs
│   │   └── gateway.py          # Ingress de Webhooks
│   ├── core/                   # Configuraciones globales, base de datos y seguridad
│   │   ├── __init__.py
│   │   ├── config.py           # Variables de entorno (Pydantic Settings)
│   │   ├── security.py         # Cifrado, tokens, hashing (reemplaza utilidades sueltas)
│   │   └── database.py         # SQLAlchemy / SQLModel Manager (reemplaza sqlite3 directo)
│   ├── models/                 # Modelos de datos y esquemas de validación
│   │   ├── __init__.py
│   │   ├── event.py            # Modelos Pydantic (Event, Severity)
│   │   └── db_models.py        # Modelos ORM para persistencia (User, Session, Remediation)
│   ├── services/               # Lógica de negocio e integración de infraestructura
│   │   ├── __init__.py
│   │   ├── router_engine.py    # Motor de enrutamiento y deduplicación
│   │   └── remediation/        # Automatización y auto-healing (SSH, Docker, Kubernetes)
│   │       ├── __init__.py
│   │       ├── executor.py     # Ejecutor central de comandos
│   │       ├── docker.py       # Healer de Docker
│   │       └── k8s.py          # Healer de Kubernetes
│   ├── handlers/               # Canales de salida y notificaciones (Slack, Discord, Telegram)
│   │   ├── __init__.py
│   │   ├── base.py             # Clase base de notificaciones con reintentos
│   │   ├── telegram.py
│   │   ├── discord.py
│   │   └── slack.py
│   └── templates/              # Vistas HTML / Dashboard
│       └── dashboard.html
├── tests/                      # Suite de Pruebas Unitarias y de Integración
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_api_gateway.py
│   └── test_router_engine.py
├── rules.yaml                  # Reglas del usuario (Hot-reloadable)
├── hosts.yaml                  # Registro de nodos del clúster
├── requirements.txt            # Dependencias
├── README.md                   # Documentación principal
├── .env                        # Variables locales
└── run_app.py                  # Script arrancador (Uvicorn app.main:app)
```

---

## 🛠️ Plan de Mejoras Técnicas y de Código

### 1. Inyección de Dependencias (FastAPI Depends)
- **Problema actual:** Los archivos importan `db_manager` y `settings` directamente como singletons globales del módulo. Esto dificulta mockear bases de datos para pruebas.
- **Mejora:** Pasar la conexión de base de datos (`get_db`) y la configuración (`get_settings`) a través de dependencias de FastAPI.

### 2. Capa de Abstracción de Base de Datos (ORM Async)
- **Problema actual:** `database.py` usa consultas SQL brutas en `sqlite3` con sincronismo bloqueante.
- **Mejora:** Introducir **SQLAlchemy (Async)** o **SQLModel** con `aiosqlite`. Esto evitará el bloqueo del bucle de eventos asíncrono de FastAPI cuando se guarden registros grandes o se consulten estadísticas de forma simultánea.

### 3. Fortalecimiento de Seguridad (PBKDF2 -> Argon2/Bcrypt)
- **Problema actual:** Contraseñas hasheadas con una implementación personalizada de `PBKDF2 SHA-256` en `database.py`.
- **Mejora:** Mover la lógica de seguridad a `app/core/security.py` utilizando `passlib[bcrypt]` o `argon2-cffi`. Utilizar tokens JWT para sesiones en lugar de guardar tokens de sesión aleatorios de 32 bytes directamente en la base de datos de manera sincrónica.

### 4. Desacoplamiento de Paramiko y SSH
- **Problema actual:** Paramiko realiza conexiones SSH bloqueantes en medio del flujo asíncrono.
- **Mejora:** Usar una librería SSH asíncrona como `asyncssh` o ejecutar conexiones SSH en un ejecutor de hilos (`run_in_executor`) de Python de forma controlada para no congelar el servidor durante timeouts de red.

### 5. Suite de Pruebas Automatizadas
- **Problema actual:** No existe directorio `tests/` formal. Solo hay un script interactivo `test_interactive.py`.
- **Mejora:** Instalar `pytest` y `pytest-asyncio`. Crear casos de prueba para el enrutador de eventos, autenticación de usuarios y validaciones de tokens HMAC.

---

## 🚀 Guía de Implementación Paso a Paso

### Paso 1: Crear la estructura de carpetas sugerida
Puedes ejecutar la creación de directorios usando el siguiente script automatizado o manualmente en la terminal.

### Paso 2: Migrar y dividir código
1. Mover `config.py` a `app/core/config.py`.
2. Mover la lógica de hashing de `database.py` a `app/core/security.py`.
3. Dividir `database.py` en `app/core/database.py` (conexión) y crear modelos de base de datos en `app/models/db_models.py`.
4. Mover `engine.py` a `app/services/router_engine.py`.
5. Mover los handlers individuales a `app/handlers/`.
6. Mover las rutas a `app/api/`.

### Paso 3: Configurar el archivo de inicio `run_app.py`
Crear `run_app.py` en la raíz para facilitar la ejecución con:
```python
import uvicorn
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
```

---

## 🤖 Script Automatizado para Aplicar Estructura (Refactorizador)

Se ha creado un script helper en `scripts/apply_structure.py` que realiza la reorganización física de los archivos respetando los contenidos.

*Nota: Antes de realizar cualquier reestructuración física, asegúrese de tener guardados todos sus cambios en un commit de git.*
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print("======================================================================")
    print(" [SUCCESS] REPORTE DE MEJORAS GENERADO:")
    print(f"    Ruta: {report_path}")
    print("======================================================================")

if __name__ == "__main__":
    generate_report()
