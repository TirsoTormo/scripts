#!/usr/bin/env python3
import os
import shutil
import re

def apply_restructuring():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Define directory structure
    dirs = [
        "app",
        "app/api",
        "app/api/admin",
        "app/core",
        "app/models",
        "app/services",
        "app/services/remediation",
        "app/handlers",
        "app/templates",
        "app/templates/static",
        "tests",
        "data"
    ]
    
    print("Creating directory structure...")
    for d in dirs:
        dir_path = os.path.join(base_dir, d)
        os.makedirs(dir_path, exist_ok=True)
        # Create __init__.py if it is a python package
        if d != "tests" and d != "data" and not d.endswith("templates") and not d.endswith("static"):
            init_file = os.path.join(dir_path, "__init__.py")
            if not os.path.exists(init_file):
                with open(init_file, "w") as f:
                    pass

    # 2. File movements mapping
    file_moves = [
        ("config.py", "app/core/config.py"),
        ("database.py", "app/core/database.py"),
        ("models.py", "app/models/event.py"),
        ("engine.py", "app/services/router_engine.py"),
        ("main.py", "app/main.py"),
        ("templates/dashboard.html", "app/templates/dashboard.html"),
        ("gateway.db", "data/gateway.db"),
        ("infra_events.log", "data/infra_events.log"),
        ("remediation_history.log", "data/remediation_history.log")
    ]
    
    print("Moving core files...")
    for src, dst in file_moves:
        src_path = os.path.join(base_dir, src)
        dst_path = os.path.join(base_dir, dst)
        if os.path.exists(src_path):
            shutil.move(src_path, dst_path)
            print(f"Moved: {src} -> {dst}")
            
    # Move directories content
    def move_dir_contents(src_dir, dest_dir):
        src_path = os.path.join(base_dir, src_dir)
        dest_path = os.path.join(base_dir, dest_dir)
        if os.path.exists(src_path):
            for item in os.listdir(src_path):
                if item == "__pycache__":
                    continue
                s = os.path.join(src_path, item)
                d = os.path.join(dest_path, item)
                if os.path.exists(d):
                    if os.path.isdir(d):
                        shutil.rmtree(d)
                    else:
                        os.remove(d)
                shutil.move(s, d)
                print(f"Moved: {os.path.join(src_dir, item)} -> {os.path.join(dest_dir, item)}")
            # Remove original dir if empty or has cache
            try:
                shutil.rmtree(src_path)
            except Exception:
                pass

    print("Moving routes...")
    move_dir_contents("routes", "app/api")
    
    print("Moving handlers...")
    move_dir_contents("handlers", "app/handlers")

    # 3. Rewrite imports recursively in all python files under app/
    print("Updating import statements in Python files...")
    app_root = os.path.join(base_dir, "app")
    
    # Import replacement rules
    replacements = [
        (r'\bfrom config\b', 'from app.core.config'),
        (r'\bimport config\b', 'from app.core import config'),
        (r'\bfrom database\b', 'from app.core.database'),
        (r'\bimport database\b', 'from app.core import database'),
        (r'\bfrom engine\b', 'from app.services.router_engine'),
        (r'\bimport engine\b', 'from app.services import router_engine'),
        (r'\bfrom models\b', 'from app.models.event'),
        (r'\bimport models\b', 'from app.models import event'),
        (r'\bfrom handlers\b', 'from app.handlers'),
        (r'\bimport handlers\b', 'from app. import handlers'),
        (r'\bfrom routes\b', 'from app.api'),
        # Specifical handlers subfolder rewrites
        (r'\bhandlers\.', 'app.handlers.'),
        (r'\broutes\.', 'app.api.'),
        # Relative template path updates
        (r'os\.path\.join\("templates", "dashboard\.html"\)', 'os.path.join("app", "templates", "dashboard.html")'),
        (r'DB_FILE = "gateway\.db"', 'DB_FILE = "data/gateway.db"'),
        (r'"gateway\.db"', '"data/gateway.db"')
    ]

    for root, dirs, files in os.walk(app_root):
        for file in files:
            if file.endswith(".py") or file.endswith(".html"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    modified = content
                    for pattern, repl in replacements:
                        modified = re.sub(pattern, repl, modified)
                        
                    if modified != content:
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(modified)
                        print(f"Updated imports/paths in: {os.path.relpath(file_path, base_dir)}")
                except Exception as e:
                    print(f"Error updating {file}: {e}")

    print("Restructuring applied successfully!")

if __name__ == "__main__":
    apply_restructuring()
