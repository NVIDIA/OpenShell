"""Connect to the developer gateway using the matching SDK wheel."""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from openshell.sandbox import SandboxClient

state = Path(os.environ['LOCALAPPDATA']) / 'OpenShell' / 'Windows-0.1.8'
settings = json.loads((state / 'settings.json').read_text(encoding='utf-8'))
endpoint = urlsplit(settings['endpoint'])
with SandboxClient(f'{endpoint.hostname}:{endpoint.port}') as client:
    print(client.health())
