from . import datamodel_pb2, ryno_pb2

# Sandbox messages and phase enums moved into ryno.proto. Keep aliases on
# datamodel_pb2 so existing Python callers and E2E tests continue to work.
for _name in (
    "Sandbox",
    "SandboxSpec",
    "SandboxTemplate",
):
    if not hasattr(datamodel_pb2, _name):
        setattr(datamodel_pb2, _name, getattr(ryno_pb2, _name))

for _name in dir(ryno_pb2):
    if _name.startswith("SANDBOX_PHASE_") and not hasattr(datamodel_pb2, _name):
        setattr(datamodel_pb2, _name, getattr(ryno_pb2, _name))
