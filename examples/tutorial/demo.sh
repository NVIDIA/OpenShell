# Import the custom endpointless provider profile
openshell provider profile import -f examples/tutorial/nv-inference-profile.yaml

# Delete the old provider instance (was bound to the built-in "openai" profile)
openshell provider delete nv-inference

# Recreate it against the custom "nv-inference" profile.
# Bare-key form reads the value from the local $OPENAI_API_KEY env var
# without it ever appearing in the command line.
openshell provider create --name nv-inference --type nv-inference --credential OPENAI_API_KEY

# Create a sandbox with the provider attached and the fixed policy applied
openshell sandbox create --provider nv-inference --policy examples/tutorial/policy.yaml --detach

curl -sS "https://inference-api.nvidia.com/v1/chat/completions"   -H "Authorization: Bearer $OPENAI_API_KEY"   -H "Content-Type: application/json"   -d '{
    "model": "azure/openai/gpt-5.6-sol",
    "messages": [{"role": "user", "content": "Where is NVIDIA'\''s headquarters in the US"}]
  }'

openshell policy update abundant-mackerel \
  --add-allow inference-api.nvidia.com:443:POST:/v1/chat/completions

curl -sS "https://inference-api.nvidia.com/v1/chat/completions"   -H "Authorization: Bearer $OPENAI_API_KEY"   -H "Content-Type: application/json"   -d '{
    "model": "azure/openai/gpt-5.6-sol",
    "messages": [{"role": "user", "content": "Where is NVIDIA'\''s headquarters in the US"}]
  }'
