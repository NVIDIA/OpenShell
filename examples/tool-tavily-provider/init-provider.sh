# Import profile
openshell provider profile import -f tavily-profile.yaml

# Create provider instance
openshell provider create --name tavily --type tavily --credential TAVILY_API_KEY=${TAVILY_API_KEY}

# Enable Providers v2 for policy composition
openshell settings set --global --key providers_v2_enabled --value true
