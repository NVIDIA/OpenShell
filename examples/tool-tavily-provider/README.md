# Tavily Search Provider Example

This example demonstrates how to integrate external SaaS APIs as OpenShell providers using custom provider profiles. Tavily Search API is used as a concrete example, but the pattern applies to any SaaS service that uses API keys or OAuth tokens.

## How It Works

1. A custom provider profile (`tavily-profile.yaml`) defines the Tavily API endpoints, credential structure, and allowed binaries
2. The profile is imported into OpenShell using `openshell provider profile import`
3. A provider instance is created with your actual Tavily API key
4. When a sandbox attaches this provider, OpenShell:
   - Injects the API key as a placeholder environment variable (`TAVILY_API_KEY`)
   - Adds network policy rules allowing access to `api.tavily.com`
   - Restricts credential injection to the specified binaries (`curl`, `python3`)
5. The proxy resolves the placeholder and injects the real credential in outbound HTTP requests

## Usage

```bash
# 1. Set your Tavily API key on host machine
# this will be consumed by setup script and is never leaked to sandbox
export TAVILY_API_KEY=your_api_key_here

# 2. Run the setup script
sh init-provider.sh

# 3. Run the test script
sh run.sh
```
