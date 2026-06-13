RANDOM_NAME=test-tavily-$(openssl rand -hex 8)

openshell sandbox create --name $RANDOM_NAME --provider tavily \
    -- curl -X POST https://api.tavily.com/search  \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TAVILY_API_KEY" \
    -d '{"query": "Who is Leo Messi?"}'

openshell sandbox delete $RANDOM_NAME
