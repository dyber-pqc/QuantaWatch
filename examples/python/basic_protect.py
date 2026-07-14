"""Basic example: protect an Anthropic client with QuantaWatch."""
from anthropic import Anthropic
from quantawatch import protect

# Route all API calls through the QuantaWatch gateway
client = protect(Anthropic(), gateway_url="http://localhost:9090")

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello! What is post-quantum cryptography?"}]
)
print(response.content[0].text)
