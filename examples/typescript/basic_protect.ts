/**
 * Basic example: protect Anthropic API calls with QuantaWatch.
 *
 * This wraps the global `fetch` so every outbound request to Anthropic is
 * routed through the QuantaWatch gateway for threat inspection and audit
 * logging.
 */
import { protect } from "@quantawatch/sdk";

const safeFetch = protect(fetch, {
  gatewayUrl: "http://localhost:9090",
  agentName: "example-agent",
});

async function main(): Promise<void> {
  const response = await safeFetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY ?? "",
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1024,
      messages: [
        { role: "user", content: "Hello! What is post-quantum cryptography?" },
      ],
    }),
  });

  const data = await response.json();
  console.log(JSON.stringify(data, null, 2));
}

main().catch(console.error);
