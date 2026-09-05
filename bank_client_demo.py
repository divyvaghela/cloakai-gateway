"""
Bank Developer Integration Example:
Shows how easily CloakAI replaces standard OpenAI without changing business logic!
"""
import requests

GATEWAY_URL = "http://127.0.0.1:8080/v1/chat/completions"

sample_banking_payload = {
    "model": "gpt-4o",
    "messages": [
        {
            "role": "user",
            "content": "Verify transaction: Customer Ramesh Shah with PAN BKZPS1234F and Card 4532015112830366 requested wire transfer of 2,00,000 INR from State Bank of India."
        }
    ]
}

headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer mock-api-key"
}

print(">> Sending confidential banking request to CloakAI Gateway...")
response = requests.post(GATEWAY_URL, json=sample_banking_payload, headers=headers)

if response.status_code == 200:
    print("\n✅ Success! Response Received:")
    print(response.json()["choices"][0]["message"]["content"])
else:
    print(f"\n❌ Error {response.status_code}:", response.text)