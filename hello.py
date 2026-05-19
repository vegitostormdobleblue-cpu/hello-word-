import anthropic

client = anthropic.Anthropic()

response = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Di 'Hola Mundo' en español y preséntate brevemente."}
    ],
)

print(response.content[0].text)
