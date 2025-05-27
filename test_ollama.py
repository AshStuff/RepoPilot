import asyncio
from cursor_agent_tools import create_agent

async def main():
    # Create an agent with a local Ollama model
    # Models must be pulled via Ollama CLI first: ollama pull MODEL_NAME
    agent = create_agent(
        model='ollama-qwen2.5-coder:32b',  # prefix with "ollama-" followed by model name
        temperature=0.3  # optional temperature setting
    )
    
    # Chat with the local model
    response = await agent.chat("Write a Python script to download YouTube videos")
    print(response)
    
    # Handle multimodal capabilities if model supports it
    # image_path = "/path/to/your/image.png"
    # image_response = await agent.query_image(
    #     image_paths=[image_path],
    #     query="What does this code screenshot show?"
    # )
    # print(image_response)

if __name__ == "__main__":
    asyncio.run(main())