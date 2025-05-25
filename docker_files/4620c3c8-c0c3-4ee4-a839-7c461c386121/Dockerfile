FROM repopilot/base:latest

# Arguments that can be passed during build
ARG REPO_URL
ARG BRANCH
ARG ACCESS_TOKEN

# Set environment variables
ENV REPO_URL=$REPO_URL
ENV BRANCH=$BRANCH
ENV ACCESS_TOKEN=$ACCESS_TOKEN
ENV DEBIAN_FRONTEND=noninteractive
# Point to Ollama server on the host machine
ENV OLLAMA_HOST=host.docker.internal:11434
ENV REPO_BASENAME=JunkRepo

# Copy the clone script (from build context) into the image
# Permissions should be preserved from the host if host script is executable.
COPY clone_repo.sh /app/clone_repo.sh
# RUN chmod +x /app/clone_repo.sh # Removed as per user request, host chmod should suffice

# --- BEGIN ADDITION FOR issue.txt ---
# Copy issue.txt into the image if it was created
COPY issue.txt /app/issue.txt
# --- END ADDITION FOR issue.txt ---

# Copy the container agent script and its requirements
COPY container_agent.py /app/container_agent.py
COPY container_agent_requirements.txt /app/container_agent_requirements.txt

# Install dependencies for the container agent
RUN pip install --no-cache-dir -r /app/container_agent_requirements.txt

# Run the clone script
RUN /app/clone_repo.sh

# Ollama setup (serve, pull) is removed from here,
# as we are now expecting to connect to Ollama on the host.

# Execute the container agent script and save its output and errors
# RUN echo "Executing container_agent.py..." && \
#     (python3 /app/container_agent.py > /workspace/analysis_results/analysis_output.json 2> /workspace/analysis_results/analysis_error.log || touch /workspace/analysis_results/agent_failed_but_run_completed) && \
#     echo "Container agent execution attempt finished."

# Set working directory to the cloned repo
WORKDIR /workspace/JunkRepo

# Default command (can be overridden)
# CMD ["/bin/bash"] # CMD will be overridden by ENTRYPOINT or used as args to ENTRYPOINT if not executable form

ENTRYPOINT ["python3", "/app/container_agent.py"]
