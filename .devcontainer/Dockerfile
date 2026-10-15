# The development environment GitHub Codespaces and Ona (formerly Gitpod) open.
FROM mcr.microsoft.com/devcontainers/python:3.13

# ping is what /cmd and /cmd-subprocess run before the injected command.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
