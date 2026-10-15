# vulnerable-python as a container: the same app.py, run under ordinary
# Python, so you can try the attacks in one command.
#
#   docker run --rm -p 127.0.0.1:5000:5000 ghcr.io/eyalsec/vulnerable-python
#
# The app is deliberately insecure. Publish the port on 127.0.0.1 only, as
# above, and never run this image on a machine reachable from the internet.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

# ping is what /cmd and /cmd-subprocess run before the injected command.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-adapters.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-adapters.txt

COPY . .

# Run as an ordinary user. The app writes its fixtures (the SQLite file,
# sample/, flag.txt) next to app.py at startup, so it owns /app.
RUN useradd --create-home --uid 10001 demo && chown -R demo:demo /app
USER demo

# Inside the container the app has to listen on all interfaces for a published
# port to reach it; the -p 127.0.0.1:... above keeps it on your machine.
ENV DEMO_HOST=0.0.0.0 \
    DEMO_PORT=5000 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=2)" || exit 1

CMD ["python", "app.py"]
