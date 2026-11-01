FROM python:3.12-slim

# A build-time secret baked into an image layer (never removed from history).
ENV DB_PASSWORD=image-db-password-7c2
ARG API_TOKEN=image-api-token-4e1

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

# The container runs as root.
USER root

CMD ["python", "-m", "app"]