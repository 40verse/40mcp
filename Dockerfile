FROM node:20-alpine

# Drop privileges to the node user before copying
# application code so the container does not run as root. Combined with
# .dockerignore (which excludes .env, .vault.json, etc.) this prevents
# host credentials from baking into the image and prevents a config-load
# RCE from gaining root inside the container.

WORKDIR /app
COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .

USER node
EXPOSE 8080
CMD ["node", "src/cli.js", "serve", "/config.json"]
