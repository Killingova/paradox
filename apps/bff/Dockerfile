# apps/bff/Dockerfile
FROM node:20-alpine

WORKDIR /app

# nur was für npm nötig ist kopieren (schnelleres Caching)
COPY package.json ./

# produktive Dependencies
RUN npm install --omit=dev

# App-Code
COPY server.js ./

EXPOSE 3000

# Healthcheck (nimm EINE Variante)
# Variante A: wget (busybox ist auf Alpine dabei)
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -qO- http://localhost:3000/bff/health || exit 1

# Variante B: curl (falls du lieber curl willst)
# RUN apk add --no-cache curl
# HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
#   CMD curl -fsS http://localhost:3000/bff/health || exit 1

CMD ["npm","start"]
