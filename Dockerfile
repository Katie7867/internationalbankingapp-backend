# Dockerfile
FROM node:20-alpine
WORKDIR /app

# Install curl so HEALTHCHECK works
RUN apk add --no-cache curl

COPY package*.json ./
RUN npm install --production

COPY . .

# Default port inside container (CircleCI maps 5000:5000)
ENV PORT=4000

# Optional (docs/visibility)
EXPOSE 4000

# Using curl for healthcheck
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["node","src/index.js"]
