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
ENV USE_HTTPS=false
ENV NODE_ENV=production

# Optional (docs/visibility)
EXPOSE 4000

# Using curl for healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -s -f http://127.0.0.1:4000/health || exit 1

CMD ["node","src/index.js"]
