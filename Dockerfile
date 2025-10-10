FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
ENV PORT=5000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || exit 1
CMD ["node","src/index.js"]