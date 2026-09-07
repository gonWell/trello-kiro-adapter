FROM node:20-alpine

WORKDIR /app

# Instala só as deps de produção primeiro (cache de layer)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
