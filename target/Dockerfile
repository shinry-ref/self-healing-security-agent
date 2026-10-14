# やられ役サイト（Next.js EC）。better-sqlite3 はネイティブなので build-essential を使う。
FROM node:20-bookworm AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app ./
ENV PORT=3001
EXPOSE 3001
CMD ["sh", "-c", "npx next start -H 0.0.0.0 -p ${PORT:-3001}"]
