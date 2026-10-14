# ダッシュボード（Next.js）。Cloud Run は $PORT を注入する。
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app ./
ENV PORT=3000
EXPOSE 3000
# 実行時に AGENT_URL / TARGET_URL を環境変数で渡す（サーバーコンポーネントが読む）。
CMD ["sh", "-c", "npx next start -H 0.0.0.0 -p ${PORT:-3000}"]
