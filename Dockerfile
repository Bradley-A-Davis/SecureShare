FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=23456
ENV INBOX_DIR=/app/inbox
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY --from=build /app/dist ./dist
RUN mkdir -p /app/inbox
VOLUME ["/app/inbox"]
EXPOSE 23456
CMD ["node", "server.js"]
