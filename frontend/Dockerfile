FROM node:20-alpine AS build

WORKDIR /build

COPY frontend/package.json ./
RUN npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /build/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# nginx:alpine already runs as a dedicated user via its default entrypoint.

EXPOSE 80
