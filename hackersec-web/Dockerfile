# Stage 1: Build the React app
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Serve with nginx
# Pin 1.24 — newer alpine/nginx builds crash on DGX CentOS 7 (kernel 3.10)
# with: pwrite() "/run/nginx.pid" failed (1: Operation not permitted)
FROM nginx:1.24-alpine

COPY nginx.main.conf /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
