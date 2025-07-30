# Stage 1: Build and minify assets
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Create package.json for minification tools
RUN echo '{ \
  "name": "frontend-build", \
  "version": "1.0.0", \
  "devDependencies": { \
    "terser": "latest", \
    "postcss": "latest", \
    "cssnano": "latest", \
    "postcss-cli": "latest", \
    "html-minifier-terser": "latest" \
  } \
}' > package.json

# Install build tools
RUN npm install

# Copy source files
COPY . .

# Create build directory
RUN mkdir -p dist

# Minify JavaScript
RUN npx terser app.js \
    --compress drop_console=true,drop_debugger=true,sequences=true,conditionals=true,booleans=true,unused=true,if_return=true,join_vars=true \
    --mangle \
    --output dist/app.js

# Minify CSS
RUN npx postcss style.css \
    --use cssnano \
    --no-map \
    --output dist/style.css

# Minify HTML files
RUN npx html-minifier-terser index.html \
    --collapse-whitespace \
    --remove-comments \
    --remove-optional-tags \
    --remove-redundant-attributes \
    --remove-script-type-attributes \
    --remove-tag-whitespace \
    --use-short-doctype \
    --minify-css true \
    --minify-js true \
    --output dist/index.html

RUN npx html-minifier-terser login.html \
    --collapse-whitespace \
    --remove-comments \
    --remove-optional-tags \
    --remove-redundant-attributes \
    --remove-script-type-attributes \
    --remove-tag-whitespace \
    --use-short-doctype \
    --minify-css true \
    --minify-js true \
    --output dist/login.html

# Copy other static files
RUN cp *.ico dist/ 2>/dev/null || true

# Stage 2: Serve the application
FROM nginx:alpine

# Copy the minified files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Add nginx configuration for better caching and gzip
RUN echo 'server { \
    listen 80; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    # Gzip compression \
    gzip on; \
    gzip_vary on; \
    gzip_min_length 1024; \
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json; \
    \
    # Cache static assets \
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ { \
        expires 1y; \
        add_header Cache-Control "public, immutable"; \
    } \
    \
    # Security headers \
    add_header X-Frame-Options "SAMEORIGIN"; \
    add_header X-XSS-Protection "1; mode=block"; \
    add_header X-Content-Type-Options "nosniff"; \
    \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80
