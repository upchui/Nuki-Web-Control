# Stage 1: Build the application
# We don't have a build step for this simple app, but this is where it would go.

# Stage 2: Serve the application
FROM nginx:alpine

# Copy the static files from the current directory to the Nginx html directory
COPY . /usr/share/nginx/html

# Expose port 80
EXPOSE 80
