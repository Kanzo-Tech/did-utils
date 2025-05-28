# Build stage
FROM node:18-alpine

# Set current working directory
WORKDIR /community-server

# Copy the package.json and package-lock.json files and any required docker context files (like a src folder)
COPY package*.json .

# Container config & data dir for volume sharing
RUN mkdir /config /data

# Copy example-data folder to /data
COPY example-data /data

# Copy all config files to /config
COPY config* /config

# Install and build the Solid community server
RUN npm install

# Remove src folder if present (not needed in container once built)
RUN rm -rf /community-server/src

# Informs Docker that the container listens on the specified network port at runtime
EXPOSE 3000

# Set command run by the container
ENTRYPOINT [ "sh", "-c", "npx community-solid-server -b ${CSS_BASE_URL}" ]

