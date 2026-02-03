# MTProto Server - Dockerfile for easy deployment

FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
# Railway pode buildar sem package-lock.json; `npm ci` falha nesse caso.
RUN npm install --omit=dev

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
