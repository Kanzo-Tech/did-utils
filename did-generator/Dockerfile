# Ejemplo de Dockerfile para vc-builder y vc-verifier
FROM node:lts-alpine

# Configuración de directorio de trabajo
WORKDIR /vc

# Copiar archivos relevantes
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el código de la aplicación
COPY . .
