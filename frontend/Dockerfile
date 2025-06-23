# Usa a imagem oficial do Nginx como base
FROM nginx:alpine

# Remove a configuração padrão do Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copia a configuração personalizada do Nginx para o contêiner
COPY nginx.conf /etc/nginx/conf.d/

# Copia os arquivos estáticos do frontend para o diretório raiz do Nginx
COPY . /usr/share/nginx/html
