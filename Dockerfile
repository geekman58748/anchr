FROM nginx:alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY *.html *.js /usr/share/nginx/html/
EXPOSE 10000
CMD ["nginx", "-g", "daemon off;"]
