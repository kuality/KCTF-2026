FROM php:8.2-apache

RUN apt-get update && \
    apt-get install -y libcurl4-openssl-dev && \
    docker-php-ext-install curl mysqli

COPY ./src /var/www/html

RUN rm -f /usr/local/lib/php/pearcmd.php \
            /usr/local/lib/php/peclcmd.php

WORKDIR /var/www/html