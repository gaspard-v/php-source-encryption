ARG BUILDER_PHP_VERSION="8.3"

FROM alpine:latest as obfuscator
WORKDIR /app
RUN apk --update --no-cache add git
RUN git clone https://github.com/pk-fr/yakpro-po.git
RUN chmod a+x /app/yakpro-po/yakpro-po.php
RUN git clone https://github.com/nikic/PHP-Parser.git --branch 4.x
RUN mv --verbose /app/PHP-Parser /app/yakpro-po

FROM php:${BUILDER_PHP_VERSION}-cli-alpine
ENV TARGET_PHP_VERSION=$BUILDER_PHP_VERSION
ENV PHP_SOURCE_FILE="index.php"
WORKDIR /app
COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY --from=obfuscator /app/yakpro-po /usr/local/yakpro-po
RUN apk --update --no-cache add git
RUN ln -s /usr/local/yakpro-po/yakpro-po.php /usr/local/bin/yakpro-po 
COPY . .
RUN composer install
CMD [ "php", "generate.php"]
