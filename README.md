# php-source-encryption

A PHP program to create an encrypted and executable PHP file.

## Build the Builder

- Execute `docker build --build-arg TARGET_PHP_VERSION=8 -t xosh/php-source-encryption-builder:latest .`

## Build with Docker

- Create a "build.php" file
- Execute `docker run -v $PWD/REPLACE_ME.php:/app/index.php -v $PWD/build.php:/app/build.php xosh/php-source-encryption-builder:latest`
