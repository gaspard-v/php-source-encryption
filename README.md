# php-source-encryption
A PHP program to create an encrypted and executable PHP file.


## Build the Builder
 - Execute `docker build --build-arg PHP_VERSION=7.3 --build-arg TARGET_PHP_VERSION=7 -t php-source-encryption-builder:7.3 .`

## Build with Docker

 - Create a "build.php" file
 - Execute `docker run -v $PWD/REPLACE_ME.php:/app/index.php -v $PWD/build.php:/app/build.php php-source-encryption-builder:8.3`