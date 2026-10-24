FROM php:8.4.26-apache

# Single-worker prefork (required for the exploit — ARM and FIRE must hit the same worker)
RUN echo '<IfModule mpm_prefork_module>\n\
StartServers 1\n\
MinSpareServers 1\n\
MaxSpareServers 1\n\
MaxRequestWorkers 1\n\
MaxConnectionsPerChild 0\n\
</IfModule>' > /etc/apache2/mods-available/mpm_prefork.conf

# PHP configuration matching the exploit requirements
RUN echo 'display_errors=1'                         > /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'memory_limit=8M'                          >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'max_input_vars=1000'                      >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'session.use_cookies=1'                    >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'session.use_strict_mode=0'                >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'session.upload_progress.enabled=1'        >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'session.save_path=/tmp'                   >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'post_max_size=64M'                        >> /usr/local/etc/php/conf.d/exploit.ini && \
    echo 'upload_max_filesize=64M'                  >> /usr/local/etc/php/conf.d/exploit.ini

# Docroot — any PHP page will do
RUN echo '<?php echo "OK";' > /var/www/html/index.php && \
    mkdir -p /var/www/html/out && \
    chmod 777 /var/www/html/out /tmp

EXPOSE 80
