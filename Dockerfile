FROM alpine
MAINTAINER sunzhi1019 "sunzhi1019@163.com"
ADD GeoIP  /root
ADD ssdeep /root
RUN     sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
	addgroup -g 499 -S nginx && \
	adduser -HDu 499 -s /sbin/nologin -g 'web server' -G nginx nginx  && \
	mkdir ~/tmpfile && \
	cd ~/tmpfile && \

	apk --update --no-cache add wget git curl geoip geoip-dev pcre libxslt gd openssl-dev pcre-dev zlib-dev build-base \ 
	linux-headers libxslt-dev gd-dev openssl-dev libstdc++ libgcc patch logrotate supervisor inotify-tools \
	autoconf automake libtool yajl yajl-dev  \
	openssl  && \
   #     libcurl lmdb lmdb-dev lua lua-dev && \
	
	mv ~/ssdeep-2.14.1/ ./  && \
	cd ssdeep-2.14.1 && ./configure  && make && make install && cd .. &&\
	rm -rf /var/cache/apk/* && \

	curl -sO http://nginx.org/download/nginx-1.14.0.tar.gz  && \ 
	tar xf nginx-1.14.0.tar.gz && \
	mv nginx-1.14.0 nginx-1.14.0-modula && \
	tar xf nginx-1.14.0.tar.gz && \
    rm -rf nginx-1.14.0.tar.gz && \ 
	
	pwd  && \
	mv ~/GeoIP-1.4.8/ ./  && \
	cd GeoIP-1.4.8/ && \
	./configure && make && make install && cd .. &&\

	git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git  && \
	git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity  && \
	cd ./ModSecurity  && \
	git submodule init && git submodule update && \
	./build.sh && ./configure --with-geoip && make && make install  && \

	cd ../nginx-1.14.0 && \
	./configure \

--prefix=/usr/local/nginx \

--conf-path=/etc/nginx/nginx.conf \

--user=nginx \

--group=nginx \

--error-log-path=/var/log/nginx/error.log \

--http-log-path=/var/log/nginx/access.log \

--pid-path=/var/run/nginx/nginx.pid \

--lock-path=/var/lock/nginx.lock \

--with-http_ssl_module \

--with-http_stub_status_module \

--with-http_gzip_static_module \

--with-http_flv_module \

--with-http_mp4_module \

--http-client-body-temp-path=/var/tmp/nginx/client \

--http-proxy-temp-path=/var/tmp/nginx/proxy \

--http-fastcgi-temp-path=/var/tmp/nginx/fastcgi \

--http-uwsgi-temp-path=/var/tmp/nginx/uwsgi \

--add-dynamic-module=../ModSecurity-nginx/&& \

	make && make install  && \

	mkdir -p /var/tmp/nginx/{client,fastcgi,proxy,uwsgi}  && \

####	echo "daemon off;" >> /etc/nginx/ngnix.conf	&& \

####	cd ../nginx-1.14.0-modula 	&& \
####	./configure --add-dynamic-module=../ModSecurity-nginx	&& \
####	make modules && \
####	mv objs/ngx_http_modsecurity_module.so /usr/local/nginx/modules/ 	&& \
####
#### configure nginx and modsecurity
#### 
	cd /etc/nginx &&  sed -i '4i\load_module /usr/local/nginx/modules/ngx_http_modsecurity_module.so;'  ./nginx.conf && \
	sed -i '34,47d' ./nginx.conf && \
	sed -i '33i\ server{ \n  listen 80; \n  modsecurity on;\n location /{  \n  modsecurity_rules_file /etc/nginx/modec/main.conf;   \n proxy_pass http://localhost:8085; \n  proxy_set_header Host $host; \n}' ./nginx.conf && \
	mkdir /etc/nginx/modec && cd  /etc/nginx/modec && \
	wget https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended && \
	mv modsecurity.conf-recommended modsecurity.conf && sed -i '7d' ./modsecurity.conf &&  sed -i '4i\SecRuleEngine On' ./modsecurity.conf && \
	mkdir waf && cd waf/ && git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git && \
	cd owasp-modsecurity-crs/ && cp crs-setup.conf.example crs-setup.conf && cd rules && \
	cp REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf && \
	cp RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf && \
###
	cd /etc/nginx/modec/ && touch main.conf && echo "####" >> main.conf && \
       	sed -i '$a\Include /etc/nginx/modec/modsecurity.conf'   main.conf && \
	sed -i '$a\Include /etc/nginx/modec/waf/owasp-modsecurity-crs/crs-setup.conf'   main.conf && \
	sed -i '$a\Include /etc/nginx/modec/waf/owasp-modsecurity-crs/rules/*.conf'	  main.conf && \

	cd ~/ && rm -rf ./tmpfile  && \
	apk del wget git supervisor py-setuptools py-meld3 build-base  g++  gcc python2

ENV PATH /usr/local/nginx/sbin:$PATH

EXPOSE 80

CMD ["/usr/local/nginx/sbin/nginx","-g","daemon off;"]
