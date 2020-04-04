# nginx-alg

1.Introducation:

    ALG MODULE support for NGINX and only ftp alg is supported currently.

2.How TO Use?

   a. configure to add the alg module into the nginx ./configure --with-stream --with-stream_alg ...

   b. add the "alg ftp" option into the upstream server syntax scope.

   server {

       listen 60.60.60.77:2121;
 
       proxy_timeout 65534;
 
       proxy_pass vpnftp1;
 
       alg ftp;
 
   }
