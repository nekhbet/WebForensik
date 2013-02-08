This is an update to the existing SourceForge project <a href="http://sourceforge.net/projects/webforensik/" target="_blank">WebForensik</a> so it works with latest <a href="https://github.com/PHPIDS/" target="_blank">PHPIDS</a>.
<hr>

To install it : 
<pre>
mkdir webforensik
cd webforensik
git clone https://github.com/nekhbet/WebForensik.git ./
git submodule init
git submodule update
cd externals/phpids
curl -s https://getcomposer.org/installer | php
php composer.phar update
cd lib/IDS
mkdir tmp
cd ../../../../
</pre>

That's all :)

To run it just :
<pre>
./webforensik.php PATH_TO_ACCESS_LOG
</pre>

Example : 
<pre>
./webforensik.php /var/log/apache2/access.log
</pre>
