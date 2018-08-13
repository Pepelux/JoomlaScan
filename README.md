# JoomlaScan

Joomla Scan v1.5 :: by Pepelux 
------------------------------
 
Joomla Scan is a Joomla! vulnerability scanner. Steps used are:

Identification of components
----------------------------
To identify components installed the program checks index page and search for 'option=com_' 

Identification of version
-------------------------
To identify Joomla! version performs several checks in files to search revision date and ID. 

Files checked for SVN updates are /htaccess.txt, /configuration.php-dist, /includes/js/joomla.javascript.js, /libraries/joomla/template/tmpl/adminlists.html, /language/en-GB/en-GB.com_media.ini and /<admin_dir>/language/en-GB/en-GB.com_media.ini. 

Also are checked some files that appear and disappear in different versions.

Fingerprinting is based in JoomScan (http://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project). This is a very nice perl script but last update is of August 2009. 

To calculate Joomla! version I check ID revision of files and compare with date of new versions (http://es.wikipedia.org/wiki/Joomla!), also check changes in revisions (http://joomlacode.org/gf/project/joomla/scmsvn/?action=browse&path=/development/trunk/) and analyze code of old Joomla! versions.

Identification of firewall
--------------------------
To identify a possible firewall installed in Joomla! it checks any directories: /components/com_rsfirewall/, /components/com_rsfirewall/, /components/com_firewall/, and /components/com_firewall/.

Display possible vulnerabilities in core and compoments for the version used
----------------------------------------------------------------------------
The program use a bugs database of Joomla!. This database is based in advisories of SecurityFocus (http://www.securityfocus.com/) and ExploitDB (http://www.exploit-db.com/). When starts it checks for new updates. I'll try to maintain the database updated with new advisories :)

This program is for educational purposes only. I'm not responsable for a bad use. 
