#!/usr/bin/perl
# -=-=-=-=-=-=-=-
# JoomlaScan v1.5
# -=-=-=-=-=-=-=-
#
# Pepelux <pepeluxx[at]gmail.com>
# www.pepelux.org
# blog.pepelux.org
# Twitter: @pepeluxx
#
# Initial date : 2010-09-04
# Last revision: 2013-03-17
#
# Changelog at the end


use warnings;
use strict;
use LWP::UserAgent;
#use LWP::Debug qw(+);
use Getopt::Long;
use HTTP::Request::Common;
use Switch;

my @data = ("admin_en-GB.txt", "admin_en-GB_media.txt", "adminlists.txt", "bugs.txt",
            "en-GB.txt", "en-GB_media.txt", "admin_en-GB_installer.txt", "files.txt", "generic.txt", "helpsites.txt",
			"htaccess.txt", "javascript.txt", "metadata.txt", "php-dist.txt");

my $joomlascanversion = "1.5";
my $dbversion = "dbversion.txt";
my $programversion = "joomlascanversionperl.txt";
my $update_path_db = "http://www.pepelux.org/programs/joomlascan/";
my $update_path_program = "http://www.pepelux.org/scripts/";

my $url = '';                 # url to check
my $proxy = '';               # optional proxy server
my $admin = 'administrator';  # admin folder
my $v = 0;                    # check version
my $c = 0;                    # check components
my $f = 0;                    # check firewall
my $co = 0;                   # check core bugs
my $cm = 0;                   # check components bugs
my $all = 0;                  # check all
my $ot = 0;                   # output to text file
my $oh = 0;                   # output to html file
my $h = 0;                    # usage help
my $about = 0;                # about joomlascan
my $version = 0;              # print version
my $update = 0;               # update program & database
my $forceupdate = 0;          # force update program & database

my $index = '';
my $firewall = '';
my @components;
my $nVerIniTmp = -1;
my $nRevIniTmp = -1;
my $nModIniTmp = -1;
my $nVerFinTmp = -1;
my $nRevFinTmp = -1;
my $nModFinTmp = -1;
my @version = ("x", "x", "x", "", "x", "x", "x", "");
my $isMambo = 0;

my @sVulnerability;
my @sVersion;
my @sFile;
my @sExploit;
my @sUrlExploit;
my @bVulnerability;
my @bVersion;
my @bFile;
my @bExploit;
my @bUrlExploit;
my @bType;
my $webserver = '';

my $ua = LWP::UserAgent->new() or die;
$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008072820 Firefox/3.0.1");
$ua->timeout(10);


##########################
# check params and start #
##########################

sub init() {
	mkdir "db";
	mkdir "reports";

	if ($^O =~ /Win/) {system("cls");}else{system("clear");}
	logo();

	# check params
	my $result = GetOptions ("u=s" => \$url, 
	                         "p=s" => \$proxy, 
	                         "a=s" => \$admin, 
	                         "v+" => \$v, 
	                         "c+" => \$c, 
	                         "f+" => \$f, 
	                         "co+" => \$co, 
	                         "cm+" => \$cm, 
	                         "ot+" => \$ot, 
	                         "oh+" => \$oh, 
	                         "force-update+" => \$forceupdate,
	                         "update+" => \$update,
	                         "about+" => \$about,
									 "version+" => \$version, 
	                         "help+" => \$h,
	                         "h+" => \$h);


	if($proxy ne '') {
		if($proxy !~ /:\/\//) { $proxy = 'http://' . $proxy; }

		$ua->proxy(['http', 'ftp'], $proxy);
	}    

	forceupdate() if ($forceupdate eq 1);
	update() if ($update eq 1);
	about() if ($about eq 1);
	version("bugs") if ($version eq 1);
	if ($h eq 1 || $url eq '' || ($co eq 1 && $v eq 0) || ($cm eq 1 && $c eq 0)) { help(); exit 1; }

	$all = 1 if ($v eq 0 && $c eq 0 && $f eq 0);
	$url = 'http://' . $url if ($url !~ /^http:/);
	$url = $url . '/' if ($url !~ /$\//);

	checkdatafiles();
	$webserver = checkwebserver($url);
	scanfirewall() if ($f eq 1 || $all eq 1);
	scancomponents() if ($c eq 1 || $all eq 1);
	scanversion() if ($v eq 1 || $all eq 1);
	scantips("generic") if ($all eq 1);
	scanbugs("bugs", "Core") if ($co eq 1 || $all eq 1);
	scanbugs("bugs", "Component") if ($cm eq 1 || $all eq 1);
	print "Scan finished\n";

	printscreen();
	printtextfile() if ($ot eq 1);
	printhtmlfile() if ($oh eq 1);
}


#############################
# search for possibles bugs #
#############################

sub scanbugs {
	my $file = shift;
	my $type = shift;
	my @tmp;
	my @verTmp;
	my @versionTmp = @version;

	$file .= ".txt";

	if ($#versionTmp > 6) {
		for (my $i = 0; $i < 8; $i++) {
			if ($versionTmp[$i] eq "x") {
				$versionTmp[$i] = "0";
			}
		}
	}

	print "Scanning " . $file . " in " . $type . " ";
	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	while (<DAT>) {
		if (($_ !~ /^#/)) {
			if ($all eq 1 || ($co eq 1 && $_ =~ /^Core/) || ($cm eq 1 && $_ =~ /^Component/)) {
				@tmp = split(/\|/, $_);

				if ($#tmp > 4) {
					my $v1 = $tmp[3];
					my $v2 = $tmp[4];
					my $v = '';

					if ($v1 eq $v2 && $v1 ne "x.x.x") {
						$v = $v1;
					}
					elsif ($v1 ne "x.x.x") {
						$v = "[" . $v1 . "-" . $v2 . "]";
					}
					elsif ($v2 ne "x.x.x") {
						$v = "<= " . $v2;
					}
					else {
						$v = "";
					}

					if ($v ne "") {
						$v = "Joomla! " . $v;
					}

					if ($tmp[5] ne "") {
						if ($v1 ne "x.x.x" || $v2 ne "x.x.x") {
							$v .= " - ";
						}

						$v .= $tmp[5];
					}

					my @aux1 = split(/\./, $v1);
					my @aux2 = split(/\./, $v2);

					$aux1[0] = "0" if ($aux1[0] eq "x");
					$aux1[1] = "0" if ($aux1[1] eq "x");
					$aux1[2] = "0" if ($aux1[2] eq "x");
					$aux2[0] = "0" if ($aux2[0] eq "x");
					$aux2[1] = "0" if ($aux2[1] eq "x");
					$aux2[2] = "0" if (defined $aux2[2] && $aux2[2] eq "x");

					@verTmp = ($aux1[0], $aux1[1], $aux1[2], "");
					push @verTmp, $aux2[0], $aux2[1], $aux2[2], "";

					my $tipo = $tmp[0];
					my $modVuln = 0;

					if ($tmp[1] ne "") {
						if ($tmp[1] !~ m/\//) {
							$tipo .= " - " . $tmp[1];
							$tipo =~ s/joomla//g;
						}

						if ($tmp[1] =~ m/ /) {
							my @aux = split(/ /, $tmp[1]);

							foreach (@aux) {
								if (checkcomp($_) eq 1 || $_ eq "joomla") {
									$modVuln = 1;
								}
							}
						}
						elsif (($tmp[1] =~ m/.php/ || $tmp[1] =~ m/.htm/) && $tmp[1] !~ m/index.php/) {
							if ($index =~ m/$tmp[1]/ || checkpage($url . $tmp[1]) eq 1) {
								$modVuln = 1;
							}
						}
						elsif ($tmp[1] =~ m/\//) {
							if ($tmp[1] !~ m/index.php/) {
								if ($index =~ m/$tmp[1]/ || checkpage($url . $tmp[1])) {
									$modVuln = 1;
								}
							}
							elsif ($index =~ m/$tmp[1]/) {
								$modVuln = 1;
							}
						}
						elsif (checkcomp($tmp[1]) eq 1) {
							$modVuln = 1;
						}
					}
					else {
						$modVuln = 1;
					}

					if ($modVuln eq 1) {
						if (($verTmp[0] <= $versionTmp[0] && $verTmp[1] <= $versionTmp[1] &&
							 $verTmp[2] <= $versionTmp[2] &&
							 $verTmp[4] >= $versionTmp[0] && $verTmp[5] >= $versionTmp[1] && 
							 $verTmp[6] >= $versionTmp[6]) ||
							($verTmp[0] >= $versionTmp[4] && $verTmp[1] >= $versionTmp[5] &&
							 $verTmp[2] >= $versionTmp[6] &&
							 $verTmp[4] <= $versionTmp[4] && $verTmp[5] <= $versionTmp[5] && 
							 $verTmp[6] <= $versionTmp[6]) ||
							($verTmp[0] eq 0 && $verTmp[1] eq 0 && $verTmp[2] eq 0 && 
							 $verTmp[4] eq 0 && $verTmp[5] eq 0 && $verTmp[6] eq 0)) {
								if ($_ =~ /$type/) {
									push @bVulnerability, $tmp[2];
									push @bType, $type;
									push @bVersion, $v;
									push @bExploit, $tmp[6];
									push @bUrlExploit, $tmp[7];
								}
						}
					}
				}
			}
		}
	}

	close(DAT);
	print "\n";
}

sub checkcomp {
	my $comp = shift;

	foreach (@components) {
		if ($_ eq $comp) {
			return 1;
		}
	}

	return 0;
}

################################
# search for unprotected files #
################################

sub scantips {
	my $file = shift;
	my @tmp;

	$file .= ".txt";

	print "Scanning " . $file . " ";
	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	while (<DAT>) {
		if (($_ !~ /^#/)) {
			@tmp = split(/\|/, $_);

			if ($#tmp > 3 && getpage($url . $tmp[0])) {
				push @sVulnerability, $tmp[1];
				push @sVersion, $tmp[2];
				push @sFile, $url . $tmp[0];
				push @sExploit, $tmp[3];
				push @sUrlExploit, $tmp[4];
			}
		}
	}

	close(DAT);
	print "\n";
}


######################
# search for version #
######################

sub scanversion {
	scancopyrigth();

	my $pag = getpage($url . "htaccess.txt");
	die ("This website is Mambo") if ($pag =~ m/package Mambo/);
	scanconfigfile($pag, "htaccess") if ($pag ne "");

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . $admin . "/manifests/files/joomla.xml");
		scanmanifestfile($pag) if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "language/en-GB/en-GB.ini");
		scanlanguagefile($pag, "en-GB") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . $admin . "/language/en-GB/en-GB.ini");
		scanlanguagefile($pag, "admin_en-GB") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . $admin . "/language/en-GB/en-GB.com_media.ini");
		scanconfigfile($pag, "admin_en-GB_media") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "configuration.php-dist");
		scanconfigfile($pag, "php-dist") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "includes/js/joomla.javascript.js");
		scanconfigfile($pag, "javascript") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "libraries/joomla/template/tmpl/adminlists.html");
		scanconfigfile($pag, "adminlists") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "components/com_contact/metadata.xml");
		scanconfigfile($pag, "metadata") if ($pag ne "");
	}

	# 1.5 => helpsites-15.xml -- 1.6 => helpsites-16.xml -- 1.7 => helpsites.xml
	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . $admin . "/help/helpsites-15.xml");
		scanconfigfile($pag, "helpsites") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "language/en-GB/en-GB.com_media.ini");
		scanconfigfile($pag, "en-GB_media") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . $admin . "/language/en-GB/en-GB.com_installer.ini");
		scanconfigfile($pag, "admin_en-GB_installer") if ($pag ne "");
	}

	if ($version[0] eq "x" || $version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		scanforfiles("files");
	}

	if ($version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "language/en-GB/en-GB.ini");
		scanspecialcases($pag);
	}
	
	# more special cases
	if ($version[0] eq "1" && $version[1] eq "7" && $version[2] eq "1" && $version[4] eq "1" && $version[5] eq "7" && $version[6] eq "2") {
		$pag = getpage($url . $admin . "/components/com_admin/sql/updates/mysql/1.7.0-2011-06-06-2.sql");

		if (length($pag) == 161) {
			$version[2] = "2";
		}
		if (length($pag) == 162) {
			$version[6] = "1";
		}
	}
	if ($version[0] eq "1" && $version[1] eq "6" && $version[2] eq "3" && $version[4] eq "1" && $version[5] eq "6" && $version[6] eq "6") {
		$pag = getpage($url . $admin . "/language/en-GB/en-GB.lib_joomla.ini");
		
		if ($pag =~ m/JLIB_INSTALLER_ABORT_FILE_INSTALL_CUSTOM_INSTALL_FAILURE/) {
			$version[2] = "4";
		}
		else {
			$version[6] = "3";
		}
	}
	if ($version[0] eq "1" && $version[1] eq "6" && $version[2] eq "4" && $version[4] eq "1" && $version[5] eq "6" && $version[6] eq "6") {
		$pag = getpage($url . "/language/en-GB/en-GB.files_joomla.sys.ini");
		
		if ($pag =~ m/1\.6\.4 Content Management System/) {
			$version[6] = "4";
		}
		else {
			$version[2] = "5";
		}
	}
}

sub scanforfiles() {
	my $file = shift;
	my $pag;
	my @tmp;
	my $aux = '';
	my @verTmp;
	my @lFile;
	my @lVersion;
	my @lVersionAlt;

	$file .= ".txt";

	print "Scanning " . $file . " ";
	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	while (<DAT>) {
		if (($_ !~ /^#/)) {
			@tmp = split(/\|/, $_);

			if ($#tmp > 1) {
				push @lFile, $tmp[0];
				push @lVersion, $tmp[1];
				push @lVersionAlt, $tmp[2];
			}
		}
	}

	close(DAT);

	for (my $i = 0; $i <= $#lFile; $i++) {
		if ($lFile[$i] =~ m/\$admin/) {
			$lFile[$i] =~ s/\$admin//g;
			$pag = checkpage($url . $admin . $lFile[$i]);
		}
		else {
			$pag = checkpage($url . $lFile[$i]);
		}

		if ($pag eq 1) {
			my @aux1 = split(/\-/, $lVersion[$i]);

			if ($#aux1 > 0) {
				my @aux2 = split(/\./, $aux1[0]);
				my @aux3 = split(/\./, $aux1[1]);

				push @aux2, "" if ($#aux2 eq 2);
				push @aux3, "" if ($#aux3 eq 2);

				@verTmp = ($aux2[0], $aux2[1], $aux2[2], $aux2[3]);
				push @verTmp, $aux3[0], $aux3[1], $aux3[2], $aux3[3];

				if ($verTmp[2] ne "x" && ($version[2] eq "x" || $verTmp[2] > $version[2] || ($verTmp[2] eq $version[2] && $verTmp[3] ne $version[3])) && $version[6] ne "x" && $verTmp[2] <= $version[6]) {
					$version[0] = $verTmp[0];
					$version[1] = $verTmp[1];
					$version[2] = $verTmp[2];
					$version[3] = $verTmp[3];
				}

				if ($verTmp[6] ne "x" && ($version[6] eq "x" || $verTmp[6] < $version[6] || ($verTmp[6] eq $version[6] && $verTmp[7] ne $version[7]))) {
					if ($version[5] eq $verTmp[5]) {
						$version[4] = $verTmp[4];
						$version[5] = $verTmp[5];
						$version[6] = $verTmp[6];
						$version[7] = $verTmp[7];
					}
				}
			}
		}
		elsif ($lVersionAlt[$i] ne "") {
			my @aux1 = split(/\-/, $lVersionAlt[$i]);

			if ($#aux1 > 0) {
				my @aux2 = split(/\./, $aux1[0]);
				my @aux3 = split(/\./, $aux1[1]);

				push @aux2, "" if ($#aux2 eq 2);
				push @aux3, "" if ($#aux3 eq 2);

				@verTmp = ($aux2[0], $aux2[1], $aux2[2], $aux2[3]);
				push @verTmp, $aux3[0], $aux3[1], $aux3[2], $aux3[3];

				if ($verTmp[2] ne "x" && ($version[2] eq "x" || $verTmp[2] > $version[2] || ($verTmp[2] eq $version[2] && $verTmp[3] ne $version[3])) && $version[6] ne "x" && $verTmp[2] <= $version[6]) {
					$version[0] = $verTmp[0];
					$version[1] = $verTmp[1];
					$version[2] = $verTmp[2];
					$version[3] = $verTmp[3];
				}

				if ($verTmp[6] ne "x" && ($version[6] eq "x" || $verTmp[6] < $version[6] || ($verTmp[6] eq $version[6] && $verTmp[7] ne $version[7]))) {
					if ($version[5] eq $verTmp[5]) {
						$version[4] = $verTmp[4];
						$version[5] = $verTmp[5];
						$version[6] = $verTmp[6];
						$version[7] = $verTmp[7];
					}
				}
			}
		}
	}

	print "\n";
}

sub scanspecialcases() {
	my $pag = shift;
	my @tmp;
	my $aux = '';
	my @verTmp;
	my @lContent;
	my @lVersion;

	if ($pag =~ m/Problem with Joomla site/) {
		if ($version[2] ne "x" && $version[2] ne $version[6]) {
			$version[0] = "1";
			$version[4] = "1";
			$version[1] = "5";
			$version[5] = "5";
			$version[2] = "17";
			$version[6] = "17";
			$version[3] = "Stable";
			$version[7] = "Stable";
		}
	}
    else {
		if ($version[0] eq "1" && $version[1] == "5") {
			if ($version[2] ne $version[6]) {
				if ($version[2] eq "17" && $version[6] > "17") {
					$version[2] = "18";
				}

				if ($version[6] == "17" && $version[2] < "17") {
					$version[6] = "16";
				}
			}
		}
	}

	if ($version[0] ne $version[4] || $version[1] ne $version[5] || $version[2] ne $version[6] || $version[3] ne $version[7]) {
		$pag = getpage($url . "libraries/joomla/template/tmpl/adminlists.html");

		if ($pag eq "" && ($version[1] eq "x" || $version[1] eq "6") && ($version[3] ne "Stable")) {
			@verTmp = ("1", "6", "0", "beta1");
			push @verTmp, "1", "6", "0", "beta8";

			if ($verTmp[6] ne "x" && ($version[2] eq "x" || $verTmp[6] > $version[2]) && $version[1] eq $verTmp[5]) {
				$version[0] = $verTmp[0];
				$version[1] = $verTmp[1];
				$version[2] = $verTmp[2];
				$version[3] = $verTmp[3];
			}

			if ($verTmp[6] ne "x" && ($version[6] eq "x" || $verTmp[6] < $version[6])) {
				$version[4] = $verTmp[4];
				$version[5] = $verTmp[5];
				$version[6] = $verTmp[6];
				$version[7] = $verTmp[7];
			}
		}
	}
}

sub scanlanguagefile() {
	my $pag = shift;
	my $file = shift;
	my @tmp;
	my $aux = '';
	my @verTmp;
	my @lContent;
	my @lVersion;

	$file .= ".txt";

	print "Scanning " . $file . " ";
	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	while (<DAT>) {
		if (($_ !~ /^#/)) {
			@tmp = split(/\|/, $_);

			push @lContent, $tmp[0];
			push @lVersion, $tmp[1];
		}
	}

	close(DAT);
	
	for (my $i = 0; $i <= $#lContent; $i++) {
		if ($lContent[$i] =~ m/\&/) {
			@tmp = split(/\&/, $lContent[$i]);

			if ($#tmp > 0) {
				$aux = $lVersion[$i] if ($pag =~ m/$tmp[0]/ && $pag =~ m/$tmp[1]/);
			}
		}
		else {
			$aux = $lVersion[$i] if ($pag =~ m/$lContent[$i]/);
		}
	}

	my @aux1 = split(/\-/, $aux);

	if ($#aux1 > 0) {
		my @aux2 = split(/\./, $aux1[0]);
		my @aux3 = split(/\./, $aux1[1]);

		push @aux2, "" if ($#aux2 eq 2);
		push @aux3, "" if ($#aux3 eq 2);

		@verTmp = ($aux2[0], $aux2[1], $aux2[2], $aux2[3]);
		push @verTmp, $aux3[0], $aux3[1], $aux3[2], $aux3[3];

		if ($version[2] eq "x" || $verTmp[1] > $version[1] || ($verTmp[2] > $version[2] && $verTmp[1] eq $version[1]) || ($verTmp[2] eq $version[2] && $verTmp[3] ne $version[3])) {
			$version[0] = $verTmp[0];
			$version[1] = $verTmp[1];
			$version[2] = $verTmp[2];
			$version[3] = $verTmp[3];
		}

		if ($verTmp[6] ne "x" && ($version[6] eq "x" || $verTmp[5] < $version[5] || ($verTmp[6] < $version[6] && $verTmp[5] eq $version[5]) || ($verTmp[6] eq $version[6] && $verTmp[7] ne $version[7]))) {
			$version[4] = $verTmp[4];
			$version[5] = $verTmp[5];
			$version[6] = $verTmp[6];
			$version[7] = $verTmp[7];
		}
	}

	print "\n";
}

sub scanconfigfile() {
	my $pag = shift;
	my $file = shift;
	my @tmp;
	my $aux = '';
	my @verTmp;
	my @lContent;
	my @lVersion;
	my @lVersionAlt;
	my @lInverse;

	$file .= ".txt";

	print "Scanning " . $file . " ";
	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	while (<DAT>) {
		if (($_ !~ /^#/)) {
			@tmp = split(/\|/, $_);

			if (($tmp[0] =~ /^!/)) {
				push @lContent, substr $tmp[0], 1;
				push @lInverse, "1";
			}
			else {
				push @lContent, $tmp[0];
				push @lInverse, "0";
			}

			push @lVersion, $tmp[1];
			push @lVersionAlt, $tmp[2] if ($#tmp > 1);
		}
	}

	close(DAT);

	for (my $i = 0; $i <= $#lContent; $i++) {
		if ($pag =~ m/$lContent[$i]/) {
			$aux = $lVersion[$i];
		}
		else {
			$aux = $lVersionAlt[$i] if ($lInverse[$i] eq "1");
		}
	}

	my @aux1 = split(/\-/, $aux);

	if ($#aux1 > 0) {
		my @aux2 = split(/\./, $aux1[0]);
		my @aux3 = split(/\./, $aux1[1]);

		push @aux2, "" if ($#aux2 eq 2);
		push @aux3, "" if ($#aux3 eq 2);

		@verTmp = ($aux2[0], $aux2[1], $aux2[2], $aux2[3]);
		push @verTmp, $aux3[0], $aux3[1], $aux3[2], $aux3[3];

		if ($version[2] eq "x" || $verTmp[1] > $version[1] || ($verTmp[2] > $version[2] && $verTmp[1] eq $version[1]) || ($verTmp[2] eq $version[2] && $verTmp[3] ne $version[3])) {
			$version[0] = $verTmp[0];
			$version[1] = $verTmp[1];
			$version[2] = $verTmp[2];
			$version[3] = $verTmp[3];
		}

		if ($verTmp[6] ne "x" && ($version[6] eq "x" || $verTmp[5] < $version[5] || ($verTmp[6] < $version[6] && $verTmp[5] eq $version[5]) || ($verTmp[6] eq $version[6] && $verTmp[7] ne $version[7]))) {
			$version[4] = $verTmp[4];
			$version[5] = $verTmp[5];
			$version[6] = $verTmp[6];
			$version[7] = $verTmp[7];
		}
	}

	print "\n";
}

sub scanmanifestfile {
	my $pag = shift;
	
		if ($pag =~ m/\<version\>/) {
			$pag =~ /\<version\>(.*)\<\/version\>/;
			my $aux = $1;
			my @tmp = split(/\./, $aux);
			$version[0] = $tmp[0];
			$version[1] = $tmp[1];

			if ($tmp[2] =~ /_/) {
				my @tmp2 = split(/_/, $tmp[2]);
				$version[2] = $tmp2[0];
				$version[3] = $tmp2[1];
				$version[6] = $tmp2[0];
				$version[7] = $tmp2[1];
			}
			else {
				$version[2] = $tmp[2];
				$version[3] = "Stable";
				$version[6] = $tmp[2];
				$version[7] = "Stable";
			}
			
			$version[4] = $tmp[0];
			$version[5] = $tmp[1];
		}
}

sub scancopyrigth {
	my @aux;
	
	# search for version 1.0
	@version = search_meta("1.0");

	# search for version 1.5
	@aux = search_meta("1.5");
	@version = @aux if ($aux[2] ne "x");
}

sub search_meta {
	my $check = shift;
	my @ver;

	print "Searching for copyright of version " . $check . "\n";

	switch ($check) {
		case "1.0" {
		    if ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\sOpen\sSource\sMatters/) {
				push @ver,  "1", "0", "0", "", "1", "0", "8", "";
			}
			elsif ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2006\sOpen\sSource\sMatters/) {
				push @ver,  "1", "0", "9", "", "1", "0", "12", "";
			}
			elsif ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2006\-\2007\sOpen\sSource\sMatters/) {
				push @ver,  "1", "0", "13", "", "1", "0", "15", "";
			}
			else {
				push @ver,  "x", "x", "x", "", "x", "x", "x", "";
			}
		}

		case "1.5" {
		    if ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2006\-\2007\sOpen\sSource\sMatters/) {
				push @ver,  "1", "5", "0", "RC1", "1", "5", "0", "RC4";
			}
			elsif ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2008\sOpen\sSource\sMatters/) {
				push @ver,  "1", "5", "0", "Stable", "1", "5", "12", "Stable";
			}
			elsif ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2009\sOpen\sSource\sMatters/) {
				push @ver,  "1", "5", "13", "Stable", "1", "5", "15", "Stable";
			}
			elsif ($index =~ m/Joomla!\s\-\sCopyright\s\(C\)\s2005\-\2010\sOpen\sSource\sMatters/) {
				push @ver,  "1", "5", "16", "Stable", "1", "5", "20", "Stable";
			}
			else {
				push @ver,  "x", "x", "x", "", "x", "x", "x", "";
			}
		}
		else {
			push @ver,  "x", "x", "x", "", "x", "x", "x", "";
		}
	}

	return @ver;
}


#########################
# search for components #
#########################

sub scancomponents {
	my $html = $index;

	print "Searching for components ";

	# search for com_ ... end with &, ", ' / 
	while ($html =~ m{com_(.*?)(&|"|'|\s|/)}ig) {
		if (checkcomponent("com_" . $1, @components) eq 0) {
			push @components, "com_" . $1;
		}
	}

	print "\n";
}

sub checkcomponent {
	my($what, @array) = @_;

	foreach (0..$#array) {
		if ($what eq $array[$_]) {
			return 1;         
		}
	}

	0;                    
}


#######################
# search for firewall #
#######################

sub scanfirewall {
	print "Searching for firewall\n";

    $firewall = "com_rsfirewall" if( checkpage($url . $admin . "/components/com_rsfirewall/") eq 1 or
		                             checkpage($url . "/components/com_rsfirewall/") eq 1 or
		                             checkpage($url . $admin . "/components/com_firewall/") eq 1 or
                                     checkpage($url . "/components/com_firewall/") eq 1)
}


####################
# check data files #
####################

sub checkdatafiles {
	for (my $i = 0; $i <= $#data; $i++) {
		open(DAT, "db/" . $data[$i]) || die("File " . $data[$i] . " not found. Try --force-update\n");
		close(DAT);
	}

	$index = getpage($url);
}


#############################
# update program & database #
#############################

sub checkversion {
	my $file = shift;

	my $req = HTTP::Request->new(GET => $update_path_db . $file);
	$req->content_type('application/x-www-form-urlencoded');
	my $res = $ua->request($req);
	my $content = $res->content;

	return $content;
}

sub download {
	my $update_path = shift;
	my $file = shift;

	my $req = HTTP::Request->new(GET => $update_path . $file);
	$req->content_type('application/x-www-form-urlencoded');
	my $res = $ua->request($req);
	my $content = $res->content;

	if ($update_path eq $update_path_db) {
		$file = "db/" . $file;
	}

	$file = "joomlascan.pl" if ($file eq "joomlascan.txt");

	open(DAT, '>', $file) || die("Error creating file " . $dbversion . "\n");
	print DAT  $content;
	close(DAT);
}

sub updatedatabase {
	print "Trying to update database ...\n";

	for (my $i = 0; $i <= $#data; $i++) {
		print "Downloading ". $data[$i] . "\n";
		download($update_path_db, $data[$i]) || die ("Error downloading " . $data[$i] . " from " . $update_path_db . $data[$i] . "\n");
	}

	print "Downloading ". $dbversion . "\n";
	download($update_path_db, $dbversion) || die ("Error downloading " . $dbversion . " from " . $update_path_db . $dbversion . "\n");

	print "Database updated sucessfuly\n";
}

sub updateprogram {
	print "Downloading joomlascan.pl\n";
	download($update_path_program, "joomlascan.txt") || die ("Error downloading joomlascan.pl from " . $update_path_program . "joomlascan.pl" . "\n");

	print "Program updated sucessfuly\n";
}

sub forceupdate {
	updatedatabase();
	print"\n";
	updateprogram();

	exit 1;
}

sub update {
	open(DAT, "db/" . $dbversion) || die("File " . $dbversion . " not found. Try --force-update\n");
	my @data = <DAT>; 
	close(DAT);
	my $currentVersion = $data[0];
	my $lastDbVersion = checkversion($dbversion);
	my $lastProgramVersion = checkversion($programversion);

	$currentVersion =~ s/\r//g;
	$lastDbVersion =~ s/\r//g;

	my $act = 0;

	if ($joomlascanversion ne $lastProgramVersion) {
		print "Current version: " . $joomlascanversion . " - Last version: " . $lastProgramVersion . "\n";
		updateprogram();
		$act = 1;
	}

	if ($currentVersion ne $lastDbVersion) {
		print "Current version: " . $currentVersion . " - Last version: " . $lastDbVersion . "\n";
		updatedatabase();
		$act = 1;
	}

	if ($act eq 0) {
		print "No new updates available\n";
	}

	exit 1;
}


#############
# show help #
#############

sub logo {
	print qq{
                                                     
    o               |                                
    .,---.,---.,-.-.|    ,---.   ,---.,---.,---.,---.   /|   ----
    ||   ||   || | ||    ,---|---`---.|    ,---||   |    |   `--,
    |`---'`---'` ' '`---'`---^   `---'`---'`---^`   '    | . ---
`---'                                                

	};

	print "\n";
}

sub help {
	print qq{
Usage:  $0 -u <joomla_url> [options]

    == Options ==
      -p <string:int>  = proxy:port
      -a               = Admin folder (default '/administrator')
      -v               = Check version
      -c               = Check components
      -f               = Check firewall
      -co              = Check bugs in core (require -v)
      -cm              = Check bugs in components (require -c)
      -all             = Check all (default)
      -ot              = Output to text file
      -oh              = Output to html file
      -update          = Search for updates
      -force-update    = Force to download updates
      -about           = About joomlascan
      -version         = Print version info
      -h, -help        = This help

    == Examples ==
      To scan running joomla version and components:
         \$$0 -u www.host.com -v -c

      To scan version and core bugs:
         \$$0 -u www.host.com -v -co

	};
 
	exit 1;
}

sub version {
	my $file = shift;

	$file .= ".txt";

	open(DAT, "db/" . $file) || die("File " . $file . " not found. Try --force-update\n");
	
	my $tot = 0;
	my $totCo = 0;
	my $totCm = 0;

	while (<DAT>) {
		if (($_ !~ /^#/)) {
			$tot++;

			if ($_ =~ /^Core/) {
				$totCo++;
			}
			if ($_ =~ /^Component/) {
				$totCm++;
			}
		}
	}

	open(DAT, "db/" . $dbversion) || die("File " . $dbversion . " not found. Try --force-update\n");
	my @data = <DAT>; 
	close(DAT);
	my $dbrevision = $data[0];

	print qq{
Current JoomlaScan version: $joomlascanversion
Database revision: $dbrevision

Total bugs in database   : $tot
     - Bugs in Core      : $totCo
     - Bugs in Components: $totCm

	};
 
	exit 1;
}

sub about {
	print qq{
Joomla Scan v$joomlascanversion :: by Pepelux <pepeluxx\@gmail.com>
http://www.pepelux.org - http://blog.pepelux.org
 
--------------------------------------------------------------------------------
 
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

	};
 
	exit 1;
}


###################
# download a page #
###################

sub getpage {
	my $pageurl = shift;

	if (checkpage($pageurl) eq 1) {
		my $req = HTTP::Request->new(GET => $pageurl);
		$req->content_type('application/x-www-form-urlencoded');
		my $res = $ua->request($req);
		my $response = $res->content;

		return $response;
	}

	"";
}


#########################
# check if exist a page #
#########################

sub checkpage {
	my $pageurl = shift;
	my $req = HEAD "$pageurl";
	my $res = $ua->request($req);

	return 1 if ($res->status_line =~ /(200|301|302|403)/);

    0;
}


####################
# check web server #
####################

sub checkwebserver {
	my $pageurl = shift;
	my $req = HEAD $pageurl;
	my $res = $ua->simple_request($req);
	return $res->header('server');
}


######################
# print final report #
######################

sub printscreen {
	if ($^O =~ /Win/) {system("cls");}else{system("clear");}
	
	logo();

	if ($webserver ne "") {
		print "Running on " . $webserver . "\n\n";
	}

	if ($f eq 1 || $all eq 1) {
		if ($firewall ne "") { print "Firewall: " . $firewall . "\n\n"; }
		else { print "No firewall detected\n\n"; }
	}

	if ($c eq 1 || $all eq 1) {
		print "\nComponents:\n";

		foreach (@components) {
			print "\t" . $_ . "\n";
		}
		
		print "\n";
	}

	if ($v eq 1 || $all eq 1) {
		my $jversion = getversion();
		print $jversion . "\n\n";
	}

	if ($all eq 1) {
		print "Security tips:\n";
		print "=============\n";

		for (my $i = 0; $i <= $#sVulnerability; $i++) {
			print "Info: " . $sVulnerability[$i] . "\n";
			print "Versions affected: " . $sVersion[$i] . "\n";
			print "Files affected: " . $sFile[$i] . "\n";
			print "Detail: " . $sExploit[$i] . "\n";

			if ($sUrlExploit[$i] =~ m/ /) {
				print "More info: ";

				my @aux = split(/ /, $sUrlExploit[$i]);

				foreach (@aux) {
					print $_ . "\n";
				}
			}
			else {
				print "More info: " . $sUrlExploit[$i] . "\n";
			}

			print "\n";
		}	
	}

	if ($co eq 1 || $all eq 1) {
		print "Possible vulnerabilities in core:\n";
		print "================================\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Core") {
				print "Possible vulnerability: " . $bVulnerability[$i] . "\n";
				print "Versions affected: " . $bVersion[$i] . "\n";
				print "Detail: " . $bExploit[$i] . "\n";

				if ($bUrlExploit[$i] =~ m/ /) {
					print "More info: ";

					my @aux = split(/ /, $bUrlExploit[$i]);

					foreach (@aux) {
						print $_ . "\n";
					}
				}
				else {
					print "More info: " . $bUrlExploit[$i] . "\n";
				}
			}
		}	

		print "\n";
	}

	if ($cm eq 1 || $all eq 1) {
		print "Possible vulnerabilities in components:\n";
		print "======================================\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Component") {
				print "Possible vulnerability: " . $bVulnerability[$i] . "\n";
				print "Versions affected: " . $bVersion[$i] . "\n";
				print "Detail: " . $bExploit[$i] . "\n";

				if ($bUrlExploit[$i] =~ m/ /) {
					print "More info: ";

					my @aux = split(/ /, $bUrlExploit[$i]);

					foreach (@aux) {
						print $_ . "\n";
					}
				}
				else {
					print "More info: " . $bUrlExploit[$i] . "\n";
				}
			}
		}	

		print "\n";
	}
}

sub printtextfile {
	my $name = $url;
	$name =~ s/http:\/\///g;
	$name =~ s/\//_/g;
	$name =~ chop($name);
	$name .= ".txt";

	open(DAT, '>', "reports/" . $name) || die("Error creating file " . $name . "\n");

	print DAT qq{
                                                     
    o               |                                
    .,---.,---.,-.-.|    ,---.   ,---.,---.,---.,---.   /|   ----
    ||   ||   || | ||    ,---|---`---.|    ,---||   |    |   `--,
    |`---'`---'` ' '`---'`---^   `---'`---'`---^`   '    | . ---
`---'                                                

	};

	print "\n";

	if ($webserver ne "") {
		print DAT "\nRunning on " . $webserver . "\n\n";
	}

	if ($f eq 1 || $all eq 1) {
		if ($firewall ne "") { print DAT "Firewall: " . $firewall . "\n\n"; }
		else { print DAT "No firewall detected\n\n"; }
	}

	if ($c eq 1 || $all eq 1) {
		print DAT "Components:\n";

		foreach (@components) {
			print DAT "\t" . $_ . "\n";
		}	

		print DAT "\n";
	}

	if ($v eq 1 || $all eq 1) {
		my $jversion = getversion();
		print DAT $jversion . "\n\n";
	}

	if ($all eq 1) {
		print DAT "Security tips:\n";
		print DAT "=============\n";

		for (my $i = 0; $i <= $#sVulnerability; $i++) {
			print DAT "Info: " . $sVulnerability[$i] . "\n";
			print DAT "Versions affected: " . $sVersion[$i] . "\n";
			print DAT "Files affected: " . $sFile[$i] . "\n";
			print DAT "Detail: " . $sExploit[$i] . "\n";

			if ($sUrlExploit[$i] =~ m/ /) {
				print DAT "More info: ";

				my @aux = split(/ /, $sUrlExploit[$i]);

				foreach (@aux) {
					print DAT $_ . "\n";
				}
			}
			else {
				print DAT "More info: " . $sUrlExploit[$i] . "\n";
			}

			print DAT "\n";
		}	
	}

	if ($co eq 1 || $all eq 1) {
		print DAT "Possible vulnerabilities in core:\n";
		print DAT "================================\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Core") {
				print DAT "Possible vulnerability: " . $bVulnerability[$i] . "\n";
				print DAT "Versions affected: " . $bVersion[$i] . "\n";
				print DAT "Detail: " . $bExploit[$i] . "\n";

				if ($bUrlExploit[$i] =~ m/ /) {
					print DAT "More info: ";

					my @aux = split(/ /, $bUrlExploit[$i]);

					foreach (@aux) {
						print DAT $_ . "\n";
					}
				}
				else {
					print DAT "More info: " . $bUrlExploit[$i] . "\n";
				}
			}
		}	

		print DAT "\n";
	}

	if ($cm eq 1 || $all eq 1) {
		print DAT "Possible vulnerabilities in components:\n";
		print DAT "======================================\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Component") {
				print DAT "Possible vulnerability: " . $bVulnerability[$i] . "\n";
				print DAT "Versions affected: " . $bVersion[$i] . "\n";
				print DAT "Detail: " . $bExploit[$i] . "\n";

				if ($bUrlExploit[$i] =~ m/ /) {
					print DAT "More info: ";

					my @aux = split(/ /, $bUrlExploit[$i]);

					foreach (@aux) {
						print DAT $_ . "\n";
					}
				}
				else {
					print DAT "More info: " . $bUrlExploit[$i] . "\n";
				}
			}
		}	

		print DAT "\n";
	}

	close(DAT);

	print "Text log saved in reports/" . $name . "\n";
}

sub printhtmlfile {
	my $name = $url;
	$name =~ s/http:\/\///g;
	$name =~ s/\//_/g;
	$name =~ chop($name);
	$name .= ".html";

	my $contDiv = 0;

	header($name);
	open(DAT, '>>', "reports/" . $name) || die("Error creating file " . $name . "\n");

	if ($webserver ne "") {
		print DAT "Running on: <b>" . $webserver . "</b><br /><br />";
	}

	if ($f eq 1 || $all eq 1) {
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Firewall</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"Firewall\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";
		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='Firewall'>\n";
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5' class='datos'>\n";

		if ($firewall ne "") { 
			my $color = "#D7FFE1";

			print DAT "<tr>\n";
			print DAT "<td bgcolor='" . $color . "'><font color='#0000ff'>" . $firewall . "</font></td>\n";
			print DAT "</tr>\n";
		}
		else { 
			print DAT "<tr>\n";
			print DAT "<td><font color='#ff0000'>No firewall detected</font></td>\n";
			print DAT "</tr>\n";
		}

			print DAT "</table>\n";
			print DAT "</div>\n";
			print DAT "</table>\n";
			print DAT "</div>\n";
			print DAT "<br />\n";
}

	if ($c eq 1 || $all eq 1) {
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Components</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"Components\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";
		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='Components'>\n";
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5' class='datos'>\n";

		foreach (@components) {
			print DAT "<tr>\n";
			print DAT "<td><font color='#0000ff'>" . $_ . "</font></td>\n";
			print DAT "</tr>\n";
		}	

		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "<br />\n";
	}

	if ($v eq 1 || $all eq 1) {
		my $jversion = getversion();

		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Version</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"Version\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";
		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='Version'>\n";
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5' class='datos'>\n";
		print DAT "<tr>\n";
		print DAT "<td><b>" . $jversion . "</b></td>\n";
		print DAT "</tr>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "<br />\n";
	}

	if ($all eq 1) {
		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Security tips (" . ($#sVulnerability+1) . ")</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"Tips\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";
		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='Tips'>\n";
		print DAT "<table width='100%' border='0' cellspacing='5' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td>\n";

		for (my $i = 0; $i <= $#sVulnerability; $i++) {
			print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td width='6%'><b>Info:</b></td>\n";
			print DAT "<td width='88%' bgcolor='#D7FFE1'><font color='#0000ff'>" . $sVulnerability[$i] . "</font>";
			print DAT "</td>\n";
			print DAT "<td width='6%' bgcolor='#D7FFE1'>";
			print DAT "<div align='right'><a style='cursor: pointer;' onclick='muestra_oculta(\"" . $contDiv . "\")'>";
			print DAT "<img src='../iw_plus.gif' width='12' height='12' /></a></div>\n";
			print DAT "</td>\n";
			print DAT "</tr>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan ='3'>\n";
			print DAT "<div id='" . $contDiv . "'>\n";

			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3'>\n";
			print DAT "<tr>\n";
			print DAT "<td width='15%'><b>Versions affected:</b></td>\n";
			print DAT "<td>" . $sVersion[$i] . "</td>\n";
			print DAT "<td width='6%'></td>\n";
			print DAT "</tr>\n";
			print DAT "<tr>\n";
			print DAT "<td><b>Files affected:</b></td>\n";
			print DAT "<td><font color='#ff0000'><a href='" . $sFile[$i] . "' target='_blank'>" . $sFile[$i] . "</a></font></td>\n";
			print DAT "</tr>\n";
			print DAT "<tr>\n";
			print DAT "<td valign='_top'><b>Exploit:</b></td>\n";
			print DAT "<td valign='_top'>" . $sExploit[$i] . "";

			if ($sUrlExploit[$i] =~ m/ /) {
				print DAT "<br /><br />More info: <font color='#0000ff'>";

				my @aux = split(/ /, $sUrlExploit[$i]);
				my $x = 0;

				foreach (@aux) {
					print DAT "<br />" if ($x ne 0);
					print DAT "<a href='" . $_ . "' target='_blank'>" . $_ . "</a>";
					$x = 1;
				}

				print DAT "</font>";
			}
			else {
				print DAT "<br /><br />More info: <font color='#0000ff'>";
				print DAT "<a href='" . $sUrlExploit[$i] . "' target='_blank'>" . $sUrlExploit[$i] . "</a></font>";
			}

			print DAT "</td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
			print DAT "</div>\n";
			print DAT "</td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";

			$contDiv++;

			if ($i < $#sVulnerability) {
				print DAT "<div align='center'><hr width='100' noshade='noshade' /></div>\n";
			}
		}
		
		if ($#sVulnerability eq -1) {
			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan='2'><font color='#ff0000'>Not found</font></td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
		}

		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "<br />\n";
	}

	if ($co eq 1 || $all eq 1) {
		my $tot = 0;

		foreach (@bType) {
			if ($_ eq "Core") {
				$tot++;
			}
		}

		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Possible vulnerabilities in Core (" . $tot . ")</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"coreVulnerabilities\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";

		if ($tot > 0) {
			print DAT "<tr><td colspan='2' class='datos'><center><font color='#ff0000'>Vulnerabilities showed are in the same range that detected Joomla! version</font></center></td><tr>\n";
		}

		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='coreVulnerabilities'>\n";
		print DAT "<table width='100%' border='0' cellspacing='5' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<tr>\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Core") {
				print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='3' class='datos'>\n";
				print DAT "<tr>\n";
				print DAT "<td width='6%'><b>Possible vulnerability:</b></td>\n";
				print DAT "<td width='88%' bgcolor='#D7FFE1'><font color='#0000ff'>" . $bVulnerability[$i] . " (" . $bType[$i] . ")</font>";
				print DAT "</td>\n";
				print DAT "<td width='6%' bgcolor='#D7FFE1'>";
				print DAT "<div align='right'><a style='cursor: pointer;' onclick='muestra_oculta(\"core" . $contDiv .+ "\")'>";
				print DAT "<img src='../iw_plus.gif' width='12' height='12' /></a></div>\n";
				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "<tr>\n";
				print DAT "<td colspan ='3'>\n";
				print DAT "<div id='core" . $contDiv . "'>\n";

				print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3'>\n";
				print DAT "<tr>\n";
				print DAT "<td width='15%'><b>Version:</b></td>\n";
				print DAT "<td><font color='#ff0000'>" . $bVersion[$i] . "</font></td>\n";
				print DAT "<td width='6%'></td>\n";
				print DAT "</tr>\n";
				print DAT "<tr>\n";
				print DAT "<td valign='_top'><b>Exploit:</b></td>\n";
				print DAT "<td valign='_top'>" . $bExploit[$i] . "";

				if ($bUrlExploit[$i] =~ m/ /) {
					print DAT "<br /><br />More info: <font color='#0000ff'>";

					my @aux = split(/ /, $bUrlExploit[$i]);
					my $x = 0;

					foreach (@aux) {

						print DAT "<br />" if ($x ne 0);
						print DAT "<a href='" . $_ . "' target='_blank'>" . $_ . "</a>";
						$x = 1;
					}

					print DAT "</font>";
				}
				else {
					print DAT "<br /><br />More info: <font color='#0000ff'>";
					print DAT "<a href='" . $bUrlExploit[$i] . "' target='_blank'>" . $bUrlExploit[$i] . "</a></font>";
				}

				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "</table>\n";
				print DAT "</div>\n";
				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "</table>\n";

				$contDiv++;

				if ($i < $#bVulnerability) {
					print DAT "<div align='center'><hr width='100' noshade='noshade' /></div>\n";
				}
			}
		}	

		if ($#bVulnerability eq -1) {
			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan='2'><font color='#ff0000'>Not found</font></td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
		}

		if ($#bVulnerability > -1 && $tot eq 0) {
			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan='2'><font color='#ff0000'>Not found</font></td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
		}

		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "<br />\n";
	}

	if ($cm eq 1 || $all eq 1) {
		my $tot = 0;

		foreach (@bType) {
			if ($_ eq "Component") {
				$tot++;
			}
		}

		print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<td bgcolor='#999999' class='titulo'>Possible vulnerabilities in Components (" . $tot . ")</td>\n";
		print DAT "<td bgcolor='#999999' class='titulo'><div align='right'>";
		print DAT "<a style='cursor: pointer;' onclick='muestra_oculta(\"componentVulnerabilities\")'><img src='../iw_plus.gif' width='12' height='12' /></a></div></td>\n";

		if ($tot > 0) {
			print DAT "<tr><td colspan='2' class='datos'><center><font color='#ff0000'>Vulnerabilities showed may affect the installed components<br/>Component version has not been checked and maybe this Joomla! version is not vulnerable</font></center></td><tr>\n";
		}

		print DAT "</tr>\n";
		print DAT "<tr>\n";
		print DAT "<td colspan='2'>\n";
		print DAT "<div id='componentVulnerabilities'>\n";
		print DAT "<table width='100%' border='0' cellspacing='5' cellpadding='5'>\n";
		print DAT "<tr>\n";
		print DAT "<tr>\n";

		for (my $i = 0; $i <= $#bVulnerability; $i++) {
			if ($bType[$i] eq "Component") {
				print DAT "<table width='100%' border='0' cellspacing='0' cellpadding='3' class='datos'>\n";
				print DAT "<tr>\n";
				print DAT "<td width='6%'><b>Possible vulnerability:</b></td>\n";
				print DAT "<td width='88%' bgcolor='#D7FFE1'><font color='#0000ff'>" . $bVulnerability[$i] . " (" . $bType[$i] . ")</font>";
				print DAT "</td>\n";
				print DAT "<td width='6%' bgcolor='#D7FFE1'>";
				print DAT "<div align='right'><a style='cursor: pointer;' onclick='muestra_oculta(\"component" . $contDiv .+ "\")'>";
				print DAT "<img src='../iw_plus.gif' width='12' height='12' /></a></div>\n";
				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "<tr>\n";
				print DAT "<td colspan ='3'>\n";
				print DAT "<div id='component" . $contDiv . "'>\n";

				print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3'>\n";
				print DAT "<tr>\n";
				print DAT "<td width='15%'><b>Version:</b></td>\n";
				print DAT "<td><font color='#ff0000'>" . $bVersion[$i] . "</font></td>\n";
				print DAT "<td width='6%'></td>\n";
				print DAT "</tr>\n";
				print DAT "<tr>\n";
				print DAT "<td valign='_top'><b>Exploit:</b></td>\n";
				print DAT "<td valign='_top'>" . $bExploit[$i] . "";

				if ($bUrlExploit[$i] =~ m/ /) {
					print DAT "<br /><br />More info: <font color='#0000ff'>";

					my @aux = split(/ /, $bUrlExploit[$i]);
					my $x = 0;

					foreach (@aux) {

						print DAT "<br />" if ($x ne 0);
						print DAT "<a href='" . $_ . "' target='_blank'>" . $_ . "</a>";
						$x = 1;
					}

					print DAT "</font>";
				}
				else {
					print DAT "<br /><br />More info: <font color='#0000ff'>";
					print DAT "<a href='" . $bUrlExploit[$i] . "' target='_blank'>" . $bUrlExploit[$i] . "</a></font>";
				}

				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "</table>\n";
				print DAT "</div>\n";
				print DAT "</td>\n";
				print DAT "</tr>\n";
				print DAT "</table>\n";

				$contDiv++;

				if ($i < $#bVulnerability) {
					print DAT "<div align='center'><hr width='100' noshade='noshade' /></div>\n";
				}
			}
		}	

		if ($#bVulnerability eq -1) {
			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan='2'><font color='#ff0000'>Not found</font></td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
		}

		if ($#bVulnerability > -1 && $tot eq 0) {
			print DAT "<table width='100%' border='0' cellspacing='3' cellpadding='3' class='datos'>\n";
			print DAT "<tr>\n";
			print DAT "<td colspan='2'><font color='#ff0000'>Not found</font></td>\n";
			print DAT "</tr>\n";
			print DAT "</table>\n";
		}

		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "</table>\n";
		print DAT "</div>\n";
		print DAT "<br />\n";
	}

	close(DAT);

	footer($name);

	print "Text log saved in reports/" . $name . "\n";
}

sub header {
	my $name = shift;

	open(DAT, '>', "reports/" . $name) || die("Error creating file " . $name . "\n");

	print DAT "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n";
	print DAT "<html xmlns='http://www.w3.org/1999/xhtml'>\n";
	print DAT "<head>\n";
	print DAT "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />\n";
	print DAT "<title>" . $name . "</title>\n";
	print DAT "<style type='text/css'>\n";
	print DAT "<!--\n";
	print DAT ".titulo {\n";
	print DAT "font-family: Verdana, Geneva, sans-serif;\n";
	print DAT "color: #FFF;\n";
	print DAT "font-weight: bold;\n";
	print DAT "}\n";
	print DAT ".datos {\n";
	print DAT "font-family: Verdana, Geneva, sans-serif;\n";
	print DAT "font-size: small;\n";
	print DAT "}\n";
	print DAT "-->\n";
	print DAT "</style>\n";
	print DAT "<script>\n";
	print DAT "function muestra_oculta(id){\n";
	print DAT "if (document.getElementById){\n";
	print DAT "var el = document.getElementById(id);\n";
	print DAT "el.style.display = (el.style.display == 'none') ? 'block' : 'none';\n";
	print DAT "}\n";
	print DAT "}\n";
	print DAT "</script>\n";
	print DAT "</head>\n";
	print DAT "<body>\n";

	print DAT "<table width='100%' border='0' cellspacing='5' cellpadding='5'>";
	print DAT "<tr>";
	print DAT "<td width='11%'><img src='http://www.pepelux.org/images/enye.jpg' width='116' height='116' /></td>";
	print DAT "<td width='89%' class='gris' align='center'>";
	print DAT "<p>Joomla Scan v" . $joomlascanversion . " :: by Pepelux <span class='grisn'>&lt;pepeluxx\@gmail.com&gt;</span></p>";
	print DAT "<p><a href='http://www.pepelux.org/' target='_blank' style='text-decoration:none;color:#F00'>http://www.pepelux.org</a> - <a href='http://blog.pepelux.org/' target='_blank' style='text-decoration:none;color:#F00'>http://blog.pepelux.org</a></p></td>";
	print DAT "</tr>";
	print DAT "</table>";

	close(DAT);
}

sub footer {
	my $name = shift;

	open(DAT, '>>', "reports/" . $name) || die("Error creating file " . $name . "\n");

	print DAT "</body>\n";
	print DAT "</html>\n";

	close(DAT);
}

sub getversion {
	my $jversion = '';

	$version[3] = "." . trim($version[3]) if ($version[3] ne "");
	$version[7] = "." . trim($version[7]) if ($version[7] ne "");

	if ($version[5] eq "x") { # generic version
		if ($version[0] ne "x") { # exact
			if ($version[1] ne "x" && $version[2] ne "x") {
				$jversion = "Joomla! version [" . $version[0] . "." + $version[1] . "." . $version[2] . $version[3] . "]";
			}
			else {
				$jversion = "Generic version family [" . $version[0] . "." . $version[1] . "." . $version[2] . $version[3] . "]";
			}
		}
		else { # unknown
			$jversion = "Version unknown";
		}
	}
	else { # exact
		if ($version[0] eq $version[4] && $version[1] eq $version[5] && $version[2] eq $version[6] && $version[3] eq $version[7]) {
			$jversion = "Joomla! version [" . $version[0] . "." . $version[1] . "." . $version[2] . $version[3] . "]";
		}
		else { # by ranks
			$jversion = "Version family " . $version[0] . "." . $version[1] . ".x ";
			$jversion .= "[" . $version[0] . "." . $version[1] . "." . $version[2] . $version[3];
			$jversion .= "-" . $version[4] . "." . $version[5].+ "." . $version[6] . $version[7] . "]";
		}
	}

	return $jversion;
}

sub trim($) {
	my $string = shift;

	$string =~ s/^\s+//;
	$string =~ s/\s+$//;

	return $string;
}


init();

# Changelog:
#
# v1.5 - 2013-03-17
# - Corrected some bugs
# - Updated recognition of version 3.1.0-beta1
#
# v1.4 - 2012-07-15
# - Corrected administrator folder shown in help
# - Updated recognition of version 2.5
# - Change exploits reference from http://inj3ct0r.com/ to http://1337day.com/
#
# v1.3 - 2011-10-30
# - Updated recognition of version 1.6 and 1.7
#
# v1.2 - 2010-09-06
# - Corrected some errors checking Joomla! version
# - Added web server fingerprinting
# - Added joomlascan version option
# - Corrected some update errors
#
# v1.1 - 2010-09-06
# - Added 'use proxy' option
#
# v1.0 - 2010-09-04
# - Initial version
