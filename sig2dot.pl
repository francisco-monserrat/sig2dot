#!/usr/bin/perl -w

# sig2dot v0.29 (c) Darxus@ChaosReigns.com, released under the GPL
# Download from: http://www.chaosreigns.com/code/sig2dot/
# sig2dot v0.35 (c) 2005 Christoph Berg <cb@df7cb.de>
# Download from: http://ftp.debian.org/debian/pool/main/s/sig2dot/
#
# Parses output of "gpg --list-sigs" into a format
# suitable for rendering into a graph by graphviz 
# (http://www.research.att.com/sw/tools/graphviz/) like so:
#
# $ gpg --list-sigs --keyring ./phillylinux.gpg | ./sig2dot.pl > phillylinux.dot
# $ neato -Tps phillylinux.dot > phillylinux.ps
# $ convert phillylinux.ps phillylinux.jpg
#
# Commandline options:
#
# -b  
#   Black and white / do not colorize.
#
# -d <date>
#   Render graph as it appeared on <date> (ignores more recent
#   signatures).  Date must be in the format "YYYY-MM-DD".
#   Will also ignore keys that have since been revoked.
#
# -a
#   Render all keys, even if they're not signed by any other key.
#
# -u <"string">
#   Support localized output of GnuPG for unknown user IDs. For
#   example, German users have to write (with sh quotation marks!)
#   "[User-ID nicht gefunden]" if they use GnuPG with German
#   messages. Default is "[User id not found]".
#
# -r <"string">
#   Support localized output of GnuPG for revoked keys. For
#   example, French users have to write "révoqué" if they use
#   GnuPG with French messages. Default is "[revoked".
#
# -s stats.html
#   Produces statistics file with number of signatures per node
#
# -h  print help
# -v  print version
# -q  be quiet
#
# -t "title" change the title of the graph
# -m "string" move generate different dots files based on the string, plotting the graph since the creation of#  the first key to the last signature, default interval : 1 month
#
# Changes:
#
# v0.9 2000-09-14 19:20  strip trailing whitespace from $id more cleanly
# v0.10 2000-09-14 19:33 skip revoked keys at the request of Peter Palfrader <ppalfrad@cosy.sbg.ac.at>
# v0.11 Nov 22 21:38     use ID for node name instead of username for uniqueness
# v0.12 Dec 15 16:20 use names instead of IDs again in stats.html
# v0.13 Jun 19 03:15 red is proportional to signatures
# v0.14 Jun 19 03:25 blue is proportional to other keys signed
# v0.15 Jun 20 17:16 fixed blue, green is proportional to ratio
# v0.16 Jun 20 18:55 uniqed %signedby
# v0.17 Jan 10 19:10 Use overlap=scale instead of fixed edge lengths.  Requires new version of graphviz.
# v0.18 Jan 23 11:53 stats.html is now valid html (v.01 transitional)
# v0.23 May  3 18:52 bunch of new stuff, including -b flag (black & white), and fixes devision by zero error
# v0.24 May  3 18:59 add black outline to nodes, prettier (changed node attribute "color" to "fillcolor")
# v0.25 May  3 19:06 cleaned up anti- devision by zero code a little
# v0.26 May  4 00:08 strip all non-digit characters from $renderdate
# v0.27 May 10 00:23:49 2002 use {}'s to write 1 line per public key instead of one line per signature (much shorter)
# v0.28 Feb 13 2003 Change regex to handle option trust digit 
#                   <kevin@rosenberg.net>
# v0.29 Feb 18 2003 Add -s option to optionally produce statistics file 
#                   <kevin@rosenberg.net>
# v0.30 Feb 18 2003 Make --list-sigs regex more robust 
#                   Marco Bodrato <bodrato@gulp.linux.it>
# v0.31 Jul 28 2003 Add -u option for localized output of GnuPG
#                   Marcus Frings <protagonist@gmx.net>
# further changes are documented in debian/changelog

use strict;
use Getopt::Long ;

my $version = "0.35";

my $chartchar = "*";
my $renderdate = "";
my ( $color ) ;


my %key_creation_date ; # Hash for the movie mode (when a key is created) key --> creation_date YYYY-MM-DD
my %key_signing_date ;  # Hash for the movie mode (when a key signed other key) signer:signed-> YYYY-MM-DD
my %dates ;	# hash for the movie mode (store all the dates)
my $first="20480000" ;  # first & last creation date
my $last= "19800000" ;
my $prefix ="";
my $title_size=60 ;
my %opt;
my $ver="" ;
my $help="" ;
my $all ="" ;
my $quiet="0" ;
my $black ="" ;
my $stats="" ;
my $revokestr="[revoked]" ;
my $title="PGP Keyring signatures" ;
my $not_found="[user id not found]" ;
my $date ;
my $seq =""  ;
my $movie ;
my $countsig = "0" ;
sub version {
  print <<EOT;
sig2dot $version
Copyright (c) 2002 Darxus\@ChaosReigns.com
Copyright (c) 2005 Christoph Berg <cb\@df7cb.de>
EOT
}

my $res= GetOptions (
	"help" => \$help ,
        "all"  => \$all,
	"version" => \$ver,
	"quiet" => \$quiet,
	"black" => \$black,
	"revoked=s" => \$revokestr,
	"stats=s" => \$stats,
	"user-id=s" =>\$not_found,
	"title=s" => \$title,
	"movie=s" => \$movie,
	"date=s" => \$date,
	"sequence" => \$seq,
	"tsize=s" => \$title_size,
	"countsig" => \$countsig 
) ;	

if ($help) {
  version();
  print <<EOT;
gpg --list-sigs | $0 [-abdhqsuv] > sigs.dot
--all            Graph all keys, even if they do not have a signature
--black          Black and white / do not colorize.
--date YYYY-MM-DD   Render graph as it appeared on date.
--help              Print this help and exit.
--quiet              Be quiet.
--revoqued sting        key-is-revoked string (default: "[revoked").
--stats stats.html   Produces statistics file with number of signatures per node.
--userid string       user-id-not-found string (default: "[user id not found]").
--version              Print version and exit.
--title TITLE	Tittle of the graph (default "PGP keyring signatures").
--movie prefix	Generate different prefix-YYYY-MM-DD , with the different PGP view (also change title).
--tsize number	Title Size 
--countsig	Put also the signature count in the Labels 

EOT
  exit 0;
}


if ($ver ne "") {
  version();
  exit 0;
}

if ($date ne "" ) { 
  $renderdate = $date; 
  print STDERR "Printing from date: $renderdate.\n";
  $renderdate =~ s/\D+//g;
}
if ($stats ne "" ) {  
  print STDERR "Print statistics to $stats.\n";
}

if ($black ne "")  
{ 
  $color = 0; 
  print STDERR "Black and White.\n" unless $quiet;
} else { 
  $color = 1; 
  print STDERR "Color.\n" unless $quiet;
}

if ($movie ne "" ) {
	$prefix = $movie  ;
	}


## THis is the parsing & load of the signing information & Key info

my ($owner, %name, %revlist, %sigstmp, %signedbytmp, @names, %revs);

while (my $line = <>)
{
  chomp $line;

# gpg 1.2
#pub  1024D/807CAC25 2003-08-01 Michael Ablassmeier (abi) <abi#grinser.de>
#sig         B3B2A12C 2004-01-28   [User id not found]
#sig 3       9456ADE2 2004-02-07   Michael Schiansky <michael#schiansky.de>
# gpg 1.4:
#pub   1024D/807CAC25 2003-08-01
#uid                  Michael Ablassmeier (abi) <abi#grinser.de>
#sig          B3B2A12C 2004-01-28  [User ID not found]
#sig 3        9456ADE2 2004-02-07  Michael Schiansky <michael#schiansky.de>

                 # type                          id       date       name
   if ($line =~ m#([\w]+)[ !\?][ \dLNPRX]{0,8} +([^ ]+) +([^ ]+)(?: +"?([^<"]*))?#)
# differences:
# " " -> "[ !\?]" (to use 'gpg --check-sigs|sig2dot.mio|springgraph|display')
# "[ \d]" -> "[ \dLRXP]" (signature attributes)
# "[^<]+" -> "[^<]*" (to recognise "pub" lines whitout a name)
#  if ($line =~ m#([\w]+) [ \d]? +([^ ]+) +([^ ]+) +([^<]+)#)
#  if ($line =~ m#([\w]+) +([^ ]+) +([^ ]+) +([^<]+)#)

  {
    my $type = $1;
    my $id = $2;
    my $date = $3;
    my $name = $4 || "";

    $date =~ tr/-//d;
    if ($type eq "pub" or $renderdate eq "" or $date <= $renderdate)
    {

      print STDERR "Using: $line\n" unless $quiet;
      # strip trailing whitespace more cleanly:
      $name =~ s/\s+$//g;

      #Remove re: http://bugs.debian.org/202484
      #$name =~ s/[^a-zA-Z \.0-9]/_/g; # handle non-7bit names

      if ($type eq "pub")
      {
        $id = (split('/',$id))[1];
        $owner = $id; 
	$key_creation_date{$id} =$date ;
	$dates{$date}++ ;
	if ($date < $first) {$first= $date ; }
	if ($date > $last ) {$last =$date ; }
      } 

      # remove comment field
      $name{$id} = (split ' \(', $name)[0] if $name; # gpg 1.4 fixup

      # skip revoked keys 
      if (index($name, $revokestr) >= 0) {
        $revlist{$id} = 1;
        next;
      }

      if ($type eq "uid") {
	$name{$owner} = $id; # gpg 1.4 fixup
      }
  
#      unless (defined @{$sigs{$owner}})
#      {
#        @{$sigs{$owner}} = ();
#      }
      if ($type eq "sig" and lc $name ne $not_found)
      {
	if ($id ne $owner) {
	  push (@{$sigstmp{$owner}},$id);
	  push (@{$signedbytmp{$id}},$owner);
	}
	if ($all or $id ne $owner) {
	  push (@names,$id,$owner);
	}
	$dates{$date} ++ ;
	$key_signing_date{"$owner:$id"} =$date ;
	if ($date < $first) {$first= $date ; }
	if ($date > $last ) {$last =$date ; }
 
      }
      if ($type eq "rev" and lc $name ne $not_found)
      {
	if ($id ne $owner) {
	  push (@{$revs{$owner}},$id);
	  #push (@{$revokedby{$id}},$owner);
	}
      }
    } else {
      print STDERR "Skipping due to date: $line\n";
    }
  } else {
    print STDERR "Skipping due to regex: $line\n" if $line ne "";
  }
}

### OK This is the "Graph generation

foreach my $k (keys %key_creation_date) {
	print STDERR "Key $k created on $key_creation_date{$k}\n" ;
}
my $hash_count = keys %dates ;
print STDERR "There is $hash_count dates!! \n" ;
print STDERR "First date =$first last date=$last\n" ;
print STDERR "Prefix is $prefix\n" ;

my $filename="" ;
my $dat="" ;
my $count=1;

if ($prefix eq "") { do_graph($filename,$dat) ; }
	else {
	foreach $dat (sort keys %dates) {
		print STDERR "Doing graph for date $dat ..\n" ;
		if ($seq ne "") {
			$filename =  "$prefix" . "_"  . sprintf "%05d" , $count++ ;
			}
		else { $filename = "$prefix" . "_$dat" ; }
		do_graph($filename, $dat) ;
	}

}

sub do_graph {
	my $filename=$_[0] ;
	my $date = $_[1] ;

my (%sigs, %signedby);

for my $id (sort {$sigstmp{$a} <=> $sigstmp{$b}} keys %sigstmp) {
  next if (defined $revlist{$id});
  foreach my $owner (@{$signedbytmp{$id}}) {
    next if (defined $revlist{$owner});
    my $revoke = 0;
    foreach my $revid (@{$revs{$owner}}) {
      if ($revid eq $id) {
        $revoke = 1;
      }
    }
    #$res = $revlist{$id};
    if (($revoke == 0)) {
      push (@{$sigs{$owner}},$id);
      push (@{$signedby{$id}},$owner);
    }
  }
}

my $text=$title ;

if ($filename ne "") 
	{
	 $text .= " " . $date ; 
	 open(OUTPUT , '>', "$filename.dot") ;
	}
	else  { *OUTPUT = *STDOUT; ; }

			
print OUTPUT "digraph  {\nlabelloc= \"t\";\nlabel=\"$text \";\nfontsize=\"$title_size\";\noverlap=scale\nsplines=true\nsep=.1\n";

my %saw;
@saw{@names} = ();
@names = keys %saw;
undef %saw;

my $maxsigcount = 0;
my (%sigcount);

for my $owner (sort {$sigs{$a} <=> $sigs{$b}} keys %sigs)
{
  undef %saw;
  @saw{@{$sigs{$owner}}} = ();
  @{$sigs{$owner}} = keys %saw;
  undef %saw;
  undef %saw;
  $signedby{$owner} ||= [];
  @saw{@{$signedby{$owner}}} = ();
  @{$signedby{$owner}} = keys %saw;
  undef %saw;

  $sigcount{$owner} = scalar(@{$sigs{$owner}});
  if ($sigcount{$owner} > $maxsigcount)
  {
    $maxsigcount = $sigcount{$owner};
  }
}

my %signedbycount;
my ($maxsignedbycount, $maxratio) = (0, 0);

for my $owner (sort {$signedby{$a} <=> $signedby{$b}} keys %signedby)
{
  $signedbycount{$owner} = scalar(@{$signedby{$owner}});
  if ($signedbycount{$owner} > $maxsignedbycount)
  {
    $maxsignedbycount = $signedbycount{$owner};
  }
  if ($sigcount{$owner} and $sigcount{$owner} > 0) {
    if ($signedbycount{$owner} / $sigcount{$owner} > $maxratio)
    {
      $maxratio = $signedbycount{$owner} / $sigcount{$owner};
    }
  }
}
print OUTPUT "//$maxratio\n";


if ($stats) {
    open (STATS,">$stats");
    print STATS "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<html><head><title>Keyring Statistics</title></head><body><table border=1>\n";

    for my $owner (sort {$sigcount{$b} <=> $sigcount{$a}} keys %sigs)
    {
	print STATS "<tr><td>$name{$owner}<td>$sigcount{$owner}<td><img src=\"/images/pipe0.jpg\" height=15 width=",$sigcount{$owner} * 20," alt=\"". $chartchar x $sigcount{$owner} ."\">\n";
    }
    
    print STATS "</table></body></html>\n";
    close STATS;
}

print OUTPUT "node [style=filled]\n";
for my $id (@names)
{
  if ((not exists $sigcount{$id}) and (not exists $signedbycount{$id}) and not $all) {
    next;
  }
  if ($color)
  {
    my ($red, $green, $blue) = (0, 1/3, 1/3);
    if ($sigcount{$id}) {
      $red = $sigcount{$id} / $maxsigcount;
    }
    if ($sigcount{$id} && $maxratio != 0)
    {
      $green = ($signedbycount{$id} / $sigcount{$id} / $maxratio * .75) * 2/3 + 1/3;
    }
    if ($signedbycount{$id} and $maxsignedbycount != 0) {
      $blue = ($signedbycount{$id} / $maxsignedbycount) * 2/3 + 1/3;
    }

    my ($hue,$saturation,$value) = rgb2hsv($red,$green,$blue);
    printf OUTPUT  "//%d %d $red,$green,$blue\n", $sigcount{$id} || 0, $signedbycount{$id} || 0;
    if ($countsig =="0" ) {
    	print  OUTPUT "\"$id\" [fillcolor=\"$hue $saturation $value\",label=\"$name{$id}\"";
	}
    else {
	printf OUTPUT "\"$id\" [fillcolor=\"$hue $saturation $value\",label=\"$name{$id} (%d/%d)\"]\n", $sigcount{$id} || 0, $signedbycount{$id} || 0 ;
	}
  } else {
     if ($countsig =="0") { 
    	print OUTPUT "\"$id\" [label=\"$name{$id}\"";
	}
      else {
	    printf "\"$id\" [label=\"$name{$id} (%d/%d)\"]\n", $sigcount{$id} || 0, $signedbycount{$id} || 0;
	}
	
  }
# Check if we are in movie mode and need to add the style="invis" ...
  if ($date < $key_creation_date{$id} ) { print OUTPUT " style=\"invis\" " ; } 
  print OUTPUT "]\n" ;

}
#print "node [style=solid]\n";


for my $owner (sort keys %sigs)
{

my $sig_print="" ;
my $sig_invis="" ;
my $sig_double="" ;
#my %dont_draw ;

 for my $id (@{$sigs{$owner}})
  {
     $sig_invis .=  "\"$id\" " if (exists($key_signing_date{"$owner:$id"}) && ($date <  $key_signing_date{"$owner:$id"})) ;

     if (exists($key_signing_date{"$owner:$id"}) && ($date >= $key_signing_date{"$owner:$id"})) {
##	if (exists($key_signing_date{"$id:$owner"}) && ($date >= $key_signing_date{"$id:$owner"}) ) {
## OK draw birectional lines "two times", need to be fixed (perhaps not grouping the elements
##  && !(exists($dont_draw{"$id:$owner"})) && !(exists($dont_draw{"$owner:$id"}) )){
##	 $sig_double .= "\"$id\"" ; 
##	$dont_draw{"$owner:$id"} = 1 ;
##	$dont_draw{"$id:$owner"} = 1 ;

#	}
#	else { 
	$sig_print .= "\"$id\"" ;
#	}
    }

}
  if ($sig_double ne ""){ print OUTPUT "{ $sig_double } -> \"$owner\" [dir=both]\n" ; }
  if ($sig_print ne "") { print OUTPUT "{ $sig_print } -> \"$owner\"\n" ; }
  if ($sig_invis ne "") { print OUTPUT "{ $sig_invis } -> \"$owner\" [style=invis]\n" ; }
}

  print OUTPUT "}\n";


}
  #  Converts rgb to hsv.  All numbers are within range 0 to 1
  #  from http://twiki.org/cgi-bin/view/Codev/WebMap
  sub rgb2hsv {
      my ($r, $g ,$b) = @_;
      my $max = maxof($r, maxof($g, $b));
      my $min = minof($r, minof($g, $b));
      my $v = $max;
      my ($s, $h);

      if ($max > 0.0) {
        $s = ($max - $min) / $max;
    } else {
        $s = 0;
    }
    if ($s > 0.0) {
        my ($rc, $gc, $bc, $diff);
            $diff = $max - $min;
        $rc = ($max - $r) / $diff;
        $gc = ($max - $g) / $diff;
        $bc = ($max - $b) / $diff;
        if ($r == $max) {
            $h = ($bc - $gc) / 6.0;
        } elsif ($g == $max) {
            $h = (2.0 + $rc - $bc) / 6.0;
        } else {
            $h = (4.0 + $gc - $rc) / 6.0;
        }
    } else {
       $h = 0.0;
    }
    if ($h < 0.0) {
       $h += 1.0;
    }
    return ($h, $s, $v);
}
sub maxof {
   my ($a, $b) = @_;

   return $a>$b?$a:$b;
}
sub minof {
   my ($a, $b) = @_;

   return $a<$b?$a:$b;
}

# vim:sw=2:
