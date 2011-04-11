#!/usr/bin/perl
# usage:
# start daemon using /etc/packetq.conf:
#       pq_tracesplit.pl 

# stop daemon:
#       pq_tracesplit.pl stop

# run in foreground with conf file
#       pq_tracesplit.pl -f  -c my.conf

# stop with custom conf file
#       pq_tracesplit.pl -c my.conf stop




use POSIX;
use POSIX qw(setsid);
use Sys::Syslog qw(:DEFAULT setlogsock);  # default set, plus setlogsock()
use File::Path; 
use File::Copy;
use Getopt::Std;
use Data::Dumper;
use strict;
no  strict "subs";

my $conffile = "/etc/packetq.conf";
my %opts;
getopts('fc:', \%opts);
if (defined $opts{c})
{
   $conffile = $opts{c};
}
my $foreground = undef;
$foreground = 1 if (defined $opts{f});

openlog('pqcollector','pid,perror','LOG_USER');

######### read config file

my %config;
open(CONFIG,$conffile) or die "error reading config file $conffile exiting";
while (<CONFIG>) 
{
    chomp;
    next if /^\s*\#/;
    next unless /=/;
    my ($key, $variable) = split(/=/,$_,2);
    $variable =~ s/(\$(\w+))/$config{$2}/g;
    $config{$key} = $variable;
}
close CONFIG;

my $pidfile  = $config{'pidfile'};
my $logfile  = "/dev/null";

##### start daemon

if (-e $pidfile)
{
    open (PFILE, $pidfile);
    my $pidfromfile = <PFILE>;
    close PFILE;

    if (($pidfromfile =~ /[0-9]+/) && kill( 0, $pidfromfile))
    {            
        if ($ARGV[0] eq 'stop')
        {
            syslog 'info',"Stopping daemon pid: $pidfromfile\n";
            while (kill( 0, $pidfromfile))
            {
                kill( - SIGQUIT, $pidfromfile);
                sleep(1);
            }
            exit;
        }
        else
        {
            syslog LOG_INFO,"Pid file $pidfile exist and the program ($pidfromfile) is running ! exiting ...\n"; 
        }
        exit;
    }
    else 
    {
        unlink($pidfile);
    }
}

if ($ARGV[0] eq 'stop')
{
    syslog 'info',"Cannot stop packetq.pl as it's not running\n";
    exit;
}
&daemonize() unless defined $foreground;
open FILE, ">$pidfile" or die "unable to open pidfile : $pidfile $!";
print FILE $$."\n";
close FILE;

##### catch signals

my $keep_going = 1;
$SIG{HUP}  = sub { print("Caught SIGHUP:   exiting gracefully\n"); $keep_going = 0; };
$SIG{INT}  = sub { print("Caught SIGINT:   exiting gracefully\n"); $keep_going = 0; };
$SIG{QUIT} = sub { print("Caught SIGQUIT:  exiting gracefully\n"); $keep_going = 0; };
$SIG{TERM} = sub { print("Caught SIGTERM:  exiting gracefully\n"); $keep_going = 0; };

########## start collection
foreach my $k (keys %config)
{
    print $k."=".$config{$k}."\n";
    $config{$k}   =~ s/^\"(.*)\"$/$1/;
}

my $interval   = $config{'interval'};
my $interface  = $config{'interface'};
my @interfaces = split(/,/,$interface);
my $filter     = $config{'filter'};
my $server     = $config{'server'};
my $destdir    = $config{'destdir'};

my $stime = floor(time()/$interval) * $interval + $interval;

syslog LOG_INFO,"Starting packetq collector daemon (pid:".$$.") destdir: $config{'destdir'}\n";

my @tdpid;
my @tspid;
my $ifcnt = 0;
foreach my $if (@interfaces)
{
    if ($config{'bsdpromischack'} eq "YES")
    {
        my $pid;
        #my $tcpdumpcmd="$config{'tcpdump'} -i $if port 100 2>/dev/null";
        my $tcpdumpcmd="$config{'tcpdump'} -i $if port 100";
        $pid = spawn ($tcpdumpcmd);
        print "tcp pid $pid";
        if ($pid == 0)
        {
            syslog LOG_ERROR,"Cannot run $tcpdumpcmd exiting \n";
            exit;
        }
        syslog LOG_INFO,"Keeping the interface ($if) in promisc mode by letting tcpdump ($pid) listen on port 100 \n";
        @tdpid[$ifcnt] = $pid;
    }

    my $tracesplitcmd = $config{'tracesplit'}." pcapint:$if -s $stime -z $config{'compression_level'} -i $interval -f \"$filter\" pcapfile:$destdir/$server-$if";
    my $tspid = spawn($tracesplitcmd);
    print "ts pid $tspid";
    if ($tspid == 0)
    {
        syslog LOG_ERROR,"Cannot run $tracesplitcmd exiting \n";
        exit;
    }
    syslog LOG_INFO,"Starting tracesplit \"$tracesplitcmd\"(pid:$tspid)\n";
    @tspid[$ifcnt] = $tspid;

    $ifcnt++;
}

########## infinite loop
reaper();

while($keep_going == 1)
{
    foreach my $if (@interfaces)
    {
        opendir(DIR, $destdir) or last;
        my @files; 

        while (my $file = readdir(DIR)) 
        {
            # Use a regular expression to ignore files beginning with a period
            next if ($file =~ m/^\./);
            next unless ($file =~ m/^$server-$if.*/);
            push(@files,$file);
        }
        @files= sort(@files);
        if (@files>1)
        {
            pop @files;
            #print "files: \n".join("\n",@files)."\n";
            foreach my $f (@files)
            {
                if($f =~ /^$server-$if-(.*)\.gz/)
                {
                    ##my ($sec, $min, $hour, $day,$month,$year) = (localtime($1))[0,1,2,3,4,5,6]; 
                    my ($sec, $min, $hour, $day,$month,$year) = (gmtime($1))[0,1,2,3,4,5,6]; 
                    $year+=1900;
                    $month++;
                    $sec    = "0".$sec   if $sec  <10;
                    $min    = "0".$min   if $min  <10;
                    $hour   = "0".$hour  if $hour <10;
                    $day    = "0".$day   if $day  <10;
                    $month  = "0".$month if $month<10;

                    my $file = "$server-$year$month$day-$hour$min$sec-$if.gz";
                    my $dir  = "$year/$month/$day/$hour";
                    my $cmd  = $config{command};
                    $cmd     =~ s/%F/$file/g; 
                    $cmd     =~ s/%S/$server/g; 
                    $cmd     =~ s/%I/$if/g; 
                    $cmd     =~ s/%P/$dir/g; 
                    $cmd     =~ s/%Y/$year/g; 
                    $cmd     =~ s/%M/$month/g; 
                    $cmd     =~ s/%D/$day/g; 
                    $cmd     =~ s/%h/$hour/g; 
                    $cmd     =~ s/%m/$min/g; 
                    $cmd     =~ s/%s/$sec/g; 
                    
                    #print "$cmd\n";

                    mkpath "$destdir/$dir";
                    move ("$destdir/$f","$destdir/$dir/$file");
                    spawn($cmd);
                    #print "hello $hour, $min, $sec,-- $day,$month,$year\n";
                    #print "mkdir $dir\n";
					#print "mv $destdir/$f $destdir/$dir/$file\n";
                }
            }
        }
        closedir(DIR);
    } 
    #printf("blipp\n");
    sleep(5);
}

########## exit cleanup

syslog 'info',"Shutting down DNS2db ...\n";
foreach my $pid (@tspid)
{
	if ($pid ne 0)
	{
        print "Stopping tracesplit ($pid)\n";
	    syslog LOG_INFO,"Stopping tracesplit ($pid)\n";
	    kill( - SIGABRT, $pid);
	}
}

foreach my $pid (@tdpid)
{
	if ($pid ne 0)
	{
	    syslog LOG_INFO,"Stopping tcpdump ($pid)\n";
	    kill( - SIGABRT, $pid);
	}
}

syslog LOG_INFO,"removing pidfile\n";
unlink($pidfile);

syslog LOG_INFO,"bye bye\n";
closelog;
exit;

##########  functions

sub spawn 
{
    my $cmd = shift;
    defined(my $pid = fork)   or die "Can't fork: $!";
    if ($pid == 0)
    {
        exec $cmd;
	    syslog LOG_ERROR,"Couldn't run $cmd\n";
        die "Couldn't run $cmd";
    }
    return $pid;
}

sub daemonize 
{
    chdir '/'                 or die "Can't chdir to /: $!";
    defined(my $pid = fork)   or die "Can't fork: $!";
    exit if $pid;
    setsid                    or die "Can't start a new session: $!";
    umask 0;

    open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
    open STDOUT, ">>$logfile" or die "Can't write to $logfile: $!";
    open STDERR, ">>$logfile" or die "Can't write to $logfile: $!";
}

sub reaper {
    my $stiff;
    while ( ($stiff = waitpid(-1, &WNOHANG) ) > 0 ) 
    {
        #print "child $stiff terminated -- status $?";
    }
    $SIG{CHLD} = \&reaper;
}   


