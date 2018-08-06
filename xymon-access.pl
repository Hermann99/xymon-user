#! /usr/bin/perl -w
use strict;
use Getopt::Long;
use Sys::Hostname;
#----------------------------------------------------------------------------------------
my $xymon_column = 'access';
#my $message = '';
#my $errmsg  = '';

my %colors  = ( green => 0, yellow => 1, red => 2,);
my $color   = 'green';

use constant ERRTXTBEGIN => q{<span style=\"color:white;background-color:red\">};
use constant ERRTXTEND => q{</span>};
use constant WARNTXTBEGIN => q{<span style=\"color:black;background-color:yellow\">};
use constant WARNTXTEND => q{</span>};
use constant CLRTXTBEGIN => q{<span style=\"color:white;background-color:green\">};
use constant CLRTXTEND => q{</span>};
use constant HITXTBEGIN => q{<span style=\"color:yellow\">};
use constant HITXTEND => q{</span>};

#----------------------------------------------------------------------------------------
my $verbose = 0;
my $testing = 0;

#-------Passwords----------------------------
my $passwd_file = "/etc/passwd";
my ($name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell);
my $user_status = '';
my $last_change = '';
my $max = '';

#my $alert_max = '';

#-------Login defs---------------------------
my $login_defs_file     = "/etc/login.defs";
my $PASS_MAX_DAYS_LIMIT = '42';
my $PASS_MIN_DAYS_LIMIT = '0';
my $LOGIN_RETRIES       = '5';
my $ENCRYPT_METHOD      = 'SHA512';
my @exclude_users       = ('root','dns');

#-------SSHD Config--------------------------
my $sshd_config_file = "/etc/ssh/sshd_config";
my $os_distro        = `/usr/bin/lsb_release -i`;

#----------------------------------------------------------------------------------------
GetOptions('verbose|v+' => \$verbose,
            'testing|t' => \$testing,
          );

#        print "$item = $sysinfo{$item}\n" if $testing;

#----------------------------------------------------------------------------------------
sub setcolor {
    my ($current, $new ) = @_;
    return ($colors{$new} > $colors{$current}) ? $new : $current;
}

#----------------------------------------------------------------------------------------
sub check_sshd {
   my ($sshd_config_file,$os_distro) =@_;
   my $output = '';

   if ( $os_distro =~ "CentOS|OracleServer" ) {
      $output = "SSH check: PermitRootLogin = default (Yes)";
   } else {
      $output = "SSH check: PermitRootLogin = default (No)";
   }
 
   open(SSHD,$sshd_config_file) or die "Can't open $sshd_config_file:$!\n";
   while (<SSHD>) {
      if ( /^\s*PermitRootLogin/ ) {
         if ( /^\s*PermitRootLogin\s+[yY][eE][sS]/ ) {
            $output = "SSH check: Root login is allowed.\n";
         }else{
            $output = "SSH check: Root login is not allowed.\n";
         }
      }
   }
   close(SSHD);
   return($output);
}

#----------------------------------------------------------------------------------------
sub check_login_defs {
   my ($login_defs_file,$PASS_MAX_DAYS_LIMIT,$PASS_MIN_DAYS_LIMIT,$LOGIN_RETRIES,$ENCRYPT_METHOD) = @_;
   my $login_defs = '';

   open(DEFS,$login_defs_file) or die "Can't open $login_defs_file:$!\n";

   while (<DEFS>) {
      if ( /^\s*PASS_MAX_DAYS\s+([0-9]+)/ ) {
         if ( $1 > $PASS_MAX_DAYS_LIMIT ) {
            $login_defs .= "The password maximum age configured ($1) is more than $PASS_MAX_DAYS_LIMIT.\n";
#            print "The password maximum age configured ($1) is more than $PASS_MAX_DAYS_LIMIT.\n";
         } else {
            $login_defs .= "The password maximum age configured ($1) is within the limit of $PASS_MAX_DAYS_LIMIT.\n";
#            print "The password maximum age configured ($1) is within the limit of $PASS_MAX_DAYS_LIMIT.\n";
         }
      }
#      elsif ( /^\s*ENCRYPT_METHOD\s+([a-zA-Z0-9]+)/ ) { 
#         $_ =$1;
##        print "encrypt $1\n";
#         if ( /SHA512/ ) {
#            print "The password encryption method is $_.\n";
#         } else { 
#            print "The password encryption method $_ is not in the list of allowed methods.\n";
#         }
#      }
   }
   close(DEFS);
   return ($login_defs);
}

#----------------------------------------------------------------------------------------
sub get_shadow_info {
   my ($name) = @_;
   my $shadow = '';
   my $user_status = '';
   my $last_change = '';
   my $max = '';
   my $epoch = '';
   
   $shadow = `/usr/bin/sudo /usr/bin/passwd -S $name`;
   ($user_status,$last_change,$max) = (split(/ /,$shadow))[1,2,4];
   if ($user_status =~ /^L/)  { $user_status = "Locked"; }
   elsif ($user_status =~ /^P/)  { $user_status = "Active"; }
   elsif ($user_status =~ /^N/)  { $user_status = "No Password"; }

   return ($user_status,$last_change,$max);
}

#----------------------------------------------------------------------------------------
sub check_accounts {
   my (@exclude_users) = @_;
   my ($name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell);
   my $accounts = '';

   while ( ($name,$passwd,$uid,$gid,$quota,$gcos,$comment,$dir,$shell) = getpwent(  ) ) {
      if ($shell !~ /(nologin|false|sync|halt|shutdown)$/ ) {
         ($user_status,$last_change,$max) = get_shadow_info($name);
         if ( grep( /^$name$/, @exclude_users ) ) {
            $accounts .= sprintf ("%-21s %-40s %-12s -\n",$name,$comment,$user_status);
         }else{
            $accounts .= sprintf ("%-21s %-40s %-12s %s\n",$name,$comment,$user_status,$max);
         }
      }
   }
   endpwent(  );
   return ($accounts);
}

#----------------------------------------------------------------------------------------
sub report_to_xymon {
    my ($login_defs,$account_info,$ssh_check) = @_;
    my $key;
    my $message = '';
    my $date = localtime();

    $message  = "<br/><b><u>Access Information</u></b></b>";
#    $message .= "\n<table border=1 style='width:100%'>\n";
#    $message .= "<table class=content border=1 cellpadding=5 cellspacing=0 width=100%'>\n";

    $message .= "<pre>\n";
    $message .= "-------------------------------------------------------\n";
    $message .= "Login Defs:\n";
    $message .= "$login_defs";
    $message .= "-------------------------------------------------------\n";
    $message .= "Accounts:\n";
    $message .= "$account_info";
    $message .= "-------------------------------------------------------\n";
    $message .= "SSH Config:\n";
    $message .= "$ssh_check\n";
    $message .= "-------------------------------------------------------\n";
    $message .= "</pre>\n";

#    $message .= "<tr><th width=200>Item</th><th width=400>Information</th></tr>\n";
#    $message .= "<tr><th width=600>Login Defs</th>\n";
#    $message .= "<tr><th width=600>$login_defs</th>\n";

#    foreach $key (keys %info) {
#        $message .= "<tr><td>$key</td><td>$info{$key}</td></tr>\n";
#    }

#    $message .= "</table>";

    system("$ENV{BB} $ENV{BBDISP} \"status+1d $ENV{MACHINE}.$xymon_column $color $date\n</pre>$message<pre>\"") unless $testing;
    print "Status $color $date\n$message\n" if $testing;
}

#----------------------------------------------------------------------------------------
#       MAIN
#----------------------------------------------------------------------------------------
#my @date = localtime(time());
#my $date = sprintf "%02i.%02i.20%02i %02i:%02i:%02i",$date[3],++$date[4],$date[5]-100,$date[2],$date[1],$date[0];
my $host  = hostname();
my $login_defs = check_login_defs ($login_defs_file,$PASS_MAX_DAYS_LIMIT,$PASS_MIN_DAYS_LIMIT,$LOGIN_RETRIES,$ENCRYPT_METHOD);
my $ssh_check  = check_sshd ($sshd_config_file, $os_distro);
my $account_info = check_accounts(@exclude_users);

#print "Hostname: $host\n";
#print "-------------------------------------------------------\n";
#print "Login Defs:\n";
#print "$login_defs";
#print "-------------------------------------------------------\n";
#print "Accounts:\n";
#print "$account_info";
#print "-------------------------------------------------------\n";
#print "SSH Config:\n";
#print "$ssh_check\n";
#print "-------------------------------------------------------\n";

report_to_xymon($login_defs,$account_info,$ssh_check);
