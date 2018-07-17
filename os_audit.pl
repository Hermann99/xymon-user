#! /usr/bin/perl -w
use strict;
use Getopt::Long;
use Sys::Hostname;
#use Time::Local;
#use User::pwent;
#use File::stat;

#----------------------------------------------------------------------------------------
my $verbose = 0;
my $testing = 0;

#-------Passwords----------------------------
my $passwd_file = "/etc/passwd";
my ($name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell);
my $user_status = '';
my $last_change = '';
my $max = '';

#my $alert_max = ''

#-------Login defs---------------------------
my $login_defs_file     = "/etc/login.defs";
my $PASS_MAX_DAYS_LIMIT = '42';
my $PASS_MIN_DAYS_LIMIT = '0';
my $LOGIN_RETRIES       = '5';
my $ENCRYPT_METHOD      = 'SHA512';

#-------SSHD Config--------------------------
my $sshd_config_file = "/etc/login.defs";
my $ssh_check = '';

#----------------------------------------------------------------------------------------
GetOptions('verbose|v+' => \$verbose,
            'testing|t' => \$testing,
          );

#        print "$item = $sysinfo{$item}\n" if $testing;

#----------------------------------------------------------------------------------------
sub check_sshd {
   my ($sshd_config_file) =@_;
   my $output = "SSH check: PermitRootLogin = default (No)";
 
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
#   my ($retries,$encryption);

   open(DEFS,$login_defs_file) or die "Can't open $login_defs_file:$!\n";

   while (<DEFS>) {
      if ( /^\s*PASS_MAX_DAYS\s+([0-9]+)/ ) {
         if ( $1 > $PASS_MAX_DAYS_LIMIT ) {
            print "The password maximum age configured ($1) is more than $PASS_MAX_DAYS_LIMIT.\n";
         } else {
            print "The password maximum age configured ($1) is within the limit of $PASS_MAX_DAYS_LIMIT.\n";
         }
      }
      elsif ( /^\s*ENCRYPT_METHOD\s+([a-zA-Z0-9]+)/ ) { 
         $_ =$1;
#        print "encrypt $1\n";
         if ( /SHA512/ ) {
            print "The password encryption method is $_.\n";
         } else { 
            print "The password encryption method $_ is not in the list of allowed methods.\n";
         }
      }
   }
   close(DEFS);

return
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

    
#my $time = timelocal($sec,$min,$hours,$day,$month,$year);
 
   return ($user_status,$last_change,$max);
}

#----------------------------------------------------------------------------------------
sub check_accounts {
   my ($name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell);

   while ( ($name,$passwd,$uid,$gid,$quota,$gcos,$comment,$dir,$shell) = getpwent(  ) ) {
#     print "name=$name,pass=$passwd,uid=$uid,gid=$gid,quota=$quota,comment=$comment,gcos=$gcos,dir=$dir,shell=$shell\n";
  
      if ($shell   !~ /(nologin|false|sync|halt|shutdown)$/ ) {
         ($user_status,$last_change,$max) = get_shadow_info($name);
#        $output{$name} = 

#        printf "%-21s %-40s %-20s %-12s %-12s %s\n",$name,$comment,$shell,$user_status,$last_change,$max;
         printf "%-21s %-40s %-12s %s\n",$name,$comment,$user_status,$max;
      }
   }
   endpwent(  );

}


#----------------------------------------------------------------------------------------
#----------MAIN--------------------------------------------------------------------------
my $host = hostname();
print "----- $host -----\n";
check_login_defs ($login_defs_file,$PASS_MAX_DAYS_LIMIT,$PASS_MIN_DAYS_LIMIT,$LOGIN_RETRIES,$ENCRYPT_METHOD);

$ssh_check = check_sshd ($sshd_config_file);
print "$ssh_check\n";

check_accounts($sshd_config_file);


#----------------------------------------------------------------------------------------
#open(PW,$login_file) or die "Can't open $passwd_file:$!\n";
#close(PW);


#----------------------------------------------------------------------------------------
#Ubuntu: Passwd -S output
#cami P 06/25/2018 0 99999 7 -1"
#2: locked password (L), has no password (NP), or has a usable password (P).
#3: The third field gives the date of the last password change.
#4: The next four fields are the minimum age, maximum age, warning period, and inactivity period for the password. These ages are expressed in days.

#Centos:
#cami PS 2017-01-19 0 99999 7 -1 (Password set, SHA512 crypt.)
#daaadm LK 2013-01-21 0 99999 7 -1 (Password locked.)
#sintrex NP 2017-02-21 0 99999 7 -1 (Empty password.)

#----------------------------------------------------------------------------------------
#HOSTNAME=`/bin/hostname`
#echo "$HOSTNAME"

#----------------------------------------------------------------------------------------
#echo "---- Active Accounts ----"
##let index=0
#for name in `cat /etc/passwd |awk -F: '{print $1}'`; do
#   if [[ "$name" != 'root' ]]; then
#      status=`sudo passwd -S $name`
#      if [[ "$status" =~ 'Password set' ]]; then
#        status="PS"
#      else
#        status="Locked"
#      fi
#
#       fullname=`getent passwd $name| awk -F: '{print$5}'`
#       printf "%-21s %-45s %-10s\n" $name "$fullname" $status
##     printf "%-15s %-25s\n" $name "$fullname"
#   fi
#done

#----------------------------------------------------------------------------------------
