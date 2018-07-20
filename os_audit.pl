#! /usr/bin/perl -w
use strict;
use Getopt::Long;
use Sys::Hostname;

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
my $os_distro        = `/usr/bin/lsb_release -i`;


#----------------------------------------------------------------------------------------
GetOptions('verbose|v+' => \$verbose,
            'testing|t' => \$testing,
          );

#        print "$item = $sysinfo{$item}\n" if $testing;

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
   my ($name,$passwd,$uid,$gid,$quota,$comment,$gcos,$dir,$shell);
   my $accounts = '';

   while ( ($name,$passwd,$uid,$gid,$quota,$gcos,$comment,$dir,$shell) = getpwent(  ) ) {
      if ($shell   !~ /(nologin|false|sync|halt|shutdown)$/ ) {
         ($user_status,$last_change,$max) = get_shadow_info($name);
         $accounts .= sprintf ("%-21s %-40s %-12s %s\n",$name,$comment,$user_status,$max);
      }
   }
   endpwent(  );
   return ($accounts);
}

#----------------------------------------------------------------------------------------
#	MAIN
#----------------------------------------------------------------------------------------
my $host = hostname();
my $login_defs = check_login_defs ($login_defs_file,$PASS_MAX_DAYS_LIMIT,$PASS_MIN_DAYS_LIMIT,$LOGIN_RETRIES,$ENCRYPT_METHOD);
my $ssh_check = check_sshd ($sshd_config_file, $os_distro);
my $account_info = check_accounts();

print "Hostname: $host\n";
print "-------------------------------------------------------\n";
print "Login Defs:\n";
print "$login_defs";
print "-------------------------------------------------------\n";
print "Accounts:\n";
print "$account_info";
print "-------------------------------------------------------\n";
print "SSH Config:\n";
print "$ssh_check\n";
print "-------------------------------------------------------\n";

#----------------------------------------------------------------------------------------


