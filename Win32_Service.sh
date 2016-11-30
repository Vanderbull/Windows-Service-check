#!/usr/bin/perl -w

######################################################
# This script is intended to monitor Win32_Service states and it's changes.
# If state != running alert messages will be sent to OMW thru opcmsg.exe
#
# 2013-12-09 First version of script
# 2014-01-24 Edited major faults with parsing
# 2014-06-30 Added support for service names with whitespaces
#
######################################################

use strict;
use warnings;

# Excluded services ##################################
my @excludeservices =(
"Tj„nsten Google Update (gupdate)",
"Citrix Print Manager Service",
"Tjänsten Google Update (gupdate)",
"Performance Logs and Alerts",
"clr_optimization_v2.0.50727_32",
"CpqNicMgmt",
"Microsoft .NET Framework NGEN v4.0.30319_X86",
"Microsoft .NET Framework NGEN v4.0.30319_X64",
"clr_optimization_v2.0.50727_64",
"RDSessMgr",
"spupdsvc",
"Windows Search",
"SysmonLog",
"ccmsetup",
"WinRM",
"Security Center",
"gupdate",
"Tjänsten Google Update (gupdate)",
"Remote Registry",
"PA Measurement Interface",
"PA Transaction Manager",
"PA Extended Collector",
"PA Alarm Generator",
"PA DSI Service",
"PA Collector",
"Windows Image Acquisition (WIA)",
"WinHTTP Web Proxy Auto-Discovery Service",
"TPM Base Services",
"Shell Hardware Detection",
"Software Protection",
"NetIQ AppManager Client Communication Manager",
"NetIQ AppManager Client Resource Monitor",
"Microsoft Exchange POP3",
"Windows Modules Installer",
"Windows Installer",
"Distributed Transaction Coordinator",
"Windows Font Cache Service",
"Volume Shadow Copy",
"VMware Tools Service",
"Real Time Metric Access Service",
"OfficeScan NT RealTime Scan",
"OfficeScan NT Listener",
"KtmRm for Distributed Transaction Coordinator",
"Distributed Transaction Coordinator",
"Diagnostic Policy Service",
"Background Intelligent Transfer Service",
"Citrix SMA Service",
"Windows Service Pack Installer update service",
"Windows Event Collector",
"Server",
"Print Spooler",
"GroupPolicy Client",
"Application Experience",
".NET Runtime Optimization Service",
"Net.Tcp Listener Adapter",
"Net.Pipe Listener Adapter",
"Net.Msmq Listener Adapter",
"Update Services",
"Google Update Service",
"NetWorker PowerSnap Service",
"HP ProLiant Rack Infrastructure Interface Service",
"Microsoft .NET Framework NGEN",
"clr_optimization_v4.0.30319_32",
"clr_optimization_v4.0.30319_64",
"Microsoft .NET Framework NGEN v2.0.50727_X64",
"Microsoft .NET Framework NGEN v2.0.50727_X86",
"BrSplService",
"Remote Management (WS-Management)",
"AudioSrv",
"Service Google Update Service (gupdate)",
"Windows Remote Management (WS-Management)",
"Windows Update",
"AppFabric Caching Service",
"Enfocus Switch Watchdog"
);

# OPCMSG variables ###################################
# Severity is handeled in open message interface policy
my $msg_g = "Windows";
my $a = "ServiceMonitor";
my $o; # Will be the monitored service
my $msg_t; # Will be a string with information.
my $severity = "Major";
my $opcmsg;

# Declaring variables ################################
my $debug = 0;
my @cmd;
my @runningservices_now;
my @notrunningservices_now;
my @runningservices_history;
my @notrunningservices_history;
my @servicestatehistory;
my $dir;
my $vbsfile = "Win32_service.vbs";
my $servicestatefile = "ServiceStateHistory.log";
my $outputline;
my $servicestatus;
my $servicename;
my $servicedisplayname;
my $servicestartmode;
my $servicestate;
my $firstpoll = 0;



my $ovagentdir = $ENV{'OvAgentDir'};
	$ovagentdir =~ s/\\/\//g; #Switches Windows path to Perl.
	$ovagentdir = $ovagentdir . "bin/instrumentation";
	print "$ovagentdir\n";
	$dir = $ovagentdir;
	
	#Dev options
	#my $dir = "C:/ProgramData/HP/HP BTO Software/bin/instrumentation";
######################################################

# Create/Read state file

if(-e "$dir/$servicestatefile"){
	#print "File exists!\n";
	
	$firstpoll = 0;
	print "File exists!!\n";
	print "FIRSTPOLL: $firstpoll\n";
	#Read file
	open READFILE, "$dir/$servicestatefile" or die $!;
	@servicestatehistory = <READFILE>;
	close READFILE;
	chomp(@servicestatehistory);
	
	#Clean configfile
	open WRITEFILE, ">", "$dir/$servicestatefile" or die $!;
	close WRITEFILE;
}
else{
	print "File does not exist!\n";
	print "FIRSTPOLL: $firstpoll\n";
	$firstpoll = 1;
	#Create file
	open WRITEFILE, ">>", "$dir/$servicestatefile" or die $!;
	close WRITEFILE;
}

# Main script

print "####### Service history #######\n";

# Push service history states into two arrays ##########
foreach $outputline(@servicestatehistory){
	#Parse output
	if($outputline =~ m/(.*) ;\s*(\S*)\s*;\s*(\S*)\s*;\s*(.*)/){
		$servicename = $1;
		$servicestate = $2;
		$servicestartmode = $3;
		$servicedisplayname = $4;
	
		if($servicestate =~ m/Running/i){
			push(@runningservices_history, "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname");
			print "RUNNING: $servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";
		}
		else{
			push(@notrunningservices_history, "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname");
			print "NOT RUNNING: $servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";
		}
	
	}
}
######################################################

# Run VBS script to get Win32_Service states.#########
@cmd = `cscript "$dir/$vbsfile"`;
chomp(@cmd);
######################################################

print "\n####### Evaluate current state #######\n";

# Evaluate service states from VBS script.############
foreach $outputline(@cmd){
	if($debug == 1){
		print "OUTPUTLINE: $outputline\n";
	}
	
	#Parse output
	if($outputline =~ m/(.*) ;\s*(\S*)\s*;\s*(\S*)\s*;\s*(.*)/){
		$servicename = $1;
		$servicestate = $2;
		$servicestartmode = $3;
		$servicedisplayname = $4;
		
		#print "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";

		open WRITEFILE, ">>", "$dir/$servicestatefile" or die $!;

	if(grep $_ eq $servicename, @excludeservices){
			print "EXCLUDED Servicename: $servicename\n";
			#Do nothing
		}
		elsif(grep $_ eq $servicedisplayname, @excludeservices){
			print "EXCLUDED Servicedisplayname: $servicedisplayname\n";
			#Do nothing
		}
		else{
		
		#print "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";
		
			if($servicestate =~ m/Running/i){
				push(@runningservices_now, "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname");
				print WRITEFILE "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";
			
				if($firstpoll == 0){
					$servicestatus = "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname";
					if(grep $_ eq $servicestatus, @runningservices_history){
						#Current state is same as history and still running, do nothing.
						print "RUNNING SAME: $servicestatus\n";
					}
					else{
						
						#Current state is running and is not same as history. send normal message.
						print "RUNNING NOT SAME: $servicestatus\n";
						$msg_t = "Service $servicedisplayname ($servicename) is $servicestate.";
						$opcmsg = `opcmsg a=\"$a\" o=\"$servicename\" msg_g=\"$msg_g\" msg_t=\"$msg_t\" s=\"normal\"`;
					}
				}
			}
			else{
				push(@notrunningservices_now, "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname");
				print WRITEFILE "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname\n";
			
				if($firstpoll == 0){
					$servicestatus = "$servicename ; $servicestate ; $servicestartmode ; $servicedisplayname";
					if(grep $_ eq $servicestatus, @notrunningservices_history){
						#Current state is same as history do nothing
					}
					else{
						#Current state is not same as history and service is not running, send alert message!!
						print "Service $servicedisplayname ($servicename) is now $servicestate\n";
						$msg_t = "Service $servicedisplayname ($servicename) is $servicestate";
						$opcmsg = `opcmsg a=\"$a\" o=\"$servicename\" msg_g=\"$msg_g\" msg_t=\"$msg_t\" s=\"$severity\"`;
					}
				}
				else{
					#Current state is not running, send alert merssage!!!
					print "Service $servicedisplayname ($servicename) is now $servicestate\n";
					$msg_t = "Service $servicedisplayname ($servicename) is $servicestate";
					$opcmsg = `opcmsg a=\"$a\" o=\"$servicename\" msg_g=\"$msg_g\" msg_t=\"$msg_t\" s=\"$severity\"`;
				}
			}
		}
		close WRITEFILE;		
	}
}
######################################################
