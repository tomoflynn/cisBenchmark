#Simple script to implement recommendations of the CIS CentOS Linux Benchmark
#Written by Tom O'Flynn, Department of Science
#This script assumes a minimal install of CentOS 7 upgraded to the latest release
#This script assumes the following directories are mounted on separate partitons:
#/tmp
#/var/
#/var/tmp
#/var/log
#/var/log/audit
#/home


#!/bin/bash
#############################################################################
#Create a file to record changes
outputFile=./outputFiles/info.`date +%d-%m-%y:%H:%M:%S`
touch $outputFile

#Create a directory to store original copy of any files modified if it does not already exist
mkdir -p backupFiles

#This script may modify /etc/sysctl.conf or any files in /etc/sysctl.d. 
#Simplest thing is to simply back up all these files in advance of running the script

mv /etc/sysctl.conf ./backupFiles/sysctl.conf.`date +%d-%m-%y:%H:%M:%S`
touch /etc/sysctl.conf
chmod 644 /etc/sysctl.conf

for file in $(ls /etc/sysctl.d/ | grep -v 99-sysctl.conf)
	do
		mv /etc/sysctl.d/$file ./backupFiles/$file.`date +%d-%m-%y:%H:%M:%S`
		touch /etc/sysctl.d/$file
		chmod 644 /etc/sysctl.d/$file
	done

echo "################################################################################################" >> ./$outputFile
echo WARNING! >> ./$outputFile
echo "The original /etc/sysctl.conf file and any files in /etc/sysctl.d/ have been moved to ./backupFiles" >> ./$outputFile
echo "Please review these files and, if necessary, add lines from the originals to the new versions" >> ./$outputFile
echo "" >> ./$outputFile


echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check user home directories and files therein" >> ./$outputFile
echo "" >> ./$outputFile

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6}' | while read username directory
	do
	if [ ! -d "$directory" ]
		then
		echo "Warning! Home directory missing for user $username" >> ./$outputFile

		else
		echo "$username: $directory" >> ./$outputFile

		dirperm=`ls -ld $directory | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]
		then
		echo "Warning! Group write permissions incorrectly set on the home directory $directory" >> ./$outputFile
		else
		echo "Group wirte permissions correctly set on the home directory $directory" >> ./$outputFile
		fi

		if [ `echo $dirperm | cut -c8` != "-" ]
		then
		echo "Warning! Other read permissons incorrectly set on the home directory $directory" >> ./$outputFile
		else
		echo "Other read permissions correctly set on the home directory $directory" >> ./$outputFile
		fi

		if [ `echo $dirperm | cut -c9` != "-" ]
		then
		echo "Warning! Other write permissions incorrectly set on the home directory $directory" >> ./$outputFile
		else
		echo "Other write permissions correctly set on the home directory $directory" >> ./$outputFile
		fi

		if [ `echo $dirperm | cut -c10` != "-" ]
		then
		echo "Warning! Other execute permissions incorrectly set on the home directory $directory" >> ./$outputFile
		else
		echo "Other execute permission correctly set on the home directory $directory" >> ./$outputFile
		fi
		
		owner=$(stat -L -c "%U" "$directory")
		if [ "$owner" != "$username" ]
		then
		echo "Warning! the home directory ($directory) of user $username is owned by $owner" >> ./$outputFile
		else
		echo "The home directory ($directory) of user $username is own by $username" >> ./$outputFile
		fi

		for file in $directory/.[A-Za-z0-9]*
		do

			if [ ! -h "$file" -a -f "$file" ]
			then
			fileperm=`ls -ld $file | cut -f1 -d" "`
			fi

			if [ `echo $fileperm | cut -c6` != "-" ]
			then
			echo "Warning! Group write permissions incorrectly set on file $file" >> ./$outputFile
			else
			echo "Group write permisisons correctly set on file $file" >> ./$outputFile
			fi
	
			if [ `echo $fileperm | cut -c9` != "-" ];
			then
			echo "Warning! Other write permissions incorrectly s set on file $file" >> ./$outputFile
			else
			echo "Other write permissions correctly set on file $file" >> ./$outputFile
			fi

		done

		if [ ! -h "$directory/.forward" -a -f "$directory/.forward" ]
		then
		echo "Warning! .forward file exists in directory $directory" >> ./$outputFile
		else
		echo "No .forward file found in directory $directory" >> ./$outputFile
		fi

		if [ ! -h "$directory/.netrc" -a -f "$directory/.netrc" ]
		then
			echo "Warning! .netrc file exists in directory $directory" >> ./$outputFile
			
			for file in $directory/.netrc
			do

			if [ ! -h "$file" -a -f "$file" ]
			then
			fileperm=`ls -ld $file | cut -f1 -d" "`
			fi
			
			if [ `echo $fileperm | cut -c5` != "-" ]
			then
			echo "Warning! Group read permissions set on $file" >> ./$outputFile
			fi

			if [ `echo $fileperm | cut -c6` != "-" ]
			then
			echo "Warning! Group write permissions set on $file" >> ./$outputFile
			fi

			if [ `echo $fileperm | cut -c7` != "-" ]
			then
			echo "Warning! Group execute permissions set on $file" >> ./$outputFile
			fi

			if [ `echo $fileperm | cut -c8` != "-" ]
			then
			echo "Warning! Other read permissions set on $file" >> ./$outputFile
			fi

			if [ `echo $fileperm | cut -c9` != "-" ]
			then
			echo "Warning! Other write permissions set on $file" >> ./$outputFile
			fi

			if [ `echo $fileperm | cut -c10` != "-" ]
			then
			echo "Warning! Other execute permissions set on $file" >> ./$outputFile
			fi

			done




			
				
		else
		echo "No .netrc file found in directory $directory" >> ./$outputFile
		fi
		
		if [ ! -h "$directory/.rhosts" -a -f "$directory/.rhosts" ]
		then
		echo "Warning! .rhosts file exists in directory $directory" >> ./$outputFile
		else
		echo "No .rhosts file found in directory $directory" >> ./$outputFile
		fi
		
		echo "" >> ./$outputFile
		
	fi
			
	done





#Install packages listed in yumInstall

while read package
do
	if ! [[ $(rpm -qa $package) ]];
	then
		yum -y install $package &>/dev/null
		echo "$package has been installed on this system" >> ./$outputFile
	
	else
		echo "$package is already installed on this system" >> ./$outputFile
	fi
done < ./inputFiles/yumInstall

#Remove packages listed in yumRemove
while read package
do
	if [[ $(rpm -qa $package) ]];
	then
		yum -y remove $package &>/dev/null
		echo "$package has been removed from this system" >> ./$outputFile
	
	else
		echo "$package was not found on this system" >> ./$outputFile
	fi
done < ./inputFiles/yumRemove
#1.1.1 Disable unused filesystems

#Create the file /etc/modprobe.d/CIS.conf
if ls /etc/modprobe.d/CIS.conf
	then
		mv /etc/modprobe.d/CIS.conf ./backupFiles/CIS.conf`date +%d-%m-%y:%H:%M:%S`
		echo "################################################################################################" >> ./$outputFile
		echo WARNING! >> ./$outputFile
		echo CIS.conf already exists in /etc/modprobe.d/! >> ./$outputFile
		echo This file has been backed up>> ./$outputFile
		echo Please review this backup and, if necessary, add lines from the orignal to the new version >> ./$outputFile
fi
touch /etc/modprobe.d/CIS.conf

#Configure system to run fake install of filesystems in ././inputFiles/fileSystems on boot 
#Unload modules (should not be neccessary after a minimal install but better safe than sorry!)
#By default ././inputFiles/fileSystems includes all systems mentioned in CIS document
#It can be modified as appropriate 

echo "################################################################################################" >> ./$outputFile
echo "DISABLING OF UNNECESSARY FILESYSTEMS AND NETWORK PROTOCOLS" >> ./$outputFile
echo The following filesystems and network protocols have been disabled:  >> ./$outputFile

for file in ./inputFiles/fileSystems ./inputFiles/protocols
do
	while read module;
	do
		if lsmod | grep $module
		then
			rmmod $module
		fi
	
		if ! grep "install $module /bin/true" /etc/modprobe.d/CIS.conf
		then	
			echo install $module /bin/true >> /etc/modprobe.d/CIS.conf
		fi
	
	
	done < $file
done




#File system mount options:

#First create a backup of fstab
cp /etc/fstab ./backupFiles/fstab.`date +%d-%m-%y:%H:%M:%S`

#Set nodev, nosuid and noexec options on /tmp, /var/tmp and /dev/shm
sed -i '/\s\/tmp\s/ s/defaults\s/defaults,nosuid,nodev,noexec\t/' /etc/fstab
sed -i '/\s\/var\/tmp\s/ s/defaults\s/defaults,nosuid,nodev,noexec\t/' /etc/fstab

#Ensure settings for /dev/shm are correct (simpler just to delete relevant line and replace it!)
sed -i '/\/dev\/shm/d' /etc/fstab.backup2
echo "tempfs	/dev/shm	tempsf	defaults,nosuid,nodev,noexec        0 0" >> /etc/fstab.backup2
	



#Remount /tmp and /var/tmp
mount -o remount /tmp
mount -o remount /var/tmp
mount -o remount /dev/shm


echo "################################################################################################" >> ./$outputFile
echo "FILESYSTEM MOUNT OPTONS:" >> ./$outputFile
echo "" >> ./$outputFile
echo nodev, nosuid and noexec options have been set for /tmp /var/tmp and /dev/shm >> ./$outputFile

#Removable media (see page 50 of CIS Benchmark Guide)
echo "Mount options for removable media have not been checked for this server." >> ./$outputFile
echo "If you have removable media see page 50 of CIS Benchmark Guide for instructions on setting mount options" >> ./$outputFile




#Find any world writable directories which not not have a sticky bit and set the sticky bit
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "################################################################################################" >> ./$outputFile
echo "SETTING OF STICKY BIT ON WORLD WRITABLE FILES" >> ./$outputFile
echo "" >> ./$outputFile
echo "Sticky bit set on all world writable directories" >> ./$outputFile

#Check if automounting is enabled and disable if it is
echo "################################################################################################" >> ./$outputFile
echo "CHECKING OF AUTOMOUNTING OPTIONS" >> ./$outputFile
echo "" >> ./$outputFile

	#if $(systemctl -q is-active autofs.service);
#then
#	systemctl disable autofs.service
#	echo "################################################################################################" >> ./$outputFile
#	echo "Autofs was running on this server but has now been disabled" >> ./$outputFile
#	echo "If you require automatic mounting of filesystems please re-enable autofs" >> ./$outputFile
#
#	
#else
#	echo "Autofs is not running on this server" >> ./$outputFile
#fi


#Save GPG key details to ./$outputFile for later analysis
echo "################################################################################################" >> ./$outputFile
echo "GPG KEY DETAILS:" >> ./$outputFile
echo "" >> ./$outputFile
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' >> ./$outputFile

#Check GPG keys configuration
echo "################################################################################################" >> ./$outputFile
echo "CHECKING OF GPG KEY CONFIGURATION" >> ./$outputFile
echo "" >> ./$outputFile

if grep -q ^gpgcheck=1$ /etc/yum.conf;
then
	echo "gpgcheck enabled in yum.conf" >> ./$outputFile
else
	echo "WARNING!!! gpgcheck not enabled in yum.conf" >> ./$outputFile
	echo "Please consider enabling gpgcheck in yum.conf" >> ./$outputFile
	echo "" >> ./$outputFile
fi

for file in $(ls /etc/yum.repos.d);
do
	if grep -q ^gpgcheck=0$ /etc/yum.repos.d/$file;
	then
		echo "Warning!!! At least one entry of gpgcheck=0  was found in $file" >> ./$outputFile
		echo "Please consider setting all gpgcheck values to 0 in $file" >> ./$outputFile
	else
		echo "gpgcheck enabled for $file" >> ./$outputFile
	fi
done


echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "SECURE GRUB FILES" >> ./$outputFile
echo "This script assumes the grub bootloader is in use." >> ./$outputFile
echo "If using a different bootloader please check relevant documentation for equivalent commands." >> ./$outputFile
echo "" >> ./$outputFile

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
echo "The file /boot/grub2/grub.cfg has been secured" >> ./$outputFile

if [[ $(find /boot -name user.cfg) ]] ; then
	chown root:root $(find /boot -name user.cfg)
	chmod og-rwx $(find /boot -name user.cfg)
	echo "The file $(find /boot -name user.cfg) exists and has been secured" >> ./$outputFile
else
	echo "The file user.cfg was not found."

	while true; do
		read -p "Do you wish to set a password for grub2 now (recommended)? Y/N"  yn
		case $yn in
			[Yy]* ) grub2-setpassword; 
				echo "Grub password has been set" >> ./$outputFile;
				chown root:root $(find /boot -name user.cfg);
				chmod og-rwx $(find /boot -name user.cfg); 
				echo "The file $(find /boot -name user.cfg) has been created and secured" >> ./$outputFile;
				echo "Grub password set and $(find /boot -name user.cfg) secured";break;; 
				
			[Nn]* ) echo "Grub password not set"; 
				echo "Please consider password protecting grub at a later stage"
				echo "" >> ./$outputFile
				echo "WARNING!!" >> ./$outputFile;
				echo "No user.cfg file found, therefore grub is not password protected!" >> ./$outputFile
				echo "Plese consider password protecting grub" >> ./$outputFile; break;;
			*) echo "Please answer Y/y for yes or N/n for no"
		esac
	done
	
fi




echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "ENSURE SINGLE USER MODE IS PROTECTED" >> ./$outputFile
echo "" >> ./$outputFile

#Ensure entries for emergency and single user mode are set to use sulogin (/sbin/sulogin or /usr/sbin/sulogin will both do)
#This is the default so it should not be necessary but better to be sure
#The if loops below simply check the appropriate files for a line starting with 'ExecStart=-/bin/sh -c'
#If the line is found it is simply re-written to ensure secure settings otherwise the desired line is appended to the appropriate file



if grep '^ExecStart=-/bin/sh -c' /usr/lib/systemd/system/emergency.service 1>/dev/null ;  
then
	sed -i 's/^ExecStart=-\/bin\/sh -c.*/ExecStart=-\/bin\/sh -c "\/usr\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/g' /usr/lib/systemd/system/emergency.service
else
	echo 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/emergency.service
fi

if grep '^ExecStart=-/bin/sh -c' /usr/lib/systemd/system/rescue.service 1>/dev/null ;  
then
	sed -i 's/^ExecStart=-\/bin\/sh -c.*/ExecStart=-\/bin\/sh -c "\/usr\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/g' /usr/lib/systemd/system/rescue.service
else
	echo 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/rescue.service
fi

echo "Single user and emergency mode are now password protected" >> ./$outputFile

echo "" >> ./$outputFile


echo "################################################################################################" >> ./$outputFile
echo "RESTRICTION OF CORE DUMPS" >> ./$outputFile
echo "" >> ./$outputFile

#Check if limits.conf file has restriction of core dumps set

if grep $'^\*\t\+hard\t\+core\t\+0\|^\*\s\+hard\s\+core\s\+0' /etc/security/limits.conf 1>/dev/null
	then
		/bin/true	
	else
		echo "*	hard	core	0" >> /etc/security/limits.conf
fi

echo "Core dumps restricted" >> ./$outputFile



#CHECK FOR MEMORY PROTECTION (XD/NX)
#This should be the default for modern processors and kernels
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "MEMORY PROTECTION (XD/NX)" >> ./$outputFile
echo "" >> ./$outputFile

if dmesg | grep $'NX (Execute Disable) protection: active' 1>/dev/null
	then
		echo 'NX protection enabled' >> ./$outputFile
	else
		echo 'WARNING!!' >> ./$outputFile
		echo 'MEMORY PROTECTION DOES NOT APPEAR TO BE ENABLED' >> ./$outputFile
		echo 'Please ensure your kernel supports Page Address Extension (PAE)' >> ./$outputFile
fi


#CHECK THAT ADDRESS SPACE LAYOUT RANDOMIZATION (ASLR) IS ENABLED 
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "ADDRESS SPACE LAYOUT RANDOMIZATOIN " >> ./$outputFile
echo "" >> ./$outputFile

if  sysctl kernel.randomize_va_space | grep 'kernel.randomize_va_space = 2' 1>/dev/null
	then
		echo 'Address space layout randomization is already enabled on this system' >> ./$outputFile
	else
		for file in $(ls /etc/sysctl.d);
		do
			echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/$file
			sysctl -w kernel.randomize_va_space=2 1>/dev/null
			echo "Address space layout randomization has been enabled" >> ./$outputFile
	done
fi


#ENSURE MANDATORY ACCESS CONTROL (SELINUX) IS ENABLED 
echo "" >> ./$outputFile
echo "MANDATORY ACCESS CONTROL (SELINUX)" >> ./$outputFile
echo "" >> ./$outputFile


#ENSURE SELINUX IS NOT DISABLED IN BOOTLOADER CONFIGURATION
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "ENSURE SELINUX IS NOT DISABLED IN BOOTLOADER CONFIGUREATION" >> ./$outputFile
echo "" >> ./$outputFile




if grep '^\s*linux\s*.*selinux=0' /boot/grub2/grub.cfg 1>/dev/null;

	then
		sed "/^GRUB_CMDLINE_LINUX/ s/selinux=0//g" -i /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
		echo "WARNING!!" >> ./$outputFile
		echo "SeLinux was disabled in the bootloader configuration!" >> ./$outputFile
		echo "It has been enabled but please check this as SeLinux is normally enabled by default" >> ./$outputFile
	else
		echo "SeLinux was not disabled in the bootloader configuration" >> ./$outputFile
fi

echo "" >> ./$outputFile


if  grep '^\s*SELINUX=enforcing\s*$' /etc/selinux/config 1>/dev/null  
	then
		echo "SELinux is enforced by default" >> ./$outputFile
	else
		sed 's/^\s*SELINUX=.*/SELINUX=enforcing/g' -i /etc/selinux/config
		echo "WARNING!!"
		echo "SELinux was not enforced by default" >> ./$outputFile
		
fi

echo "" >> ./$outputFile

if egrep -h '^\s*SELINUXTYPE=targeted\s*$|^\s*SELINUXTYPE=mls' /etc/selinux/config 1>/dev/null
	then
		echo "SELinux type is set to targeted or mls" >> ./$outputFile
	else
		sed 's/^\s*SELINUXTYPE=.*/SELINUXTYPE=targeted/g' -i /etc/selinux/config
		echo "WARNING!!" >> ./$outputFile
		echo "SELINUXTYPE was not correctly set" >> ./$outputFile
		echo "It has been set to targeting" >> ./$outputFile
		echo "Please check this as it should be set to targeting or mls by default" >> ./$outputFile
fi






echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "DETECT UNCONFINED DAEMONS" >> ./$outputFile
echo "" >> ./$outputFile


ucDaemons=$(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' '   | awk '{print $NF }')
if [ -z "$ucDaemons" ]
	then
		echo "No unconfined daemons" >> ./$outputFile
	else
		echo "WARNING!!" >> ./$outputFile
		echo "The following unconfined daemons are running!" >> ./$outputFile
		echo "Please analyze these daemons and, if necessary, assign a security context to them" >> ./$outputFile
		echo $ucDaemons >> ./$outputFile
fi
#echo $ucDaemons





echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "CHECK MOTD AND OTHER FILES WHICH MAY PROVIDE SYSTEM INFORMATION" >> ./$outputFile
echo "" >> ./$outputFile

#Rather than modify the original files this script copies new files to /etc/ssh and /etc and backs up the original files to ./backFiles

sshBackup=sshd_config.`date +%d-%m-%y:%H:%M:%S`
issueBackup=issue.net.`date +%d-%m-%y:%H:%M:%S`
motdBackup=motd.`date +%d-%m-%y:%H:%M:%S`
password_auth_acBackup=password-auth-ac.`date +%d-%m-%y:%H:%M:%S`
passwdBackup=passwd.`date +%d-%m-%y:%H:%M:%S`
login_defsBackup=login.defs.`date +%d-%m-%y:%H:%M:%S`
bashrcBackup=bashrc.`date +%d-%m-%y:%H:%M:%S`
profileBackup=profile.`date +%d-%m-%y:%H:%M:%S`
securettyBackup=securetty.`date +%d-%m-%y:%H:%M:%S`

mv /etc/ssh/sshd_config ./backupFiles/$sshBackup
mv /etc/issue.net ./backupFiles/$issueBackup
mv /etc/motd ./backupFiles/$motdBackup
mv /etc/pam.d/password-auth-ac ./backupFiles/$password_auth_acBackup
mv /etc/pam.d/passwd ./backupFiles/$passwdBackup
mv /etc/login.defs ./backupFiles/$login_defsBackup
mv /etc/bashrc ./backupFiles/$bashrcBackup
mv /etc/profile ./backupFiles/$profileBackup
mv /etc/securetty ./backupFiles/$securettyBackup
cp ./newFiles/sshd_config /etc/ssh
cp ./newFiles/issue.net /etc
cp ./newFiles/motd /etc
cp ./newFiles/password-auth-ac /etc/pam.d
cp ./newFiles/passwd /etc/pam.d
cp ./newFiles/login.defs /etc
cp ./newFiles/bashrc /etc
cp ./newFiles/securetty /etc
cp ./newFiles/profile /etc

chmod 644 /etc/profile
chmod 644 /etc/bashrc

echo "The files /etc/ssh/sshd_config, /etc/motd and /etc/issue.net have been replaced" >> ./$outputFile
echo "Please review the new files and ensure the settings are in accordance with site policy" >> ./$outputFile
#Change ownership to root and set permissions to 644 (should be the default anyway)

for file in /etc/motd /etc/issue /etc/issue.net /etc/pam.d/password-auth-ac
	do
		chown root:root $file
		chmod 644 $file
		echo "Ownership of $file set to root:root and permissions set to 644" >> ./$outputFile
		echo "" >> ./$outputFile

		if egrep '(\\v|\\r|\\m|\\s)' $file 1>/dev/null
			then
				echo "WARNING!!" >> ./$outputFile
				echo "The following file may provide information useful to intruders" >> ./$outputFile
				echo "Consider modifying this file in accordance with company policy" >> ./$outputFile
				echo "$file" >> ./$outputFile
			else
				echo "The following file does not appear to provide information useful to intruders" >> ./$outputFile
				echo "However, it may still be beneficial to review the file" >> ./$outputFile
				echo "$file" >> ./$outputFile
		fi
	done




echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "DISABLE INETD SERVICES" >> ./$outputFile
echo "" >> ./$outputFile

while read service
	do
		chkconfig $service off 2> /dev/null
		echo "$service disabled" >> ./$outputFile
	done < ./inputFiles/inetdServices

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "CHECK FOR UNNECESSARY SERVICES AND DISABLE THEM" >> ./$outputFile
echo "" >> ./$outputFile

while read service
do
	systemctl is-enabled $service 2>/dev/null |  grep 'enabled' &> /dev/null
	if [ $? == 0 ]
	then
		systemctl disable $service;
		echo "$service has been disabled" >> ./$outputFile
	else
		echo "$service is not enabled on this system" >> ./$outputFile
	fi
done < ./inputFiles/disableServices

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "CHECK FOR NECESSARY SERVICES AND ENABLE THEM" >> ./$outputFile
echo "" >> ./$outputFile

while read service
do
	systemctl is-enabled $service 2>/dev/null |  grep 'enabled' &> /dev/null
	if [ $? == 0 ]
	then
		systemctl enable $service;
		echo "$service has been enabled" >> ./$outputFile
	else
		echo "$service is enabled on this system" >> ./$outputFile
	fi
done < ./inputFiles/enableServices

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "REMOVE UNWANTED PACKAGES" >> ./$outputFile
echo "" >> ./$outputFile



echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "ENSURE MAIL TRANSFER AGENT IS CONFIGURED FOR LOCAL-ONLY MODE" >> ./$outputFile
echo "" >> ./$outputFile

netstat -an | grep LIST | grep ":25[[:space:]]"  &>/dev/null
if [ $? == 0 ]
	then
		cp /etc/postfix/main.cf ./backupFiles/main.cf.`date +%d-%m-%y:%H:%M:%S`
		sed -i 's/^inet_interfaces.*/inet_interfaces = loopback-only/g' /etc/postfix/main.cf
		systemctl restart postfix
		echo "MTA has been modified to run in local-only mode" >> ./$outputFile
	else
		echo "MTA is configured for local-only mode" >> ./$outputFile
fi

echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "NETWORK CONFIGURATION" >> ./$outputFile
echo "" >> ./$outputFile
echo "See the files ./network/ip4Enable and ./network/ip4Disable for details of network parameter settings" >> ./$outputFile
echo "" >> ./$outputFile

#Disable ip4 parameters

IFS=$'\n'
set -f
for i in $(cat < ./network/ip4Disable); 
	do 
		if (echo $i | xargs sysctl | grep "= 1" &>/dev/null)
			then
				echo echo "$i = 0" >> /etc/sysctl.conf
		
				for file in $(ls /etc/sysctl.d/ | grep -v 99-sysctl.conf)
				do
					echo "$ = 0" >> /etc/sysctl.d/$file
				done
				sysctl -w $i=0 &>/dev/null
				sysctl -w net.ipv4.route.flush=1 &>/dev/null	
		fi
	done 

#Enable ip4 parameters

IFS=$'\n'
set -f
for i in $(cat < ./network/ip4Enable); 
	do 
		if (echo $i | xargs sysctl | grep "= 0" &>/dev/null)
			then
				echo echo "$i = 1" >> /etc/sysctl.conf
		
				for file in $(ls /etc/sysctl.d/ | grep -v 99-sysctl.conf)
				do
					echo "$ = 1" >> /etc/sysctl.d/$file
				done
				sysctl -w $i=1 &>/dev/null
				sysctl -w net.ipv4.route.flush=1 &>/dev/null	
		fi
	done 

#Ip version 6 settings

#Check if ip 6 is enabled and, if so, ask if it should be disabled
#If the user chooses to keep it enabled then disabled parameters listed in ./network/ip6Disable


if test -f /proc/net/if_inet6; then
	while true; do
		read -p "Ip 6 is enabled on this system. Do you wish to disabled it (recommended)? Y/N"  yn
		case $yn in
			[Yy]* ) echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf; 
				sysctl -p &>/dev/null;
				chmod 700 /proc/net/if_inet6
				mv /proc/net/if_inet6 ./backupFiles;
				echo "Ip 6 has been disabled on this system" >> ./$outputFile;
				echo "" >> ./$outputFile;break;;
				
			[Nn]* ) echo "IP 6 has not been disabled on this system" >> ./$outputFile; 
				echo "Please consider disabling IP 6 at a later stage" >> ./$outputFile;
				echo "" >> ./$outputFile;
				IFS=$'\n';
				set -f;
				for i in $(cat < ./network/ip6Disable); 
					do 
						if (echo $i | xargs sysctl | grep "= 1" &>/dev/null)
							then
								echo echo "$i = 0" >> /etc/sysctl.conf
						
								for file in $(ls /etc/sysctl.d/ | grep -v 99-sysctl.conf)
								do
									echo "$ = 0" >> /etc/sysctl.d/$file
								done
								sysctl -w $i=0 &>/dev/null
								sysctl -w net.ipv6.route.flush=1 &>/dev/null	
						fi
					done 
		
						echo "Please see the file ./network/ip6Disable for details of network parameters diabled" >> ./$outputFile
						echo "" >> ./$outputFile; break;;
					*) echo "Please answer Y/y for yes or N/n for no"
		esac
			done
	
fi


echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Configure TCP Wrappers" >> ./$outputFile
echo "" >> ./$outputFile


#Configure TCP wrappers
while true; do
	read -p "Do you wish to configure tcp_wrappers for ssh now (recommended)? Y/N
Please answer Y/y for yes or N/n for no"  yn
	case $yn in
			[Yy]* ) 

			echo "Please enter subnets or individual ip addresses due to be granted access via ssh"
			echo "Subnets should be entered in the form of <subnet/subnetMask> separated by  commas"
			echo "Individal ip addresses should be entered in the form of <ipAddress> separated by commas"
			echo "WARNING! If you enter incorrect details you may lose remote access to your server!"
			echo "Please exercise caution when entering the relevant details"

			read -e ipDetails
			echo "sshd: "$ipDetails >> /etc/hosts.allow
			echo "The following ip addresses have been granted access via ssh to this system:" >> $outputFile
			echo $ipDetails >> ./$outputFile

			while true; do
				read -p "Do you wish to deny default access to all services protected by TCP Wrappers or just ssh?
Please type 1 for all services or 2 for only ssh" yn
				case $yn in
					[1]*) echo "ALL: ALL" >> /etc/hosts.deny
						echo "TCP Wrappers are protecing all relevant services on this system" >> $outputFile; break;;
					[2]*) echo "sshd: ALL" >> /etc/hosts.deny
						echo "Only ssh is protected by TCP Wrappers on this system" >> $outputFile; break;;
					*) 
				esac 
			done;

			break;;
		
				
			
			
		[Nn]* ) echo "TCP Wrappers not configured"
			echo "Please consider configuring TCP Wrappers at a later stage" ; break;;
		*) 
	esac
done


#Configure permissions for /etc/hosts.allow and /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

#Configure basic firewall rules
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Configure Basic Firewall Rules" >> ./$outputFile
echo "" >> ./$outputFile

#Flush IPTables rules
iptables -F

#Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#Ensure loopback tracfic is consigured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

#Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT 
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT 
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#Allow inbound ssh connections (assumes default port of 22 is being used)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

echo "Firewall rules have been configured in accordance with recommendations given in the CIS manual" >> ./$outputFile
echo "Please note these are basic rules and they may need further modifcation based on your organisation's policy" >> ./$outputFile
echo "" >> ./$outputFile

#Enable auditing for processes which start prior to auditd

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Auditing of processes which start prior to auditd" >> ./$outputFile

if  grep '^\s*audit=1\s*$' /boot/grub2/grub.cfg 1>/dev/null  
	then
		echo "Auditing for all processes is enforced by default" >> ./$outputFile
	else
		sed 's/GRUB_CMDLINE_LINUX="/&audit=1 /' -i /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
		echo "Auditing for all processes enabled" >> ./$outputFile
		
fi

#Add new auditing rules from newFiles/cis.rules
echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Add auditing rules from .newFiles/cis.rules" >> ./$outputFile

if [ -f /etc/audit/rules.d/cis.rules ]
then
	echo "The file /etc/audit/rules.d/cis.rules already exists" >> ./$outputFile
	cp /etc/audit/rules.d/cis.rules ./backupFiles/cis.rules.`date +%d-%m-%y:%H:%M:%S`.
	echo "This file has been backed up to ./backupFiles" >> ./$outputFile
	cp ./newFiles/cis.rules /etc/audit/rules.d/
else
	cp ./newFiles/cis.rules /etc/audit/rules.d/
	echo "/etc/audit/rules.d/cis.rules has been added to /etc/audit/rules.d" >> ./$outputFile
fi


echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Configure Logging" >> $outputFile

#First backup the rsyslog.conf
cp /etc/rsyslog.conf ./backupFiles/rsyslog.conf.`date +%d-%m-%y:%H:%M:%S`

#Now modify rsyslog.conf
cat ./inputFiles/rsyslogRules >> /etc/rsyslog.conf

#Reload rsyslogd configuration
pkill -HUP rsyslogd

#ensure permissions on files in /var/log are restrictive
find /var/log -type f -exec chmod g-wx,o-rwx {} +

echo "" >> $outputFile
echo "Loggging configured in accordance with recommendations in CIS manual" >> $outputFile
echo "New rules have been appended to /etc/rsyslog.conf" >> $outputFile
echo "Please review these configurations by inspecting this file" >> $outputFile

#Do not modify log rotation rules but advise that they be reviewed

echo "" >> $outputFile
echo "WARNING! This script does not modify log rotation policies" >> $outputFile
echo "Please review the /etc/logrotate.conf and /etc/logrotate.d/* and ensure log files are rotated in accordance with site policy" >> $outputFile

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Configure permissions on important files" >> $outputFile

while read file;
do
	chown root:root $file
	chmod og-rwx $file
	echo "Access to $file restricted to root" >> $outputFile
done < ./inputFiles/filePermissions

echo "" >> $outputFile
echo "Ownership of all Cron files set to root" >> $outputFile
echo "Permissions on all Cron files restricted to root" >> $outputFile

#Restrict access to at/Cron

if [ -f /etc/cron.deny ]
then
	rm /etc/cron.deny
fi

if [ -f /etc/at.deny ]
then
	rm /etc/at.deny
fi

touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

echo "Access to at/Cron restricted to root" >> $outputFile

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "SSH Configuration" >> ./$outputFile



#Limit ssh access to specific accounts
while true; do
	read -p "Do you wish to restrict ssh access to specific accounts (recommended)? Y/N
Please answer Y/y for yes or N/n for no"  yn
	case $yn in
			[Yy]* ) 

			echo "Please enter username(s)"
			echo "If entering more than one user please separate usernames with a space"
			echo "Please exercise caution when entering the relevant details"

			read -e userName
			echo "AllowUsers "$userName>> /etc/ssh/sshd_config
			echo "The following users have been granted access to this system via ssh" >> $outputFile
			echo $userName >> ./$outputFile ; break;;

			
		[Nn]* ) echo "Access via ssh not restricted to specific users"
			echo "Please consider restricting ssh access" ; break;;
		*) 
	esac
done

echo "This script sets a basic Banner warning via /etc/issue.net" >> ./$outputFile
echo "Please consider setting a more detailed warning in accordance with site policies" >> ./$outputFile

#Now restart sshd
systemctl restart sshd

#Set default inactive password lock to 30 days

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Set default inactive account lock" >> ./$outputFile

useradd -D -f 30
 
echo "" >> $outputFile
echo "Default inactive account lock has been set to 30 days" >> ./$outputFile
echo "" >> $outputFile

#Run authconfig
authconfig --update

echo "Authconfig has been run to update authentication settings" >> ./$outputFile
echo "" >> ./$outputFile


echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Set system accounts to non-login" >> ./$outputFile
echo "" >> ./$outputFile

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd` ; do
	if [ $user != "root" ]; then
		usermod -L $user &> /dev/null
		if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ];
	then
		usermod -s /sbin/nologin $user &> /dev/null
		fi
	fi
done

echo "Environment set to /sbin/nologin for system accounts" >> ./$outputFile

echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Set GID for root to 0" >> ./$outputFile
echo "" >> ./$outputFile

usermod -g 0 root
 
echo "GID set to 0 for root accout" >> ./$outputFile

echo "" >> ./$outputFile
echo "The following defaults have been set" >> ./$outputFile
echo "umask:	027" >> ./$outputFile
echo "Inactivity timeout:	30 minutes" >> ./$outputFile
echo "Root login restricted to console and tty1 - tty10" >> ./$outputFile

echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Restrict access to the su command" >> ./$outputFile
echo "" >> ./$outputFile

#First backup /etc/group and then add root and at least one normal user to the wheel group
cp /etc/group ./backupFiles/group.`date +%d-%m-%y:%H:%M:%S`

#Check to see if root and at least one other user have already been added to the wheel group
#If they have do nothing otherwise add root and at least one normal user to wheel

if grep '^wheel.*root,.*' /etc/group
	then
		echo "Root and at least one other user already added to the wheel group" >> ./$outputFile
	else
		echo "Please enter at least one normal user to be added to the wheel group"
		read -e wheelUser
		echo $wheelUser
		sed -i "s/^wheel.*/&root,$wheelUser/" /etc/group
		echo "Root and $wheelUser have been added to the wheel group" >> ./$outputFile
fi


#Next enforce access to su via the wheel group by modifying /etc/pam.d/su

if grep '^auth.*required.*pam_wheel.so.*use_uid$' /etc/pam.d/su
	then	
		echo "Requirement for wheel membership to access su command is already in force" >> ./$outputFile
	else 
		echo "auth	required	pam_wheel.so use_uid" >> /etc/pam.d/su
		echo "Requirement of wheel membership to access su command has been enforced on this computer" >> ./$outputFile
fi

#Set permissions on important files (should be the default)
chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod 000 /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/shadow-
chmod 000 /etc/shadow-
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
chown root:root /etc/gshadow-
chmod 000 /etc/gshadow-

echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Set permissons on group and password files" >> ./$outputFile
echo"" >> ./$outputFile
echo "Correct permissions set on all passwd, shadow and group files (including backup files)" >> ./$outputFile

#Check for world writable, ungrouped or unowned files and directories
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Restrict access to the su command" >> ./$outputFile
echo "" >> ./$outputFile

echo "Check for world writable files" >> ./$outputFile
touch inputFiles/localPartitions
df --local -P | awk {'if (NR!=1) print $6'} > inputFiles/localPartitions

	while read partition;
	do 
	if [[ $(find $partition -xdev -type f -perm -0002) ]]; then
		echo "WARNING! The following world writable file(s) found in $partition!" >> ./$outputFile
		find $partition -xdev -type f -perm -0002 >> ./$outputFile
	else
		echo "No world writable files found in $partition" >> ./$outputFile	
	fi
	done <./inputFiles/localPartitions

echo "" >> ./$outputFile

echo "Check for unowned files" >> ./$outputFile
	while read partition;
	do 
	if [[ $(find $partition -xdev -nouser) ]]; then
		echo "WARNING! The following unowned file(s) found in $partition!" >> ./$outputFile
		find $partition -xdev -nouser >> ./$outputFile
	else
		echo "No unowned files found in $partition" >> ./$outputFile	
	fi
	done <./inputFiles/localPartitions

echo "" >> ./$outputFile

echo "Check for ungrouped files" >> ./$outputFile

	while read partition;
	do 
	if [[ $(find $partition -xdev -nogroup) ]]; then
		echo "WARNING! The following ungrouped file(s) found in $partition!" >> ./$outputFile
		find $partition -xdev -nouser >> ./$outputFile
	else
		echo "No ungrouped files found in $partition" >> ./$outputFile	
	fi
	done <./inputFiles/localPartitions

echo "" >> ./$outputFile

echo "Check for suid executables" >> ./$outputFile

	while read partition;
	do 
	if [[ $(find $partition -xdev -type f -perm -4000) ]]; then
		echo "WARNING! The following suid executable(s) found in $partition!" >> ./$outputFile
		find $partition -xdev -type f -perm -4000 >> ./$outputFile
	else
		echo "No suid executables found in $partition" >> ./$outputFile	
	fi
	done <./inputFiles/localPartitions

echo "" >> ./$outputFile

echo "Check for guid executables" >> ./$outputFile

	while read partition;
	do 
	if [[ $(find $partition -xdev -type f -perm -2000) ]]; then
		echo "WARNING! The following world sgid executable(s) found in $partition!" >> ./$outputFile
		find $partition -xdev -type f -perm -2000 >> ./$outputFile
	else
		echo "No sgid executables found in $partition" >> ./$outputFile	
	fi
	done <./inputFiles/localPartitions


#Check for user accounts with blank passwords
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check for empty passwords" >> ./$outputFile
echo "" >> ./$outputFile

if [[ $( cat /etc/shadow | awk -F: '($2 == "") { print $1}' ) ]]
	then
		cat /etc/shadow | awk -F: '($2 == "") { print "Warning! " $1 "does not have a password"}' >> ./$outputFile
	else
		echo "No empty passwords found" >> ./$outputFile
fi


#Check for legacy + entries 
echo "" >> ./$outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check for legacy + entries" >> ./$outputFile
echo "" >> ./$outputFile

for file in /etc/passwd /etc/shadow /etc/group
	do
		if [[ $(grep '^\+:' $file) ]]; then
			echo "Warning! One or more legacy + entries found in $file" >> ./$outputFile
			echo "Please review this $file and delete any unnecessary legacy + entries" >> ./$outputFile
			echo "" >> ./$outputFile
		else
			echo "No legacy + entries found in $file" >> ./$outputFile
		fi
	done


echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check for non root accounts with UID 0" >> ./$outputFile
echo "" >> ./$outputFile

if (cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -v root &> /dev/null)
	then
		echo "Warning! The non root user(s) below have UID 0" >> ./$outputFile
		echo $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -v root) >> ./$outputFile
	else
		echo "Only root has UID 0" >> ./$outputFile
fi

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check root PATH variable" >> ./$outputFile
echo "" >> ./$outputFile

echo "Please ensure there are no relative paths or world writable directories in the root PATH variable (printed below)" >> ./$outputFile

IFS=: read -r -d '' -a pathArray < <(printf '%s:\0' "$PATH")
for ((i = 0; i<${#pathArray[@]};++i))
	do
		echo ${pathArray[i]} >> ./$outputFile
	done


echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check that all groups in /etc/passwd exist in /etc/group" >> ./$outputFile
echo "" ./$outputFile

if [[ $(comm -23 <(awk -F: '{print $4}' /etc/passwd | sort -u) <(awk -F: '{print $3}' /etc/group | sort -u)) ]]
then
	group="$(echo  `comm -23 <(awk -F: '{print $4}' /etc/passwd | sort -u) <(awk -F: '{print $3}' /etc/group | sort -u)` )"
	echo "Warning! $group exists in /etc/passwd but not in /etc/group" >> ./$outputFile
else
	echo "All groups in /etc/passwd exist in /etc/group" >> ./$outputFile
fi 


echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "Check for duplicate usernames, groupnames, UIDs and GIDs" >> ./$outputFile
echo "" >> ./$outputFile

if [[ $(cut -d: -f3 /etc/passwd | sort | uniq -d) ]]
	then
	cut -d: -f3 /etc/passwd | sort | uniq -d|
	while read -r uid 
	do
		echo "Warning! The following users have duplicate UID values" >> ./$outputFile
		awk -F: -vu="$uid" '$3 == u { print $1, $3}' /etc/passwd >> ./$outputFile
		echo "" >> ./$outputFile
	done
	else
		echo "No duplicate UID values found" >> ./$outputFile
		echo "" >> ./$outputFile
fi

if [[ $(cat /etc/passwd | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f4 | sort | uniq -d) ]]
	then
	cat /etc/passwd | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f4 | sort | uniq -d|
	while read -r group
	do
		echo "Warning! The following users have duplicate GID values" >> ./$outputFile
		awk -F: -vu="$group" '$4 == u { print $1, $4}' /etc/passwd >> ./$outputFile
		echo "" >> ./$outputFile
	done
	else
		echo "No duplicate GID values found" >> ./$outputFile
		echo "" >> ./$outputFile
fi


if [[ $(cat /etc/passwd | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f1 | sort | uniq -d) ]]
	then
	cat /etc/passwd | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f1 | sort | uniq -d|
	while read -r user
	do
		echo "Warning! The following users have duplicate usernames" >> ./$outputFile
		awk -F: -vu="$user" '$1 == u { print $1}' /etc/passwd >> ./$outputFile
		echo "" >> ./$outputFile
	done
	else
		echo "No duplicate usernames found" >> ./$outputFile
		echo "" >> ./$outputFile
fi

if [[ $(cat /etc/group | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f1 | sort | uniq -d) ]]
	then
	cat /etc/group | egrep -v '^(root|sync|halt|shutdown)' | cut -d: -f1 | sort | uniq -d|
	while read -r group
	do
		echo "Warning! The following groups have duplicate groupnames" >> ./outputFile
		awk -F: -vu="$group" '$1 == u { print $1}' /etc/group >> ./outputFile
		echo "" >> ./outputFile
	done
	else
		echo "No duplicate groupnames found" >> ./$outputFile
		echo "" >> ./$outputFile
fi




#./directories.sh

echo "" >> $outputFile
echo "################################################################################################" >> ./$outputFile
echo "FURTHER WORK TO BE CARRIED OUT" >> ./$outputFile
echo "This script does not configure time synchronisation on the system" >> ./$outputFile
echo "This script does not check for active wireless interfaces" >> ./$outputFile
echo "Please consider manually checking that all user accounts password change dates are in the past" >> ./$outputFile
echo "If this server contains active wireless interfaces please consider disabling them" >> ./$outputFile
echo "Please consider installing/configuring ntp and chrony see section 2.2.1 of CIS manual" >> ./$outputFile
echo "Please consider installing an intrusion detection system such as AIDE" >> ./$outputFile
echo "" >> $outputFile



#To do
#Configure automatic updates
#Create a single text file for any files that need to be backed up and back them up in a single go
#Configure a single file to iterate through settings recommended in chapter 3 that have similar command line structure
#Do I need to check for install of selinux?? (page 87)
#Put all files which need permissions and ownership changes into a single text file and iterate through them

