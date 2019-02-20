#cisBenchmark
Script to implement recommendations of CIS CentOS Linux 7 Benchmark Guide by Tom O'Flynn:

This script automates the recommendations of the CIS CentOS Linux 7 Benchmark PDF (see https://www.cisecurity.org/benchmark/centos_linux/). It is designed to be run on a fresh minimal install.

While this script should work on any RedHat variant (and possibly other Linux releases with basic modifications) it has only been tested on a minimum install of CentOS 7 (CentOS release 7.6.1810 (Core)) with the following separate partitions:

/tmp

/var

/var/tmp

/var/log

/var/log/audit

/home

The author makes no claims to originality as most of the settings are directly taken from the above mentioned guide. Furthermore, much of the bash code has been written after consultation with online sources (particularly https://stackoverflow.com). Finally, similar scripts are no doubt available elsewhere so anyone interested in this work is encouraged to investigate other options. The author created this script because he felt more comfortable working with code of his own creation. In the event of there being a programming error it can be easier to troubleshoot code you have written yourself than somebody else's work.

In order to run this script download all files and folders to a suitable location and run cis.sh as root. Most of the changes to the host system require no user input. However, the user is prompted for input in the cases listed below:

The script checks for a secure user.cfg file in /boot or subdirectories therein. If it is not found the user is asked if grub should be password protected?

The user is asked if ip version 6 should be disabled? 

The user is asked if tcp wrappers should be configured?

If the above questioned is answered in the affirmative the user is then asked if tcp wrappers should only protect ssh or all services provided via TCP?

This user is asked if ssh access should be restricted to specific accounts? If answered yes the user is prompted for at least one username to which ssh access should be granted

Access to su is restricted using wheel. The script then checks to see if at least one normal user has been added to the wheel group. If not it prompts for a username to add

There are a number of folders containing files which are consulted by the code. These will be tidied up in future but at present they consist of the following folders:

1. backupFiles - before any system files are modified they are backed up to this folder. Files are labelled originalName.<date/time> where <date/time> takes the form of dd-mm-yy:hour:minute:second and represents the time at which the script was run. 
2. inputFiles - this folder contains files which are read by the code when running commands. For example the yumInstall/yumRemove files list packages to be installed or removed by the yum command. These files can be modified in advance of running the code. The one exception to this is the file named localPartitions which is created by the code and subsequently used for input. As this file is created as the code runs it obviously cannot be prepared in advance.
3. network - this folder contains files which list ip settings (versions 4 and 6) which are enabled/disabled by the code. These files can be modified in advance of running the code.
4. newFiles - when this script was originally written system files were directly altered by the code. At a later stage the author felt it would be better to prepare some files in advance and overwrite the originals. This folder contains those files. As mentioned in point 1 above all original files can be found in the backupFiles folder with a date and time stamp appended to their names. 
5. outputFiles - as the code runs information about modifications made are saved to a file in this folder. The filename is info.<date/time> where <date/time> takes the same format as given in point 1 above. It is envisaged that other outputFiles will be produced by future versions of the code (see "Future Work" below).

Future Work:
1. At present standard error and most of standard out are redirected to /dev/null. Upon reflection this has been deemed a bad decision so future releases will redirect them to separate log files to be saved in the outputFiles folder
2. The script was written in the author's limited spare time over an extended period of time. This has resulted in an inconsistent style. For example in some cases system files are modified directly while in others they are simply overwritten. At some stage when time permits the author intends to rewrite the script in a more consistent style (see point 5 below).
3. At present the code only implements recommendations of the CIS Benchmark PDF. This is obviously not the sole source of information so it may be good practice to mine other sources for security recommendations.
4. At present there are a number of settings not automated by the code. These will hopefully be included in furture. The info.<date/time> file saved in outputFiles contains information about these settings but they are reproduced here:
(a) Automatic updates are not configured and need to be set up manually
(b) Time synchronisation is not configured and needs to be set up manually
(c) The script does not check that password change dates are in the past
(d) Wireless interfaces are not inspected
(e) Neither ntp nor chrony are installed
5. The author is considering a project to re-write the code using python

