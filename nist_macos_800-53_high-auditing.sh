#!/bin/zsh

################################################################################
## Description: Check for and apply documented suggestions
## Audit Type: Audit Compliance
## Author: Paul Goffar (@n3tl0kr)
## OS Compat: macOS 10.14.x Catalina
################################################################################

echo "Beginning CCE Audit for Audit Compliance"

# root
if [[ $EUID != 0 ]]; then # Check for sudo
    echo "This utility must be ran with elevated privilege.  Please retry"
    exit 2
fi
# Check for Args and give help
program_name=$0

function usage {
    echo "Usage: $program_name [--audit] [--enforce]"
    echo "  Audit - Items will be checked and logged only."
    echo "  Enforce - Items will be checked and forced to compliance.  Must be ROOT!"
    echo "  Example: $program_name --audit or $program_name --enforce"
    exit 1
}

if [ $# = 0 ]; then
 usage
fi

### Script Work ###
## Configure Logging

LOGDIR=/tmp/cce_audit_logs/ #CHANGE THIS

if [[ -d $LOGDIR ]]; then
  echo "$LOGDIR found, continuing..."
else
  mkdir -p $LOGDIR
  echo "$LOGDIR created, continuing..."
fi

function loggy(){
   while read data; do
    TIMESTAMP=$(date '+%d/%m/%Y %H:%M:%S')
    LOG="$LOGDIR$(date +'%Y%m%d')_auditing.log" #CHANGE THIS
    echo "$(hostname):$TIMESTAMP -> $data" | tee $LOG
  done
}

# Logic for Audit vs. Enforce
if [ $1 = '--audit' ]; then
  MODE=audit
elif [ $1 = '--enforce' ]; then
  MODE=enforce
fi

################################################################################
echo "!!!!!!!!BEGINNING WORK!!!!!!!!!!" | loggy
echo "Audit: Audit Compliance" | loggy
echo "MODE: $MODE" | loggy
echo "Hostname: $(hostname)" | loggy
echo "OS Name: $(sw_vers -productName)" | loggy
echo "OS Version: $(sw_vers -productVersion)" | loggy
echo "OS Build: $(sw_vers -buildVersion)" | loggy
echo "#########################################################################"

################################################################################

RULE="CCE-84717-8 audit_folder_group_configure"
# Description: Configure Audit Log Folders Group to Wheel

# Rule Logic
if [[ $(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}') -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/sbin/chgrp wheel $(/usr/bin/awk -F : '/^dir/{print $2}' /etc/security/audit_control)
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84708-7 audit_failure_halt"
# Description: Configure System to Shut Down Upon Audit Failure

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^policy.*ahlt" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84704-6 audit_acls_folders_configure"
# Description: Configure Audit Log Folder to Not Contain Access Control Lists

# Rule Logic
if [[ $(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":") -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84715-2 audit_flags_fm_configure"
# Description: Configure System to Audit All Change of Object Attributes

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*fm" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,fm/' /etc/security/audit_control;/usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84706-1 audit_auditd_enabled"
# Description: Enable Security Auditing

# Rule Logic
if [[ $(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84712-9 audit_flags_ad_configure"
# Description: Configure System to Audit All Administrative Action Events

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*ad" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84913-3 audit_flags_ex_configure"
# Description: Configure System to Audit All Failed Program Execution on the System

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*-ex" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,-ex/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84702-0 audit_files_mode_configure"
# Description: Configure Audit Log Files to Mode 440 or Less Permissive

# Rule Logic
if [[ $(/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' ') -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/chmod 440 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84711-1 audit_flags_aa_configure"
# Description: Configure System to Audit All Authorization and Authentication Events

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*aa" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84710-3 audit_files_owner_configure"
# Description: Configure Audit Log Files to be Owned by Root

# Rule Logic
if [[ $(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}') -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/sbin/chown -R root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84719-4 audit_retention_configure"
# Description: Configure Audit Retention to a Minimum of Seven Days

# Rule Logic
if [[ $(/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control) != "7d" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak 's/^expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84713-7 audit_flags_fr_configure"
# Description: Configure System to Audit All Failed Read Actions on the System

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*-fr" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,-fr/' /etc/security/audit_control;/usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84720-2 audit_settings_failure_notify"
# Description: Configure Audit Failure Notification

# Rule Logic
if [[ $(/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84718-6 audit_folder_owner_configure"
# Description: Configure Audit Log Folders to be Owned by Root

# Rule Logic
if [[ $(/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}') -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/sbin/chown root $(/usr/bin/awk -F : '/^dir/{print $2}' /etc/security/audit_control)
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84716-0 audit_flags_lo_configure"
# Description: Configure System to Audit All Log In and Log Out Events

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags*.lo" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84714-5 audit_flags_fw_configure"
# Description: Configure System to Audit All Failed Write Actions on the System

# Rule Logic
if [[ $(/usr/bin/grep -Ec "^flags.*-fw" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak '/^flags/ s/$/,-fw/' /etc/security/audit_control;/usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84705-3 audit_folders_mode_configure"
# Description: Configure Audit Log Folders to Mode 700 or Less Permissive

# Rule Logic
if [[ $(/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')) -ne "700" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/chmod 700 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84707-9 audit_configure_capacity_notify"
# Description: Configure Audit Capacity Warning

# Rule Logic
if [[ $(/usr/bin/grep -c "^minfree:25" /etc/security/audit_control) -ne "1" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84709-5 audit_files_group_configure"
# Description: Configure Audit Log Files Group to Wheel

# Rule Logic
if [[ $(/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}') -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/chgrp -R wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

RULE="CCE-84701-2 audit_acls_files_configure"
# Description: Configure Audit Log Files to Not Contain Access Control Lists

# Rule Logic
if [[ $(/bin/ls -le $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control) | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":") -ne "0" ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $MODE == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/chmod -RN $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control)
  fi
else
  echo "$RULE: COMPLIANT" | loggy
fi

###### ##### #####

echo "Audit Complete, please see $LOG for details" | loggy














