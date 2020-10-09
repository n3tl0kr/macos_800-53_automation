#!/bin/zsh

################################################################################
## Description: Check for and apply documented suggestions
## Audit Type: Smartcard Authentication
## Author: Paul Goffar (@n3tl0kr)
## OS Compat: macOS 10.14.x Catalina
################################################################################

echo "Beginning CCE Audit for Smartcard Authentication"

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

# Logic for Audit vs. Enforce
if [ $1 = '--audit' ]; then
  MODE=audit
elif [ $1 = '--enforce' ]; then
  MODE=enforce
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
    LOG="$LOGDIR$(date +'%Y%m%d')_smartcard.log" #CHANGE THIS
    echo "$(hostname):$TIMESTAMP -> $data" | tee $LOG
  done
}
################################################################################
echo "!!!!!!!!BEGINNING WORK!!!!!!!!!!" | loggy
echo "MODE: $MODE" | loggy
echo "Hostname: $(hostname)" | loggy
echo "OS Name: $(sw_vers -productName)" | loggy
echo "OS Version: $(sw_vers -productVersion)" | loggy
echo "OS Build: $(sw_vers -buildVersion)" | loggy
echo "#########################################################################"

################################################################################

RULE="CCE-84721-0 auth_pam_login_smartcard_enforce"
# Description: Enforce Multifactor Authentication for Login

# Rule Logic
if [[ $(/usr/bin/grep -Ecq '^(auth\s+sufficient\s+pam_smartcard.so\|auth\s+required\s+pam_deny.so)' /etc/pam.d/login) != 2 ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END

/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login
  fi
fi

###### ##### #####

RULE="CCE-84723-6 auth_pam_sudo_smartcard_enforce"
# Description: Enforce Multifactor Authentication for Privilege Escalation Through the sudo Command

# Rule Logic
if [[ $(/usr/bin/grep -Ecq  '^(auth\s+sufficient\s+pam_smartcard.so\|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo) != 2 ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/cat > /etc/pam.d/sudo << SUDO_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so
SUDO_END

/bin/chmod 444 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo
  fi
fi

###### ##### #####

RULE="CCE-84729-3 auth_ssh_smartcard_enforce"
# Description: Enforce Smartcard Authentication for SSH

# Rule Logic
if [[ $(/usr/bin/grep -Ecq '^(PasswordAuthentication\s+no\|ChallengeResponseAuthentication\s+no)' /etc/ssh/sshd_config) != 2 ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /usr/bin/sed -i.bak_$(date "+%Y-%m-%d_%H:%M") "s\|#PasswordAuthentication yes\|PasswordAuthentication no\|; s\|#ChallengeResponseAuthentication yes\|ChallengeResponseAuthentication no\|" /etc/ssh/sshd_config; /bin/launchctl kickstart -k system/com.openssh.sshd
  fi
fi

###### ##### #####

RULE="CCE-84722-8 auth_pam_su_smartcard_enforce"
# Description: Enforce Multifactor Authentication for the su Command

# Rule Logic
if [[ $(/usr/bin/grep -Ecq '^(auth\s+sufficient\s+pam_smartcard.so\|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su) != 2 ]]; then
  echo "$RULE: NOT COMPLIANT" | loggy
  if [[ $mode == enforce ]]; then
    echo "Enforcing $RULE" | loggy
    /bin/cat > /etc/pam.d/su << SU_END
# su: auth account password session
auth        sufficient    pam_smartcard.so
auth        required      pam_rootok.so
auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account     required      pam_permit.so
account     required      pam_opendirectory.so no_check_shell
password    required      pam_opendirectory.so
session     required      pam_launchd.so
SU_END

    # Fix new file ownership and permissions
    /bin/chmod 644 /etc/pam.d/su
    /usr/sbin/chown root:wheel /etc/pam.d/su
  fi
fi

echo "Audit Complete, please see $LOG for details" | loggy














