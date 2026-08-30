#!/bin/bash
set -e
set -o pipefail
set -u

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m"  # No Color

source ./environ

info(){
  echo -e "✅ [INFO] $1\n"
}

warn(){
  echo -e "⚠️ [WARN] $1\n"
}

fatal(){
  echo -e "❌ ERROR] $1\n"
  exit 1
}

checkBinary(){
  local listOfBins=$1
  for cmd in $listOfBins; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      fatal "$cmd is missing"
    else
      info "$cmd is installed"
    fi
  done
}

destroy(){
  info "🖥️ Decommisioning VMs..."
  count=1
  until [ $count -gt $NODE_COUNT ]
  do  
    if $MULTIPASS_BIN list | awk '{print $1}' | grep -x "$NODE_PREFIX$count"; then
        info "$NODE_PREFIX$count found..."
        if [[ "$($MULTIPASS_BIN list | awk '$1 == "'$NODE_PREFIX$count'" {print $2}')" == "Stopped" ]]; then
            warn "⚡️ $NODE_PREFIX$count is Stopped. Deleting VM..."
            $MULTIPASS_BIN delete "$NODE_PREFIX$count"
            ((count=count+1))
            continue
        fi
        $MULTIPASS_BIN stop "$NODE_PREFIX$count"
        $MULTIPASS_BIN delete "$NODE_PREFIX$count"
        ((count=count+1))
    fi
  done

  info "🖥️ VM list..."
  $MULTIPASS_BIN purge
  $MULTIPASS_BIN list
}

checkBinary multipass
destroy

# STOP ALL: multipass stop --all
# RESTART Multipass: sudo launchctl kickstart -k system/com.canonical.multipassd
# For Empty file mounts, make sure to allow FullDisk access to multipass and multipassd