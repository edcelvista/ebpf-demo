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

provision(){
  info "🖥️ Provisioning VMs..."
  count=1
  until [ $count -gt $NODE_COUNT ]
  do  
    if $MULTIPASS_BIN list | awk '{print $1}' | grep -x "$NODE_PREFIX$count"; then
      warn "$NODE_PREFIX$count already exists... ignoring.."
        if [[ "$($MULTIPASS_BIN list | awk '$1 == "'$NODE_PREFIX$count'" {print $2}')" == "Stopped" ]]; then
          warn "⚡️ $NODE_PREFIX$count is Stopped. Starting VM..."
          $MULTIPASS_BIN start "$NODE_PREFIX$count"
        fi
      ((count=count+1))
      continue
    fi
    $MULTIPASS_BIN launch $UBUNTU_REL -n "$NODE_PREFIX$count" -c $CPU -m $MEM -d $DISK --cloud-init $CLOUD_INIT --network $NETWORKINTERFACE
    info "Mounting host path $PROJECT_HOME to /mnt/workspace"
    $MULTIPASS_BIN mount $PROJECT_HOME "$NODE_PREFIX$count":/mnt/workspace --uid-map $(id -u):1000
    
    info "Access the VM: multipass shell $NODE_PREFIX$count"
    ((count=count+1))
  done

  info "🖥️ VM list..."
  $MULTIPASS_BIN list
}

checkBinary multipass
provision
