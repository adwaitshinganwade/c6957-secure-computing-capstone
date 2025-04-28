#!/bin/bash

# Create file to save auditd logs
touch auditd-logs/logs
echo "Created auditd-logs/logs to save live auditd logs"  

echo "Creating directories to simulate safe and unsafe locations." 

# Create the necessary folders and files 
mkdir -p $HOME/safe-location
echo "The directory ${HOME}/safe-location has been created / aready exists."

mkdir -p $HOME/unsafe-location

echo "Creating test files for the demo"
echo "The directory ${HOME}/unsafe-location has been created / aready exists."

cd $HOME/safe-location
for command in cp dd fork_test mv rsync
do
    touch "${command}_source_file"
    echo "The contents of this file are secret. This file should not be transferred to an unsafe location" >> "${command}_source_file"
done



# Set up auditd rules
echo "Setting up auditd rules"

sudo auditctl -a always,exit -F arch=b64 -S openat -F dir=/home/cs4440/safe-location -F perm=rw -k exfil-final-demo
sudo auditctl -a always,exit -F arch=b64 -S openat -F dir=/home/cs4440/unsafe-location -F perm=rw -k exfil-final-demo
sudo auditctl -a always,exit -F arch=b64 -S clone,execve,fork,vfork -k exfil-final-demo