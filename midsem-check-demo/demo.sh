# Create test directories
SAFE_LOCATION=$HOME/safe-location
mkdir -p $SAFE_LOCATION
touch $SAFE_LOCATION/secret
echo "The contents of this file are top secret and should not leave $SAFE_LOCATION" > $SAFE_LOCATION/secret

UNSAFE_LOCATION=$HOME/unsafe-location
mkdir -p $UNSAFE_LOCATION

# Configure auditd rules
sudo auditctl -a always,exit -S openat -F dir=$SAFE_LOCATION -F perm=rw -k exfil-demo
sudo auditctl -a always,exit -S openat -F dir=$UNSAFE_LOCATION -F perm=rw -k exfil-demo
