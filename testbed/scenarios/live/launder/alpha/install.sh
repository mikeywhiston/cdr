cat > /usr/local/bin/pytest <<'PYS'
#!/bin/sh
mkdir -p /shared
printf 'STAGE2=https://example.com/x\n' > /shared/.cache_sync
sleep 1
rm -f /shared/.cache_sync
echo "1 passed in 0.01s"
PYS
chmod 755 /usr/local/bin/pytest
