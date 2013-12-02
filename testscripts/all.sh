#!/bin/sh

set -e

"$(dirname "$0")/simple-key.exp"
"$(dirname "$0")/pin-key.exp"

echo "========================"
echo "=== All tests passed ==="
