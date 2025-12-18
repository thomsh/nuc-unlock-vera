#!/usr/bin/env bash
# Simple integration test
set -eEuo pipefail
exit_code=1 # bad by default
srvpid=""
output=$(mktemp)
function exit_trap {
    rm -f -- "$output"
    kill "$srvpid"
    echo cleaned
    exit $exit_code
}
trap exit_trap EXIT ERR
pushd tests
./start-python-server.sh &
srvpid=$!
popd
sleep 0.1
echo "📝 test1: run unlock mode"
go run main.go -m unlock -r 2>&1 |tee "$output"
# Check output
if ! grep -Fq 'word 1 word 2 word 3' "$output"; then
    echo "failed ❌ partial payload content not found, should be outputed by the executed cmd"
    exit 1
fi
if ! grep -Fq 'NUC unlocked' "$output"; then
    echo "failed ❌ expected sucess msg not found"
    exit 1
fi
echo "Test for mode unlock passed ✅"

echo "📝 test2: encrypt mode"
go run main.go -m encrypt -p "UT0EVP😆xStu3q" -d "0BGG7zyFqhauu42tESRMtlBt92C1tYaF"  2>&1 |tee "$output"
ciphertext=$(grep -A 1 -F -- '----COPY FROM HERE----' "$output" |tail -n 1)

echo "📝 test3: decrypt mode"
go run main.go -m decrypt -p "UT0EVP😆xStu3q" -d "$ciphertext"  2>&1 |tee "$output"
if ! grep -Fq '0BGG7zyFqhauu42tESRMtlBt92C1tYaF' "$output"; then
    echo "failed ❌ expected decrypted text not found"
    exit 1
fi

echo "📝 test4: decrypt mode with empty password"
if go run main.go -m decrypt -p "" -d "$ciphertext"; then
    echo "failed ❌ expected error when password is empty"
    exit 1
fi
echo "Test for mode encrypt & decrypt passed ✅"

echo "🏁 all done"
exit_code=0