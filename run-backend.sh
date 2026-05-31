#!/bin/bash
echo "╔══════════════════════════════╗"
echo "║  VaultSentry — Java Backend  ║"
echo "╚══════════════════════════════╝"
cd "$(dirname "$0")/backend"
mkdir -p out
find src -name "*.java" > sources.txt
javac -d out @sources.txt
if [ $? -ne 0 ]; then echo "❌ Compilation failed."; exit 1; fi
echo "✅ Compiled. Starting server on http://localhost:8080"
java -cp out com.vaultsentry.Main
