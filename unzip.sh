#!/bin/bash
cd "$(dirname "$0")"
unzip -o pentest-notes.zip
rm pentest-notes.zip
git add -A
git commit -m "Extract pentest-notes.zip contents to root" || true
git push
