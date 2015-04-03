#!/usr/bin/env bash

set -x

#
# Update the database
#
if [ ! -d "data" ]; then
  git clone https://github.com/vulndb/data.git
fi

cd data
git pull
cd ..

cp -rf data/db/*.json vulndb/db/
git add vulndb/db/

# Bump the version numbers
tools/semver.sh bump patch

cd data
git rev-parse HEAD > ../vulndb/db-version.txt
cd ..

# Push to repo
git commit vulndb/db/ vulndb/version.txt vulndb/db-version.txt -m 'Updated vulnerability database'
git push