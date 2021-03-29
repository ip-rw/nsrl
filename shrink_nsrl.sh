#!/bin/sh

# copyright: (c) 2014 by Josh "blacktop" Maine.
# license: MIT

set -ex

RDS_URL=https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
RDS_SHA_URL=https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip.sha

if ls ./db/*.zip 1> /dev/null 2>&1; then
   echo "File '.zip' Exists."
else
    echo "[INFO] Downloading NSRL Reduced Sets..."
    wget --progress=bar:force -P ./db $RDS_URL
    wget --progress=bar:force -P ./db $RDS_SHA_URL
    echo " * files downloaded"
    ls -lah ./db
    RDS_SHA1=$(cat /nsrl/rds_modernm.zip.sha | grep -o -E -e "[0-9a-f]{40}")
    echo " * checking downloaded ZIPs sha1 hash"
    if [ "$RDS_SHA1" ]; then
      echo "$RDS_SHA1 */nsrl/rds_modernm.zip" | sha1sum -c -; \
    fi
fi

echo "[INFO] Unzip NSRL Database zip to /nsrl/ ..."
# 7za x -o/nsrl/ /nsrl/*.zip
cd ./db && unzip -j *.zip && cd ..

echo "[INFO] Build bloomfilter from NSRL Database ..."
nsrl --verbose build

echo "[INFO] Listing created files ..."
ls -lah ./db

echo "[INFO] Saving uncompressed NSRL DB size..."
ls -lah ./db/NSRLFile.txt | awk '{print $5}' > ./db/DBSZIE

echo "[INFO] Saving bloomfilter size..."
ls -lah ./db/nsrl.bloom | awk '{print $5}' > ./db/BLOOMSIZE

echo "[INFO] Deleting all unused files ..."
rm -f *.zip *.txt *.sh *.sha
ls -lah ./db