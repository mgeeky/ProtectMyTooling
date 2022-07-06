#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt install python3 python3-dev nim=1.6.2 mingw-64=8.0.0-1 golang=2:1.18~3 -y

pip3 install -r requirements.txt
nimble install nimcrypto docopt ptr_math strenc winim
