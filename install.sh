#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt install python3 python3-dev golang=2:1.18~3 -y

pip3 install -r requirements.txt
