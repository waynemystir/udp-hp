#!/bin/sh

NETWORK=`pwd`/common/network

if [ ! -d "$NETWORK" ]; then
	git clone git@github.com:waynemystir/network.git ./common/network
fi