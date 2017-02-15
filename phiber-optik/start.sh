#!/bin/bash
cd $(dirname $0)
lein figwheel &
lein run
