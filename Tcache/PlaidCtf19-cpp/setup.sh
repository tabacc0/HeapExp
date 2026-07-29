#!/usr/bin/bash
patchelf --set-rpath . libstdc++.so.6
patchelf --set-rpath . libgcc_s.so.1
