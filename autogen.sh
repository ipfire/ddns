#!/bin/sh

intltoolize --force --automake
autoreconf --force --install --symlink
