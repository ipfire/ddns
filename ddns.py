#!/usr/bin/python

import ddns

d = ddns.DDNSCore(debug=1)
d.load_configuration("/etc/ddns.conf")

d.updateall()
