Bro-BitTorrent
==============

Bro scripts to identify BitTorrent connections.

Signature files scans all udp or tcp connections for the string "BitTorrent Protocol"

If BitTorrent Protocol is obsserved in a tcp connection then the service tag is set to 'bit'.
If observed in a udp connection then the service tag in conn.log to 'utp'.

Other files (-log and -notify) can log the number of peers seen in a new log (utp.log) or to notice.log.

Michel Laterman (2015)
