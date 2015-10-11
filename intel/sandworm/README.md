Bro Module for iSIGHT Partners Sandworm Report
==============================================

Source: https://github.com/hosom/bro-sandworm.git

This is a Bro script module for Bro 2.3.1+ that detects activity related to the sandworm report.

Installation
------------

::

	cd <prefix>/share/bro/site/
	git clone git://github.com/hosom/bro-sandworm.git Sandworm
	echo "@load Sandworm" >> local.bro

Configuration
-------------

There is no configuration necessary.

Output
-------------

This module will output two types of output. The first type consists of Intel alerts in intel.log and Intel::HIT notices in notice.log. The second is a notice for Signatures::Sensitive_Signature, referencing the URI seen.


Example Output
-------------

::

	1413461520.464836       Cbsqf2wPT386DSa56       10.246.50.4     64147   66.35.59.249    80      -       -	-       tcp     Signatures::Sensitive_Signature 10.246.50.4: Sandworm URI       /YXJyYWtpczAy/dlfkjasdlfkja.php	10.246.50.4     66.35.59.249    80      -       bro     Notice::ACTION_LOG      3600.000000     F	-       -       -       -       -

