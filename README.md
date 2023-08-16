1. Description
==============

QLog is a tool used to catch log data from Quectel modules.

2. Prerequisities
=================

The application should only be used with drivers either open source or from Quectel driver release. 

2.1 PCIe driver
The mhictrl driver should be used for SDX55/SDX62/SDX65 based modems in PCIe mode. The modem should be recognized as /dev/mhixxx which can be listed via command "ls /dev/mhi*".

2.2 USB driver
The following drivers should be used for modems in USB mode: 
- Network Driver: Open Source cdc_mbim driver (for the MBIM interface) or the qmi_wwan driver (for the RmNet interface)
- Serial Driver: Open Source option driver

The modem should be recognized as /dev/cdc_wdm which can be listed via command "ls /dev/cdc_wdm*"
DM/AT/NMEA ports should be recognized as /dev/ttyUSB* which can be listed via command "ls /dev/ttyUSB*"


2.4 Modem preparation
- Modem running latest firmware


3. Supported Modems
====================
- EMO60K

4 Build "QLog"
====================
- from source file folder just run "make", it will generate QLog

5 Catch DM logs to local folder named /logs with filter conf/default.cfg
====================
sudo QLog -f conf/default.cfg -s logs

