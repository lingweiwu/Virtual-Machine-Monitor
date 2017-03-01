# Virtual-Machine-Monitor

This is a CSE612 Cloud Computing coursework.

Develop a VM Monitor (VMM) using the VSphere SDK to monitor the host machine and vms on cloud. The VMM have the following functionalities:
1. Every 10 seconds, the program outputs the CPU (MHz) and memory (MB) usages of your VM to a txt file with a timestamp.
2. Every 10 seconds, the program outputs the CPU (MHz) and memory (MB) usages and available network bandwidth (Mbps) of the server where your VM runs to a txt file with a timestamp.

In thsi program, our vCenter Server address is 128.230.247.56.
(https://128.230.247.56/sdk wwould be the vCenter Server url in the program)

The username is “vsphere.local\CloudComputing”. The password is “CSE612@2017”.

There are 10 virtual machines named "CloudComputing0X" (X ranges from 0 to 9).

The address of the physical server that holds those virtual machines is 128.230.208.175.
