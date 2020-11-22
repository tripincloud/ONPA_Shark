# ONPA_Shark
An Offline Networks Protocoles Analyser

## This is a work in progress !! 

The objective of this project is to program an offile networks protocoles analyser. It takes as input a trace file (data frame) containing the captured bytes beforehand on an Ethernet network. This software can be displayed in a graphical user interface.

The list of protocols that the analyzer understands are the following :
- Layer 2: Ethernet
- Layer 3: IP
- Layer 4: TCP
- Layer 7: HTTP (only the header of requests and responses)

At each run, the result of the analyzer are saved in a text file format to make it easier to read. 
