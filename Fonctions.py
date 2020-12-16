import codecs

protocole = {"0800" : "IPv4","86DD" : "IPv6","0806" : "ARP","8100" : "VLAN"}
protocoleIP = {1 : "ICMP",2 : "IGMP",6 : "TCP",17 : "UDP",41 : "ENCAP",89 : "OSPF",132 : "SCTP"}
IPoptions = {0 : "End of Option List",1 : "No Operation",7 : "Record Route",68 : "Time Stamp",131 : "Loose Routing",137 : "Strict Routing"}

def CleanVertical(liste):
    for i in liste :
        if(len(i)<2) :
            liste.remove(i)
        else :
            try :
                int(i[0],16) 
            except :
                liste.remove(i)

def CleanHorizontal(liste):
    for i in liste :
        for j in i :
            try :
                int(j,16)
            except :
                i.remove(j)

def OffsetChecker(liste):
    i = 0
    temp = 0
    while (i < len(liste)):
        if(int(liste[i][0],16) == 0):
            temp = 0
        while (int(liste[i][0],16) != 0 and int(liste[i][0],16) != temp)  :
            liste.remove(liste[i])
        temp = temp + (len(liste[i])-1)
        i = i + 1
    
def NBtrames(liste):
    cpt = 0
    for i in liste :
        if (int(i[0],16) == 0) :
            cpt = cpt + 1
    return cpt

def affichage(liste,Ethernet,IP,TCP,HTTP):
    NBt = NBtrames(liste)
    for i in range(NBt):
        #Ethernet
        print("\nTrame N°" + str(i+1) + "\n\n--Ethernet--")
        print("MAC Destination: " + Ethernet[i][0] + ":" + Ethernet[i][1] + ":" + Ethernet[i][2] + ":" + Ethernet[i][3] + ":" + Ethernet[i][4] + ":" + Ethernet[i][5])
        print("MAC Source: " + Ethernet[i][6] + ":" + Ethernet[i][7] + ":" + Ethernet[i][8] + ":" + Ethernet[i][9] + ":" + Ethernet[i][10] + ":" + Ethernet[i][11])
        print("Type: " + protocole[Ethernet[i][12]+Ethernet[i][13]] + " (0x" + Ethernet[i][12] + Ethernet[i][13] + ")" +"\n")

        #IP
        print("--IP--\n" + "Version: " + IP[i][0][0] + "\nHeader Length: " + str(int(IP[i][0][1],16)*4) + " Bytes")
        print("Differentiated Services Field: " + "0x" + IP[i][1] + "\nTotal Length: " + str(int(IP[i][2]+IP[i][3],16)) + "\nIdentification: 0x" + IP[i][4] + IP[i][5] + " (" + str(int(IP[i][4]+IP[i][5],16)) + ")" )
        print("Flags: 0x" + IP[i][6] + IP[i][7] + "\nTime to live: " + str(int(IP[i][8],16)) + "\nProtocol: " + protocoleIP[int(IP[i][9],16)])
        print("Header checksum: 0x" + IP[i][10] + IP[i][11] + "\nIP Source: " + str(int(IP[i][12],16)) + "." + str(int(IP[i][13],16)) + "." + str(int(IP[i][14],16)) + "." + str(int(IP[i][15],16)))                                                                                    
        print("IP Destination: "+ str(int(IP[i][16],16)) + "." + str(int(IP[i][17],16)) + "." + str(int(IP[i][18],16)) + "." + str(int(IP[i][19],16)) + "\n")

        if((int(IP[i][0][1],16)*4)-20 != 0):
            #IP Options
            print("Option Type: " + IPoptions[int(IP[i][20],16)] + "\nOption Segment Length: " + str(int(IP[i][21])) + "\nPointer: " + str(int(IP[i][22])))


        if (IP[i][9] == "06"):
            #TCP
            print("--TCP--\n" + "Source Port: " + str(int(TCP[i][0]+TCP[i][1],16)) + "\nDestination Port: " + str(int(TCP[i][2]+TCP[i][3],16)) )
            print("Sequence number: 0x" + TCP[i][4] + TCP[i][5] + TCP[i][6] + TCP[i][7] + "\nSequence number (raw): " + str(int(TCP[i][4] + TCP[i][5] + TCP[i][6] + TCP[i][7],16)))  
            print("Acknowledgment number: 0x" + TCP[i][8] + TCP[i][9] + TCP[i][10] + TCP[i][11] + "\nAcknowledgment number (raw): " + str(int(TCP[i][8] + TCP[i][9] + TCP[i][10] + TCP[i][11],16)))
            print("Header Length: " + str(int(TCP[i][12][0],16)*4) + "\nTCP Segment Length: " + str((int(IP[i][2]+IP[i][3],16)-(int(TCP[i][12][0],16)*4)-(int(IP[i][0][1],16)*4))) + "\nFlags: 0x" +TCP[i][13])
            print("Window size value: " + str(int(TCP[i][14]+TCP[i][15],16)) + "\nChecksum: 0x" + TCP[i][16] + TCP[i][17] +"\nUrgent pointer: " + str(int(TCP[i][18]+TCP[i][19],16)))

            #HTTP
            if(int(TCP[i][0]+TCP[i][1],16) == 80 or int(TCP[i][2]+TCP[i][4],16) == 80):
                res=""
                print("\n--HTTP--")
                for j in range(len(HTTP[i])):
                    res = res + HTTP[i][j]
                print(codecs.decode(res, "hex").decode('utf-8'))



def Extract(liste,Ethernet,IP,TCP,HTTP):
    trame=0
    temp=""
    cptIP=0

    for i in range(len(liste)):
        if (int(liste[i][0],16) == 0) :
            Ethernet.append([])
            IP.append([])
            TCP.append([])
            HTTP.append([])
            cptE=14
            cptTCP=13
            curseurl=0
            curseurc=0

            #Ethernet
            for j in range(i,len(liste)):
                for k in range(1,len(liste[j])):
                    if(cptE > 0):
                        Ethernet[trame].append(liste[j][k])
                        cptE = cptE -1
                        curseurl = j
                        curseurc = k

            #IP
            if (len(liste[curseurl])-(curseurc+1) == 0):
                curseurl = curseurl+1
                curseurc = curseurc+1
                temp = liste[curseurl][curseurc]
                cptIP = int(temp[1],16)*4
            else :
                curseurl = curseurl
                curseurc = curseurc+1
                temp = liste[curseurl][curseurc]
                cptIP = int(temp[1],16)*4

            for l in range (curseurl,len(liste)):
                for m in range (curseurc,len(liste[l])):
                    if(m == len(liste[l])-1 and cptIP > 0):
                        IP[trame].append(liste[l][m])
                        cptIP = cptIP -1
                        curseurl = l 
                        curseurc = 1
                    elif(cptIP > 0):
                        IP[trame].append(liste[l][m])
                        cptIP = cptIP -1
                        curseurl = l
                        curseurc = m

            #TCP
            if (int(IP[trame][9],16) == 6):
                if (len(liste[curseurl])-(curseurc+1) == 0):
                    curseurl = curseurl+1
                    curseurc = curseurc+1
                else :
                    curseurl = curseurl
                    curseurc = curseurc+1

                for o in range (curseurl,len(liste)):
                    for p in range (curseurc,len(liste[o])):
                        if(p == len(liste[l])-1 and cptTCP > 0):
                            TCP[trame].append(liste[o][p])
                            cptTCP = cptTCP -1
                            curseurl = o
                            curseurc = 1
                        elif(cptTCP > 0):
                            TCP[trame].append(liste[o][p])
                            cptTCP = cptTCP -1
                            curseurl = o
                            curseurc = p

                if (len(liste[curseurl])-(curseurc+1) == 0):
                    temp = liste[curseurl][curseurc]
                    cptTCP = (int(temp[0],16)*4)-13
                    curseurl = curseurl+1
                    curseurc = curseurc+1
                else :
                    temp = liste[curseurl][curseurc]
                    cptTCP = (int(temp[0],16)*4)-13
                    curseurl = curseurl
                    curseurc = curseurc+1
                
                for o in range (curseurl,len(liste)):
                    for p in range (curseurc,len(liste[o])):
                        if(p == len(liste[o])-1 and cptTCP > 0):
                            TCP[trame].append(liste[o][p])
                            cptTCP = cptTCP -1
                            curseurl = o
                            curseurc = 1
                        elif(cptTCP > 0):
                            TCP[trame].append(liste[o][p])
                            cptTCP = cptTCP -1
                            curseurl = o
                            curseurc = p
                
                #HTTP
                if ( int(TCP[trame][0]+TCP[trame][1],16) == 80 or int(TCP[trame][2]+TCP[trame][3],16) == 80 ):

                    if (len(liste[curseurl])-(curseurc+1) == 0):
                        curseurl = curseurl+1
                        curseurc = curseurc+1
                    else :
                        curseurl = curseurl
                        curseurc = curseurc+1
                    
                    for l in range (curseurl,len(liste)):
                        for m in range (curseurc,len(liste[l])):
                            if(m == len(liste[l])-1):
                                HTTP[trame].append(liste[l][m])
                                curseurl = l 
                                curseurc = 1
                            else :
                                HTTP[trame].append(liste[l][m])
                                curseurl = l
                                curseurc = m

            trame = trame +1
                        

            

