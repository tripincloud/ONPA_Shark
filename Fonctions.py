
protocole = {"0x0800" : "IPv4","0x86DD" : "IPv6","0x0806" : "ARP","0x8100" : "VLAN"}

def CleanVertical(liste):
    for i in liste :
        if(len(i)<2) :
            liste.remove(i)
        else :
            try :
                int(i[0],16) 
            except :
                liste.remove(i)
    return liste

def CleanHorizontal(liste):
    for i in liste :
        for j in i :
            try :
                int(j,16)
            except :
                i.remove(j)
    return liste

"""def OffsetChecker(liste):
    i = 0
    while (i < len(liste)):
        if ((len(liste[i])-1) < int(liste[i+1][0],0)):
            print("la ligne "+str(i)+" est incomplète")
        elif ((len(liste[i])-1) > int(liste[i+1][0],16)):
            liste.remove(liste[i])
        i = i + 1"""


def NBtrames(liste):
    cpt = 0
    for i in liste :
        if (int(i[0],0) == 0) :
            cpt = cpt + 1
    return cpt


def Extract(liste,Ethernet,IP,TCP):
    trame=0
    temp=""
    cptIP=0
    
    for i in range(len(liste)):
        if (int(liste[i][0],0) == 0) :
            Ethernet.append([])
            IP.append([])
            TCP.append([])
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

            trame = trame +1
                        

            

