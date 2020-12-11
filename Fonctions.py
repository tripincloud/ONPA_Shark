
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

def NBtrames(liste):
    cpt = 0
    for i in liste :
        if (int(i[0],0) == 0) :
            cpt = cpt + 1
    return cpt


def Extract(liste,Ethernet,IP):
    curseurl=0
    curseurc=0
    temp=""
    cptE=14
    cptIP=0
    for i in range(len(liste)):
        if (int(liste[i][0],0) == 0) :
                for j in range(i,len(liste)):
                        for k in range(1,len(liste[j])):
                            if(cptE > 0):
                                Ethernet.append(liste[j][k])
                                cptE = cptE -1
                                curseurl = j
                                curseurc = k

                if (len(liste[curseurl])-(k+1) == 0):
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
                    print(l)
                    for m in range (curseurc,len(liste[l])):
                        print(m)
                        if(m == len(liste[l])-1 and cptIP > 0):
                            IP.append(liste[l][m])
                            cptIP = cptIP -1
                            curseurc = 1
                            m = 0
                        elif(cptIP > 0):
                            IP.append(liste[l][m])
                            cptIP = cptIP -1
                            curseurl = l
                            curseurc = m     


            

