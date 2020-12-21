import sys
import Fonctions

print("---------------------------------------------------------------------------------------------------------------------------------------\n"+
" ++++++++++++++++   +++++++++++++++  +++++++++++++++              +++++++++++++++   +          +   +++++++++++   ++++++++++   +       +\n"+
"+                +  +                +                           +                  +          +  +           +  +         +  +      +\n"+
"+                +  +                +                           +                  +          +  +           +  +         +  +     +\n"+
"+                +  +                +                           +                  +          +  +           +  +         +  +    +\n"+
"+                +  +++++++++++++++  +++++++++++++++             +                  +          +  +           +  +         +  +   +\n"+
"+                +  +                +                +++++++++   +++++++++++++++   ++++++++++++  +++++++++++++  ++++++++++   ++++\n"+
"+                +  +                +                                           +  +          +  +           +  +    +       +   +\n"+
"+                +  +                +                                           +  +          +  +           +  +     +      +    +\n"+
"+                +  +                +                                           +  +          +  +           +  +      +     +     +\n"+
"+                +  +                +                                           +  +          +  +           +  +       +    +      +\n"+
" ++++++++++++++++   +                +                            +++++++++++++++   +          +  +           +  +        +   +       +\n"+
"-----------------------------------------------------By Rida TALEB and Achraf JDAY-----------------------------------------------------\n")

fichier = input("Please enter the frame to analyze: ")
t = open(fichier)

liste = []

for ligne in t :
    f = ligne.split()
    liste.append(f)

liste = [x for x in liste if x != []]

liste = Fonctions.CleanVertical(liste)
liste = Fonctions.CleanHorizontal(liste)
try:
    liste = Fonctions.OffsetChecker(liste)
except:
    print("\nWARNING: Le format de la trame n'a pas été respecté l'OffsetChecker a été désactivé")

cpt = 1
for elem in liste:
    if(int(elem[0],16) == 0):
        print("\n-------------------------Trame N°"+str(cpt)+"-------------------------\n")
        cpt = cpt + 1
    print(elem)

Ethernet = []
IPv4 = []
TCP = []
HTTP = []

try:
    Fonctions.Extract(liste,Ethernet,IPv4,TCP,HTTP)
except:
    print("ERROR: La trame présente une anomalie")

Fonctions.FrameCheck(liste,Ethernet,IPv4,TCP)

try:
    Fonctions.affichage(liste,Ethernet,IPv4,TCP,HTTP)
except:
    print("ERROR: La trame présente une anomalie")

original_stdout = sys.stdout
with open('result.txt', 'w') as f:
    sys.stdout = f
    Fonctions.affichage(liste,Ethernet,IPv4,TCP,HTTP)
    sys.stdout = original_stdout
