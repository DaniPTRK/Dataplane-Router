## Tema 1 - PCom
### Protocol IPv4
In implementarea procesului de dirijare al pachetelor IPv4, am urmat pasii
expusi in tema, astfel ca initial verific ce fel de pachet am primit
(ARP sau IPv4), iar dupa aceea verific checksum-ul, TTL-ul, obtin cea mai
buna ruta folosindu-ma de trie-ul construit cu ajutorul datelor din rtable.txt,
dau update la noul checksum si caut in tabela ARP dinamica MAC-ul adresei
urmatoare. In cazul in care nu gasesc aceasta adresa, realizez un request
si trec pachetul intr-o coada de asteptare pana cand obtin MAC-ul.
<br>
Pe langa aceste verificari, mai verific de asemenea daca cumva destinatia
pachetului primit este chiar routerul meu, caz in care avem un Echo Reply.
<br>
Implementarea dirijarii pachetelor IPv4 a fost inspirata din solutia 
laboratorului 4, schimband totusi modul in care se obtine adresa MAC prin 
folosirea ARP-ului.

### LPM
Pentru eficientizarea procesului de obtine a celei mai bune rute, am
decis sa implementez o trie cu urmatoarea structura pentru fiecare nod:

```C
struct TrieNode {
	struct route_table_entry *rtable;
	struct TrieNode* next[2];
};
````

Structura route_table_entry din interiorul nodului reprezinta ruta
pe care o am pentru drumul pe care il realizez prin trie-ul construit,
iar cei 2 fii reprezinta urmatorii biti din prefixul pe care il am.
Sugestiv, next[0] este pentru bitul 0 si next[1] este pentru bitul 1. 
Construirea drumului catre rtable se realizeaza pana cand am obtinut 
masca rutei.
<br>

Astfel, pentru Trie, am implementat 3 functii:
- create_trie_node() care creeaza un nod in trie;
- insert_trie_node() care insereaza adresa primita in trie folosindu-se
de bitii prefixului si de masca;
- get_best_route() care returneaza bazandu-se pe bitii IP-ului dat cea mai
buna ruta spre destinatie.

### Protocol ARP
Pentru protocolul ARP, am realizat 4 functii diferite care ajute atat
la popularea tabelei dinamice, cat si la extragerea valorilor din tabela
ARP:
- get_arp_entry() returneaza fie entry-ul gasit in tabela ARP, fie NULL
daca IP-ul dat ca input nu se poate gasi in tabela. In cazul NULL,
trec datele intr-o coada cu elemente care au urmatoarea structura:
```C
struct package {
	struct route_table_entry *route;
	char buf[MAX_PACKET_LEN];
	size_t len;
};
````
In interiorul acestei structuri, tin minte ruta obtinuta dupa parcurgerea
trie-ului, pachetul pe care voiam sa-l trimit si lungimea acestui pachet.
Dupa ce trec in coada aceasta structura, apelez ARP_message();
- ARP_message() construieste in conformitate cu cerinta
bufferul pe care il voi trimite pentru a obtine adresa MAC;
- ARP_reply() raspunde la requesturile primite oferind atat MAC-ul adresei
hardware sender cat si MAC-ul sursa din ethernet header;
- ARP_solve() care se executa la primirea unui reply. Dupa acest reply,
se trece prin tabela de ARP-uri si se verifica daca MAC-ul gasit se afla deja
sau nu in tabela de adrese. Daca nu exista, atunci il trecem inauntru. Dupa
aceea, se trece prin coada de asteptare si se cauta pentru fiecare ruta daca
exista in tabela de ARP-uri sau nu MAC-ul cautat. Daca exista, trimitem
pachetul care se afla in asteptare.

### Protocol ICMP
Pentru protocolul ICMP am realizat 2 functii pe care le apelez in anumite
conditii:
- ICMP_reply() folosit pentru a raspunde la Echo Request-uri. Aceasta functie
este apelata doar atunci cand stiu ca router-ul meu este destinatia pachetului
primit. In interior, schimb adresele de send si destination intre ele si trimit
pachetul inapoi;
- ICMP_message() generat de catre router in momentul in care fie avem Destination
unreachable sau Time exceeded. In interiorul acestei functii construiesc mesajul
ce trebuie trimis inapoi catre host.