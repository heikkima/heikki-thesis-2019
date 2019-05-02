![](media/62847a44f44aeb4d4b39a990b4ca6918.png)

Kubernetes ja AWS EKS

Heikki Ma

Opinnäytetyö

Tietojenkäsittely

2018

| **Tekijä(t)**  Heikki Ma                                                                                                                                                                                                                                                                                                                                                                                                                       |                                    |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| **Koulutusohjelma** Tietojenkäsittelyn koulutusohjelma                                                                                                                                                                                                                                                                                                                                                                                         |                                    |
| **Raportin/Opinnäytetyön nimi**                                                                                                                                                                                                                                                                                                                                                                                                                | **Sivu- ja liitesivumäärä** 20 + 2 |
| Kubernetes ja AWS EKS                                                                                                                                                                                                                                                                                                                                                                                                                          |                                    |
| Tiivistelmä edellytetään pääsääntöisesti vain opinnäytetöissä. Opinnäytetyön tiivistelmässä esitetään työn keskeiset kohdat siten, että lukija ymmärtää tiivistelmän luettuaan työn sisältämät pääasiat. Tiivistelmässä esitetään selvitettävän asian tausta, työn tavoite ja rajaus, työn toteutustapa ja mahdolliset menetelmät, työn tekemisen ajankohta sekä tulokset ja päätelmät. Tiivistelmä etenee raportin mukaisessa järjestyksessä. |                                    |
| **Asiasanat** Tärkeysjärjestyksessä 3–6 asiasanaa, jotka kuvaavat työn sisältöä parhaiten. Käytä asiasanojen valinnassa. Yleistä suomalaista asiasanastoa (YSA) osoitteessa <http://finto.fi/fi/>                                                                                                                                                                                                                                              |                                    |

Sisällys

[1 Johdanto 1](#johdanto)

[2 Lyhenteet, termit ja käännökset 2](#lyhenteet-termit-ja-käännökset)

[3 Kubernetes 3](#kubernetes)

[3.1 Kuberneteksen tausta 3](#kuberneteksen-tausta)

[3.2 Kuberneteksen arkkitehtuuri 5](#kuberneteksen-arkkitehtuuri)

[3.2.1 Master node 5](#master-node)

[3.2.2 Pod 7](#pod)

[3.2.3 Service 7](#service)

[3.2.4 Minion node 9](#minion-node)

[3.3 Kuberneteksen hyödyt 10](#kuberneteksen-hyödyt)

[3.3.1 Nopeus 10](#nopeus)

[3.3.2 Skaalautuvuus 11](#skaalautuvuus)

[3.3.3 Infrastruktuurin abstrahointi 12](#infrastruktuurin-abstrahointi)

[3.3.4 Tehokkuus 12](#tehokkuus)

[4 Amazon Elastic Container Service for Kubernetes
13](#amazon-elastic-container-service-for-kubernetes)

[4.1 AWS EKS tausta 13](#aws-eks-tausta)

[4.2 EKS toiminta AWS ympäristössä 13](#eks-toiminta-aws-ympäristössä)

[4.3 Kilpailijat 15](#kilpailijat)

[5 Harjoitusympäristö 17](#harjoitusympäristö)

[5.1 Suunnitelma 17](#suunnitelma)

[5.2 Toteutus 17](#toteutus)

[5.2.1 Virtuaaliverkko 18](#virtuaaliverkko)

[5.2.2 EKS klusteri 19](#eks-klusteri)

[5.2.3 Kätyrisolmut 21](#kätyrisolmut)

[5.2.4 Sovelluskontin rakentaminen 23](#sovelluskontin-rakentaminen)

[5.2.5 Kuormantasaaja 23](#kuormantasaaja)

[5.2.6 Klusterin skaalautuminen 24](#klusterin-skaalautuminen)

[6 Pohdinta 27](#pohdinta)

[6.1 EKS vahvuudet (ei vielä valmis) 27](#eks-vahvuudet-ei-vielä-valmis)

[6.2 EKS heikkoudet (ei vielä valmis) 27](#eks-heikkoudet-ei-vielä-valmis)

[Lähteet 28](#lähteet)

[Liitteet 32](#liitteet)

Johdanto
========

Lyhenteet, termit ja käännökset
===============================

>   **AKS** Azure Kubernetes Service  
>   **ASG** Auto Scaling Group

>   **AWS ECS** Amazon Elastic Container Service

>   **AWS** Amazon Web Services. Amazonin pilvipalvelu

>   **CNCF** Cloud Native Computing -säätiö,

>   **Docker-levykuva** Docker image. Levykuva, josta kontti rakentuu

>   **EC2** Pilvipalvelin AWS ympäristössä

>   **EKS** Elastic Container Service for Kubernetes

>   **GKE** Google Kubernetes Engine

>   **HA -klusteri** Korkeakäytettävyyden klusteri

>   **Isäntäkone** Host. Fyysinen tai virtuaalinenpalvelin

>   **K8s** Kubernetes

>   **Kapseli** Pod

>   **Klusteri** Cluster. Joukko palvelimia, jotka muodostavat yhdessä
>   järjestelmän

>   **Kontti** Container

>   **Konttiorkestrointityökalu** Container orchestration tool

>   **Korkeankäytettävyys** Highly Available, HA

>   **kuormantasaaja** Loadbalancer

>   **Kätyrisolmu** Minion node

>   **Mestari komponentti** Master components

>   **Mestarisolmu** Master node

>   **Varanto** Pool, resurssi varasto

>   **VPC** Virtual private cloud, oma pilvi verkko

<br>Kubernetes 
===============

Tässä luvussa käsittelemme Kubernetesta, tämän arkkitehtuuria ja hyötyjä.
Kubernetes tunnetaan myös lyhenteellä K8s. Koko tutkimuksessa käytetään kyseistä
lyhennettä, kun viitataan Kubernetekseen.

Kuberneteksen tausta
--------------------

![](media/dbe99e3fe4280305033c24001b42a502.png)

Vuonna 2013 Docker julkaistiin avoimena lähdekoodina. Siitä lähtien
konttiteknologia on ollut suuressa suosiossa sovelluskehityksessä. Docker
tarjoaa työkalut sovelluksen ja tämän riippuvuuksien paketointiin
Docker-levykuvaksi. Hakkaraisen (2018) mukaan sovellus tulee kuitenkin pilkkoa
pienempiin mikropalveluihin ennen paketointia. Mikropalvelut ovat jaettuja
kokonaisuuksia sovelluksesta. Jokaisella mikropalvelulla on oma tehtävänsä ja
nämä kommunikoivat keskenään tarvittaessa (kuva 1). Jokaisen mikropalvelun tulee
olla itsenäisesti hallittavissa ja muutettavissa. Paketoidusta mikropalvelusta
voidaan käynnistää kontti missä tahansa käyttöjärjestelmässä, kunhan tämä tukee
Docker teknologiaa. Kontit ovat hyvin kevyitä ja yhdessä isäntäkoneessa voidaan
ajaa samanaikaisesti useita kontteja. Teknologian etuna on sovellusten
yksinkertainen pakkaaminen ja monistaminen erilaisiin ympäristöihin. Tämä
nopeuttaa sovelluksen julkaisemista tuotantoon, ja tuotannossa tämän
skaalaamista (Docker, s.a.).

Kuva 1. Mikropalvelut (mukailen Nadareishvili, Mitra, McLarty, & Amundsen, 2016)

Google julkaisi K8s projektin avoimena lähdekoodina vuonna 2014. Google ja Linux
-säätiö perustivat yhdessä Cloud Native Computing -säätiön, jolle Google
lahjoitti K8s:n hallittavakseen vuonna 2015 (Lardinois, 2015). K8s on
konttiorkestrointityökalu, jonka tarkoituksena on tarjota alusta ja työkalut
konttien keskitettyyn hallintaan. Tämän avulla voidaan hallita useista
isäntäkoneista muodostunutta klusteria, sovelluksien välisiä verkkoyhteyksiä ja
näiden skaalaamista nopeasti ja helposti. Muita samantyylisiä alustoja ovat
esimerkiksi AWS ECS ja Docker Swarm. K8s:ia käytetään useimmiten Dockerin
konttien kanssa. K8s kuitenkin tukee myös muita kontti järjestelmiä, jotka
täyttävät Open Container Initiative (OCI) standardit (Yegulalp, 2019;
Kubernetes, 2018a).

*AWS ECS* on Amazonin pilvipalvelualustalla toimiva konttiorkestrointityökalu.
AWS ECS hyödyntää AWS ympäristössä jo olemassa olevia resursseja esimerkiksi
pilvi-instanssit EC2 ja näiden automaatti skaalaus työkalua. AWS ECS ajaa
kontteja pilvi-instanssin sisällä ja tarjoaa työkalut konttien hallintaan AWS
konsolin tai AWS rajapinnan avulla. AWS ECS skaalaa kontteja tarvittaessa
ylöspäin/alaspäin automaattisesti. Automaattiskaalaus noudattaa skaalaamisessa
ennalta määrättyjä sääntöjä, jotka määrittelevät vähimmäis- ja enimmäismäärän
konteille. Mikäli resurssit loppuvat pilvi-instanssilta voidaan instanssien
määrää myös skaalata ylös päin tai alas päin. AWS ECS on saatavilla vain AWS
ympäristössä (Sarkar & Shah. 2018)*.*

*Docker Swarm* on Dockerin kehittämä orkestrointi työkalu Docker konteille.
Docker Swarm ryhmittää konttien isäntäkoneet yhteen varantoon ja tarjoaa
käyttäjälle työkalut hallita varantoa yhtenäisesti (Ravindra, 2018; Paraiso,
Challita, Al-Dhuraibi & Merle 2016).

K8s on hyvin tehokas konttiorkestrointityökalu, joka on suunniteltu hallitsemaan
ja ohjaamaan useita kontteja samanaikaisesti. K8s järjestelmä toimii Mestari -
kätyri (master - minion) konseptilla. Mestari – kätyri järjestelmä koostuu
yleensä yhdestä mestarista ja monesta kätyristä. Mestarin tehtävänä on hallita
järjestelmää ja jakaa käskyjä kätyreille.

Guptan (2017) mukaan K8s suosio johtuu siitä, että sillä on yksi maailman
isoimmista avoimen lähdekoodin yhteisöistä. Yhteisö on ollut aktiivisesti mukana
kehittämässä K8s ohjelmaa GitHubissa. Gupta kertoo myös, että CNCF -säätiöllä on
suuri rooli K8s:n suosioon. CNCF kuuluu isoon Linux säätiöön (Linux Foundation),
jota tukevat monet suuret yritykset kuten pilvipalveluntarjoajat Google,
Microsoft ja AWS. Tämän lisäksi CNCF:llä on omia tukijoita esimerkiksi Oracle ja
SAP.

Moni pilvipalvelun tarjoaja on ottanut K8s:n tuotteekseen, esimerkiksi
Microsoftin AKS, Googlen GKE ja Amazonin EKS. Pilvipalvelun tarjoajat voivat
hyödyntää K8s avointa lähdekoodia ja luoda lisäominaisuuksia palvelulleen. Tämä
parantaa palvelun käyttökokemusta ja mahdollistaa K8s palvelun liittämisen
tarjoajan omaan ekosysteemiin. Tämän lisäksi palveluntarjoajat voivat hyödyntää
olemassa olevia työkaluja, joita K8s yhteisö on luonut ja jakanut.

Kuberneteksen arkkitehtuuri
---------------------------

K8s koostuu klusterista. Klusteri muodostuu monesta koneesta (fyysisestä tai
virtuaalisesta), joissa ajetaan K8s ohjelmaa. Koneita voidaan liittää
jälkikäteen järjestelmään helposti, mikäli järjestelmän resurssit eivät riitä.
Klusterin sisällä on yksi tai useampia mestarisolmuja ja useita kätyrisolmuja
(Kubernetes 2019a). Tässä kappaleessa käymme läpi muutamaa isompaa komponenttia
K8s:n klusterissa. Näiden lisäksi K8s sisältää pienempiä mutta silti tärkeitä
komponentteja.

### Master node

Mestarisolmu toimii klusterin ohjaamona. Ohjaamossa päätetään klusterin
asioista, kuten esimerkiksi ajastetuista tehtävistä ja klusterin muutoksiin
liittyvissä asioissa. Mestarisolmut koostuvat useista eri mestari
komponenteista. Näitä komponentteja ovat kube-apiserver, kube-scheduler,
kube-controller-manager ja etcd. Komponentit voidaan jakaa usealle koneelle,
mutta yksinkertaisuuden vuoksi komponentit ovat yleensä samassa koneessa (pois
lukien etcd, tästä lisää seuraavassa kappaleessa) (Kubernetes 2019a; Arundel &
Domingus, 2019).

*Kube-apiserver* on klusterin ulkopuolelle näkyvä rajapinta. Rajapintaan tehdään
kutsuja ja lähetetään haluttuja muutoksia klusteriin. Kätyrisolmut käyttävät
myös kyseistä rajapintaa kommunikoidessaan mestarisolmun kanssa. *Etcd* on
klusterin oma tietokanta. Klusterin rajapinta, Kube-apiserver, tallentaa datan
avain-arvo pareina tietokantaan. Tietokantaan tallennetaan muun muassa klusterin
nykyinen tila ja haluttu tila. K8s klusteri käyttää etcd tietokantaa totuuden
lähteenä. On tärkeää luoda varmuuskopioita etcd tietokannasta. K8s dokumentaatio
suosittelee luomaan etcd komponentille oman klusterin. Etcd klusteri voi olla
K8s klusterin sisällä tai ulkopuolella (kuva 2). *Kube-scheduler* tarkkailee,
jos uusia kapseleita (komponentti, joka pitää sisällään kontteja) luodaan ja
ohjaa nämä oikeisiin kätyrisolmuihin. Kube-scheduler valitsee kapseleille
sopivia kätyrisolmuja ja osaa ottaa huomioon näiden resurssi- ja muut
vaatimukset.

*Kube-controller-manager* komponentti hallinnoi ja tarkkailee klusterin tilaa.
Tämä hakee nykyisen ja halutun tilan etcd tietokannasta kube-apiserverin kautta,
ja muuttaa klusteria haluttuun suuntaan, mikäli se on erilainen.
Kube-controller-manager käyttää klusterin tarkkailuun erilaisia valvojia.
Jokaisella valvojalla on oma tehtävänsä ja tarkkailu kohteensa.

Valvojia ovat esimerkiksi:

-   Node Controller

    -   Tarkkailee kätyrisolmuja. Jos kätyrisolmu kuolee, pyrkii valvoja
        nostamaan uuden tilalle.

-   Replication Controller

    -   Tarkkailee kapseleiden lukumäärä solmujen sisällä. Jos kapselien määrä
        on eri kuin halutussa tilassa, valvoja tiputtaa tai nostaa kapseleita
        kätyrisolmuun.

Valvojia on näiden lisäksi monia, joko K8s virallisia tai K8s yhteisön luomia,
ja jokaisella valvojalla on oma tehtävänsä (Baier 2017; Kublr, 2017; Kubernetes,
2019a).

K8s klusterilla on yleensä yksi mestari, joka ohjaa ja käskee muita koneita
klusterissa (Yegulalp, S, 2019). Mestareita voi kuitenkin olla klusterissa
monta, kun rakennetaan korkeankäytettävyyden (lyhenne HA) klusteria. HA
klusterissa yksi kone kerrallaan toimii mestarina. Mestari ajaa ajastettuja
tehtäviä ja ohjaa muita koneita klusterissa. HA:n ideana on ylläpitää
sovelluksen hallintaa mestari koneella, myös silloin kun yksi mestareista kaatuu
esimerkiksi laitevian vuoksi. Kätyrisolmut ottavat mestariin yhteyttä
kuormantasaajan kautta (kuva 2). Kuormantasaaja ohjaa liikenteen mestarille,
jonka tämä tunnistaa olevan pystyssä (Kubernetes 2019b; Arundel & Domingus,
2019).

![](media/a604d9ce2211b3e62f6f8eeb9b7fe16e.png)

Kuva 2. Vasemmalla sisänen etcd klusteri. Oikealla ulkoinen etcd klusteri
(mukailen Kubernetes 2019a).

### Pod

Kapseli muodostuu usein miten yhdestä kontista. On kuitenkin mahdollista luoda
kapseli useammasta hyvin tiiviiksi kytketyistä konteista, jotka ovat hyvin
riippuvaisia toisistaan. Kapseli sijoitetaan aina kätyrisolmuun. Tämän sisällä
olevat kontit jakavat saman IP osoitteen ja muistin. Jokaisella kapselilla on
oma elämänkaarensa. Elämänkaaren eri vaiheita ovat:

-   Tulossa oleva (Pending)

    -   K8s klusteri on hyväksynyt kapselin, mutta kapselin kontti ei ole vielä
        luotu.

-   Käynnissä (Running)

    -   Kapseli on ohjattu kätyrisolmulle ja kontti on luotu kapselin sisälle
        luotu.

-   Onnistunut (Succeeding)

    -   Kaikki kontit kapselin sisällä on poistettu onnistuneesti.

-   Epäonnistunut (Failed)

    -   Kaikki kontit kapselin sisällä on poistettu, mutta yksi tai useampi
        kontti on palauttanut virhekoodin poistaessa.

-   Tuntematon (Unknown)

    -   Tuntemattomasta syystä kapselin tilaa ei tiedetä.

-   Valmis (Completed)

    -   Kapseli on suorittanut tehtävänsä.

Kun kapseli poistetaan tai se kuolee pois, sitä ei nosteta enää takaisin ylös.
K8s järjestelmä luo uuden tilalle käyttäen mestarisolmun valvojaa, jos on tarve
uudelle kapselille (Kublr, 2017; Kubernetes, 2019c).

### Service

Aikaisemmin kerrottiin kapseleiden elämänkaaresta, nämä nousevat ylös ja
kuolevat lopulta pois. Tämä luo uuden ongelman. Kapseleiden sisällä olevalle
sovellukselle pitäisi ohjata liikennettä, mutta kun kapselit muuttuvat
dynaamisesti, ei sovelluksella ole pysyvää osoitetta. K8s järjestelmässä on
palvelu-objekti, jonka tehtävänä on ratkaista kyseinen ongelma. Palvelu-objekti
on abstraktinen käsite, joka pitää sisällään tiedon yhden sovelluksen olemassa
olevista kapseleista ja miten näihin kapseleihin saa yhteyden. Palvelu-objekteja
tulee siis luoda jokaiselle sovellukselle oma. Palvelu-objektin oletus tyyppi on
ClusterIP. Muita palvelu-objektin tyyppejä on NodePort ja LoadBalancer.
*ClusterIP* tyyppinen palvelu-objekti saa itselleen sisäisen IP-osoitteen.
IP-osoitetta voidaan kutsua vain klusterin sisältä (kuva 3). Palvelu-objektissa
on sisäänrakennettu kuormantasaaja, joka lähettää yhteyden vain saatavilla
oleville kapseleille

![](media/8b02216fabb9bd0072ad3bc06a1efad3.png)

Kuva 3. Palvelu-objekti ClusterIP

*NodePort* tyyppinen palvelu-objekti näkyy K8s klusterin ulkopuolelle.
Palvelu-objekti avaa jokaisen klusterin kätyrisolmusta saman portin (kuva 4).
Kätyrisolmu ohjaa portista tulevan liikenteen ClusterIP objektille (ClusterIP
objekti, luodaan automaattisesti NodePort palveluobjektin kanssa).

Palvelu-objekti tyyppiä *LoadBalancer* on käytössä vain pilvipalvelutarjoajilla,
joilla on yhteensopiva kuormantasaaja K8s kanssa. Kuormantasaajalle määritellään
portti, jonka liikenne ohjataan eteenpäin palvelulle (kuva 4). Kuormantasaaja
ohjaa kaiken tyyppiset liikenteet palvelulle esimerkiksi HTTP, TCP ja UDP.
Kuormantasaaja ei tue salauksen purkamista. Samalla kuormantasaajalla voi olla
useampi portti määritelty eri palveluille. (Kubernetes, 2018c; Kubernetes,
2018d; Yegulalp, 2019; Sandeep, 2018).

![](media/b4d791ba38ebc95ab79af7ed10e7dfb3.png)

![](media/e39064b34f809f80c22eee2f5cd85781.png)

Kuva 4. Vasemalla palvelu-objekti NodePort. Oikealla palvelu-objekti
LoadBalancer

### Minion node

Kätyrisolmut ovat koneita, joissa sijaitsevat sovelluksen kapselit. Kätyrisolmut
koostuvat kubelet, kube-proxy ja container runtime -komponenteista. *Kubelet*
komponentin tehtävänä on valvoa solmun sisällä olevia kapseleita. Tämä
varmistaa, että kapselit ovat terveitä ja täyttävät niille annetut vaatimukset.
Kubelet saa pääsääntöisesti kapselien vaatimukset mestarisolmulta ja raportoi
mestarisolmulle, mikäli kapseli ei täytä vaatimuksia.

*Kube-proxy* komponentin tehtävä on ohjaa liikenne oikealle kapselille. K8s
versiossa 1.0 kube-proxy:llä on vain yksi välitys tila, ”*userspace*”. Tässä
tilassa komponentin tehtävä on ohjata klusteri IP:stä tullut kutsu tälle
tarkoitetulle kapselille (kuva 5). Kube-proxy tarkkailee uusia ja poistettavia
palvelu-objekteja. Jos uusi palvelu-objekti luodaan. Komponentti avaa
sattumavaraisen portin kätyrisolmussa tälle palvelulle. Kun klusteri IP:stä
tulee kutsu komponenttiin avatun portin kautta, ohjaa tämä yhteyden oikealle
kapselille. Kube-proxy saa tiedon kenelle yhteys kuuluu etcd tietokannasta
kommunikoimalla mestari rajapinnan kanssa. Mikäli kapseleita oli useampi,
määräytyi yhteys round robin -säännön mukaisesti (kiertovuorottelu). K8s version
1.1 mukana tuli uusi välitys tila kube-proxy:lle nimeltään ”iptables”. Tässä
tilassa kube-proxy tarkkailee mestarisolmua. Jos mestari luo tai poistaa uuden
palvelu-objektin, kube-proxy muuttaa oman koneensa IP taulua (iptables,
palomuuri Linux-kerneleissä. Iptablesissa voi luoda filtteröinti sääntöjä
IP-paketeille ja NAT sääntöjä) (kuva 5). Tällä tavoin kube-proxy ohjaa
liikenteen oikealle kapselille.

![](media/3d715d18bec1aa3d17e0c6fe7d08df66.png)

![](media/5b3d708e6ebcadf336fcb7ea478a8165.png)

Kuva 5. Vasemmalla: välitys tila: userspace; Oikealla: välitystila: ip-tables

(mukailen Kubernetes, 2018c; Openstack, 2018)

*Container runtime* komponentin tehtävänä on ajaa kontteja. K8s tukee useita eri
runtime ohjelmia kuten Docker, containerd, cri-o, rktlet sekä muita ohjelmia,
joissa on K8s CRI (Container Runtime Interface) tuki (Kubernetes, 2019a).

Kuberneteksen hyödyt
--------------------

Hightower, Burns & Beda (2017) kertoivat kirjassaan neljä yleisintä hyötyä mitä
K8s:n käyttäjät hakevat, kun ottavat käyttöön K8s alustan.

-   Nopeus (Velocity)

-   Skaalautuvuus (Scaling)

-   Infrastruktuurin abstrahointi (Abstracting your infrastructure)

-   Tehokkuus (Efficency)

### Nopeus

Nykyään loppukäyttäjät vaativat sivustoilta ja sovelluksilta jatkuvaa
saatavuutta ja katkokset sovelluksessa tuovat huonon kuvan. Sovelluksen
pakkaaminen kontteihin ja näiden hallitseminen K8s ympäristössä nopeuttaa uusien
päivityksien viemistä tuotantoon ilman että sovellukseen tulisi huoltokatkoksia.
Nopeuden mahdollistaa kontteihin pakattujen sovelluksien muuttumaton rakenne,
K8s konfiguraatioiden deklaratiivinen muotoilu ja K8s:n automaattinen valvonta.

Sovelluksen *muuttumaton* rakenne perustuu siihen, miten kontteja rakennetaan.
Kontit luodaan konttilevykuvasta. Kun sovellusta päivitetään ja luodaan uusia
ominaisuuksia, luodaan lopputuotteesta uusi levykuva. Uudesta levykuvasta
käynnistetään kontti. K8s odottaa, että uusi kontti on käynnissä ja terve ennen
kuin alkaa sammuttamaan vanhaa konttia. Tämän avulla palveluun ei muodostu
katkoksia. Jo luotuja levykuvia ei ole tarkoitus muuttaa vaan joka kerta tulisi
luoda uusi levykuva. Tämän etuna on muun muassa siinä, kun vanha versio
sovelluksesta pitäisi palauttaa. Kontti pitää vain käynnistää vanhalla
levykuvalla. (Rize, 2017; Arundel & Domingus, 2019).

K8s konfiguraatio tiedostot kirjoitetaan YAML tai JSON tiedostoina. Tiedostoihin
ei kirjoiteta komentoja mitä K8s tulisi tehdä. Konfiguraatio tiedostoon
kuvaillaan deklaratiivisesti, millainen ympäristö halutaan. K8s lukee tiedoston
ja päättää miten toimitaan, jotta päästään haluttuun tilaan. Esimerkiksi jos
halutaan kaksi kopiota samasta kapselista, kirjoitetaan replicas: 2
konfiguraatiotiedostoon. Konfiguraation kirjoittajan ei tarvitse kirjoittaessa
tietää montako kopiota on jo olemassa, jotta pääsisi haluttuun tilaan.
Vastaavasti jos samaan lopputulokseen halutaan päästä käyttämällä komentoja
imperatiivisesti. Tulisi komentojen kirjoittaja tietää montako kopiota on jo
olemassa sillä hetkellä, jotta voidaan päätellä, tuleeko ympäristöstä poistaa
vai lisätä kapseleita (Ali, 2018).

K8s valvoo jatkuvasti klusteria ja korjaa itse itseään. Tämä kykenee
tunnistamaan automaattisesti muutoksia ympäristössä ja pystyy toimimaan heti
korjatakseen muutoksen. Hyvänä esimerkkinä on replikaatio valvoja. Kyseinen
valvoja tarkistaa tietyin väliajoin ympäristössä käynnissä olevien konttien
lukumäärää. Mikäli valvoja huomaa konttien määrän olevan liikaa tai liian vähän.
Käynnistää tämä uuden työn, jonka tehtävänä on saada ympäristön konttien
lukumäärän samaksi kuin konfiguraatiotiedoston halutussa tilassa (Sayfan, 2017).

### Skaalautuvuus

Kun sovellus siirtyy tuotantoon, tulee sovelluksen pystyä skaalautumaan nopeasti
ja huomaamattomasti sovelluksen käyttäjille. Suorituskyvyn pullonkaulana voi
olla esimerkiksi yhden mikropalvelun kontti. Konttien lukumäärää voidaan K8s:sa
lisätä muuttamalla kapselien määrää konfiguraatiotiedossa. Tämän voi kuitenkin
myös tehdä automaattisesti K8s:sa automaattiskaalauksella. Skaalaaja kykenee
automaattisesti skaalaamaan kapseleita horisontaalisesti annettujen sääntöjen
puitteissa. Automaattiskaalaaja ei itse luo tai poista kopioita kapseleista.
Vaan tämä kommunikoi replikaatio valvojan kanssa, joka sitten luo tai poistaa
kapseleita (kuva 6). Näin kapseleiden skaalaus ei luo konflikteja
replikaatiovalvojan kanssa. Uudet kapselit käynnistetään vierekkäin jakaen
sovelluksen kuormaa. Automaattiskaalaajalle voi määrittää metriikkaa, jonka
perusteella tämä skaalaa kapseleita ylös tai alaspäin. Metriikka voi olla
esimerkiksi prosessorin käyttöprosentti tai joku sovelluksen tarjoama oma
metriikka.

![](media/5248df1123cd43b4dd4671591fefa487.png)

Kuva 6. Automaattiskaalaaja (mukailen Sayfan, 2017)

Kapseleita ei voi skaalata loputtomiin ylöspäin. Jokainen kapseli sijoitetaan
palvelimelle ja tämä käyttää palvelimen resursseja. Kun resurssit loppuvat
klusterista, uudet kapselit jäävät odottamaan resurssien vapautumista olemassa
olevilta kapseleilta tai uusien palvelimien liittämistä klusteriin. Koneiden
lisääminen olemassa olevaan K8s klusteriin ei häiritse jo klusterissa olevia
sovelluksia. Uudet palvelimet rekisteröivät itsensä mestarisolmuun
automaattisesti, mikäli K8s käynnistetään koneissa komennolla, josta löytyy
--register-node lippu. (Kubernetes, 2018b).

Moni pilvipalveluntarjoaja kuten Google Cloud, Amazon Web Services ja Microsoft
Azure tarjoaa hyvät työkalut K8s klusterin skaalaamiseen. Edellä mainituilla
palveluntarjoajilla on mahdollista skaalata K8s klusteria automaattisesti.
Klusterin automaattinen skaalautuminen tapahtuu, kun palvelu tunnistaa
mestarisolmun yrittävän luoda uuden kapselin, mutta resurssit eivät riitä tai
eivät vastaa kapselin vaatimuksia. Tällöin palvelu liittää uuden koneen K8s
klusteriin ennalta määrättyjen sääntöjen mukaisesti. Vastaavasti palvelut
osaavat skaalata klusteria myös alaspäin (Arundel & Domingus, 2019).

Tutkimuksessa tulemme vielä tutkimaan AWS:n tarjoamaa Amazon Elastic Container
Service for Kubernetes (EKS) palvelua syvemmin.

### Infrastruktuurin abstrahointi

K8s ei ole riippuvainen alla olevasta infrastruktuurista. Tämä on nähty yhtenä
K8s:n suurimmista hyödyistä. K8s:n voi pystyttää omaan konesaliin,
pilviympäristöön tai hyödyntää kumpaakin hybridipilvessä. Tämä ei siis lukitse
käyttäjäänsä yhteen tiettyyn ympäristöön tai palveluntarjoajan alustaan (vendor
lock-in). Käyttäjä voi siirtää sovelluksensa helposti omasta konesalistaan
esimerkiksi pilvipalvelutarjoajalle, käyttäen melkein samoja
konfiguraatiotiedostoja (Hightower & ym. 2017; Jayanandana, 2018)

### Tehokkuus

Konttiteknologian ansiosta K8s:n käyttäminen on tehokasta. K8s osaa
automaattisesti sijoittaa kapseleita koneisiin, joihin nämä mahtuvat. Tämän
ansiosta jokaisen koneen resursseja käytetään tehokkaasti hyödyksi ja koneita ei
tarvita ympäristössä niin paljon. Näin voidaan välttää tarpeettomien laitteiden
hankinta omassa konesalissa ja säästää rahaa ylimääräisten resurssien
maksamisesta pilvipalveluissa (Hightower & ym. 2017; Sanders, 2018).

Amazon Elastic Container Service for Kubernetes
===============================================

Amazonin tarjoama palvelu K8s:ta on Amazon Elastic Container Service for
Kubernetes. Tutkimuksessa käytetään lyhennettä EKS, kun viitataan Amazonin
Kubernetes palveluun.

AWS EKS tausta
--------------

AWS avasi EKS palvelun asiakkailleen 2018 kesäkuussa. EKS palvelussa
järjestelmän vastuu jakautuu palveluntarjoajan AWS:n ja asiakkaan kanssa (kuva
7). AWS takaa pilvipalveluntarjoajana laitteiston, ohjelmiston, verkkoyhteyden
toimivuuden ja fyysisen turvauksen konesaleilla. Edellä mainittujen lisäksi AWS
huolehtii EKS palvelussa K8s klusterin ohjaamon konfiguraatiosta ja
toimivuudesta sekä etcd -tietokannan saatavuudesta. Mestareiden ja tietokannan
saatavuuden takaamiseksi AWS ajaa mestarit usealla saatavuus alueella
(availability zones, fyysesti eri paikoissa olevia konesaleja). Toiminta jatkuu
tällä tavoin normaalisti, vaikka yksi saatavuus alueista putoaisi pois verkosta
esimerkiksi sähkökatkoksen vuoksi. AWS tarkkailee myös jatkuvasti mestarisolmuja
ja korvaa vialliset solmut uusilla. Asiakkaan vastuulla ovat K8s klusterin muu
konfiguraatiot, esimerkiksi kätyrisolmun konfiguraatio, ohjaamon yhteys
asiakkaan VPC -verkkoon. Asiakkaan vastuulla on myös kätyrisolmujen
pystyttäminen, käyttöjärjestelmien valitseminen ja päivittäminen (Amazon Web
Services, 2018a).

![](media/13262e39b840152934b45ecbc5934b2c.png)

Kuva 7. EKS jaettu vastuu (mukailen Amazon Web Services, 2018a)

EKS toiminta AWS ympäristössä
-----------------------------

EKS palvelu toimii muiden AWS:n olemassa olevien palveluiden kanssa. Nämä
palvelut tukevat ja parantavat EKS palvelun skaalautumista ja tietoturvaa. AWS
palvelut, jotka toimivat suoraan EKS palvelun kanssa ovat: Elastic Load
Balancing, IAM, VPC ja PrivateLink.

*Elastic Load Balancing* (ELB) on AWS:n tarjoama kuormantasaajapalvelu. EKS
tukee kahden tyyppistä ELB kuormantasaajaa, Network Load Balancer (NLB) ja
Classic Load Balancer (CLB). Oletuskuormantasaajatyyppi on CLB. NLB jakaa
kuormaa hyödyntäen TCP tai TLS protokollaa. Kuormantasaajilla on oma IP-osoite,
joka näkyy ulkoverkkoon. NLB:n ohjauksessa välittyy alkuperäisen kutsun tekijän
IP osoite. Osoitetta voidaan hyödyntää tällöin myös sovelluksessa. Protokolla
tason ohjauksen ansiosta NLB on erittäin nopea ja tehokas. Tämä
kuormantasaajamalli on vielä alpha-vaiheessa, eikä suositella vielä K8s
tuotantoklustereihin (Kubernetes, 2018c). CLB toimii samalla tavalla kuin
palvelu-objekti jonka tyyppi on *LoadBalancer* (otsikko 2.2.3). (Bala 1.12.2017)

*EKS* palvelu luo käyttäjän puolesta resursseja, joita hyödynnetään K8s
klusterissa. EKS tarvitsee oikeudet näiden resurssien luontiin*. IAM* on AWS
alustalla identiteetin ja pääsynhallinta -palvelu. Palvelun ideana on vastata
kysymykseen: Kenellä on oikeus tehdä mitä ja missä? IAM palvelussa määritellään
rooleja, käyttäjiä ja ryhmiä. Näihin objekteihin liitetään policy, jossa
määritellään oikeuksista. AWS kertoo dokumentaatiossaan vähimmäisoikeudet EKS
palvelulle (Amazon Web Services, s.a. (a)).

*VPC* on virtuaaliverkko johon käyttäjä voi luoda AWS resurssejaan. VPC:n
sisälle luodaan pienempiä aliverkkoja. Aliverkot määritellään saatavuusalueilla
ja ne voivat olla joko julkisia tai suljettuja verkkoja. Julkiseen aliverkkoon
voidaan olla yhteydessä VPC -verkon ulkopuolelta. Suljettuun aliverkkoon ei
voida olla yhteydessä verkon ulkopuolelta, mutta suljetusta aliverkosta voidaan
ottaa yhteyttä VPC verkon ulkopuolelle. EKS vaatii klusterin luonnin yhteydessä
vähintään kaksi aliverkkoa eri saatavuusalueilta. AWS suosittelee
kuormantasaajan sijoittamista julkiselle aliverkolle ja kätyrisolmujen
sijoittamista suljetulle aliverkolle (kuva 8). AWS luo EKS klusterin luonnin
yhteydessä asiakkaan aliverkoille Elastic Network Interface (ENI) resurssin,
mikäli klusterin oikeudet tämän sallivat. Klusterin ohjaamo käyttää ENI
-resurssia kommunikoidakseen kätyreiden kanssa. Klusterin ylläpitäjä ja
kätyrisolmut ottavat yhteyttä klusterin ohjaamon API palvelimelle
kuormantasaajan kautta. Ohjaamon API palvelin voidaan muuttaa myös yksityiseksi.
Tällöin yhteydet API palvelimeen menevät ENI resurssin kautta. Tämä vaatii
ylläpitäjää luomaan VPC:n sisälle bastion -instanssin, jonka kautta ylläpitäjä
voi ottaa yhteyttä klusterin ohjaamoon. Bastion -instanssi on virtuaalikone,
joka näkyy ulkoverkkoon ja jolla on pääsy sisäverkkoon.

![](media/de36c1045505160d40a5f390d5081088.png)

Kuva 8. AWS:n suosittelema verkko infrastruktuuri EKS palvelulle (Amazon Web
Services, s.a (b))

Kilpailijat
-----------

Monet pilvipalveluntarjoajat ovat ottaneet K8s tarjottavaksi palveluksi. AWS:n
kilpailijoita K8s pilvipalvelutarjoajana ovat esimerkiksi Googlen GKE,
Microsoftin AKS ja DigitalOceanin Kubernetes. Acreman, S. (s.a.) julkaisi
artikkelissaan taulukon (liite 1). Taulukossa vertaillaan pilvipalvelutarjoajien
K8s palvelua.

*GKE* on Googlen täysin hallittu K8s palvelu. Asiakas määrittelee, kuinka monta
kätyrisolmua klusteriin tulee ja Google luo tämän perusteella koko klusterin.
Google huolehtii, että mestarisolmuissa ja kätyrisolmuissa on uusimmat
tietoturvapäivitykset. Palvelu tunnistaa vialliset solmut ja korvaa solmut
uusilla. Klusterin saatavuudessa on kaksi tilaa: *multi-zonal* ja *regional*.
Mutli-zonal -tilassa klusterilla on vain yksi mestarisolmu. Regional tilassa
mestarisolmuja on useampi ja nämä on hajautettu eri saatavuusalueille. Googlella
on K8s:ta eniten kokemusta ja Arundel, J & Domingus, J (2019) mukaan tämä näkyy
heidän palvelussaan. He kertovat, että Google on paras K8s palveluntarjoaja,
joka on tehnyt K8s käyttöönoton nopeaksi, edulliseksi ja yksinkertaiseksi heidän
tarjoamien työkalujen ansiosta.

*AKS* tarjoaa GKE tapaan täysin hallitun K8s palvelun. Microsoft Azure ylläpitää
ja hoitaa mestarisolmujen ja kätyrisolmujen tietoturvapäivitykset. AKS, GKE ja
DigitalOcean Kubernetes palveluissa ei veloiteta mestarisolmujen pystyttämisestä
eikä ylläpidosta. Palveluissa veloitetaan muista maksullisista resursseista
käytön mukaan, esimerkiksi kätyrisolmujen pilvipalvelimet. AKS palvelussa
mestarisolmuja on vain yksi jokaista klusteria kohden (Selvan, 2018; Microsoft
Azure, 2019).

DigitalOcean julkaisi oman K8s palvelun (DOK8s, epävirallinen lyhenne)
joulukuussa 2018. Haider, H (2019) mukaan DOK8s on yksinkertainen ja
kustannustehokas. DOK8s hallinnoi klusterin ohjaamoa ja tarkkailee klusterin
kätyrisolmuja. Klusterille luodaan yksi tai useampi kätyrisolmuvaranto (minion
node pool). Samanlaisia ominaisuuksia löytyy myös GKE ja EKS palveluissa. Kaikki
kätyrisolmut ovat identtisiä oman varantonsa sisällä. DOK8s poistaa tarvittaessa
vialliset solmut varannosta ja korvaa nämä uudella. DOK8s palvelussa koko
klusteri pystytetään yhdelle saatavuusalueelle. Tämä huonontaa klusterin
vikasietoisuutta, esimerkiksi paikallinen sähkökatkos kaataa koko sovelluksen.
DOK8s klustereissa mestarisolmuja on vain yksi kappale (DigitalOcean, 2018).

Harjoitusympäristö
==================

Tässä otsikossa käsitellään sovellusta joka hyöyntää AWS EKS palvelua.
Harjoituksessa käytämme olemassa olevaa sovellusta nimeltä strm/helloworld-http
(<https://hub.docker.com/r/strm/helloworld-http/>). Sovellus on yksinkertainen
verkkosivu, joka palauttaa kontin nimen, jossa sovellusta pidetään ajossa.

Suunnitelma
-----------

Harjoituksen pääpainona on sovelluksen arkkitehtuuri. Koko sovellusta ajetaan
konteissa. Kontteja ajetaan useita vierekkäin eristettyinä toisistaan ja näitä
hallitaan AWS EKS palvelun avulla. Sovellukselle luodaan oma VPC -verkko.
Virtuaaliverkko tulee pitämään sisällään kaksi julkista aliverkkoa ja kaksi
suljettua aliverkkoa. Julkisissa aliverkoissa tulee olemaan kuormantasaaja.
Suljetuissa aliverkoissa tulee olemaan kummassakin oma pilvipalvelin.
Sovelluksen verkkorakenne on samanlainen kuin kuvassa 8. Suljetun aliverkon
pilvipalvelimet yhdistetään AWS EKS palvelun K8s klusteriin.

Toteutus
--------

Tässä kappaleessa käsitellään harjoitusympäristön toteutusta. Kaikki
toteutuksessa käytetyt koodit ja mallitiedostot löytyvät GitHub säilytyspaikasta
(<https://github.com/heikkima/heikki-thesis-2019>). Kaikki AWS resurssit luodaan
AWS CloudFormation -palvelulla. CloudFormation on palvelu, joka luo AWS
resurssit automaattisesti. Palvelulle lähetetään YAML tai JSON mallitiedosto.
Tiedostossa tulee kuvailla minkälaisia AWS resursseja halutaan ja miten nämä
ovat mahdollisesti konfiguroitu. Tämä mahdollistaa ympäristöjen monistaminen
automaattisesti ja nopeasti. Mallitiedostot voidaan myös säilyttää
versiohallinta järjestelmässä, kuten GitHub säilytyspaikassa. CloudFormation
mallitiedostot tulee noudattaa AWS:n omaa dokumentaatiota (Amazon Web Services,
s.a (c)).

AWS CloudFormation palvelun kanssa tullaan käyttämään Sceptre työkalua. Sceptre
helpottaa CloudFormation mallien hallintaa ja tarjoaa hyvät työkalut
ympäristöjen luomiseen nopeasti. Muita ohjelmia, joita hyödynnetään
harjoitusympäristössä, on AWS CLI ja kubectl. AWS CLI tarjoaa komentoriviltä
kommunikoinnin AWS ympäristöön. Kubectl on komentorivi työkalu, jonka avulla
kommunikoidaan K8s klusterin ohjaamon kanssa. Kaikki K8s konfiguraatiotiedostot
on YAML muodossa harjoituksessa. Kaikki konfiguraatio tiedostot lähetetään
ohjaamoon kubectl komennolla kubectl apply -f \<tiedoston nimi\>.

### Virtuaaliverkko

Harjoitusympäristölle luodaan VPC -verkko. Verkko pitää sisällään kaksi julkista
aliverkkoa ja kaksi suljettua. VPC -verkon luomista varten luodaan
CloudFormation mallitiedosto. Mallitiedosto aloitetaan ilmoittamalla mitä AWS
formaatti versiota käytetään (Kuva 9). Harjoituksessa käytetään uusinta
versiota, eli 2010-09-09. Parameters: -otsikon alle kuvaillaan minkä nimisiä
muuttujia mallitiedostossa käytetään. Kyseisessä mallitiedostossa käytetään
muuttujia Project ja CidrBlock. Project muuttujan arvoksi tulee projektin nimi.
CidrBlock muuttujaa käytetään mallitiedoston ensimmäisessä resurssissa Vpc, joka
on tyyppiä AWS::EC2::VPC. Yksi AWS::EC2::VPC -tyyppisten resurssien vaadituista
arvoista on CidrBlock. Tämän arvo määrittelee koko VPC -verkon CIDR-notaation ja
samalla verkon IP avaruuden. Esimerkiksi arvo 10.20.0.0/16, rajaisi VPC-verkon
IP osoitteet 10.20.0.0 – 10.20.255.255 sisälle (Amazon Web Services, s.a (d)).

![](media/b798a4a1563e62636edc6db9a9c187de.png)

Kuva 9. VPC mallitiedoston alku

![](media/2d650629ba5bab185d2001e4d9a9dd3b.png)

VPC mallitiedostossa luodaan myös muita tarvittavia resursseja VPC -verkolle.
Muita resursseja ovat esimerkiksi kaksi (2) kappaletta julkisia aliverkkoa ja
kaksi (2) kappaletta suljettuja aliverkkoa (Kuva 10). Tämä kaikki toimii
harjoituksen perustuksena.

Kuva 10. Luotu VPC

### EKS klusteri

VPC -verkon luotua voidaan siirtyä sovelluksen K8s ohjaamon rakentamiseen.
Ohjaamolle tulee luoda IAM rooli, joka määrittelee EKS klusterin oikeudet. AWS
dokumentaation mukaan vähimmäisoikeudet EKS klusterin toiminnalle on kerätty
heidän luomalle

policy -listoille AmazonEKSClusterPolicy ja AmazonEKSServicePolicy (Amazon Web
Services, s.a. (a)).

Luotu rooli syötetään parametrina EKS mallitiedostossa (Kuva 11). EKS resurssi
omaksuu annetun roolin, joka annetaan RoleArn -arvoksi. EKS pystyy tämän jälkeen
tekemään vain toimintoja, joita roolin policy -listoille on määritelty. EKS
resurssille on tärkeä antaa SubnetIds arvoiksi suljettujen ja julkisten
aliverkkojen ID tunnisteet. Tällä tavoin EKS palvelulla on oikeus luoda
kuormantasaajia julkisille aliverkoille. Harjoituksessa ei valittu uusinta
tuettua K8s 1.12 versiota koska tämän tuki tuli äskettäin EKS palvelulle. AWS ei
myöskään ole omaa dokumentaatiotaan päivittänyt tämän mukaiseksi.

![](media/278736f44a1b675a7df3721c153a6748.png)

Kuva 11. EKS mallitiedosto

EKS mallitiedostojen resurssien luotua on projektiin luotu K8s ohjaamo.
Mallitiedostoon on määritelty ulostuloksi K8s klusterin nimi. Klusterin nimi on
tärkeä ottaa talteen, koska tätä tarvitaan silloin kun yhdistetään kätyrisolmut
mestariin ja kun ylläpitäjä muodostaa ensimmäisen kerran yhteyden ohjaamoon.

EKS klusterin ohjaamo tulee konfiguroida sallimaan yhteys järjestelmän
valvojalta. EKS klusteri voidaan konfiguroida nopeasti AWS CLI:n tarjoamalla
komennolla:

\<region\> tulee korvata klusterin AWS aluetunnuksella, esimerkiksi eu-west-1.
\<cluster_name\> korvataan klusterin nimellä. Mikäli komento palauttaa
virheviestin tulee järjestelmänvalvojan tarkistaa omat IAM oikeudet ja varmistaa
että oikeudet riittävät toimintoon. Järjestelmänvalvoja voi tarkistaa yhteyden
toimivuuden EKS klusterin ohjaamoon kubectl -komennolla. Komento palauttaa
tietoa klusterista, mikäli yhteys toimii.

### Kätyrisolmut

Kätyreitä luodessa tulee pitää mielessä tietoturva. Vaikka kätyrit luodaan VPC
-verkon suljettuun aliverkkoon, on hyvä käytäntö luoda securitygroup -resurssi.
Tällä resurssilla voidaan määritellä mistä voidaan ottaa yhteyttä
kätyrisolmuihin ja mihin portteihin yhteydenotto sallitaan. Kuvassa 12 luodaan
kaksi resurssia. Molemmat resurssit lisäävät säännön securitygroup -resurssiin.
AWS::EC2::SecurityGroupIngress -tyyppinen resurssi luo säännön tulevasta
liikenteestä. Vastaavasti AWS::EC2::SecurityGroupEgress luo säännön lähtevästä
liikenteestä. Mikäli lähtevä tai tuleva yhteys ei ole sääntöjen mukainen,
tiputetaan tämä pois ja yhteys ei koskaan pääse perille asti. GroupId
määrittelee resursseissa mitä securitygroup -resurssia sääntö koskee.
Resursseissa tulee määritellä mistä porteista liikenne sallitaan tai mihin
porttiin yhteys voi mennä määränpäässä. Harjoitusympäristössä sallitaan yhteys
kätyreistä ohjaamoon porteista 1025 – 65535 ja 443. AWS dokumentaatio
suosittelee käyttämään näitä portteja (Amazon Web Services, s.a (e)). Tässä
vaiheessa ei tarvitse vielä ajatella järjestelmävalvojan pääsystä ohjaamoon.

![](media/2578872ef8ead23af0c9da0b1de9807a.png)

Kuva 12. SecurityGroup sääntöjen määrittely mallitiedostossa

Kätyreitä voidaan luoda EKS klusteriin käsin, mutta tämä ei ole suositeltavaa
tuotanto käytössä. Tämä lisää riskiä inhimillisille virheille ja vaikeuttaa
klusterin skaalautumista nopeasti. AWS ympäristössä on mahdollista ryhmittää
pilvipalvelininstanssit yhdeksi ryhmäksi Auto Scaling Group:illa (lyh. ASG).
ASG:ssa voidaan määrittää instansseihin liittyviä konfiguraatioita, kuten
minkälaisia instansseja halutaan, kuinka monta pilvipalvelininstanssia voi olla
samanaikaisesti päällä ja kuinka monta voi olla vähimmillään. Tämän lisäksi ASG
konfiguraatioon voidaan lisätä bash -scripti, joka ajetaan aina kun instanssi
luodaan. Jokainen ASG:n luoma instanssi on käynnistyessä samanlaisia. Jokainen
instanssin saa saman IAM roolin, joka määrittelee mitä oikeuksia instansseilla
on.

Harjoituksessa ASG käynnistää kaksi (2) instanssia heti ja ajaa kummassakin bash
-scriptin. Kyseinen bash -scripti käynnistää kubelet -komponentin, joka yrittää
jatkuvasti ottaa yhteyttä klusterin ohjaamoon. Yhteydenotto ei onnistu ennen
kuin ohjaamolle ilmoitetaan mitä IAM roolia instanssit käyttävät. Tiedon
ilmoittaminen ohjaamolle tapahtuu konfiguraatiotiedostolla (Kuva 13).
Tiedostossa tulee vain korvata rolearn arvoksi instanssien IAM rooli tunnus
(Amazon Web Services, s.a (f)).

![](media/f93959ef0567897a354f371454b6b528.png)

Kuva 13. EKS klusterille kätyrisolmujen yhdistämistiedosto

![](media/454230ea061f48e8890e4b79a222fb8f.png)

Tässä kohtaa harjoitusympäristöön on luotu VPC -verkko, EKS klusteri ja kaksi
(2) kappaletta kätyrisolmuja (Kuva 14). Kätyrit ovat konfiguroitu kommunikoimaan
EKS ohjaamon kanssa ja järjestelmänvalvojakin pystyy ottamaan yhteyttä
ohjaamoon. Järjestelmänvalvoja voi tarkistaa yhdistyneiden ohjaamoiden tilan
kubectl komennolla kubectl get nodes

Kuva 14. Harjoitusympäristön välikatsaus kaaviolla

### Sovelluskontin rakentaminen

Sovelluksien vieminen K8s ympäristöön tapahtuu konfiguraatiotiedostolla (Kuva
15). Konfiguraatiotiedostoon tulee asettaa tyypiksi Deployment. Tämä kertoo
ohjaamolle, että kyseessä on sovelluksen luonti tai päivitys. Ohjaamo osaa
automaattisesti luoda tarvittavat komponentit sovellukselle, esimerkiksi
kapselit. Koko konfiguraatiotiedostolle voi asettaa yleistietoja ylimpään
metadata -kenttään. spec.template sisälle määritellään sovellukselle nimi, joka
leimataan kaikkiin sovelluksen kapseleihin. spec.selector -kenttään määritellään
vastaavasti minkä nimisiä kapseleita korvataan/muutetaan, mikäli näitä on jo
olemassa. Kaikki klusterissa käynnissä olevien ohjelmien nimet ja kapselien
lukumäärän saa selville kubectl komennolla kubectl get deploy.

![](media/d8145a6368b0bd0b4d7af30cda5fe828.png)

Kuva 15. Harjoitussovelluksen deployment konfiguraatio

### Kuormantasaaja

Vaikka sovellus on luotu harjoitusympäristöön, ei voida siihen ottaa yhteyttä
klusterin ulkopuolelta. Harjoitussovellus tarvitsee palvelu-objektin, jotta
tähän voi ottaa yhteyttä klusterin ulkopuolelta. Kappaleessa [3.2.3
Service](#service) käydään läpi erilaisia palvelu-objektin tyyppejä. Yksi
mainituista tyypeistä on *LoadBalancer*. Harjoitusympäristössä käytetään
kyseistä tyyppiä. EKS luo automaattisesti LoadBalancer tyyppisen
palvelu-objektin julkiselle aliverkolle. Mikäli EKS ei löydä yhtään julkista
aliverkkoa klusterin verkosta, palauttaa tämä virhe ilmoituksen. Palvelu-objekti
luodaan K8s konfiguraatiotiedostolla. Konfiguraatiotiedostoon tulee määritellä
minkä nimiselle sovellukselle palvelu-objektia luodaan, mitä protokollaa
käytetään ja mikä portti avataan ulkoverkkoon.

Harjoitusympäristössä sovellus on HTTP -sivusto, joten portti 80 avataan
palvelu-objektissa ulkoverkkoon.

Kun sovelluksen kuormantasaaja on luotu, näkyy tämä AWS konsolissa. Konsolista
löytää myös kuormantasaajan DNS osoitteen, jonka kautta pääsee ottamaan yhteyttä
sovellukseen. Kun osoitetta haetaan selaimesta, avautuu sovelluksen sivusto
(Kuva 16). Koska kuormantasaaja ohjaa liikenteen eri konteille, palautuu
sivuston mukana eri konttien nimet, vaikka DNS osoite on sama.

![](media/692cde9cf587abaf12c3b0ceca6dfe78.png)

![](media/14442a73bb3b947d48e137778826bf4d.png)

Kuva 16. Harjoitussovelluksen avaaminen selaimella

### Klusterin skaalautuminen

AWS on luonut valmiin EKS konfiguraatiotiedoston, jolla voidaan skaalata
klusterin kätyrisolmujen määrää
(<https://eksworkshop.com/scaling/deploy_ca.files/cluster_autoscaler.yml>).
Konfiguraatiotiedoston lopussa on command -kenttä, jossa määritellään
parametreja klusterin automaatti skaalaamiselle (Kuva 17). Viimeinen rivi
kyseisessä kentässä määrittelee automaatti skaalaamisen rajat ja mitä ASG
resurssia käytetään. Järjestelmävalvojan ei tarvitse konfiguraatio tiedostossa
muita arvoja muuttaa, kuin command -kentän viimeisen parametrin arvot.

![](media/7fc7955fbb71ed0a79f6bf6a084fee44.png)

Kuva 17. Automaatti skaalaamisen parametrit

command -kentän viimeinen parametri selitettynä:

-   Punainen

    -   Vähimmäisinstanssien lukumäärä yhtäaikaisesti ajossa

        -   Tämä tulee olla sama tai suurempi kuin ASG:ssä määritelty

-   Keltainen

    -   Enimmäisinstanssien lukumäärä yhtäaikaisesti ajossa

        -   Tämä tulee olla sama tai pienempi kuin ASG:ssä määritelty

-   Sininen

    -   ASG resurssin nimi

Konfiguraatiotiedostossa luodaan yhden replikan sovellus nimeltä
*cluster-autoscaler.* Sovellukselle annetaan konfiguraatiotiedostossa lupa
käyttää ohjaamon rajapintaa hyödyksi, jotta tämä saisi tarvittavat tiedot
kätyrisolmuista ja muista sovelluksista klusterissa. Näiden tietojen perusteella
sovellus skaalaa klusteria ylöspäin ja alaspäin automaattisesti hyödyntäen
kätyrisolmujen ASG:ta. *Cluster-autoscaler* -sovellusta ajetaan normaalisti
kätyrisolmuissa. Tämä tarkoittaa, sitä että kätyrisolmun IAM rooleissa tulee
olla oikeus hallinnoida ASG:tä.

Kun konfiguraatiotiedosto on lähetetty klusterin ohjaamolle, voidaan
harjoitussovelluksen replikaatioiden määrää nostaa. Replikaatioiden määrän
nostaminen tapahtuu kappaleessa [5.2.4](#sovelluskontin-rakentaminen) luodun
deployment konfiguraatiotiedoston replicas arvoa muuttamalla.

Pian replikaatio määrän nostamisen jälkeen voidaan huomata, että uusien
kapseleiden luominen pysähtyy (Kuva 18). K8s klusterin ohjaamo jää odottamaan
vapautuvia resursseja tai uusia kätyrisolmuja, johon jonossa olevat kapselit
voidaan sijoittaa.

![](media/99f81c0dc7a03cca3285b680bfce0a1c.png)

Kuva 18. Harjoitussovelluksen replikaatio jono

*Cluster-autoscaler* -sovellus huomaa, että klusterin ohjaamolle on muodostunut
jono. Sovellus skaalaa automaattisesti ASG ryhmää ylöspäin ja luo samalla
tarvittavan määrän uusia kätyrisolmuja, jotta jono saadaan purettua. Kuvasta 19
nähdään, että automaatti skaalaaja on luonut yhteensä neljä (4) instanssia lisää
alkuperäisen kahden (2) instanssin avuksi. Kaikki viisikymmentä kapselia on
luotu kätyrisolmuihin ja jokaiseen kapseliin on mahdollista ottaa yhteys
kuormantasaajan kautta.

![](media/50838cccfea975001376a651cdec561d.png)

![](media/45bd8e72f377d7a8cdf2eea6de741199.png)

Kuva 19. Klusterin tila automaatti skaalaamisen jälkeen

*Cluster-autoscaler* -sovellus skaalaa klusteria alaspäin myös automaattisesti.
Tämä tunnistaa kätyrisolmut, joissa ei ole kapseleita ajossa. Sovellus odottaa
noin kymmenen (10) minuuttia ennen kuin sammuttaa instanssin.

Pohdinta
========

EKS vahvuudet (ei vielä valmis)
-------------------------------

-   EKS tarjoaa paljon hallintaa kätyrisolmuihin.

-   mestarit ovat HA

    -   Kannustaa jakamaan kätyrit usealle saatavuusalueelle

-   Toimii hyvin muiden AWS resurssien kanssa

-   mukautettava VPC ympäristö

-   Klusterissa mahdollista erilaisia kätyrisolmuja

EKS on hyvä palvelu, mikäli haluaa paljon hallintaa omassa ympäristössään.

EKS heikkoudet (ei vielä valmis)
--------------------------------

-   AWS käyttäjille max 3 klusteria / tili (mahdollista pyytää lisää ottamalla
    yhteyttä)

-   Mestari maksaa (\$0.20 / 1h)

    -   Muu infrastruktuuri klusterissa maksaa myös

-   Enemmänkin ”master as a service”

    -   Kätyrisolmut tulee käyttäjän luoda itse ja liittämään klusteriin

    -   Kätyreiden tietoturvapäivitykset ja autoscaling on myös käyttäjän
        vastuulla

-   Liikaa hallintaa (?)

-   DIY ratkaisu KOPS parempi (?)

<br>Lähteet
===========

>   Acreman, S. s.a. Kubernetes Cloud Services. Luettavissa:
>   <https://kubedex.com/google-gke-vs-microsoft-aks-vs-amazon-eks/>. Luettu
>   19.3.2019

>   Ali, S. 2018. Kubernetes Design and Development Explained. Luettavissa:
>   <https://thenewstack.io/kubernetes-design-and-development-explained/>.
>   Luettu: 18.2.2019

>   Amazon Web Services, 2018a. Amazon EKS – Now Generally Available.
>   Luettavissa:
>   <https://aws.amazon.com/blogs/aws/amazon-eks-now-generally-available/>.
>   Luettu 06.03.2019

>   Amazon Web Services, s.a (a). Amazon EKS Service IAM Role. Luettavissa:
>   [https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html](https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html.%20Luettu%2013.03.2019).
>   Luettu 13.03.2019

>   Amazon Web Services, s.a (b). Cluster VPC Considerations. Luettavissa:
>   <https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html>. Luettu
>   18.03.2019

>   Amazon Web Services, s.a (c). AWS Resource and Property Types Reference.
>   Luettavissa:
>   [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html.
>   Luettu
>   22.04.2019](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html.%20Luettu%2022.04.2019)

>   Amazon Web Services, s.a (d). AWS::EC2::VPC. Luettavissa:
>   [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc.html.
>   Luettu
>   29.04.2019](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc.html.%20Luettu%2029.04.2019)

>   Amazon Web Services, s.a (e). Cluster Security Group Considerations.
>   Luettavissa:
>   [https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html.
>   Luettu
>   01.05.2019](https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html.%20Luettu%2001.05.2019)

>   Amazon Web Services, s.a (f). Launching Amazon EKS Worker Nodes.
>   Luettavissa:
>   <https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html>.
>   Luettu 02.05.0219

>   Arundel, J & Domingus, J. 2019. Cloud Native DevOps with Kubernetes.
>   O’Reilly Media, Inc. Sebastopol

>   Baier, J. 2017. Getting Started with Kubernetes. Packt Publishing Ltd.
>   Birmingham

>   Bala, E. 1.12.2017. Software Development Manager, Amazon Elastic Container
>   Services for Kubernetes Deep Dive. Amazon Web Services. Seminaariesitys. Las
>   Vegas. Nähtävissä: <https://youtu.be/vrYLrx-a_Wg>

>   DigitalOcean, 2018. Kubernetes Overview. Luettavissa:
>   <https://www.digitalocean.com/docs/kubernetes/overview/>. Luettu 20.3.2019

>   Docker, s.a. What is Container. Luettavissa:
>   <https://www.docker.com/resources/what-container>. Luettu: 12.01.2019

>   Gupta, A. 2017. Why is Kubernetes so popular? Luettavissa:
>   <https://opensource.com/article/17/10/why-kubernetes-so-popular>. Luettu:
>   19.01.2019

>   Haider, H. 2019. DigitalOcean Managed Kubernetes: An Interview with the
>   Experts. Luettavissa:
>   [https://www.replex.io/blog/digitalocean-managed-kubernetes-an-interview-with-the-experts.
>   Luettu
>   20.3.2019](https://www.replex.io/blog/digitalocean-managed-kubernetes-an-interview-with-the-experts.%20Luettu%2020.3.2019)

>   Hakkarainen, P. 2018. Docker, Kubernetes, SUSE CaaS Platform – musiikkia
>   kontilleni. Luettavissa:
>   <https://susesuomi.fi/ajankohtaista/uutiset/3/10/2018/docker-kubernetes-suse-caas-platform-musiikkia-kontilleni/>.
>   Luettu: 12.01.2019

>   Hightower, K., Burns, B. & Beda, J. 2017. Kubernetes Up & Running. O’Reilly
>   Media, Inc. Sebastopol

>   Jayanandana, N. 2018. Benefits of Kubernetes. Luettavissa:
>   <https://medium.com/platformer-blog/benefits-of-kubernetes-e6d5de39bc48>.
>   Luettu: 22.2.2019

>   Kubernetes 2018a. What is Kubernetes? Luettavissa:
>   <https://kubernetes.io/docs/concepts/overview/what-is-kubernetes/>. Luettu:
>   12.01.2019

>   Kubernetes, 2018b. Resizing a cluster. Luettavissa:
>   <https://kubernetes.io/docs/tasks/administer-cluster/cluster-management/>.
>   Luettu 20.2.2019

>   Kubernetes, 2018c. Services. Luettavissa:
>   <https://kubernetes.io/docs/concepts/services-networking/service/>. Luettu
>   20.2.2019

>   Kubernetes, 2018d. Running Multiple Instances of Your App. Luettavissa:
>   <https://kubernetes.io/docs/tutorials/kubernetes-basics/scale/scale-intro/>.
>   Luettu 20.2.2019

>   Kubernetes, 2019a. Kubernetes Components. Luettavissa:
>   <https://kubernetes.io/docs/concepts/overview/components/>. Luettu: 9.2.2019

>   Kubernetes, 2019b. Options for Highly Available Topology. Luettavissa:
>   <https://kubernetes.io/docs/setup/independent/ha-topology/#what-s-next>.
>   Luettu: 2.2.2019

>   Kubernetes, 2019c. Pod Lifecycle. Luettavissa:
>   <https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/>. Luettu:
>   20.2.2019

>   Kublr, 2017. Under the Hood: An Introduction to Kubernetes Acrhitecture.
>   Luettavissa:
>   <https://kublr.com/blog/under-the-hood-an-introduction-to-kubernetes-architecture/>.
>   Luettu: 9.2.2019

>   Lardinois, F. 2015. As Kubernetes Hits 1.0, Google Donates Technology To
>   Newly Formed Cloud Native Computing Foundation. Luettavissa:
>   <https://techcrunch.com/2015/07/21/as-kubernetes-hits-1-0-google-donates-technology-to-newly-formed-cloud-native-computing-foundation-with-ibm-intel-twitter-and-others/>.
>   Luettu: 19.01.2019

>   Microsoft Azure, 2019. Kubernetes core concepts for Azure Kubernetes Service
>   (AKS). Luettavissa:
>   <https://docs.microsoft.com/en-us/azure/aks/concepts-clusters-workloads#cluster-master>.
>   Luettu 20.3.2019

>   Nadareishvili, I., Mitra, R., McLarty, M. & Amundsen, M. 2016. Microservice
>   Architecture. O’Reilly Media, Inc. Sebastopol

>   Openstack, 2018. How to run a Kubernetes cluster in OpenStack. Luettavissa:
>   <https://superuser.openstack.org/articles/how-to-run-a-kubernetes-cluster-in-openstack/>.
>   Luettu 19.3.2019

>   Paraiso, F., Challita, S., Al-Dhuraibi, Y. & Merle P. 2016. Model-Driven
>   Management of Docker Containers. University of Lille & inria Lille. France

>   Ravindra, S. 2018. Kubernetes vs. Docker Swarm: What’s the Difference?
>   Luettavissa:
>   <https://thenewstack.io/kubernetes-vs-docker-swarm-whats-the-difference/>.
>   Luettu 21.3.2019

>   Rize, L. 2017. Container Image Immutability and the Power of Metadata.
>   Luettavissa:
>   <https://blog.codeship.com/container-image-immutability-power-metadata/>.
>   Luettu: 16.2.2019

>   Sandeep, D. 2018. Kubernetes NodePort vs LoadBalancer vs Ingress? When
>   should I use what? Luettavissa:
>   <https://medium.com/google-cloud/kubernetes-nodeport-vs-loadbalancer-vs-ingress-when-should-i-use-what-922f010849e0>.
>   Luettu 21.3.2019

>   Sanders, S. 2018. How Kubernetes improves IT’s operational efficency.
>   Luettavissa:
>   <https://jaxenter.com/kubernetes-improves-efficiency-147699.html>. Luettu:
>   23.2.2019

>   Sarkar, A & Shah, A. 2018. Learning AWS second Edition. Packt Publishing
>   Ltd. Birmingham

>   Sayfan, G. 2017. Mastering Kubernetes. Packt Publishing Ltd. Birmingham

>   Selvan, T. 2018. GKE vs AKS vs EKS. Luettavissa:
>   <https://blog.hasura.io/gke-vs-aks-vs-eks-411f080640dc/>. Luettu 20.3.2019

>   Yegulalp, S. 2019. What is Kubernetes? Container orchestration explained.
>   Luettavissa:
>   [https://www.infoworld.com/article/3268073/kubernetes/what-is-kubernetes-container-orchestration-explained.html](https://www.infoworld.com/article/3268073/kubernetes/what-is-kubernetes-container-orchestration-explained.html.).
>   Luettu: 31.01.2019

Liitteet
========

![](media/bb1df4f70a3f1f9ef013928e08a7fd4a.png)

**Liite 1. GKE, AKS, EKS vertailu taulu (Acreman, S. s.a.)**

![](media/ed3c1c40b68ba4f40db15529d5443dec.gif)
