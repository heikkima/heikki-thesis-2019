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

[2 Kubernetes 2](#kubernetes)

[2.1 Kuberneteksen tausta 2](#kuberneteksen-tausta)

[2.2 Kuberneteksen arkkitehtuuri 3](#kuberneteksen-arkkitehtuuri)

[2.2.1 Master node 3](#master-node)

[2.2.2 Pod 5](#pod)

[2.2.3 Service 6](#service)

[2.2.4 Minion node 7](#minion-node)

[2.3 Kuberneteksen hyödyt 8](#kuberneteksen-hyödyt)

[2.3.1 Nopeus 8](#nopeus)

[2.3.2 Skaalautuvuus 9](#skaalautuvuus)

[2.3.3 Infrastruktuurin abstrahointi 11](#infrastruktuurin-abstrahointi)

[2.3.4 Tehokkuus 11](#tehokkuus)

[3 Amazon Elastic Container Service for Kubernetes
11](#amazon-elastic-container-service-for-kubernetes)

[3.1 AWS EKS tausta 11](#aws-eks-tausta)

[3.2 EKS toiminta AWS ympäristössä 12](#eks-toiminta-aws-ympäristössä)

[3.3 Kilpailijat 13](#kilpailijat)

[Lähteet 16](#lähteet)

[Liitteet 20](#_Toc3914231)

Johdanto
========

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
Docker-levykuvaksi (Docker image). Hakkaraisen (2018) mukaan sovellus tulee
kuitenkin pilkkoa pienempiin mikropalveluihin ennen paketointia. Mikropalvelut
ovat jaettuja kokonaisuuksia sovelluksesta. Jokaisella mikropalvelulla on oma
tehtävänsä ja nämä kommunikoivat keskenään tarvittaessa (kuva 1). Jokaisen
mikropalvelun tulee olla itsenäisesti hallittavissa ja muutettavissa.
Paketoidusta mikropalvelusta voidaan käynnistää kontti (container) missä tahansa
käyttöjärjestelmässä, kunhan tämä tukee Docker teknologiaa. Kontit ovat hyvin
kevyitä ja yhdessä isäntäkoneessa (host) voidaan ajaa samanaikaisesti useita
kontteja. Teknologian etuna on sovellusten yksinkertainen pakkaaminen ja
monistaminen erilaisiin ympäristöihin. Tämä nopeuttaa sovelluksen julkaisemista
tuotantoon, ja tuotannossa tämän skaalaamista (Docker, s.a.).

Kuva 1. Mikropalvelut (mukailen Nadareishvili, Mitra, McLarty, & Amundsen, 2016)

Google julkaisi K8s projektin avoimena lähdekoodina vuonna 2014. Google ja Linux
-säätiö perustivat yhdessä Cloud Native Computing -säätiön (Cloud Native
Computing Foundation, CNCF), jolle Google lahjoitti K8s:n hallittavakseen vuonna
2015 (Lardinois, 2015). K8s on konttiorkestrointityökalu (Container
orchestration tool) jonka tarkoituksena on tarjota alusta ja työkalut konttien
keskitettyyn hallintaan. Tämän avulla voidaan hallita useista isäntäkoneista
muodostunutta klusteria (cluster), sovelluksien välisiä verkkoyhteyksiä ja
näiden skaalaamista nopeasti ja helposti. Muita samantyylisiä alustoja ovat
esimerkiksi Amazon Elastic Container Service (AWS ECS) ja Docker Swarm. K8s:ia
käytetään useimmiten Dockerin konttien kanssa. K8s kuitenkin tukee myös muita
kontti järjestelmiä, jotka täyttävät Open Container Initiative (OCI) standardit
(Yegulalp, 2019; Kubernetes, 2018a).

*AWS ECS* on Amazonin pilvipalvelualustalla toimiva konttiorkestrointityökalu.
AWS ECS hyödyntää AWS ympäristössä jo olemassa olevia resursseja esimerkiksi
pilvi-instanssit EC2 ja näiden automaatti skaalaus työkalua. AWS ECS ajaa
kontteja pilvi-instanssin sisällä ja tarjoaa työkalut konttien hallintaan AWS
konsolin tai AWS rajapinnan avulla. AWS ECS skaalaa kontteja tarvittaessa
ylöspäin/alaspäin automaattisesti. Automaattiskaalaus noudattaa skaalaamisessa
ennalta määrättyjä sääntöjä, jotka määrittelevät vähimmäis- ja enimmäismäärän
konteille. Mikäli resurssit loppuvat pilvi-instanssilta voidaan instanssien
määrää myös skaalata ylös päin tai alas päin. AWS ECS on saatavilla vain Amazon
Web Services ympäristössä (Sarkar & Shah. 2018)*.*

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
Microsoft ja Amazon Web Services. Tämän lisäksi CNCF:llä on omia tukijoita
esimerkiksi Oracle ja SAP.

Moni pilvipalvelun tarjoaja on ottanut K8s:n tuotteekseen, esimerkiksi
Microsoftin Azure Kubernetes Service (AKS), Google Kubernetes Engine (GKE) ja
Amazon Elastic Container Service for Kubernetes (AWS EKS). Pilvipalvelun
tarjoajat voivat hyödyntää K8s avointa lähdekoodia ja luoda lisäominaisuuksia
palvelulleen. Tämä parantaa palvelun käyttökokemusta ja mahdollistaa K8s
palvelun liittämisen tarjoajan omaan ekosysteemiin. Tämän lisäksi
palveluntarjoajat voivat hyödyntää olemassa olevia työkaluja, joita K8s yhteisö
on luonut ja jakanut.

Kuberneteksen arkkitehtuuri
---------------------------

K8s koostuu klusterista. Klusteri muodostuu monesta koneesta (fyysisestä tai
virtuaalisesta), joissa ajetaan K8s ohjelmaa. Koneita voidaan liittää
jälkikäteen järjestelmään helposti, mikäli järjestelmän resurssit eivät riitä.
Klusterin sisällä on yksi tai useampia mestarisolmuja (master node) ja useita
kätyrisolmuja (minion node) (Kubernetes 2019a). Tässä kappaleessa käymme läpi
muutamaa isompaa komponenttia K8s:n klusterissa. Näiden lisäksi K8s sisältää
pienempiä mutta silti tärkeitä komponentteja.

### Master node

Mestarisolmu toimii klusterin ohjaamona (control plane). Ohjaamossa päätetään
klusterin asioista, kuten esimerkiksi ajastetuista tehtävistä ja klusterin
muutoksiin liittyvissä asioissa. Mestarisolmut koostuvat useista eri mestari
komponenteista (master components). Näitä komponentteja ovat kube-apiserver,
kube-scheduler, kube-controller-manager ja etcd. Komponentit voidaan jakaa
usealle koneelle, mutta yksinkertaisuuden vuoksi komponentit ovat yleensä
samassa koneessa (pois lukien etcd, tästä lisää seuraavassa kappaleessa)
(Kubernetes 2019a; Arundel & Domingus, 2019).

*Kube-apiserver* on klusterin ulkopuolelle näkyvä rajapinta. Rajapintaan tehdään
kutsuja ja lähetetään haluttuja muutoksia klusteriin. Kätyrisolmut käyttävät
myös kyseistä rajapintaa kommunikoidessaan mestarisolmun kanssa. *Etcd* on
klusterin oma tietokanta. Klusterin rajapinta, Kube-apiserver, tallentaa datan
avain-arvo (key-value) pareina tietokantaan. Tietokantaan tallennetaan muun
muassa klusterin nykyinen tila ja haluttu tila. K8s klusteri käyttää etcd
tietokantaa totuuden lähteenä (source of truth). On tärkeää luoda
varmuuskopioita etcd tietokannasta. K8s dokumentaatio suosittelee luomaan etcd
komponentille oman klusterin. Etcd klusteri voi olla K8s klusterin sisällä tai
ulkopuolella (kuva 2). *Kube-scheduler* tarkkailee, jos uusia kapseleita (pod.
Komponentti, joka pitää sisällään kontteja) luodaan ja ohjaa nämä oikeisiin
kätyrisolmuihin. Kube-scheduler valitsee kapseleille sopivia kätyrisolmuja ja
osaa ottaa huomioon näiden resurssi- ja muut vaatimukset.

*Kube-controller-manager* komponentti hallinnoi ja tarkkailee klusterin tilaa.
Tämä hakee nykyisen ja halutun tilan etcd tietokannasta kube-apiserverin kautta,
ja muuttaa klusteria haluttuun suuntaan, mikäli se on erilainen.
Kube-controller-manager käyttää klusterin tarkkailuun erilaisia valvojia
(controller). Jokaisella valvojalla on oma tehtävänsä ja tarkkailu kohteensa.
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
monta, kun rakennetaan korkeankäytettävyyden (highly available, lyhenne HA)
klusteria. HA klusterissa yksi kone kerrallaan toimii mestarina. Mestari ajaa
ajastettuja tehtäviä ja ohjaa muita koneita klusterissa. HA:n ideana on
ylläpitää sovelluksen hallintaa mestari koneella, myös silloin kun yksi
mestareista kaatuu esimerkiksi laitevian vuoksi. Työkoneet (minion nodes)
ottavat mestariin yhteyttä kuormantasaajan (loadbalancer) kautta (kuva 2).
Kuormantasaaja ohjaa liikenteen mestarille, jonka tämä tunnistaa olevan pystyssä
(Kubernetes 2019b; Arundel & Domingus, 2019).

![](media/a604d9ce2211b3e62f6f8eeb9b7fe16e.png)

Kuva 2. Vasemmalla sisänen etcd klusteri. Oikealla ulkoinen etcd klusteri
(mukailen Kubernetes 2019a).

### Pod

Kapseli (pod) muodostuu usein miten yhdestä kontista. On kuitenkin mahdollista
luoda kapseli useammasta hyvin tiiviiksi kytketyistä konteista, jotka ovat hyvin
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
palvelu-objekti (service), jonka tehtävänä on ratkaista kyseinen ongelma.
Palvelu-objekti on abstraktinen käsite, joka pitää sisällään tiedon yhden
sovelluksen olemassa olevista kapseleista ja miten näihin kapseleihin saa
yhteyden. Palvelu-objekteja tulee siis luoda jokaiselle sovellukselle oma.
Palvelu-objektin oletus tyyppi on ClusterIP. Muita palvelu-objektin tyyppejä on
NodePort ja LoadBalancer. *ClusterIP* tyyppinen palvelu-objekti saa itselleen
sisäisen IP-osoitteen. IP-osoitetta voidaan kutsua vain klusterin sisältä (kuva
3). Palvelu-objektissa on sisäänrakennettu kuormantasaaja, joka lähettää
yhteyden vain saatavilla oleville kapseleille

![](media/8b02216fabb9bd0072ad3bc06a1efad3.png)

Kuva 3. Palvelu-objekti ClusterIP

*NodePort* tyyppinen palvelu-objekti näkyy K8s klusterin ulkopuolelle.
Palvelu-objekti avaa jokaisen klusterin kätyrisolmusta saman portin (kuva 4).
Kätyrisolmu ohjaa portista tulevan liikenteen ClusterIP objektille (ClusterIP
objekti, luodaan automaattisesti NodePort palvelu.objektin kanssa).

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
versiossa 1.0 kube-proxy:llä on vain yksi välitys tila (proxy-mode),
”*userspace*”. Tässä tilassa komponentin tehtävä on ohjata klusteri IP:stä
tullut kutsu tälle tarkoitetulle kapselille (kuva 5). Kube-proxy tarkkailee
uusia ja poistettavia palvelu-objekteja. Jos uusi palvelu-objekti luodaan.
Komponentti avaa sattumavaraisen portin kätyrisolmussa tälle palvelulle. Kun
klusteri IP:stä tulee kutsu komponenttiin avatun portin kautta, ohjaa tämä
yhteyden oikealle kapselille. Kube-proxy saa tiedon kenelle yhteys kuuluu etcd
tietokannasta kommunikoimalla mestari rajapinnan kanssa. Mikäli kapseleita oli
useampi, määräytyi yhteys round robin -säännön mukaisesti (kiertovuorottelu).
K8s version 1.1 mukana tuli uusi välitys tila kube-proxy:lle nimeltään
”iptables”. Tässä tilassa kube-proxy tarkkailee mestarisolmua. Jos mestari luo
tai poistaa uuden palvelu-objektin, kube-proxy muuttaa oman koneensa IP taulua
(iptables, palomuuri Linux-kerneleissä. Iptablesissa voi luoda filtteröinti
sääntöjä IP-paketeille ja NAT sääntöjä) (kuva 5). Tällä tavoin kube-proxy ohjaa
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
Nopeuden mahdollistaa kontteihin pakattujen sovelluksien muuttumaton
(immutability) rakenne, K8s konfiguraatioiden selittävä (deklaratiivinen)
muotoilu, ja K8s:n automaattinen valvonta.

Sovelluksen *muuttumaton* rakenne perustuu siihen, miten kontteja rakennetaan.
Kontit luodaan konttilevykuvasta (image). Kun sovellusta päivitetään ja luodaan
uusia ominaisuuksia, luodaan lopputuotteesta uusi levykuva. Uudesta levykuvasta
käynnistetään kontti. K8s odottaa, että uusi kontti on käynnissä ja terve ennen
kuin alkaa sammuttamaan vanhaa konttia. Tämän avulla palveluun ei muodostu
katkoksia. Jo luotuja levykuvia ei ole tarkoitus muuttaa vaan joka kerta tulisi
luoda uusi levykuva. On etuna muun muassa siinä, kun vanha versio sovelluksesta
pitäisi palauttaa. Kontti pitää vain käynnistää vanhalla levykuvalla. (Rize,
2017; Arundel & Domingus, 2019).

K8s konfiguraatio tiedostot kirjoitetaan YAML tai JSON tiedostoina. Tiedostoihin
ei kirjoiteta komentoja mitä K8s tulisi tehdä. Konfiguraatio tiedostoon
kuvaillaan deklaratiivisesti, millainen ympäristö halutaan. K8s lukee tiedoston
ja päättää miten toimitaan, jotta päästään haluttuun tilaan. Esimerkiksi jos
halutaan kaksi kopiota (replicas) samasta kapselista, kirjoitetaan replicas: 2
konfiguraatiotiedostoon. Konfiguraation kirjoittajan ei tarvitse kirjoittaessa
tietää montako kopiota on jo olemassa, jotta pääsisi haluttuun tilaan.
Vastaavasti jos samaan lopputulokseen halutaan päästä käyttämällä komentoja
imperatiivisesti (imperative). Tulisi komentojen kirjoittaja tietää montako
kopiota on jo olemassa sillä hetkellä, jotta voidaan päätellä, tuleeko
ympäristöstä poistaa vai lisätä kapseleita (Ali, 2018).

K8s valvoo jatkuvasti klusteria ja korjaa itse itseään. Tämä kykenee
tunnistamaan automaattisesti muutoksia ympäristössä ja pystyy toimimaan heti
korjatakseen muutoksen. Hyvänä esimerkkinä on replikaatio valvoja (replication
controller). Kyseinen valvoja tarkistaa tietyin väliajoin ympäristössä käynnissä
olevien konttien lukumäärää. Mikäli valvoja huomaa konttien määrän olevan liikaa
tai liian vähän. Käynnistää tämä uuden työn, jonka tehtävänä on saada ympäristön
konttien lukumäärän samaksi kuin konfiguraatiotiedoston halutussa tilassa
(Sayfan, 2017).

### Skaalautuvuus

Kun sovellus siirtyy tuotantoon, tulee sovelluksen pystyä skaalautumaan nopeasti
ja huomaamattomasti sovelluksen käyttäjille. Suorituskyvyn pullonkaulana voi
olla esimerkiksi yhden mikropalvelun kontti. Konttien lukumäärää voidaan K8s:sa
lisätä muuttamalla kapselien määrää konfiguraatiotiedossa. Tämän voi kuitenkin
myös tehdä automaattisesti K8s:sa automaattiskaalauksella (autoscaling).
Skaalaaja kykenee automaattisesti skaalaamaan kapseleita horisontaalisesti
annettujen sääntöjen puitteissa. Automaattiskaalaaja ei itse luo tai poista
kopioita kapseleista. Vaan tämä kommunikoi replikaatio valvojan kanssa, joka
sitten luo tai poistaa kapseleita (kuva 6). Näin kapseleiden skaalaus ei luo
konflikteja replikaatiovalvojan kanssa. Uudet kapselit käynnistetään vierekkäin
jakaen sovelluksen kuormaa. Automaattiskaalaajalle voi määrittää metriikkaa,
jonka perusteella tämä skaalaa kapseleita ylös tai alaspäin. Metriikka voi olla
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
automaattisesti, mikäli K8s käynnistetään koneissa --register-node lipulla
(flag). (Kubernetes, 2018b).

Moni pilvipalveluntarjoaja kuten Google Cloud, Amazon Web Services ja Microsoft
Azure tarjoaa hyvät työkalut K8s klusterin skaalaamiseen. Edellä mainituilla
palveluntarjoajilla on mahdollista skaalata K8s klusteria automaattisesti.
Klusterin automaattinen skaalautuminen tapahtuu, kun palvelu tunnistaa
mestarisolmun yrittävän luoda uuden kapselin, mutta resurssit eivät riitä tai
eivät vastaa kapselin vaatimuksia. Tällöin palvelu liittää uuden koneen K8s
klusteriin ennalta määrättyjen sääntöjen mukaisesti. Vastaavasti palvelut
osaavat skaalata klusteria myös alaspäin (Arundel & Domingus, 2019).

Tutkimuksessa tulemme vielä tutkimaan Amazon Web Services (AWS):n tarjoamaa
Amazon Elastic Container Service for Kubernetes (EKS) palvelua syvemmin.

### Infrastruktuurin abstrahointi

K8s ei ole riippuvainen alla olevasta infrastruktuurista. Tämä on nähty yhtenä
K8s:n suurimmista hyödyistä. K8s:n voi pystyttää omaan konesaliin,
pilviympäristöön tai hyödyntää kumpaakin hybridipilvessä. Tämä ei siis lukitse
käyttäjäänsä yhteen tiettyyn ympäristöön tai palveluntarjoajan alustaan (vendor
lock-in). Käyttäjä voi siirtää sovelluksensa helposti omasta konesalistaan
esimerkiksi pilvipalvelutarjoajalle, käyttäen melkein samoja konfiguraatio
tiedostoja (Hightower & ym. 2017; Jayanandana, 2018)

### Tehokkuus

Konttiteknologian ansiosta K8s:n käyttäminen on tehokasta. K8s osaa
automaattisesti sijoittaa kapseleita koneisiin, joihin nämä mahtuvat. Tämä
ansiosta jokaisen koneen resursseja käytetään tehokkaasti hyödyksi ja koneita ei
tarvita ympäristössä niin paljon. Näin voidaan välttää tarpeettomien laitteiden
hankinta omassa konesalissa ja säästää rahaa ylimääräisten resurssien
maksamisessa pilvipalveluissa (Hightower & ym. 2017; Sanders, 2018).

Amazon Elastic Container Service for Kubernetes
===============================================

Amazonin tarjoama palvelu K8s:ta on Amazon Elastic Container Service for
Kubernetes. Tutkimuksessa käytetään lyhennettä EKS, kun viitataan Amazonin
Kubernetes palveluun.

AWS EKS tausta
--------------

Amazon Web Services (AWS) avasi EKS palvelun asiakkailleen 2018 kesäkuussa. EKS
palvelussa järjestelmän vastuu jakautuu palveluntarjoajan, AWS:n, ja asiakkaan
kanssa (kuva 7). AWS takaa pilvipalveluntarjoajana laitteiston, ohjelmiston,
verkkoyhteyden toimivuuden ja fyysisen turvauksen konesaleilla. Edellä
mainittujen lisäksi AWS huolehtii EKS palvelussa K8s klusterin ohjaamon
(mestarisolmut muodostavat klusterin ohjaamon) konfiguraation ja toimivuuden
sekä etcd -tietokannan saatavuuden. Mestareiden ja tietokannan saatavuuden
takaamiseksi AWS ajaa mestarit usealla saatavuus alueella (availability zones,
fyysesti eri paikoissa olevia konesaleja). Tämän lisäksi AWS tarkkailee
jatkuvasti mestarisolmuja ja korvaa vialliset solmut uusilla. Asiakkaan
vastuulla ovat K8s klusterin muu konfiguraatiot, esimerkiksi kätyrisolmun
konfiguraatio, ohjaamon yhteys asiakkaan VPC verkkoon (virtual private cloud,
asiakkaan oma verkko pilvessä). Asiakkaan vastuulla on myös kätyrisolmujen
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
kuormaa hyödyntäen TCP tai TLS protokollaa. Kuormantasaajalla on oma IP-osoite,
joka näkyy ulkoverkkoon. NLB:n ohjauksessa välittyy alkuperäisen kutsun tekijän
IP osoite. Osoitetta voidaan hyödyntää tällöin myös sovelluksessa. Protokolla
tason ohjauksen ansiosta NLB on erittäin nopea ja tehokas. Tämä
kuormantasaajamalli on vielä alpha-vaiheessa, eikä suositella vielä K8s
tuotantoklustereihin (Kubernetes, 2018c). CLB toimii samalla tavalla kuin
palvelu-objekti jonka tyyppi on *LoadBalancer* (otsikko 2.2.3). (Bala 1.12.2017)

*EKS palvelu luo käyttäjän puolesta resursseja, joita hyödynnetään K8s
klusterissa. EKS tarvitsee oikeudet näiden resurssien luontiin. IAM* on AWS
alustalla identiteetin ja pääsynhallinta -palvelu. Palvelun ideana on vastata
kysymykseen: Kenellä on oikeus tehdä mitä ja missä? IAM palvelussa määritellään
rooleja, käyttäjiä ja ryhmiä. Näihin objekteihin liitetään menettelytapa
(policy), jossa määritellään oikeuksista. AWS kertoo dokumentaatiossaan
vähimmäisoikeudet EKS palvelulle (Amazon Web Services, s.a. (a)).

*VPC* (Virtual Private Cloud) on virtuaaliverkko johon käyttäjä voi luoda AWS
resurssejaan. VPC:n sisälle luodaan pienempiä aliverkkoja (subnet). Aliverkot
määritellään saatavuusalueilla ja ne voivat olla joko julkisia tai suljettuja
verkkoja. EKS vaatii klusterin luonnin yhteydessä vähintään kaksi aliverkkoa eri
saatavuusalueilta. AWS suosittelee kuormantasaajan asentamista julkiselle
aliverkolle ja kätyrisolmujen asentamista suljetulle aliverkolle (kuva 8). AWS
luo klusterin luonnin yhteydessä asiakkaan aliverkoille Elastic Network
Interface (ENI) resurssin, mikäli klusterin oikeudet tämän sallivat. Klusterin
ohjaamo käyttää ENI -resurssia kommunikoidakseen kätyreiden kanssa. Klusterin
ylläpitäjä ja kätyrisolmut ottavat yhteyttä klusterin ohjaamon API palvelimelle
kuormantasaajan kautta. Ohjaamon API palvelin voidaan muuttaa myös yksityiseksi.
Tällöin yhteydet API palvelimeen menevät ENI resurssin kautta. Tämä vaatii
ylläpitäjää luomaan VPC:n sisälle bastion -instanssin (virtuaalikone, joka näkyy
ulkoverkkoon ja jolla on pääsy sisäverkkoon), jonka kautta ylläpitäjä voi ottaa
yhteyttä klusterin ohjaamoon.

![](media/de36c1045505160d40a5f390d5081088.png)

Kuva 8. AWS:n suosittelema verkko infrastruktuuri EKS palvelulle (Amazon Web
Services, s.a (b))

Kilpailijat
-----------

Monet pilvipalveluntarjoajat ovat ottaneet K8s tarjottavaksi palveluksi. AWS:n
kilpailijoita K8s pilvipalvelutarjoajana ovat esimerkiksi Microsoftin Googlen
Kubernetes Engine (GKE), Azure Kubernetes Service (AKS) ja DigitalOceanin
Kubernetes. Acreman, S. (s.a.) julkaisi artikkelissaan taulukon (liite 1).
Taulukossa vertaillaan pilvipalvelutarjoajien K8s palvelua.

*GKE* on täysin hallittu K8s palvelu. Asiakas määrittelee, kuinka monta
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

*AKS* tarjoaa GKE tapaan hallitun K8s palvelun. Microsoft Azure ylläpitää ja
hoitaa mestarisolmujen ja kätyrisolmujen tietoturvapäivitykset. AKS, GKE ja
DigitalOcean Kubernetes palveluissa ei veloiteta mestarisolmujen pystyttämisestä
eikä ylläpidosta. Palveluissa veloitetaan muista maksullisista resursseista
käytön mukaan (esimerkiksi kätyrisolmujen pilvipalvelimet). AKS palvelussa
mestarisolmuja on vain yksi jokaista klusteria kohden (Selvan, 2018; Microsoft
Azure, 2019).

DigitalOcean julkaisi oman K8s palvelun (DOK8s, epävirallinen lyhenne)
joulukuussa 2018. Haider, H (2019) mukaan DOK8s on yksinkertainen ja
kustannustehokas. DOK8s hallinnoi klusterin ohjaamoa ja tarkkailee klusterin
kätyrisolmuja. Klusterille luodaan yksi tai useampi kätyrisolmuvaranto (minion
node pool). Samanlaisia ominaisuuksia löytyy myös GKE ja EKS palveluissa. Kaikki
kätyrisolmut ovat identtisiä oman varannon sisällä. DOK8s poistaa tarvittaessa
vialliset solmut varannon sisältä ja korvaa nämä uudella. DOK8s palvelussa koko
klusteri pystytetään yhdelle saatavuusalueelle. Tämä huonontaa klusterin
vikasietoisuutta, esimerkiksi paikallinen sähkökatkos kaataa koko sovelluksen.
DOK8s klustereissa mestarisolmuja on vain yksi kappale (DigitalOcean, 2018).

AWS EKS pystytys
----------------

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
>   [https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html.
>   Luettu
>   13.03.2019](https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html.%20Luettu%2013.03.2019)

>   Amazon Web Services, s.a (b). Cluster VPC Considerations. Luettavissa:
>   [https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html. Luettu
>   18.03.2019](https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html.%20Luettu%2018.03.2019)

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
