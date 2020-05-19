------------------------------
Szenario:
------------------------------

Die virtuellen Maschinen sind ein Windows Server 2012R2, welches mit dem Ransomware Virus WannaCry infiziert werden soll und später zur dynamischen Analyse genutzt wird, sowie ein Linux-Ubuntu System, welches zur statischen Analyse genutzt wird.

Auf dem Desktop befindet sich jeweils ein Ordner "WCry", in dem sich alle Dateien anfinden, welche für dieses Showcase benötigt werden.


In dem Ordner auf dem Windows Desktop befinden sich eine Email mit Anhang, ein paar Dokumente, eine Kurzanleitung namens README, sowie drei Dateien, die später zur dynamischen Analyse genutzt werden.
Im Ornder unter Linux befindet zum einen ein Ornder mit der Malware und einem vorgeschriebenen Skript zum finden von Passwörtern und außerdem ein backup Ordner.


------------------------------
START (Windows VM)
------------------------------
In diesem Teil des Showcase wird der Anhang der Phishing Mail heruntergeladen und geöffnet, welcher sich als Malware entpuppt und alle Dokumente verschlüsselt. Dies kann anhand der Dokumente im Ordner Documents verfiziert werden.

Öffnen Sie die Mail-Datei "Bewerbung" mit dem Mail-Programm Thunderbird und melden Sie sich an mit:
mmssec@gmx.de
Nutzername: mmssec
Passwort: mmssec

Es ist eine spezifische Bewerbungs-Mail mit Anhang, die völlig unverdächtig wirkt.
Der Anhang der Mail "Application & CV.pdf" kann nun heruntergeladen werden. Die Mail kann nun wieder geschlossen werden.

++++++++++++++++++++++++++++++
MALWARE AUSFÜHREN
++++++++++++++++++++++++++++++

Mit dem Ausführen der Anhangsdatei startet die Malware und damit die Verschlüsselung der Daten. Es erscheint in regelmäßigen Abständen ein Popup Fenster.

Um die Verschlüsselung zu verfizieren, können die Dokumente zum Thema Forensik geöffnet werden. Dabei kommt es nun zu einem Fehler.

An dieser Stelle würde nun ein Abbild des Speichers zur späteren Analyse erzeugt werden.


------------------------------
STATISCHE ANALYSE (Ubuntu VM)
------------------------------

In der statischen Analyse werden Informationen über die Malware gesammelt, ohne diese auszuführen.
Als erstes wird sie mit binwalk untersucht, um eingebettete Dateien zu finden.

Wechseln Sie in den Ordner Analysis, wo die Datei Application & CV.exe abgelegt ist.
Öffnen Sie in diesem Ordner ein Terminal.

Das Tool binwalk untersucht Binärdateien nach eingebetteten Dateitypen und ausführbarem Code:

$ binwalk Application\ \&\ CV.exe

Es findet Zip-komprimierte Daten in der Portable Executable (PE).

++++++++++++++++++++++++++++++
ZIP entpacken
++++++++++++++++++++++++++++++

Jetzt versuchen wir, diese ZIP komprimierten Daten zu entpacken:

$ sudo unzip Application\ \&\ CV.exe

Dies führt zu einer Eingabeaufforderung, die nach einem Passwort für die ZIP Datei fragt. Noch ist das Passwort nicht bekannt.

Da wir aber annehmen, dass die Malware die ZIP entpackt, wenn sie ausgeführt wird, können wir davon ausgehen, dass sie das Passwort enthält.

++++++++++++++++++++++++++++++
Passwort finden
++++++++++++++++++++++++++++++

Dazu haben wir ein Skript geschrieben, welches alle Zeichenketten aus der Datei ausliest, und diese dann als Passwort testet.

Zum Auslesen der Strings wird das Unix Tool "strings" verwendet. Dieses sucht nach Zeichenketten, die aus mindestens vier druckbaren Zeichen bestehen.

$ ./findPassword.sh Application\ \&\ CV.exe

Output:
Correct Password is WNcry@2ol7

Unser Skript findet das Passwort WNcry@2ol7. Mit diesem können wir die ZIP-Datei nun entpacken. Achten Sie auf die Schreibweise!:

$ sudo unzip -P WNcry@2ol7 Application\ \&\ CV.exe

Sollte es beim Entpacken Probleme geben, liegt eine bereits entpackte Variante im Ordner ~/backup


Dabei werden nur die in der Malware eingebetteten Dateien entschlüsselt. Diese Verschlüsselung hängt aber nicht mit der Dateiverschlüsselung zusammen, mit der die Daten des Opfers verschlüsselt werden.

++++++++++++++++++++++++++++++
Dateien untersuchen
++++++++++++++++++++++++++++++

Die entpackten Dateien werden nun untersucht, um die Dateitypen zu erkennen.

$ sudo file *.wnry

Die Anmerkungen dazu kann man teilweise leicht erschließen, teilweise sind sie aus einem Factsheet übernommen.

b.wnry Bitmap   Hintergrundbild mit Anleitung
c.wnry Text     URLs zu TOR HiddenServices
r.wnry Text     WannaCry FAQ
S.wnry ZIP-File ZIP-Archiv mit TOR-Installation
t.wnry Binary   Verschlüsselte DLL für Verschlüsselungsfunktionen
u.wnry PE	Decryptor Tool

++++++++++++++++++++++++++++++
Prüfsumme & Virustotal
++++++++++++++++++++++++++++++

Malware Plattformen nutzen in der Regel Dateihashes zur Identifikation, virustotal.com unterstützt beispielsweise MD5, SHA1 and SHA256.

Die die Plattformen öffentlich sind, sollte man nie eine Malware hochladen, denn so könnte dieser erfahren, dass sein Angriff bemerkt wurde und eine neue Version in Umlauf bringen. Deshalb berechnen wir die Prüfsumme, und suchen nach dieser. Diese ist eindeutig, um die Malware zu identifizieren, dafür kann aber nur bereits auf virustotal hochgeladene Malware gefunden werden.


$ sha256sum *

Die folgende Liste sind die gefundenen SHA256-Hashes, die jeweils auf der Virustotal Seite geprüft werden können.

d5e0e8694ddc0548d8e6b87c83d50f4ab85c1debadb106d6a6a794c3e746f4fa    b.wnry

055c7760512c98c8d51e4427227fe2a7ea3b34ee63178fe78631fa8aa6d15622    c.wnry

402751fa49e0cb68fe052cb3db87b05e71c1d950984d339940cf6b29409f2a7c    r.wnry

e18fdd912dfe5b45776e68d578c3af3547886cf1353d7086c8bee037436dff4b    s.wnry

4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79    taskdl.exe

2ca2d550e603d74dedda03156023135b38da3630cb014e3d00b1263358c5f00d    taskse.exe

97ebce49b14c46bebc9ec2448d00e1e397123b256e2be9eba5140688e7bc0ae6    t.wnry

ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa    Application & CV.exe

b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25    u.wnry
	

------------------------------
Dynamische Analyse (Windows VM)
------------------------------

Als erstes muss der Ordner Dynamic Analysis geöffnet werden und das Tool procmon gestartet werden.
Akzeptieren Sie dazu die Nutzungsbesdingungen beim ersten Start des Programms.
	
++++++++++++++++++++++++++++++
Filterliste bestätigen
++++++++++++++++++++++++++++++

Um den Überblick nicht zu verlieren, werden die aufgezeichneten Daten gefiltert. Dieser Filter wurde bereits vorkonfiguriert und liegt im WCry Ordner bereit. Um den Filter einzubinden, klicken Sie im Procmon auf:

Filter --> Organize Filters... --> Import...

Wählen Sie nun Die Datei ProcMon_Filter.PMF aus und Bestätigen Sie die Änderung mit OK.
Nun kann der neue Filter mit 

Filter --> Load Filter

ausgewählt werden.

++++++++++++++++++++++++++++++
Malware ausführen
++++++++++++++++++++++++++++++

Nun muss Application & CV.exe im Ordner Dynamic Analysis ausgeführt werden, direkt danach sollte wieder zu Procmon gewechselt werden.

Während der Ausführung öffnet sich regelmäßig ein Popup, welches bedenkenlos geschlossen werden kann.

Ziemlich zu Beginn ist zu sehen, dass die Malware einen Eintrag in der Registry hinterlässt, dessen Wert der Ordner ist, in dem die Malware liegt.

Danach entpackt die Malware offenbar das von uns bereits gefundene ZIP-Archiv.
	
++++++++++++++++++++++++++++++
Verschlüsselung beobachten
++++++++++++++++++++++++++++++

Wenn man weiter scrollt sieht man, dass die Dateien in unserem präparierten Dokumente Ordner geöffnet werden, und dazu Dateien erstellt werden, mit der Endung .WNCRYT

Offenbar werden hier die vorhandenen Dateien verschlüsselt und dann überschrieben.

++++++++++++++++++++++++++++++
Autostart
++++++++++++++++++++++++++++++

Nach einem Klick in in der oberen Leiste auf das Dateisymbol werden die Dateioperationen ausgeblendet, nun ist die Liste wesentlich kürzer.

So kann man nachvollziehen, dass durch einen Registry Eintrag die Malware in den Autostart eingefügt wurde.
	
++++++++++++++++++++++++++++++
Auswertung
++++++++++++++++++++++++++++++

Die beiden gefundenen Registry Einträge:

HKU\S-1-5-21-3463664321-2923530833-3546627382-1000\Software\Microsoft\Windows\CurrentVersion\Run\tkwnjpfsktmsg478:
"C:\Users\IEUser\Desktop\tasksche.exe"

HKU\S-1-5-21-3463664321-2923530833-3546627382-1000\Software\WanaCrypt0r\wd: "C:\Users\IEUser\Desktop"


------------------------------
IOC Analyse (Windows VM)
------------------------------
Szenario

Aus den Beobachtungen und Findings können wir nun Indicators of Compromise ableiten.

IOCs sind z.B. Dateihashes, Registry Einträge oder Metainformationen, aus denen man schließen kann, dass ein System kompromittiert wurde. Mit diesen können automatisiert weitere Systeme untersucht werden, um infizierte Geräte zu erkennen.
	

++++++++++++++++++++++++++++++ 
IOCs ableiten
++++++++++++++++++++++++++++++

Aus unserer Untersuchung können wir bspw. folgende IOCs nutzen:

MD5 Hash der Datei: 84c82835a5d21bbcf75a61706d8ab549

Strings in der PE:

    WNcry@2ol7
    r.wnry
    s.wnry
    t.wnry
    u.wnry
    b.wnry
    c.wnry
    tasksche.exe
    taskse.exe
    taskdl.exe

Angelegte Registry Keys:

    HKU\S-1-5-21-3463664321-2923530833-3546627382-1000\Software\WanaCrypt0r\wd
    HKU\S-1-5-21-3463664321-2923530833-3546627382-1000\Software\Microsoft\Windows\CurrentVersion\Run\tkwnjpfsktmsg478

	

------------------------------ 
YARA
------------------------------

YARA durchsucht Dateien nach bestimmten Pattern, die man in YARA-Rules beschreiben kann. Wir können nun also eine Yara Rule für unsere Malware schreiben, und mit dieser in unserem gesamten Netzwerk nach weiteren, infizierten Rechnern durchsuchen.

Yara Rule

import "hash"


rule wannaCry {

    strings:

        $password = "WNcry@2ol7"

        $zip1 = "r.wnry"

        $zip2 = "s.wnry"

        $zip3 = "t.wnry"

        $zip4 = "u.wnry"

        $zip5 = "b.wnry"

        $zip6 = "c.wnry"

        $zip7 = "tasksche.exe"

        $zip8 = "taskse.exe"

        $zip9 = "taskdl.exe"

 

    condition:

        $password or

        6 of ($zip*) or

        hash.md5(0, filesize) == "84c82835a5d21bbcf75a61706d8ab549"

}

Dies ist bspw. eine mögliche Regel. Es gibt zwei Blöcke innerhalb der Regel: Im Block "Strings" werden Zeichenketten definiert, nach denen eine Datei durchsucht wird. Im "Condition" Block werden dann Bedingungen festgelegt, bei denen die Regel "anschlagen" soll. In diesem Fall passiert dies, wenn das Passwort vorkommt, oder mindestens 6 der extrahierten Dateinamen oder der MD5-Hash der Datei übereinstimmt.
	

++++++++++++++++++++++++++++++
Yara Regel nutzen
++++++++++++++++++++++++++++++

Die Yara Regel ist als rule.txt im persönlichen Ordner hinterlegt, in der Kommandozeile muss auf den Desktop gewechselt werden:

$ cd Desktop

$ sudo yara64.exe -r .\WCry\rule.txt .

Mit diesem Kommando wird yara mit der von uns definierten Regel gestartet, und durchsucht rekursiv Ihren Desktop. Dabei wird jede Datei analysiert. Das Ergebnis ist, dass die Regel WannaCry auf der Datei \Dynamic Analysis\Application & CV.pdf.exe und auf andere Dateien im WCry, die die gesuchten Strings beinhalten, angeschlagen hat.

Das ist keine Überraschung, allerdings besteht die Stärke darin, dass nun Dateien auf allen Computern im System auf diese Regel gescannt werden können, unabhängig vom Betriebssystem.	
