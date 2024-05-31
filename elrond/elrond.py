#!/usr/bin/env python3 -tt
import argparse
import hashlib
import os

from rivendell.main import main


parser = argparse.ArgumentParser()
parser.add_argument("case", nargs=1, help="Investigation/Case/Incident Number")
parser.add_argument(
    "directory",
    nargs="+",
    help="Source directory where the artefact files are located; Optional: Provide a destination directory (default is current directory)",
)
parser.add_argument(
    "-K",
    "--Keywords",
    nargs=1,
    help="Search for keywords throughout image and artefacts based on provided Keyword File; Example syntax: -K /path/to/keyword_file.txt",
)
parser.add_argument(
    "-Y",
    "--Yara",
    nargs=1,
    help="Run Yara signatures against all files on disk image or just collected files; Example syntax: -Y /path/to/directory_of_yara_files",
)
parser.add_argument(
    "-F",
    "--collectFiles",
    nargs="?",
    help="Collect files from disk including binaries, documents, scripts etc.; Optional: Provide an inclusion/exclusion file; Example syntax: -F include:/path/to/include_file.txt",
    const=True,
)
parser.add_argument(
    "-A",
    "--Analysis",
    help="Conduct 'automated forensic analysis' for disk artefacts; Extended Attributes; Alternate Data Streams; Timestomping",
    action="store_const",
    const=True,
    default=False,
)  # outstanding - Out-of-Sequence Windows-based file activity
parser.add_argument(
    "-a",
    "--auto",
    help="Automatic mode - minimal prompting when mounting disk images",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-B",
    "--Brisk",
    help="'Brisk Mode.' Invokes -AacINPQqU. You MUST provide either -C (--collect), -G (--gandalf) or -O (--reorganise) depending on whether you've acquired disk images, leveraged gandalf or seperately acquired artefacts, respectively.",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-C",
    "--Collect",
    help="Collect artefacts from disk image (artefacts have NOT been collected seperately)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-c",
    "--vss",
    help="Collect & process artefacts on Volume Shadow Copies (if available)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-D",
    "--Delete",
    help="Delete raw data after processing",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-E",
    "--Elastic",
    help="Output data and index into local Elastic instance",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-G",
    "--Gandalf",
    help="Read artefacts acquired using gandalf",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-I",
    "--extractIocs",
    help="Extract IOCs from processed files collected from disk; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-i",
    "--imageinfo",
    help="Obtain E01 disk image metadata and information including acquired date/time; disk size, ID & sector sizes",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-l",
    "--lotr",
    help="Show Tolkien-themed ASCII art upon running elrond",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-M",
    "--Memory",
    help="Collect, process and analyse memory image using Volatility Framework",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-m",
    "--metacollected",
    help="Only hash artefacts which have been collected, processed & analysed (if applicable) and extract metadata from collected files (if applicable)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-N",
    "--Navigator",
    help="Map identified artefacts to MITRE ATT&CK® navigator (requires Splunk (-S) flag)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-n",
    "--nsrl",
    help="Compare hashes against known-goods from NSRL database; connection to Internet required",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-P",
    "--Process",
    help="Process disk artefacts which have been collected",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-Q",
    "--superQuick",
    help="Super Quick mode. Do NOT obtain last access & creation times, hash files, perform entropy analysis or extract metadata; WARNING: Not invoking this flag can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-q",
    "--quick",
    help="Quick mode. Obtain last access & creation times but do NOT hash files, perform entropy analysis or extract metadata; WARNING: Not invoking this flag can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-R",
    "--Reorganise",
    help="Reorganise artefacts NOT collected using gandalf",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-S",
    "--Splunk",
    help="Output data and index into local Splunk instance",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-s",
    "--symlinks",
    help="Copy contents of folders, including following full paths of symbolic links; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-T",
    "--Timeline",
    help="Create Timeline of disk image using plaso; WARNING: This can take a VERY long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-t",
    "--memorytimeline",
    help="Create Timeline of memory image using timeliner plugin; WARNING: This can take a long time!",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-U",
    "--Userprofiles",
    help="Collect user profile artefacts",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-u",
    "--unmount",
    help="Do not unmount, currently mounted images (in /mnt/elrond_mountXX)",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-V",
    "--clamaV",
    help="Run ClamAV against mounted image",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-X",
    "--eXhaustive",
    help="Exhaustive mode. Invoke all flags: -BDElMnSTtZ. You MUST provide either -C (--collect), -G (--gandalf) or -O (--reorganise) depending on whether you've acquired disk images, leveraged gandalf or seperately acquired artefacts, respectively.",
    action="store_const",
    const=True,
    default=False,
)
parser.add_argument(
    "-Z",
    "--Ziparchive",
    help="Archive raw data as zip after processing",
    action="store_const",
    const=True,
    default=False,
)

args = parser.parse_args()
directory = args.directory
case = args.case
analysis = args.Analysis
auto = args.auto
brisk = args.Brisk
collect = args.Collect
vss = args.vss
delete = args.Delete
elastic = args.Elastic
gandalf = args.Gandalf
collectfiles = args.collectFiles
extractiocs = args.extractIocs
imageinfo = args.imageinfo
lotr = args.lotr
keywords = args.Keywords
volatility = args.Memory
metacollected = args.metacollected
navigator = args.Navigator
nsrl = args.nsrl
process = args.Process
superquick = args.superQuick
quick = args.quick
reorganise = args.Reorganise
splunk = args.Splunk
symlinks = args.symlinks
timeline = args.Timeline
memorytimeline = args.memorytimeline
userprofiles = args.Userprofiles
unmount = args.unmount
clamav = args.clamaV
yara = args.Yara
exhaustive = args.eXhaustive
archive = args.Ziparchive

d = directory[0]
case = case[0]
cwd = os.getcwd()
sha256 = hashlib.sha256()
allimgs = {}
flags = []
elrond_mount = [
    "/mnt/elrond_mount00",
    "/mnt/elrond_mount01",
    "/mnt/elrond_mount02",
    "/mnt/elrond_mount03",
    "/mnt/elrond_mount04",
    "/mnt/elrond_mount05",
    "/mnt/elrond_mount06",
    "/mnt/elrond_mount07",
    "/mnt/elrond_mount08",
    "/mnt/elrond_mount09",
    "/mnt/elrond_mount10",
    "/mnt/elrond_mount11",
    "/mnt/elrond_mount12",
    "/mnt/elrond_mount13",
    "/mnt/elrond_mount14",
    "/mnt/elrond_mount15",
    "/mnt/elrond_mount16",
    "/mnt/elrond_mount17",
    "/mnt/elrond_mount18",
    "/mnt/elrond_mount19",
]
ewf_mount = [
    "/mnt/ewf_mount00",
    "/mnt/ewf_mount01",
    "/mnt/ewf_mount02",
    "/mnt/ewf_mount03",
    "/mnt/ewf_mount04",
    "/mnt/ewf_mount05",
    "/mnt/ewf_mount06",
    "/mnt/ewf_mount07",
    "/mnt/ewf_mount08",
    "/mnt/ewf_mount09",
    "/mnt/ewf_mount10",
    "/mnt/ewf_mount11",
    "/mnt/ewf_mount12",
    "/mnt/ewf_mount13",
    "/mnt/ewf_mount14",
    "/mnt/ewf_mount15",
    "/mnt/ewf_mount16",
    "/mnt/ewf_mount17",
    "/mnt/ewf_mount18",
    "/mnt/ewf_mount19",
]
# to add new artefacts, include the directory or file in this list, and include it in process/select.py
system_artefacts = [
    "/",
    "/$MFT",
    "/$Extend/$UsnJrnl",
    "/$Extend/$ObjId",
    "/$Extend/$Reparse",
    "/$LogFile",
    "/$Recycle.Bin",
    "/Users/",
    "/Windows/AppCompat/Programs/RecentFileCache.bcf",
    "/Windows/AppCompat/Programs/Amcache.hve",
    "/Windows/inf/setupapi.dev.log",
    "/Windows/Prefetch/",
    "/Windows/System32/config/",
    "/Windows/System32/LogFiles/Sum/",
    "/Windows/System32/LogFiles/WMI/",
    "/Windows/System32/sru/",
    "/Windows/System32/wbem/Repository/",
    "/Windows/System32/wbem/Logs/",
    "/Windows/System32/winevt/Logs/",
    "/.Trashes",
    "/Library/Logs",
    "/Library/Preferences",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/Library/StartupItems",
    "/System/Library/LaunchDaemons",
    "/System/Library/StartupItems",
    "/boot",
    "/etc/crontab",
    "/etc/group",
    "/etc/hosts",
    "/etc/passwd",
    "/etc/security",
    "/etc/shadow",
    "/home",
    "/root",
    "/tmp",
    "/usr/lib/systemd/user",
    "/var/cache/cups",
    "/var/log",
    "/var/log/journal",
    "/var/vm/sleepimage",
    "/var/vm/swapfile",
]
quotes = [
    "Not come the days of the King.\n     May they be blessed.",
    "If my old gaffer could see me now.",
    "I'll have no pointy-ear outscoring me!",
    "I think there is more to this hobbit, than meets the eye.",
    "You are full of surprises Master Baggins.",
    "One ring to rule them all, one ring to find them.\n     One ring to bring them all, and in the darkness bind them.",
    "The world is changed.\n     I feel it in the water.\n     I feel it in the earth.\n     I smell it in the air.",
    "Who knows? Have patience. Go where you must go, and hope!",
    "All we have to decide is what to do with the time that is given us.",
    "Deeds will not be less valiant because they are unpraised.",
    "It is not the strength of the body, but the strength of the spirit.",
    "But in the end it’s only a passing thing, this shadow; even darkness must pass.",
    "It’s the job that’s never started as takes longest to finish.",
    "Coward? Not every man's brave enough to wear a corset!",
    "Bilbo was right. You cannot see what you have become.",
    "He is known in the wild as Strider.\n     His true name, you must discover for yourself.",
    "Legolas said you fought well today. He's grown very fond of you.",
    "You will take NOTHING from me, dwarf.\n     I laid low your warriors of old.\n     I instilled terror in the hearts of men.\n     I AM KING UNDER THE MOUNTAIN!",
    "You've changed, Bilbo Baggins.\n     You're not the same Hobbit as the one who left the Shire...",
    "The world is not in your books and maps. It's out there.",
    "That is private, keep your sticky paws off! It's not ready yet!",
    "I wish you all the luck in the world. I really do.",
    "No. No. You can't turn back now. You're part of the company.\n     You're one of us.",
    "True courage is about knowing not when to take a life, but when to spare one.",
    "The treacherous are ever distrustful.",
    "Let him not vow to walk in the dark, who has not seen the nightfall.",
    "He that breaks a thing to find out what it is has left the path of wisdom.",
    "I was there, Gandalf.\n     I was there three thousand years ago, when Isildur took the ring.\n     I was there the day the strength of Men failed.",
    "I don't know half of you half as well as I should like,\n     and I like less than half of you half as well as you deserve.",
    "Certainty of death. Small chance of success.\n     What are we waiting for?",
    "Do not spoil the wonder with haste!",
    "It came to me, my own, my love... my... preciousssss.",
    "One does not simply walk into Mordor...",
    "Nine companions. So be it. You shall be the fellowship of the ring.",
    "You have my sword. You have my bow; And my axe!",
    "Build me an army, worthy of Mordor!",
    "Nobody tosses a Dwarf!",
    "If in doubt, Meriadoc, always follow your nose.",
    "This is beyond my skill to heal; he needs Elven medicine.",
    "No, thank you! We don't want any more visitors, well-wishers or distant relations!",
    "Mordor! I hope the others find a safer road.",
    "YOU SHALL NOT PASS!",
    "You cannot hide, I see you!\n     There is no life, after me.\n     Only!.. Death!",
    "A wizard is never late, Frodo Baggins.\n     Nor is he early.\n     He arrives precisely when he means to.",
    "Is it secret?! Is it safe?!",
    "Even the smallest person can change the course of the future.",
    "We must move on, we cannot linger.",
    "I wish the ring had never come to me. I wish none of this had happened.",
    "Moonlight drowns out all but the brightest stars.",
    "A hunted man sometimes wearies of distrust and longs for friendship.",
    "The world is indeed full of peril and in it there are many dark places.",
    "Someone else always has to carry on the story.",
    "Your time will come. You will face the same Evil, and you will defeat it.",
    "It is useless to meet revenge with revenge; it will heal nothing.",
    "Despair is only for those who see the end beyond all doubt. We do not.",
    "Anyways, you need people of intelligence on this sort of… mission… quest… thing.",
    "Oh, it’s quite simple. If you are a friend, you speak the password, and the doors will open.",
    "The wise speak only of what they know.",
    "Not all those who wander are lost.",
    "It's the deep breath before the plunge.",
]
asciitext = [
    "\n\n        \033[1;36mWelcome to Minas Tirith\n\n\n      |||            _.'   _      _.-. |        | |--\n     \\|||         _.'    -    _.-'  _|-|       -| |__\n      ||;-,    _.'   '-  _.-'' _.-''|  |-'      | `._\n     -'| / \\_,' _    _.-'   _.' |   |  |    -|  |\n     ----|,`   |  _.'   _.-' | ,| ,'| _| |      |_   \n        _:  _   ,'   .-'    _|/ \\ | | -|  _|_   | '\n       | |    ,'  .-'     , )|)-( |_|  |-       |    -\n     -   |  ,'  ,'(   `  /_\\||`.'   |- |   -|_  |\n     ___-| /  ,'   )     `.'||.-| _ | ||        | '-'\n     __( |;  /    / ,-    | ||  |/ \\|_ | _|    -|    \n       | :  ; ,-.-)       | ||  || ||  |   |_   |    _\n      _| | :/` _..\\  `-.  | ||__||_|;--;--------:  ,'`\n       | | |,-'  _/       |,-/\\_|  /__/__________\\::::\n       |-| |   ,' \\, ` ___|||||-|  |  |  _|_     ||___\n     _ | | | ,'   (   ;   :'''' /| ||_|       _  ||---\n     - | | |/     ;  /     :   : | |  |   _|_    ||---\n       | | |      |,'______|-..| | |_||      |  _||---\n       | | |      ||_      |   | | |_ |  -      -|----   \n     _|| | |      ;|-:  _  |   | |,|- |-   _|  _ |--,'\n       | | |______\\| |,' `.|`-.| |:|  | _|    |  |,','\n       |-| | ~   ~|| ||__|||! !| | ;--;----__---,','|\n       | | |,._,~_|:.||-'|||! !| |/__/____/\\_\\,','|\\|\n     -.| | ;     _.-'|| - ||`.!| ||  |    ||_|,'| | |,\n      || ;'|_,-''    -    - `.`| ||  | ___|| ||\\| |,',\n     , | | |    -     -     -  ) '|__||\\  || | \\|,','\n       ; | | -     -      -      |\\    \\\\ || |_,',' \n      /| | ;    -     -           \\\\    \\\\|| |','\n     / | |/                        \\\\    \\|| |' SSt\033[1;m",
    "\n\n        \033[1;36mWelcome to Bag End\n\n\n                        . .:.:.:.:. .:\\     /:. .:.:.:.:. ,\n                   .-._  `..:.:. . .:.:`- -':.:. . .:.:.,'  _.-.\n                  .:.:.`-._`-._..-''_...---..._``-.._.-'_.-'.:.:.\n               .:.:. . .:_.`' _..-''._________,``-.._ `.._:. . .:.:.\n            .:.:. . . ,-'_.-''      ||_-(O)-_||      ``-._`-. . . .:.:.\n           .:. . . .,'_.'           '---------'           `._`.. . . .:.\n         :.:. . . ,','               _________               `.`. . . .:.:\n        `.:.:. .,','            _.-''_________``-._            `._.     _.'\n      -._  `._./ /            ,'_.-'' ,       ``-._`.          ,' '`:..'  _.-\n     .:.:`-.._' /           ,','                   `.`.       /'  '  \\\\.-':.:.\n     :.:. . ./ /          ,','               ,       `.`.    / '  '  '\\\\. .:.: \n    :.:. . ./ /          / /    ,                      \\ \\  :  '  '  ' \\\\. .:.:\n    .:. . ./ /          / /            ,          ,     \\ \\ :  '  '  ' '::. .:.\n    :. . .: :    o     / /                               \\ ;'  '  '  ' ':: . .:\n    .:. . | |   /_\\   : :     ,                      ,    : '  '  '  ' ' :: .:.\n    :. . .| |  ((<))  | |,          ,       ,             |\\'__',-._.' ' ||. .:\n    .:.:. | |   `-'   | |---....____                      | ,---\\/--/  ' ||:.:.\n    ------| |         : :    ,.     ```--..._   ,         |''  '  '  ' ' ||----\n    _...--. |  ,       \\ \\             ,.    `-._     ,  /: '  '  '  ' ' ;;..._\n    :.:. .| | -O-       \\ \\    ,.                `._    / /:'  '  '  ' ':: .:.:\n    .:. . | |_(`__       \\ \\                        `. / / :'  '  '  ' ';;. .:.\n    :. . .<' (_)  `>      `.`.          ,.    ,.     ,','   \\  '  '  ' ;;. . .:\n    .:. . |):-.--'(         `.`-._  ,.           _,-','      \\ '  '  '//| . .:.\n    :. . .;)()(__)(___________`-._`-.._______..-'_.-'_________\\'  '  //_:. . .:\n    .:.:,' \\/\\/--\\/--------------------------------------------`._',;'`. `.:.:.\n    :.,' ,' ,'  ,'  /   /   /   ,-------------------.   \\   \\   \\  `. `.`. `..:\n    ,' ,'  '   /   /   /   /   //                   \\\\   \\   \\   \\   \\  ` `.SSt\033[1;m",
    "\n\n\n\n\n                                                \033[1;36m_______________________\n       _______________________-------------------                       `\\\n     /:--__                                                              |\n    ||< > |                                   ___________________________/\n    | \\__/_________________-------------------                         |\n    |                                                                  |\n     |                       THE LORD OF THE RINGS                      |\n     |                                                                  |\n     |      Three Rings for the Elven-kings under the sky,              |\n      |        Seven for the Dwarf-lords in their halls of stone,        |\n      |      Nine for Mortal Men doomed to die.                          |\n      |        One for the Dark Lord on his dark throne,                  |\n      |      In the Land of Mordor where the Shadows lie.                 |\n       |       One Ring to rule them all, One Ring to find them,          |\n       |       One Ring to bring them all and in the darkness bind them   |\n       |     In the Land of Mordor where the Shadows lie.                |\n      |                                              ____________________|_\n      |  ___________________-------------------------                      `\\\n      |/`--_                                                                 |\n      ||[ ]||                                            ___________________/\n       \\===/___________________--------------------------\033[1;m",
    "\n\n    ||                                ..........',:clooddddoolc:;''...   .......  .....'..'''||\n    ||                             ........'',;:clodxkkkkkkkkkxoc;,'............   ......''''||\n    ||                         ......',;,,;;:lddxxdxxxxxkkkkOOOkxdl:;'....... ...  ..........||\n    ||                      .....',;;;::;;:cloddoooodxxkkOOOOOOOOkkkxdolc;'...     ..........||\n    ||                  .....''',;;;;::c::;:ccllllodxxxxxxk0K000000OOkkkkxo:,'..     ........||\n    ||                ........',;,,;,,;:llclooooddxkkkxolokkxdk0Oxdxxdodddl:::,....  ........||\n    ||                ..........'''',,;;:cllddxkkOOOO00xox000KXX0xoolcccodocc:,'''......''''.||\n    ||               ...''....'''''.',;:coddxxkOOOOOOO0OxkO00K00Okdl:,'',;,';:cc;'.''....''..||\n    ||              ..........''''''';:cloxxkkkOOOOOO000KXXKKK00Okdol:,'..''...;:c'...''.....||\n    ||            ...'''''....',,;;;;;:cloxkkOOOOOOOO000KKKKKK00Okdooc;'...''....';,. .'''...||\n    ||            ..',,,,;;;;;;:::::::ccldxkkOOOOOOOO00KKKKKKK0OOxolc:;'....'.......'..','...||\n    ||            ..',,,;;;;;:::::::::clodkkOOOOOOOO0000KKKKKK00Okdl:;,'........... .........||\n    ||             .',;;;;::::::::::::cldxkkOOOOO0000000KKKXXKKKK0kdc;,''. ........    .....'||\n    ||             .',;;;:ccllcc::::cclodxkkkkkkOO000OOOO0KKKKKKKK0Oxc,'..   .......  ... .;;||\n    ||             ..,,;;:cllllc:::ccllodxxxxxxxxxxxdodxkO0KKKXKKKK0Oo;...    ......';:oo;...||\n    ||             ..',;;:cllllc::cclllooddollc:::cldxOO0000KKKKKKKK0x:'..    .....,codxkx:. ||\n    ||             .',,;;::cclll::clllllc::,'''',:oxOO0000000KKKKKKKKkl,...   .....,;;:okOd'.||\n    ||             ...',;::::clcc:::c:;,''..'''',,;:cldxkO0000KKKXKKKOo:...   ...'.,,;:cdkk;.||\n    ||            .......',;;:::::::::;;;,'''.......,:ccldxkO0KKXXXK0Odc'.    ...',;;:cldOk;.||\n    ||             .....  .....';clddxdlc;,,'',,,'',:loxOOOO00KKXXXKOkdc'........',,;;:lxOd' ||\n    ||              ...    .....;cok00Oxdoc;,,,,,,;:cldkO0000KKKKXK0Okoc,......'..',,;:okOc. ||\n    ||                ......','';ldOKKK0Okoc::::::ccloxkO0000KXXXKKOkdo:,..',..'..',;:lxko.. ||\n    ||                 ....'',',:lx0XXXXKK0kxoccccloodkOOOOO00KKKK0kxdl:'...'.....';ldkko'  .||\n    ||                 ..''',,,;cxOKXXXXXXXK0OxxdoooodxkkOOO000000Okxdl;'.........,:dOOd'   .||\n    ||                 ...',,,,:ok0KXXXXKXXXK000OkkkxdxxkkOOO00OOOOkxoc;'.........';oko'     ||\n    ||                 .,,,,,,;cok0KKKXK00000OOOOOOOOkkkkOOOOOOOOOkxdoc;,.........';l:..     ||\n    ||                 .,,,,,,;cdO000KKK00K0OdddxkkOOOOOOOO000OOOkxddl:;'...... ..';c;.      ||\n    ||                 .',,,,,,:lxkOxxxdoxO0OxllloxkkOOOO00000OOOkxdol:;'.....  ..':o:.      ||\n    ||                  .',,,,''',:lllllccdkOxdoooodxkOOO00000OOkxdolc:,'.....  ..,cxc.      ||\n    ||                   .''',,'...,:cdkxxkkkkxxxxddxkOO00000OOOkxdolc;,......  ..,oko'      ||\n    ||                   ...',,,''';::ldxxxxxkkkkkkkxxxkOO000OOOkxolc:;'......  ..;xkd,      ||\n    ||                    ..'',,'',:c;:ldxxxxkkOOkkkkkxxkOOOOOkkkdlc:;,'.....   ..:xkk:.     ||\n    ||                     ..''',,,:c::cllloooddddoodxkkkOOOOkkxxol:;,,'''...   ..ckOkl.   ..||\n    ||                      .''',,,,,,,;;;::cloolllcclodxkOOOkxddlc:;,,,;,..    ..:xxdc'..;ld||\n    ||                      ..''..''',;:cloodxkkkkkkxdooodxxkxddolc;,,;:c:..    .';lollodkkkx||\n    ||                       ..'''',,;;:cclloooddddxxddooodxxdddol:;;::clc,.  ...';ldkkkkkxoc||\n    ||                       .....',,;;;;;;::cccclloooooodxxxxdolc:::cclc:;......'coxkOkxoc;'||\n    ||                    ...''....',,,;;;;::clccclllllloodxxdolc::::c:::;;'.....,ldxxxdl:,..||\n    || .':lcc;,''',,;:cllloddxko:'..'',;::ccloddddoodoooooooolc:;;;;;;,;;;;,.....:oddooc;,.. ||\n    ||.:xO0KKK00OOOOOOOOOOkkkkO00Odc,',;:cccloddxxxxddooolcc:;;;,,,'',;:::cc:...'collcc;'..  ||\n    ||'lxO0KKKKKK0000000000OkOO00000kl:;;::::cllooddddoolc:;;,,,''',,;::clool,...;:cc:;'.. ..||\n    ||;lxO0KXXXXKKKK0000000OOO0KXKOkOOkdoc;;;;:::cclllc:::;,,''.',;::::cllooc.   .'::,...... ||\n    ||:ok0KKKKKKKKKKKKKKKK0OO0KXXNXOxdkOOkdlc;;,,,,,,,,,,,'''..',:ccccclooo:..    .,'......  ||\n    ||cdkO00KKKKKKKKKK0000OO0KXKKXNX0dldxkkOkxl:,.............',:cccclool:,..'.  .''......   ||\n    ||cdxkOOOO0KKKKKKK0O0K0kkKXXK00XNKd::clodxoc,.............':cccllooo;. ......,,'......   ||\n    ||coxxk00OkxxxxkkOOO0KK0kk0XXKOOKKKxlcloddol;. .......'''',:ccloooooc'.......'''.....    ||\n    ||loodk000Oxc'',,,cdk0KXKkk0KX0xxOO00kdol:'...........'''':ccloooololc;'....''......    .||\n    ||loodxOOxl,.......,cdO0K0kxOKXOooxO00x;... ...........'',cclloollllllc:..'''..'..       ||",
]


if __name__ == "__main__":
    if exhaustive:
        brisk = True
        delete = True
        elastic = True
        lotr = True
        volatility = True
        nsrl = True
        superquick = False
        quick = False
        splunk = True
        timeline = True
        memorytimeline = True
        archive = True
    if brisk:
        analysis = True
        auto = True
        vss = True
        extractiocs = True
        metacollected = True
        navigator = True
        process = True
        superquick = True
        quick = True
        userprofiles = True
        clamav = True
    veryverbose = True
    verbose = True
    main(
        directory,
        case,
        analysis,
        auto,
        collect,
        vss,
        delete,
        elastic,
        gandalf,
        collectfiles,
        extractiocs,
        imageinfo,
        lotr,
        keywords,
        volatility,
        metacollected,
        navigator,
        nsrl,
        process,
        superquick,
        quick,
        reorganise,
        splunk,
        symlinks,
        timeline,
        memorytimeline,
        userprofiles,
        unmount,
        clamav,
        veryverbose,
        verbose,
        yara,
        archive,
        d,
        cwd,
        sha256,
        allimgs,
        flags,
        elrond_mount,
        ewf_mount,
        system_artefacts,
        quotes,
        asciitext,
    )
