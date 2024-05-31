#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def compare_iocs(
    output_directory,
    verbosity,
    img,
    stage,
    vssimage,
    iocfiles,
    lineno,
    previous_state,
):
    print("      Commencing IOC extraction for '{}'...\n".format(img.split("::")[0]))
    for iocfile in iocfiles:
        if os.path.exists(iocfile.split(": ")[0]):
            with open(iocfile.split(": ")[0], "r") as reading_for_iocs:
                lines_iocs, current_progress = (
                    {},
                    round(
                        int(iocfiles.index(iocfile)) / int(len(iocfiles)),
                        1,
                    )
                    * 100,
                )
                if (
                    current_progress != previous_state
                    and str(current_progress).split(".")[0] != "100"
                ):
                    print(
                        "\n\t\033[1;96m------------------------------------------------------------\n\t {}% of IOC extraction completed for '{}'... \n\t------------------------------------------------------------\033[1;m\n".format(
                            str(current_progress).split(".")[0],
                            img.split("::")[0],
                        )
                    )
                    previous_state = current_progress
                try:
                    for line in reading_for_iocs:
                        lineno = lineno + 1
                        if ("." in line or ":" in line or "=" in line) and len(
                            line
                        ) > 7:
                            iocs = re.findall(
                                r"((?:\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:https?\:\/\/)?([A-Za-z]{2,100}\.(?:xn--vermgensberatung-pwb|xn--vermgensberater-ctb|xn--clchc0ea0b2g2a9gcd|xn--w4r85el8fhu5dnra|northwesternmutual|travelersinsurance|xn--3oq18vl8pn36a|xn--5su34j936bgsg|xn--bck1b9a5dre4c|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgberp4a5d4ar|xn--xkc2dl3a5ee0h|xn--fzys8d69uvgm|xn--mgba7c0bbn0a|xn--mgbcpq6gpa1a|xn--xkc2al3hye2a|americanexpress|kerryproperties|sandvikcoromant|xn--i1b6b1a6a2e|xn--kcrx77d1x4a|xn--lgbbat1ad8j|xn--mgba3a4f16a|xn--mgbaakc7dvf|xn--mgbc0a9azcg|xn--nqv7fs00ema|afamilycompany|americanfamily|bananarepublic|cancerresearch|cookingchannel|kerrylogistics|weatherchannel|xn--54b7fta0cc|xn--6qq986b3xl|xn--80aqecdr1a|xn--b4w605ferd|xn--fiq228c5hs|xn--h2breg3eve|xn--jlq480n2rg|xn--jlq61u9w7b|xn--mgba3a3ejt|xn--mgbaam7a8h|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbca7dzdo|xn--mgbi4ecexp|xn--mgbx4cd0ab|xn--rvc1e0am3e|international|lifeinsurance|spreadbetting|travelchannel|wolterskluwer|xn--cckwcxetd|xn--eckvdtc9d|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--h2brj9c8c|xn--tiq49xqyj|xn--yfro4i67o|xn--ygbi2ammx|construction|lplfinancial|scholarships|versicherung|xn--3e0b707e|xn--45br5cyl|xn--80adxhks|xn--80asehdb|xn--8y0a063a|xn--gckr3f0f|xn--mgb9awbf|xn--mgbab2bd|xn--mgbgu82a|xn--mgbpl2fh|xn--mgbt3dhd|xn--mk1bu44c|xn--ngbc5azd|xn--ngbe9e0a|xn--ogbpf8fl|xn--qcka1pmc|accountants|barclaycard|blackfriday|blockbuster|bridgestone|calvinklein|contractors|creditunion|engineering|enterprises|foodnetwork|investments|kerryhotels|lamborghini|motorcycles|olayangroup|photography|playstation|productions|progressive|redumbrella|rightathome|williamhill|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--3bst00m|xn--3ds443g|xn--3hcrj9c|xn--42c2d9a|xn--45brj9c|xn--55qw42g|xn--6frz82g|xn--80ao21a|xn--9krt00a|xn--cck2b3b|xn--czr694b|xn--d1acj3b|xn--efvy88h|xn--fct429k|xn--fjq720a|xn--flw351e|xn--g2xx48c|xn--gecrj9c|xn--gk3at1e|xn--h2brj9c|xn--hxt814e|xn--imr513n|xn--j6w193g|xn--jvr189m|xn--kprw13d|xn--kpry57d|xn--mgbbh1a|xn--mgbtx2b|xn--mix891f|xn--nyqy26a|xn--otu796d|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--rovu88b|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--vuq861b|xn--w4rs40l|xn--xhq521b|xn--zfr164b|accountant|apartments|associates|basketball|bnpparibas|boehringer|capitalone|consulting|creditcard|cuisinella|eurovision|extraspace|foundation|healthcare|immobilien|industries|management|mitsubishi|nationwide|newholland|nextdirect|onyourside|properties|protection|prudential|realestate|republican|restaurant|schaeffler|swiftcover|tatamotors|technology|university|vlaanderen|volkswagen|xn--30rr7y|xn--3pxu8k|xn--45q11c|xn--4gbrim|xn--55qx5d|xn--5tzm5g|xn--80aswg|xn--90a3ac|xn--9dbq2a|xn--9et52u|xn--c2br7g|xn--cg4bki|xn--czrs0t|xn--czru2d|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--io0a7i|xn--kput3i|xn--mxtq1m|xn--o3cw4h|xn--pssy2u|xn--q7ce6a|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--y9a3aq|accenture|alfaromeo|allfinanz|amsterdam|analytics|aquarelle|barcelona|bloomberg|christmas|community|directory|education|equipment|fairwinds|financial|firestone|fresenius|frontdoor|fujixerox|furniture|goldpoint|hisamitsu|homedepot|homegoods|homesense|institute|insurance|kuokgroup|lancaster|landrover|lifestyle|marketing|marshalls|melbourne|microsoft|panasonic|passagens|pramerica|richardli|scjohnson|shangrila|solutions|statebank|statefarm|stockholm|travelers|vacations|xn--90ais|xn--c1avg|xn--d1alf|xn--e1a4c|xn--fhbei|xn--j1aef|xn--j1amh|xn--l1acc|xn--ngbrx|xn--nqv7f|xn--p1acf|xn--qxa6a|xn--tckwe|xn--vhquv|yodobashi|abudhabi|airforce|allstate|attorney|barclays|barefoot|bargains|baseball|boutique|bradesco|broadway|brussels|budapest|builders|business|capetown|catering|catholic|cipriani|cityeats|cleaning|clinique|clothing|commbank|computer|delivery|deloitte|democrat|diamonds|discount|discover|download|engineer|ericsson|etisalat|exchange|feedback|fidelity|firmdale|football|frontier|goodyear|grainger|graphics|guardian|hdfcbank|helsinki|holdings|hospital|infiniti|ipiranga|istanbul|jpmorgan|lighting|lundbeck|marriott|maserati|mckinsey|memorial|merckmsd|mortgage|observer|partners|pharmacy|pictures|plumbing|property|redstone|reliance|saarland|samsclub|security|services|shopping|showtime|softbank|software|stcgroup|supplies|training|vanguard|ventures|verisign|woodside|xn--90ae|xn--node|xn--p1ai|xn--qxam|yokohama|abogado|academy|agakhan|alibaba|android|athleta|auction|audible|auspost|avianca|banamex|bauhaus|bentley|bestbuy|booking|brother|bugatti|capital|caravan|careers|channel|charity|chintai|citadel|clubmed|college|cologne|comcast|company|compare|contact|cooking|corsica|country|coupons|courses|cricket|cruises|dentist|digital|domains|exposed|express|farmers|fashion|ferrari|ferrero|finance|fishing|fitness|flights|florist|flowers|forsale|frogans|fujitsu|gallery|genting|godaddy|grocery|guitars|hamburg|hangout|hitachi|holiday|hosting|hoteles|hotmail|hyundai|ismaili|jewelry|juniper|kitchen|komatsu|lacaixa|lanxess|lasalle|latrobe|leclerc|limited|lincoln|markets|metlife|monster|netbank|netflix|network|neustar|okinawa|oldnavy|organic|origins|philips|pioneer|politie|realtor|recipes|rentals|reviews|rexroth|samsung|sandvik|schmidt|schwarz|science|shiksha|shriram|singles|staples|storage|support|surgery|systems|temasek|theater|theatre|tickets|tiffany|toshiba|trading|walmart|wanggou|watches|weather|website|wedding|whoswho|windows|winners|xfinity|yamaxun|youtube|zuerich|abarth|abbott|abbvie|africa|agency|airbus|airtel|alipay|alsace|alstom|amazon|anquan|aramco|author|bayern|beauty|berlin|bharti|bostik|boston|broker|camera|career|caseih|casino|center|chanel|chrome|church|circle|claims|clinic|coffee|comsec|condos|coupon|credit|cruise|dating|datsun|dealer|degree|dental|design|direct|doctor|dunlop|dupont|durban|emerck|energy|estate|events|expert|family|flickr|futbol|gallup|garden|george|giving|global|google|gratis|health|hermes|hiphop|hockey|hotels|hughes|imamat|insure|intuit|jaguar|joburg|juegos|kaufen|kinder|kindle|kosher|lancia|latino|lawyer|lefrak|living|locker|london|luxury|madrid|maison|makeup|market|mattel|mobile|monash|mormon|moscow|museum|mutual|nagoya|natura|nissan|nissay|norton|nowruz|office|olayan|online|oracle|orange|otsuka|pfizer|photos|physio|pictet|quebec|racing|realty|reisen|repair|report|review|rocher|rogers|ryukyu|safety|sakura|sanofi|school|schule|search|secure|select|shouji|soccer|social|stream|studio|supply|suzuki|swatch|sydney|taipei|taobao|target|tattoo|tennis|tienda|tjmaxx|tkmaxx|toyota|travel|unicom|viajes|viking|villas|virgin|vision|voting|voyage|vuelos|walter|webcam|xihuan|yachts|yandex|zappos|actor|adult|aetna|amfam|amica|apple|archi|audio|autos|azure|baidu|beats|bible|bingo|black|boats|bosch|build|canon|cards|chase|cheap|cisco|citic|click|cloud|coach|codes|crown|cymru|dabur|dance|deals|delta|drive|dubai|earth|edeka|email|epson|faith|fedex|final|forex|forum|gallo|games|gifts|gives|glade|glass|globo|gmail|green|gripe|group|gucci|guide|homes|honda|horse|house|hyatt|ikano|intel|irish|iveco|jetzt|koeln|kyoto|lamer|lease|legal|lexus|lilly|linde|lipsy|lixil|loans|locus|lotte|lotto|lupin|macys|mango|media|miami|money|movie|nexus|nikon|ninja|nokia|nowtv|omega|osaka|paris|parts|party|phone|photo|pizza|place|poker|praxi|press|prime|promo|quest|radio|rehab|reise|ricoh|rocks|rodeo|rugby|salon|sener|seven|sharp|shell|shoes|skype|sling|smart|smile|solar|space|sport|stada|store|study|style|sucks|swiss|tatar|tires|tirol|tmall|today|tokyo|tools|toray|total|tours|trade|trust|tunes|tushu|ubank|vegas|video|vodka|volvo|wales|watch|weber|weibo|works|world|xerox|yahoo|aarp|able|adac|aero|akdn|ally|amex|arab|army|arpa|arte|asda|asia|audi|auto|baby|band|bank|bbva|beer|best|bike|bing|blog|blue|bofa|bond|book|buzz|cafe|call|camp|care|cars|casa|case|cash|cbre|cern|chat|citi|city|club|cool|coop|cyou|data|date|dclk|deal|dell|desi|diet|dish|docs|duck|dvag|erni|fage|fail|fans|farm|fast|fiat|fido|film|fire|fish|flir|food|ford|free|fund|game|gbiz|gent|ggee|gift|gmbh|gold|golf|goog|guge|guru|hair|haus|hdfc|help|here|hgtv|host|hsbc|icbc|ieee|imdb|immo|info|itau|java|jeep|jobs|jprs|kddi|kiwi|kpmg|kred|land|lego|lgbt|lidl|life|like|limo|link|live|loan|loft|love|ltda|luxe|maif|meet|meme|menu|mini|mint|mobi|moda|moto|name|navy|news|next|nico|nike|ollo|open|page|pars|pccw|pics|ping|pink|play|plus|pohl|porn|post|prod|prof|qpon|raid|read|reit|rent|rest|rich|rmit|room|rsvp|ruhr|safe|sale|sarl|save|saxo|scot|seat|seek|sexy|shaw|shia|shop|show|silk|sina|site|skin|sncf|sohu|song|sony|spot|star|surf|talk|taxi|team|tech|teva|tiaa|tips|town|toys|tube|vana|visa|viva|vivo|vote|voto|wang|weir|wien|wiki|wine|work|xbox|yoga|zara|zero|zone|aaa|abb|abc|aco|ads|aeg|afl|aig|anz|aol|app|art|aws|axa|bar|bbc|bbt|bcg|bcn|bet|bid|bio|biz|bms|bmw|bom|boo|bot|box|buy|bzh|cab|cal|cam|car|cat|cba|cbn|cbs|ceb|ceo|cfa|cfd|com|cpa|crs|csc|dad|day|dds|dev|dhl|diy|dnp|dog|dot|dtv|dvr|eat|eco|edu|esq|eus|fan|fit|fly|foo|fox|frl|ftr|fun|fyi|gal|gap|gay|gdn|gea|gle|gmo|gmx|goo|gop|got|gov|hbo|hiv|hkt|hot|how|ibm|ice|icu|ifm|inc|ing|ink|int|ist|itv|jcb|jcp|jio|jll|jmp|jnj|jot|joy|kfh|kia|kim|kpn|krd|lat|law|lds|llc|llp|lol|lpl|ltd|man|map|mba|med|men|mil|mit|mlb|mls|mma|moe|moi|mom|mov|msd|mtn|mtr|nab|nba|nec|net|new|nfl|ngo|nhk|now|nra|nrw|ntt|nyc|obi|off|one|ong|onl|ooo|org|ott|ovh|pay|pet|phd|pid|pin|pnc|pro|pru|pub|pwc|qvc|red|ren|ril|rio|rip|run|rwe|sap|sas|sbi|sbs|sca|scb|ses|sew|sex|sfr|ski|sky|soy|srl|stc|tab|tax|tci|tdk|tel|thd|tjx|top|trv|tui|tvs|ubs|uno|uol|ups|vet|vig|vin|vip|wed|win|wme|wow|wtc|wtf|xin|xxx|xyz|you|yun|zip|ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)(\.(ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw))?)|(?:[\w\-\.]+ ?(\[|\()?\@(\]|\))? ?[A-Za-z0-9]{2,100}\.[A-Za-z]{2,8})|([\w\+\/]{100,}\=\=)|([\w\+\/\-\{\}\%\\\'\"]{100,}\=?\=?)",
                                line,
                            )
                            lines_iocs[str(lineno) + ":±§±:" + line] = iocs
                    lineno = 0
                except:
                    pass
            ioc_before = ""
            for line, indicators in lines_iocs.items():
                if len(indicators) > 0:
                    if len(indicators[0]) > 0:
                        iocs, ioctype = list(set(indicators[0])), ""
                        if len(iocs) > 1:
                            for eachioc in iocs:
                                if (
                                    "<" not in eachioc
                                    and ">" not in eachioc
                                    and "/windows/" not in eachioc
                                    and "/get/anytime-upgrade" not in eachioc
                                    and eachioc != "0.0.0.000"
                                    and eachioc != ""
                                    and "YnBsaXN0MDDUAQIDBAUG" not in eachioc
                                    and "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                    not in eachioc
                                    and "AAAAAAAAAAAAAAAAAAAB" not in eachioc
                                ) and (
                                    (
                                        (len(eachioc) > 7 and "." in eachioc)
                                        and eachioc != "255.0.0.0"
                                        and eachioc != "255.255.0.0"
                                        and eachioc != "255.255.255.0"
                                        and eachioc != "255.255.255.255"
                                        and not eachioc.startswith("172.16.")
                                        and not eachioc.startswith("172.17.")
                                        and not eachioc.startswith("172.18.")
                                        and not eachioc.startswith("172.19.")
                                        and not eachioc.startswith("172.20.")
                                        and not eachioc.startswith("172.21.")
                                        and not eachioc.startswith("172.22.")
                                        and not eachioc.startswith("172.23.")
                                        and not eachioc.startswith("172.24.")
                                        and not eachioc.startswith("172.25.")
                                        and not eachioc.startswith("172.26.")
                                        and not eachioc.startswith("172.27.")
                                        and not eachioc.startswith("172.28.")
                                        and not eachioc.startswith("172.29.")
                                        and not eachioc.startswith("172.30.")
                                        and not eachioc.startswith("172.31.")
                                        and not eachioc.startswith("10.")
                                        and not eachioc.startswith("192.168.")
                                    )
                                    or (len(eachioc) > 7 and ":" in eachioc)
                                    or (
                                        len(eachioc) > 100
                                        and (
                                            "+" in eachioc
                                            or "/" in eachioc
                                            or "=" in eachioc
                                        )
                                        and len(
                                            eachioc.strip("/")
                                            .strip("+")
                                            .strip("{")
                                            .strip("}")
                                            .strip("\\")
                                            .strip('"')
                                            .strip("'")
                                            .strip("%")
                                        )
                                        != 172
                                    )
                                ):
                                    with open(
                                        "/opt/elrond/elrond/rivendell/analysis/ioc_exclusions"
                                    ) as ioc_exclusions:
                                        match = []
                                        for each_exclusion in ioc_exclusions:
                                            if (
                                                eachioc.lower().strip()
                                                == each_exclusion.lower().strip()
                                            ):
                                                match.append("Y")
                                                break
                                            else:
                                                match.append("N")
                                        matches = list(set(match))
                                        if "Y" not in str(matches):
                                            eachioc = (
                                                eachioc.strip("/")
                                                .strip("+")
                                                .strip("{")
                                                .strip("}")
                                                .strip("\\")
                                                .strip('"')
                                                .strip("'")
                                                .strip("%")
                                            )
                                            iocfiletimes = "{},{},{}".format(
                                                str(
                                                    datetime.fromtimestamp(
                                                        os.path.getctime(
                                                            iocfile.split(": ")[0]
                                                        )
                                                    )
                                                ),
                                                str(
                                                    datetime.fromtimestamp(
                                                        os.path.getatime(
                                                            iocfile.split(": ")[0]
                                                        )
                                                    )
                                                ),
                                                str(
                                                    datetime.fromtimestamp(
                                                        os.path.getmtime(
                                                            iocfile.split(": ")[0]
                                                        )
                                                    )
                                                ),
                                            )
                                            if (
                                                len(eachioc) > 7
                                                and "." in eachioc
                                                and ":" not in eachioc
                                                and "=" not in eachioc
                                            ):
                                                try:
                                                    hostout = str(
                                                        subprocess.Popen(
                                                            [
                                                                "host",
                                                                "-W",
                                                                "4",
                                                                str(
                                                                    eachioc.split("@")[
                                                                        -1
                                                                    ]
                                                                ),
                                                            ],
                                                            stdout=subprocess.PIPE,
                                                            stderr=subprocess.PIPE,
                                                        ).communicate()
                                                    )
                                                    resolve = "resolvable"
                                                except:
                                                    hostout, resolve = (
                                                        "",
                                                        "unknown",
                                                    )
                                                if (
                                                    hostout != ""
                                                    and "92.242.130." not in hostout
                                                    and "92.242.131." not in hostout
                                                    and "92.242.132." not in hostout
                                                    and (
                                                        "has address" in hostout
                                                        or "has IPv6 address" in hostout
                                                        or "is an alias for" in hostout
                                                        or "mail is handled by"
                                                        in hostout
                                                    )
                                                ):
                                                    resolve = "resolvable"
                                                else:
                                                    resolve = "N/A"
                                                for domainorip in re.findall(
                                                    r"^[A-Za-z]+\.",
                                                    eachioc.split("@")[-1],
                                                ):
                                                    if domainorip != "":
                                                        ioctype = "domain"
                                                for domainorip in re.findall(
                                                    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                                                    eachioc.split("@")[-1],
                                                ):
                                                    if domainorip != "":
                                                        ioctype = "IPv4_address"
                                            elif (
                                                len(eachioc) > 7
                                                and ":" in eachioc
                                                and "." not in eachioc
                                                and "=" not in eachioc
                                            ):
                                                ioctype = "IPv6_address"
                                                resolve = "-"
                                            elif len(eachioc) > 100 and (
                                                ("+" in eachioc and "=" in eachioc)
                                                or ("+" in eachioc and "/" in eachioc)
                                                or ("=" in eachioc and "/" in eachioc)
                                            ):
                                                if (
                                                    "-" not in eachioc
                                                    and "{" not in eachioc
                                                    and "}" not in eachioc
                                                    and "%" not in eachioc
                                                    and "\\" not in eachioc
                                                    and "'" not in eachioc
                                                    and '"' not in eachioc
                                                ):
                                                    ioctype = (
                                                        "pure_base64_encoded_string"
                                                    )
                                                else:
                                                    ioctype = "obfuscated_base64_encoded_string"
                                                resolve = "-"
                                            else:
                                                ioctype = ""
                                            if ioctype != "":
                                                with open(
                                                    output_directory
                                                    + img.split("::")[0]
                                                    + "/analysis/iocs.csv",
                                                    "a",
                                                ) as ioccsv:
                                                    ioccsv.write(
                                                        "{},{},{},{},{},{}\n".format(
                                                            iocfiletimes,
                                                            iocfile.split(": ")[0]
                                                            .replace(",", "%2C")
                                                            .strip(),
                                                            eachioc.split("@")[-1],
                                                            ioctype.replace("_", " "),
                                                            str(line.split(":±§±:")[0]),
                                                            resolve,
                                                        )
                                                    )
                                        match.clear()
                                        matches.clear()
                                    if (
                                        ioctype != ""
                                        and ioc_before.lower()
                                        != eachioc.split("@")[-1].lower()
                                    ):
                                        (
                                            entry,
                                            prnt,
                                        ) = "{},{},{},IOC '{}' ({}) extracted from '{}'".format(
                                            datetime.now().isoformat(),
                                            img.split("::")[0],
                                            stage,
                                            eachioc.split("@")[-1],
                                            ioctype.replace("_", " "),
                                            iocfile.split(": ")[0],
                                        ), " -> {} -> potential IOC '{}' ({}) extracted from '{}' for '{}'".format(
                                            datetime.now()
                                            .isoformat()
                                            .replace("T", " "),
                                            eachioc.split("@")[-1],
                                            ioctype.replace("_", " "),
                                            iocfile.split(": ")[0].split("/")[-1],
                                            img.split("::")[0],
                                        )
                                        write_audit_log_entry(
                                            verbosity,
                                            output_directory,
                                            entry,
                                            prnt,
                                        )
                                        ioc_before = eachioc.split("@")[-1]
    print("      IOC extraction completed for {}.\n".format(vssimage))
