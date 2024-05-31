#!/usr/bin/env python3 -tt
import os

from rivendell.collect.files.compare import compare_include_exclude


def collect_files(
    output_directory,
    verbosity,
    stage,
    img,
    vssimage,
    recovered_file_root,
    recovered_file,
    increment,
    collectfiles,
    file_selection,
):
    if collectfiles == True:
        if (
            (
                recovered_file.lower().startswith(".")
                or recovered_file.lower().endswith(".exe")
                or recovered_file.lower().endswith(".dll")
                or recovered_file.lower().endswith(".sys")
                or recovered_file.lower().endswith(".elf")
                or recovered_file.lower().endswith(".bin")
                or recovered_file.lower().endswith(".dmg")
                or recovered_file.lower().endswith(".app")
                or recovered_file.lower().endswith(".docx")
                or recovered_file.lower().endswith(".doc")
                or recovered_file.lower().endswith(".docm")
                or recovered_file.lower().endswith(".xlsx")
                or recovered_file.lower().endswith(".xls")
                or recovered_file.lower().endswith(".xlsm")
                or recovered_file.lower().endswith(".pptx")
                or recovered_file.lower().endswith(".ppt")
                or recovered_file.lower().endswith(".pptm")
                or recovered_file.lower().endswith(".pdf")
                or recovered_file.lower().endswith(".rtf")
                or recovered_file.lower().endswith(".ott")
                or recovered_file.lower().endswith(".odt")
                or recovered_file.lower().endswith(".ods")
                or recovered_file.lower().endswith(".odg")
                or recovered_file.lower().endswith(".pages")
                or recovered_file.lower().endswith(".numbers")
                or recovered_file.lower().endswith(".keynote")
                or recovered_file.lower().endswith(".zip")
                or recovered_file.lower().endswith(".rar")
                or recovered_file.lower().endswith(".7z")
                or recovered_file.lower().endswith(".tar")
                or recovered_file.lower().endswith(".tar.gz")
                or recovered_file.lower().endswith(".arj")
                or recovered_file.lower().endswith(".ps1")
                or recovered_file.lower().endswith(".py")
                or recovered_file.lower().endswith(".bat")
                or recovered_file.lower().endswith(".vba")
                or recovered_file.lower().endswith(".vb")
                or recovered_file.lower().endswith(".vbscript")
                or recovered_file.lower().endswith(".js")
                or recovered_file.lower().endswith(".c")
                or recovered_file.lower().endswith(".o")
                or recovered_file.lower().endswith(".cpp")
                or recovered_file.lower().endswith(".cc")
                or recovered_file.lower().endswith(".pl")
                or recovered_file.lower().endswith(".go")
                or recovered_file.lower().endswith(".lnk")
                or recovered_file.lower().endswith(".apsx")
                or recovered_file.lower().endswith(".html")
                or recovered_file.lower().endswith(".htm")
                or recovered_file.lower().endswith(".php")
                or recovered_file.lower().endswith(".asp")
                or recovered_file.lower().endswith(".ost")
                or recovered_file.lower().endswith(".pst")
                or recovered_file.lower().endswith(".eml")
                or recovered_file.lower().endswith(".vmware")
                or recovered_file.lower().endswith(".vmdk")
                or recovered_file.lower().endswith(".vmx")
            )
            and (
                "archive.ubuntu" not in recovered_file
                and "security.ubuntu" not in recovered_file
                and not recovered_file.lower().endswith("hiberfil.sys")
                and not recovered_file.lower().endswith("pagefile.sys")
                and not recovered_file.lower().endswith("swapfile.sys")
                and not recovered_file.lower().startswith("_")
                and not recovered_file.lower().startswith(".builtin")
                and not recovered_file.lower().startswith(".conf")
                and not recovered_file.lower().startswith(".decode")
                and not recovered_file.lower().startswith(".gitignore")
                and not recovered_file.lower().startswith(".lib")
                and not recovered_file.lower().startswith(".meta")
                and not recovered_file.lower().startswith(".parser")
                and not recovered_file.lower().startswith(".symbol")
                and not recovered_file.lower().startswith(".unist")
                and not recovered_file.lower().startswith(".uuid")
                and not recovered_file.lower().startswith("about this folder.")
                and not recovered_file.lower().startswith("about")
                and not recovered_file.lower().startswith("accessibility")
                and not recovered_file.lower().startswith("acknowledgement")
                and not recovered_file.lower().startswith("aclayers")
                and not recovered_file.lower().startswith("action")
                and not recovered_file.lower().startswith("acxtrnal")
                and not recovered_file.lower().startswith("addin")
                and not recovered_file.lower().startswith("additional")
                and not recovered_file.lower().startswith("adwsmigrate")
                and not recovered_file.lower().startswith("afd")
                and not recovered_file.lower().startswith("airportinmenu")
                and not recovered_file.lower().startswith("alttool")
                and not recovered_file.lower().startswith("api_")
                and not recovered_file.lower().startswith("api-ms-win-core-")
                and not recovered_file.lower().startswith("appid")
                and not recovered_file.lower().startswith("apple-pay")
                and not recovered_file.lower().startswith("apprl")
                and not recovered_file.lower().startswith("asp")
                and not recovered_file.lower().startswith("async")
                and not recovered_file.lower().startswith("atmfd")
                and not recovered_file.lower().startswith("atmlib")
                and not recovered_file.lower().startswith("authfw")
                and not recovered_file.lower().startswith("auxiliary")
                and not recovered_file.lower().startswith("aw-")
                and not recovered_file.lower().startswith("awdmetadata")
                and not recovered_file.lower().startswith("axes_")
                and not recovered_file.lower().startswith("backend")
                and not recovered_file.lower().startswith("basicconstraints")
                and not recovered_file.lower().startswith("batterylevel")
                and not recovered_file.lower().startswith("bdatunepia")
                and not recovered_file.lower().startswith("bench_")
                and not recovered_file.lower().startswith("bl.bin")
                and not recovered_file.lower().startswith("bluetooth_")
                and not recovered_file.lower().startswith("board")
                and not recovered_file.lower().startswith("bonaire_")
                and not recovered_file.lower().startswith("boot_")
                and not recovered_file.lower().startswith("brain_")
                and not recovered_file.lower().startswith("brcmfmac")
                and not recovered_file.lower().startswith("brm")
                and not recovered_file.lower().startswith("brserib")
                and not recovered_file.lower().startswith("brus2sti")
                and not recovered_file.lower().startswith("brusbsib")
                and not recovered_file.lower().startswith("bthmigplugin")
                and not recovered_file.lower().startswith("btkeyboard")
                and not recovered_file.lower().startswith("btmouse")
                and not recovered_file.lower().startswith("bttrackpad")
                and not recovered_file.lower().startswith("build_")
                and not recovered_file.lower().startswith("bus-")
                and not recovered_file.lower().startswith("bxt_")
                and not recovered_file.lower().startswith("caidentity")
                and not recovered_file.lower().startswith("caidentityname")
                and not recovered_file.lower().startswith("carrizo_")
                and not recovered_file.lower().startswith("categoryimage")
                and not recovered_file.lower().startswith("cayman_")
                and not recovered_file.lower().startswith("cbfw-")
                and not recovered_file.lower().startswith("cedar_")
                and not recovered_file.lower().startswith("cfgmgr32")
                and not recovered_file.lower().startswith("check")
                and not recovered_file.lower().startswith("chooseissu")
                and not recovered_file.lower().startswith("cli-")
                and not recovered_file.lower().startswith("clibrl")
                and not recovered_file.lower().startswith("client.")
                and not recovered_file.lower().startswith("clipping")
                and not recovered_file.lower().startswith("cmauires")
                and not recovered_file.lower().startswith("cmiadapter")
                and not recovered_file.lower().startswith("cmiv2")
                and not recovered_file.lower().startswith("cmmigr")
                and not recovered_file.lower().startswith("cnt-")
                and not recovered_file.lower().startswith("cntrtextmig")
                and not recovered_file.lower().startswith("code")
                and not recovered_file.lower().startswith("comctl32")
                and not recovered_file.lower().startswith("command")
                and not recovered_file.lower().startswith("common")
                and not recovered_file.lower().startswith("company_placeholder")
                and not recovered_file.lower().startswith("compat")
                and not recovered_file.lower().startswith("conclusionca")
                and not recovered_file.lower().startswith("config")
                and not recovered_file.lower().startswith("contour")
                and not recovered_file.lower().startswith("core.")
                and not recovered_file.lower().startswith("coremldata.")
                and not recovered_file.lower().startswith("corerl")
                and not recovered_file.lower().startswith("cp")
                and not recovered_file.lower().startswith("cpfilters")
                and not recovered_file.lower().startswith("credits.")
                and not recovered_file.lower().startswith("crypto_")
                and not recovered_file.lower().startswith("csc")
                and not recovered_file.lower().startswith("cursor.")
                and not recovered_file.lower().startswith("custommarshalers")
                and not recovered_file.lower().startswith("cypress_")
                and not recovered_file.lower().startswith("d2d1")
                and not recovered_file.lower().startswith("d3d10_1")
                and not recovered_file.lower().startswith("d3d10warp")
                and not recovered_file.lower().startswith("dciman32")
                and not recovered_file.lower().startswith("debug.")
                and not recovered_file.lower().startswith("decoder.")
                and not recovered_file.lower().startswith("decomp_")
                and not recovered_file.lower().startswith("decorators.")
                and not recovered_file.lower().startswith("demo")
                and not recovered_file.lower().startswith("desc-")
                and not recovered_file.lower().startswith("descriptor")
                and not recovered_file.lower().startswith("destkeychain")
                and not recovered_file.lower().startswith("develop")
                and not recovered_file.lower().startswith("device")
                and not recovered_file.lower().startswith("devobj")
                and not recovered_file.lower().startswith("devrtl")
                and not recovered_file.lower().startswith("dhcp")
                and not recovered_file.lower().startswith("diagpackage")
                and not recovered_file.lower().startswith("dialog")
                and not recovered_file.lower().startswith("distupgrade")
                and not recovered_file.lower().startswith("dnsapi")
                and not recovered_file.lower().startswith("dnscacheugc")
                and not recovered_file.lower().startswith("dot3")
                and not recovered_file.lower().startswith("dot4")
                and not recovered_file.lower().startswith("doublearrow")
                and not recovered_file.lower().startswith("dpx")
                and not recovered_file.lower().startswith("dragcsr")
                and not recovered_file.lower().startswith("drmmgrtn")
                and not recovered_file.lower().startswith("drvinst")
                and not recovered_file.lower().startswith("drvstore")
                and not recovered_file.lower().startswith("dsp_fw_")
                and not recovered_file.lower().startswith("dwrite")
                and not recovered_file.lower().startswith("dxmasf")
                and not recovered_file.lower().startswith("emojiim")
                and not recovered_file.lower().startswith("encdec")
                and not recovered_file.lower().startswith("encoder")
                and not recovered_file.lower().startswith("ep0ic")
                and not recovered_file.lower().startswith("error.")
                and not recovered_file.lower().startswith("esent")
                and not recovered_file.lower().startswith("esfw")
                and not recovered_file.lower().startswith("esscli")
                and not recovered_file.lower().startswith("eula")
                and not recovered_file.lower().startswith("evalcerts")
                and not recovered_file.lower().startswith("eventcollection")
                and not recovered_file.lower().startswith("exception")
                and not recovered_file.lower().startswith("explorer")
                and not recovered_file.lower().startswith("ext-ms-win-")
                and not recovered_file.lower().startswith("extendedku")
                and not recovered_file.lower().startswith("fastprox")
                and not recovered_file.lower().startswith("faxwizard")
                and not recovered_file.lower().startswith("fdewarning")
                and not recovered_file.lower().startswith("fecs_")
                and not recovered_file.lower().startswith("fiji_")
                and not recovered_file.lower().startswith("file_")
                and not recovered_file.lower().startswith("finder_")
                and not recovered_file.lower().startswith("firstaid")
                and not recovered_file.lower().startswith("fix_")
                and not recovered_file.lower().startswith("fontsandcolo")
                and not recovered_file.lower().startswith("fontsub")
                and not recovered_file.lower().startswith("formatter")
                and not recovered_file.lower().startswith("formatting")
                and not recovered_file.lower().startswith("fsutil")
                and not recovered_file.lower().startswith("fw_")
            )
            and (
                not recovered_file.lower().startswith("gen_")
                and not recovered_file.lower().startswith("glas-")
                and not recovered_file.lower().startswith("goopdate")
                and not recovered_file.lower().startswith("gpccs_")
                and not recovered_file.lower().startswith("gui-")
                and not recovered_file.lower().startswith("hainan_")
                and not recovered_file.lower().startswith("hashes.")
                and not recovered_file.lower().startswith("hawaii_")
                and not recovered_file.lower().startswith("help")
                and not recovered_file.lower().startswith("helpers.")
                and not recovered_file.lower().startswith("hist_")
                and not recovered_file.lower().startswith("house_")
                and not recovered_file.lower().startswith("hp")
                and not recovered_file.lower().startswith("hud")
                and not recovered_file.lower().startswith("hxdsui")
                and not recovered_file.lower().startswith("icl_")
                and not recovered_file.lower().startswith("iconmask")
                and not recovered_file.lower().startswith("iedkcs32")
                and not recovered_file.lower().startswith("iedvtool")
                and not recovered_file.lower().startswith("ieframe")
                and not recovered_file.lower().startswith("iepeers")
                and not recovered_file.lower().startswith("ieproxy")
                and not recovered_file.lower().startswith("iertutil")
                and not recovered_file.lower().startswith("ieshims")
                and not recovered_file.lower().startswith("ieui")
                and not recovered_file.lower().startswith("iexplore")
                and not recovered_file.lower().startswith("iis")
                and not recovered_file.lower().startswith("ik-disclosure")
                and not recovered_file.lower().startswith("image")
                and not recovered_file.lower().startswith("imapi")
                and not recovered_file.lower().startswith("indeterminate")
                and not recovered_file.lower().startswith("inetcomm")
                and not recovered_file.lower().startswith("inetres")
                and not recovered_file.lower().startswith("info.")
                and not recovered_file.lower().startswith("input")
                and not recovered_file.lower().startswith("install_")
                and not recovered_file.lower().startswith("install.")
                and not recovered_file.lower().startswith("ipad license")
                and not recovered_file.lower().startswith("iphone license")
                and not recovered_file.lower().startswith("ipod license")
                and not recovered_file.lower().startswith("ipod touch license")
                and not recovered_file.lower().startswith("irda")
                and not recovered_file.lower().startswith("isbew64")
                and not recovered_file.lower().startswith("iso")
                and not recovered_file.lower().startswith("isymwrapper")
                and not recovered_file.lower().startswith("jscript")
                and not recovered_file.lower().startswith("jscript9")
                and not recovered_file.lower().startswith("json_")
                and not recovered_file.lower().startswith("jsproxy")
                and not recovered_file.lower().startswith("juniper_")
                and not recovered_file.lower().startswith("kabini_")
                and not recovered_file.lower().startswith("kaveri_")
                and not recovered_file.lower().startswith("kbl_")
                and not recovered_file.lower().startswith("kd")
                and not recovered_file.lower().startswith("kerberos")
                and not recovered_file.lower().startswith("kernel")
                and not recovered_file.lower().startswith("kernel32")
                and not recovered_file.lower().startswith("kernelbase")
                and not recovered_file.lower().startswith("kex_")
                and not recovered_file.lower().startswith("keypair")
                and not recovered_file.lower().startswith("keyusage")
                and not recovered_file.lower().startswith("kyw")
                and not recovered_file.lower().startswith("lang")
                and not recovered_file.lower().startswith("legaltext")
                and not recovered_file.lower().startswith("legend_")
                and not recovered_file.lower().startswith("letterwizard")
                and not recovered_file.lower().startswith("license.")
                and not recovered_file.lower().startswith("licmgr10")
                and not recovered_file.lower().startswith("line")
                and not recovered_file.lower().startswith("lio_")
                and not recovered_file.lower().startswith("live")
                and not recovered_file.lower().startswith("log_status")
                and not recovered_file.lower().startswith("lpk")
                and not recovered_file.lower().startswith("mac_")
                and not recovered_file.lower().startswith("main.")
                and not recovered_file.lower().startswith("manager")
                and not recovered_file.lower().startswith("markers")
                and not recovered_file.lower().startswith("mathtext")
                and not recovered_file.lower().startswith("matrix.")
                and not recovered_file.lower().startswith("mcshield")
                and not recovered_file.lower().startswith("mcstoredb")
                and not recovered_file.lower().startswith("mctrayhiprl")
                and not recovered_file.lower().startswith("mctrayres")
                and not recovered_file.lower().startswith("media")
                and not recovered_file.lower().startswith("message")
                and not recovered_file.lower().startswith("mf")
                and not recovered_file.lower().startswith("microcode_")
                and not recovered_file.lower().startswith("microsoft")
                and not recovered_file.lower().startswith("mime")
                and not recovered_file.lower().startswith("miniaudio")
                and not recovered_file.lower().startswith("misc.")
                and not recovered_file.lower().startswith("modules.")
                and not recovered_file.lower().startswith("mofd")
                and not recovered_file.lower().startswith("month-allday")
                and not recovered_file.lower().startswith("mrxsmb")
                and not recovered_file.lower().startswith("ms")
                and not recovered_file.lower().startswith("mueres")
                and not recovered_file.lower().startswith("mullens_")
                and not recovered_file.lower().startswith("navi1")
                and not recovered_file.lower().startswith("ndismigplugin")
                and not recovered_file.lower().startswith("netfx")
                and not recovered_file.lower().startswith("netshrrl")
                and not recovered_file.lower().startswith("nls")
                and not recovered_file.lower().startswith("ntdll")
                and not recovered_file.lower().startswith("ntkrnlpa")
                and not recovered_file.lower().startswith("ntoskrnl")
                and not recovered_file.lower().startswith("ntprint")
                and not recovered_file.lower().startswith("ntshrui")
                and not recovered_file.lower().startswith("ntvdm64")
                and not recovered_file.lower().startswith("nvm_")
                and not recovered_file.lower().startswith("odbc32")
                and not recovered_file.lower().startswith("office_")
                and not recovered_file.lower().startswith("oland_")
                and not recovered_file.lower().startswith("ole")
                and not recovered_file.lower().startswith("option")
                and not recovered_file.lower().startswith("optionsavailable")
                and not recovered_file.lower().startswith("orca_")
                and not recovered_file.lower().startswith("osa_")
                and not recovered_file.lower().startswith("osxsoftware")
                and not recovered_file.lower().startswith("package")
                and not recovered_file.lower().startswith("packager")
                and not recovered_file.lower().startswith("palm_")
                and not recovered_file.lower().startswith("parse")
                and not recovered_file.lower().startswith("patch_")
                and not recovered_file.lower().startswith("patheffect")
                and not recovered_file.lower().startswith("peer")
                and not recovered_file.lower().startswith("pgf_")
                and not recovered_file.lower().startswith("ph3xib64")
                and not recovered_file.lower().startswith("picasso_")
                and not recovered_file.lower().startswith("pitcairn_")
                and not recovered_file.lower().startswith("pkgmgr")
                and not recovered_file.lower().startswith("polar_")
                and not recovered_file.lower().startswith("polaris1")
                and not recovered_file.lower().startswith("policy.")
                and not recovered_file.lower().startswith("portabledeviceapi")
                and not recovered_file.lower().startswith("ppp")
                and not recovered_file.lower().startswith("presentationbuildtasks")
                and not recovered_file.lower().startswith("prevhost")
                and not recovered_file.lower().startswith("print_")
                and not recovered_file.lower().startswith("print")
                and not recovered_file.lower().startswith("privacynote")
                and not recovered_file.lower().startswith("productinfo")
                and not recovered_file.lower().startswith("psisdecd")
                and not recovered_file.lower().startswith("pydev")
                and not recovered_file.lower().startswith("qat_")
                and not recovered_file.lower().startswith("qdvd")
                and not recovered_file.lower().startswith("qed_")
                and not recovered_file.lower().startswith("qlfullscreen")
                and not recovered_file.lower().startswith("quartz")
                and not recovered_file.lower().startswith("rampatch_")
                and not recovered_file.lower().startswith("rasmigplugin")
                and not recovered_file.lower().startswith("raven")
                and not recovered_file.lower().startswith("rdpcore")
                and not recovered_file.lower().startswith("reachframework")
                and not recovered_file.lower().startswith("redwood_")
                and not recovered_file.lower().startswith("regulatory")
                and not recovered_file.lower().startswith("remote")
                and not recovered_file.lower().startswith("renoir_")
                and not recovered_file.lower().startswith("resource")
                and not recovered_file.lower().startswith("response")
                and not recovered_file.lower().startswith("rl_")
                and not recovered_file.lower().startswith("rmactivate")
                and not recovered_file.lower().startswith("round-")
                and not recovered_file.lower().startswith("rt")
                and not recovered_file.lower().startswith("rv")
            )
            and (
                not recovered_file.lower().startswith("sb")
                and not recovered_file.lower().startswith("scatter_")
                and not recovered_file.lower().startswith("schannel")
                and not recovered_file.lower().startswith("script_")
                and not recovered_file.lower().startswith("script.")
                and not recovered_file.lower().startswith("scrubber.")
                and not recovered_file.lower().startswith("sd")
                and not recovered_file.lower().startswith("search")
                and not recovered_file.lower().startswith("secproc")
                and not recovered_file.lower().startswith("secur32")
                and not recovered_file.lower().startswith("selog")
                and not recovered_file.lower().startswith("serun")
                and not recovered_file.lower().startswith("server.")
                and not recovered_file.lower().startswith("servicemodel")
                and not recovered_file.lower().startswith("seshow")
                and not recovered_file.lower().startswith("sestatus")
                and not recovered_file.lower().startswith("setdefaultca")
                and not recovered_file.lower().startswith("settings.")
                and not recovered_file.lower().startswith("setup")
                and not recovered_file.lower().startswith("shell32")
                and not recovered_file.lower().startswith("shmig")
                and not recovered_file.lower().startswith("sig.")
                and not recovered_file.lower().startswith("simple_")
                and not recovered_file.lower().startswith("skl_")
                and not recovered_file.lower().startswith("snap.")
                and not recovered_file.lower().startswith("snmp")
                and not recovered_file.lower().startswith("software")
                and not recovered_file.lower().startswith("sos")
                and not recovered_file.lower().startswith("source_")
                and not recovered_file.lower().startswith("spdxcheck.")
                and not recovered_file.lower().startswith("speech")
                and not recovered_file.lower().startswith("spp")
                and not recovered_file.lower().startswith("spwmp")
                and not recovered_file.lower().startswith("sqmapi")
                and not recovered_file.lower().startswith("square-")
                and not recovered_file.lower().startswith("sspicli")
                and not recovered_file.lower().startswith("starfire_")
                and not recovered_file.lower().startswith("statusbar")
                and not recovered_file.lower().startswith("stl-")
                and not recovered_file.lower().startswith("stoney_")
                and not recovered_file.lower().startswith("strings")
                and not recovered_file.lower().startswith("subjaltnameext")
                and not recovered_file.lower().startswith("suggestions-")
                and not recovered_file.lower().startswith("sumo_")
                and not recovered_file.lower().startswith("sw_")
                and not recovered_file.lower().startswith("sxsmigplugin")
                and not recovered_file.lower().startswith("symbols")
                and not recovered_file.lower().startswith("sync")
                and not recovered_file.lower().startswith("system")
                and not recovered_file.lower().startswith("t2embed")
                and not recovered_file.lower().startswith("table")
                and not recovered_file.lower().startswith("tahiti_")
                and not recovered_file.lower().startswith("task")
                and not recovered_file.lower().startswith("tb-")
                and not recovered_file.lower().startswith("tcpip")
                and not recovered_file.lower().startswith("test_")
                and not recovered_file.lower().startswith("text_")
                and not recovered_file.lower().startswith("text")
                and not recovered_file.lower().startswith("tg")
                and not recovered_file.lower().startswith("tight_")
                and not recovered_file.lower().startswith("token")
                and not recovered_file.lower().startswith("tonga_")
                and not recovered_file.lower().startswith("topaz_")
                and not recovered_file.lower().startswith("tp")
                and not recovered_file.lower().startswith("tquery")
                and not recovered_file.lower().startswith("trayrl")
                and not recovered_file.lower().startswith("trigger_")
                and not recovered_file.lower().startswith("ts")
                and not recovered_file.lower().startswith("turks_")
                and not recovered_file.lower().startswith("txt.")
                and not recovered_file.lower().startswith("type_")
                and not recovered_file.lower().startswith("types")
                and not recovered_file.lower().startswith("tzres")
                and not recovered_file.lower().startswith("tzupd")
                and not recovered_file.lower().startswith("ucode_")
                and not recovered_file.lower().startswith("ui")
                and not recovered_file.lower().startswith("unittest")
                and not recovered_file.lower().startswith("unload_")
                and not recovered_file.lower().startswith("url")
                and not recovered_file.lower().startswith("usb8023")
                and not recovered_file.lower().startswith("useraccountcontrolsettings")
                and not recovered_file.lower().startswith("utf_")
                and not recovered_file.lower().startswith("util")
                and not recovered_file.lower().startswith("vault")
                and not recovered_file.lower().startswith("vbc")
                and not recovered_file.lower().startswith("vbscript")
                and not recovered_file.lower().startswith("vega")
                and not recovered_file.lower().startswith("verde_")
                and not recovered_file.lower().startswith("version")
                and not recovered_file.lower().startswith("vgx")
                and not recovered_file.lower().startswith("vm")
                and not recovered_file.lower().startswith("volume")
                and not recovered_file.lower().startswith("wab32")
                and not recovered_file.lower().startswith("wab32res")
                and not recovered_file.lower().startswith("wabimp")
                and not recovered_file.lower().startswith("wbe")
                and not recovered_file.lower().startswith("wc")
                and not recovered_file.lower().startswith("wd")
                and not recovered_file.lower().startswith("webengine")
                and not recovered_file.lower().startswith("webio")
                and not recovered_file.lower().startswith("welcomescreen")
                and not recovered_file.lower().startswith("wfapigp")
                and not recovered_file.lower().startswith("wilc")
                and not recovered_file.lower().startswith("win32k")
                and not recovered_file.lower().startswith("winb")
                and not recovered_file.lower().startswith("wind")
                and not recovered_file.lower().startswith("windows_")
                and not recovered_file.lower().startswith("wininet")
                and not recovered_file.lower().startswith("winload")
                and not recovered_file.lower().startswith("winresume")
                and not recovered_file.lower().startswith("wl")
                and not recovered_file.lower().startswith("wlan")
                and not recovered_file.lower().startswith("wmicmiplugin")
                and not recovered_file.lower().startswith("wmimigrationplugin")
                and not recovered_file.lower().startswith("wmiutils")
                and not recovered_file.lower().startswith("wmp")
                and not recovered_file.lower().startswith("wpd")
                and not recovered_file.lower().startswith("wpfgfx")
                and not recovered_file.lower().startswith("wsearchmigplugin")
                and not recovered_file.lower().startswith("ww")
                and not recovered_file.lower().startswith("wwan")
                and not recovered_file.lower().startswith("xmllite")
                and not recovered_file.lower().startswith("xpsgdiconverter")
                and not recovered_file.lower().startswith("xpsprint")
                and not recovered_file.lower().startswith("youtubeterms")
            )
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/")
            if "H" in file_selection or "A" in file_selection:
                if (
                    recovered_file.lower().startswith(".")
                    and recovered_file != ".localized"
                    and recovered_file != ".DS_Store"
                    and recovered_file != ".CFUserTextEncoding"
                    and recovered_file != ".file"
                ):
                    try:
                        os.stat(output_directory + img.split("::")[0] + "/files/hidden")
                    except:
                        os.makedirs(
                            output_directory + img.split("::")[0] + "/files/hidden"
                        )
                    compare_include_exclude(
                        output_directory,
                        verbosity,
                        stage,
                        img,
                        vssimage,
                        "/files/hidden/",
                        "hidden file",
                        recovered_file_root,
                        recovered_file,
                        increment,
                        collectfiles,
                    )
            if ("B" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".exe")
                or recovered_file.lower().endswith(".dll")
                or recovered_file.lower().endswith(".sys")
                or recovered_file.lower().endswith(".elf")
                or recovered_file.lower().endswith(".bin")
                or recovered_file.lower().endswith(".dmg")
                or recovered_file.lower().endswith(".app")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/binaries")
                except:
                    os.makedirs(
                        output_directory + img.split("::")[0] + "/files/binaries"
                    )
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/binaries/",
                    "binary file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if (
                ("D" in file_selection or "A" in file_selection)
                and (
                    recovered_file.lower().endswith(".docx")
                    or recovered_file.lower().endswith(".doc")
                    or recovered_file.lower().endswith(".docm")
                    or recovered_file.lower().endswith(".xlsx")
                    or recovered_file.lower().endswith(".xls")
                    or recovered_file.lower().endswith(".xlsm")
                    or recovered_file.lower().endswith(".pptx")
                    or recovered_file.lower().endswith(".ppt")
                    or recovered_file.lower().endswith(".pptm")
                    or recovered_file.lower().endswith(".pdf")
                    or recovered_file.lower().endswith(".rtf")
                    or recovered_file.lower().endswith(".ott")
                    or recovered_file.lower().endswith(".odt")
                    or recovered_file.lower().endswith(".ods")
                    or recovered_file.lower().endswith(".odg")
                    or recovered_file.lower().endswith(".pages")
                    or recovered_file.lower().endswith(".numbers")
                    or recovered_file.lower().endswith(".keynote")
                )
                and not recovered_file.lower().endswith("eula.rtf")
                and not recovered_file.lower().endswith("license.rtf")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/documents")
                except:
                    os.makedirs(
                        output_directory + img.split("::")[0] + "/files/documents"
                    )
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/documents/",
                    "document file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("R" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".zip")
                or recovered_file.lower().endswith(".rar")
                or recovered_file.lower().endswith(".7z")
                or recovered_file.lower().endswith(".tar")
                or recovered_file.lower().endswith(".gz")
                or recovered_file.lower().endswith(".arj")
                or recovered_file.lower().endswith(".jar")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/archives")
                except:
                    os.makedirs(
                        output_directory + img.split("::")[0] + "/files/archives"
                    )
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/archives/",
                    "archive file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("S" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".ps1")
                or recovered_file.lower().endswith(".py")
                or recovered_file.lower().endswith(".bat")
                or recovered_file.lower().endswith(".vba")
                or recovered_file.lower().endswith(".vb")
                or recovered_file.lower().endswith(".vbscript")
                or recovered_file.lower().endswith(".js")
                or recovered_file.lower().endswith(".c")
                or recovered_file.lower().endswith(".o")
                or recovered_file.lower().endswith(".cpp")
                or recovered_file.lower().endswith(".cc")
                or recovered_file.lower().endswith(".pl")
                or recovered_file.lower().endswith(".go")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/scripts")
                except:
                    os.makedirs(
                        output_directory + img.split("::")[0] + "/files/scripts"
                    )
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/scripts/",
                    "script file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("L" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".lnk")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/lnk")
                except:
                    os.makedirs(output_directory + img.split("::")[0] + "/files/lnk")
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/lnk/",
                    "lnk file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("W" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".apsx")
                or recovered_file.lower().endswith(".html")
                or recovered_file.lower().endswith(".htm")
                or recovered_file.lower().endswith(".php")
                or recovered_file.lower().endswith(".asp")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/web")
                except:
                    os.makedirs(output_directory + img.split("::")[0] + "/files/web")
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/web/",
                    "web file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("M" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".ost")
                or recovered_file.lower().endswith(".pst")
                or recovered_file.lower().endswith(".eml")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/mail")
                except:
                    os.makedirs(output_directory + img.split("::")[0] + "/files/mail")
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/mail/",
                    "mail file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
            if ("V" in file_selection or "A" in file_selection) and (
                recovered_file.lower().endswith(".vmware")
                or recovered_file.lower().endswith(".vmdk")
                or recovered_file.lower().endswith(".vmx")
                or recovered_file.lower().endswith(".vdi")
            ):
                try:
                    os.stat(output_directory + img.split("::")[0] + "/files/virtual")
                except:
                    os.makedirs(
                        output_directory + img.split("::")[0] + "/files/virtual"
                    )
                compare_include_exclude(
                    output_directory,
                    verbosity,
                    stage,
                    img,
                    vssimage,
                    "/files/virtual/",
                    "virtual file",
                    recovered_file_root,
                    recovered_file,
                    increment,
                    collectfiles,
                )
    else:
        compare_include_exclude(
            output_directory,
            verbosity,
            stage,
            img,
            vssimage,
            "/files/",
            "file",
            recovered_file_root,
            recovered_file,
            increment,
            collectfiles,
        )
