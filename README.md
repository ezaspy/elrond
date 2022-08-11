<!-- PROJECT LOGO -->
<p align="center">
  <a href="https://github.com/ezaspy/elrond">
    <img src="elrond/images/logo_trans_big.png" alt="Logo" width="400" height="400">
  </a>
  <p align="center">
    Accelerating the collection, processing, analysis and outputting of digital forensic artefacts.
    <br><br>
    <a href="https://mit-license.org">
      <img src="https://img.shields.io/github/license/ezaspy/elrond" alt="License: MIT">
    </a>
    <a href="https://github.com/ezaspy/elrond/issues">
      <img src="https://img.shields.io/github/issues/ezaspy/elrond" alt="Issues">
    </a>
    <a href="https://github.com/ezaspy/elrond/network/members">
      <img src="https://img.shields.io/github/forks/ezaspy/elrond" alt="Forks">
    <a href="https://github.com/ezaspy/elrond/stargazers">
      <img src="https://img.shields.io/github/stars/ezaspy/elrond" alt="Stars">
    </a>
    <a>
      <img src="https://img.shields.io/badge/subject-DFIR-red" alt="Subject">
    </a>
    </a>
      <img src="https://img.shields.io/github/last-commit/ezaspy/elrond" alt="Last Commit">
    </a>
    <a href="https://github.com/psf/black">
      <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg">
    </a>
    <br><br>
  </p>
</p>

<!-- TABLE OF CONTENTS -->

## Table of Contents

- [About the Project](#about-the-project)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)

<br><br>

<!-- ABOUT THE PROJECT -->

## About The Project

elrond has been created to help fellow digitial forensicators with the identification, collection, processing, analysis and outputting of forensic artefacts from a Windows E01 or VMDK, macOS DMG/E01 or VMDK, Linux dd or VMDK disk images as well as raw memory images and previously collected artefacts which can all be outputted into Splunk. I have spent many an incident repeating the same processes by mounting, collecting (mainly Windows) forensic artefacts and then attempting to correlate them together with other data sources and artefacts. Thus, as mentioned above elrond has been built to consolidate those seperate processes into one single script helping to accerlate and automate these otherwise repetitive, tedious and often occasionally-referenced commands. As elrond outputs the artefact information as either CSV or JSON, they can be processed by many commonly-used log file analysis tools, consequently, elrond does have the capability to stand up a local [Splunk](https://www.splunk.com/) or [elastic](https://www.elastic.co/) instance, whereby the artefacts are automatically assigned and aligned with the [MITRE ATT&CK® Framework](https://attack.mitre.org/). In addition, elrond can also populate a local [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) instance providing a visual representation of potential attack techniques leveraged as part of said incident.
elrond also provides additional features such as image and file hashing, metadata extraction, file recovery and carving, IOC extraction, keyword searching and timelining.<br>
 or  instance whilst mapping the evidence within those artefacts to the  using , if desired.

### Related Projects

elrond is responsible for the analysis-side of digital forensic, but what about acquisition? An acompanying script(s) called [gandalf](https://github.com/ezaspy/gandalf) can be deployed (locally or remotely) on either Windows, macOS or Linux hosts to acquire forensic artefacts. 
<br><br><br>

<!-- Prerequisites -->

## Prerequisites

There are several software package required for using elrond but almost all of them are contained within the [SANS SIFT Worksation](https://www.sans.org/tools/sift-workstation/) virtual machine OVA. However, for the software which is not included, I have provided a script ([make.sh](https://github.com/ezaspy/elrond/make.sh)) which installs and configures the additional software which will be potentially required during running elrond (volatility3, apfs-fuse etc.).<br>
To invoke the script, simply follow the instructions in [CONFIG.md](https://github.com/ezaspy/elrond/blob/main/elrond/CONFIG.md#configuration). **Please note, you will only need to run the make.sh script once, per SIFT instance**

- [SANS SIFT Workstation](https://digital-forensics.sans.org/community/downloads) (20.04)
  - Note: SANS SIFT 18.04 is not supported.
- See [CONFIG.md](https://github.com/ezaspy/elrond/blob/main/elrond/CONFIG.md) to install and configure the additional software for SIFT 20.04.
  - Please note the elrond also only supports x64 memory images.
  - If you encounter errors with [CONFIG.md](https://github.com/ezaspy/elrond/blob/main/elrond/CONFIG.md), individual scripts for each of the software packages are contained in [.../elrond/elrond/tools/scripts/](https://github.com/ezaspy/elrond/tree/main/elrond/tools/scripts/)
<br><br>

Alternatviely, if you prefer to install the packages yourself... (bear in mind there may be additional dependency requirements)<br>

- [volatility3](https://github.com/volatilityfoundation/volatility3/) - (optional)
- [dwarfdump](https://manpages.ubuntu.com/manpages/trusty/man1/dwarfdump.1.html) - processing Linux memory images in volatility3
- [apfs-fuse](https://github.com/ezaspy/apfs-fuse) - macOS disk analysis
  <br><br>

<!-- USAGE EXAMPLES -->

## Usage

`python3 elrond.py <case_id> <directory> [<output_directory>] [-h] [-AaBCcDEGHIiMoPpQqRrSsTtUVvZ] [-K <keyword_file>] [-Y <yara_dir>] -F (include|exclude):[<include/exclude_file>]`

<br>

### Collect (-C)<br>
#### Examples<br>

- Invoking DBM (-B) flag (instead of using -acINoPQqRUVv), Process (**-P**) index artefacts in Splunk (**-S**) and conduct File Collection (-F) with inclusion list<br>

`python3 elrond.py case_name /path/to/disk/images -BCPS  -F include:./include_file.txt`

- Automatically (**-a**) and super-quietly (**-Q**) Collect (**-C**), Process (**-P**), Analyse (**-A**) and index artefacts (including memory (**-M**)) in Splunk (**-S**)<br>

`python3 elrond.py case_name /path/to/disk_and_memory/images -aqQvVMCPAS`

- Very verbosely (**-V**), automatically (**-a**), super-quietly (**-Q**) Collect (**-C**), Process (**-P**) and conduct IOC Extraction (**-I**)<br>

`python3 elrond.py case_name /path/to/disk/images -avVqQCPI`
<br><br>

### Gandalf (-G)<br>
#### Examples<br>

- Automatically (**-a**) and superquietly (**-Q**) Process (**-P**), Analyse (**-A**) and index artefacts in Splunk (**-S**) (acquired using [gandalf](https://github.com/ezaspy/gandalf))<br>

`python3 elrond.py case_name /path/to/disk/images -aqvVGPAS`

- Invoking DBM (-B) flag (instead of using -acINoPQqRUVv), Process (**-P**) index artefacts in Splunk (**-S**) and conduct Keyword Searching (-K <file_name>)<br>

`python3 elrond.py case_name /path/to/disk/images -BGPS -K keywords.txt`
<br><br>


### Not using Collect (-C) or Gandalf (-G)<br>
#### Examples<br>

- Automatically (**-a**) and quietly (**-q**) Process (**-P**), Analyse (**-A**) and index artefacts in Splunk (**-S**) (previously collected disk artefacts (no **-C**))<br>

`python3 elrond.py case_name /path/to/disk/images -aqvVPAS`

- Invoking DBM (-B) flag (instead of using -acINoPQqRUVv), Process (**-P**) index artefacts in Splunk (**-S**) and conduct Keyword Searching (-K <file_name>)<br>

`python3 elrond.py case_name /path/to/disk/images -BPS -Y <directory/of/yara/files>`
<br><br>

### Support

Please note that if you are NOT using the -C flag (i.e. your artefacts have already been collected via another means, not using [gandalf](https://github.com/ezaspy/gandalf)). Please ensure your folder structure is as follows: `<path_to_folder>/`acquisitions`/<hostname(s)>/<artefacts(s)>`<br><br>
See the [support file](https://github.com/ezaspy/elrond/SUPPORT.md) for a list of commands and additional third-party tools to help with preparing images or data for elrond.<br><br><br>

<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/ezaspy/elrond/issues) for a list of proposed features (and known issues).<br> _If you do experience any issues, please try building a new SIFT Workstation VM and then raise an issue via the [issues](https://github.com/ezaspy/elrond/issues) page._<br><br><br>
<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
   <br><br><br>

<!-- LICENSE -->

## License

Distributed under the MIT License. See [LICENSE](https://github.com/ezaspy/elrond/LICENSE.txt) for more information.
<br><br><br>

<!-- CONTACT -->

## Contact

ezaspy - ezaspython (at) gmail (dot) com

Project Link: [https://github.com/ezaspy/elrond](https://github.com/ezaspy/elrond)

Other Projects: [https://github.com/ezaspy/](https://github.com/ezaspy/)
<br><br><br>

<!-- ACKNOWLEDGEMENTS -->

## Acknowledgements

- [Joff Thyor](https://www.blackhillsinfosec.com/team/joff-thyer/)
- [alexandercarruthers](https://github.com/alexandercarruthers)
- [SANS](https://www.sans.org)
- [Harbingers LLC](https://uspto.report/company/Harbingers-L-L-C)<br><br>
- Tooling
  - [joachimmetz](https://github.com/joachimmetz)
  - [Harlan Carvey](https://github.com/hcarvey)
  - [williballenthin](https://github.com/williballenthin)
  - [dkovar](https://github.com/dkovar)
  - [Richard Penman](https://github.com/richardpenman)
  - [mnrkbys](https://github.com/mnrkbys/macosac)
  - [The Volatility Foundation](https://github.com/volatilityfoundation)
  - [AVML](https://github.com/microsoft/avml)
  - [Jonathon Poling](https://ponderthebits.com/2017/02/osx-mac-memory-acquisition-and-analysis-using-osxpmem-and-volatility/)
  - [@binaryz0ne](https://www.binary-zone.com/2019/06/20/acquiring-linux-memory-using-avml-and-using-it-with-volatility/)
  - [JPCERTCC](https://github.com/JPCERTCC/Windows-Symbol-Tables)
  - [John - Python Awesome](https://pythonawesome.com/windows-symbol-tables-for-volatility-3-in-python/)<br><br>
- Documentation
  - [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
  - [hatchful](https://hatchful.shopify.com)
  - [Image Shields](https://shields.io)<br><br>
- Theme &amp; Artwork
  - [J.R.R. Tolkien](https://en.wikipedia.org/wiki/J._R._R._Tolkien)
  - [Peter Jackson](https://twitter.com/ReaPeterJackson)
  - [ASCII Text Generator](https://textkool.com/en/ascii-art-generator?hl=default&vl=default&font=Red%20Phoenix&text=Your%20text%20here%20)
  - [ASCII Art Generator](https://www.ascii-art-generator.org)
  - [ASCII Art](http://www.asciiworld.com/-Lord-of-the-Rings-.html)
  - [SIFT-elrond Desktop background](https://www.hdwallpaper.nu/wp-content/uploads/2015/04/rings_the_lord_of_the_rings_one_ring_hd_wallpaper.jpg)

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[elrond-screenshot]: images/screenshot.png
