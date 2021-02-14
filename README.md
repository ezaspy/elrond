<!-- PROJECT LOGO -->
<p align="center">
  <a href="https://github.com/ezaspy/elrond">
    <img src="images/logo_trans_big.png" alt="Logo" width="400" height="400">
  </a>
  <p align="center">
    Accelerating the collection, processing, analysis and outputting of digital forensic artefacts.
    <br><br>
    <a href="https://mit-license.org">
    <img src="https://img.shields.io/badge/license-MIT-black.svg" alt="License: MIT">
    </a>
    <a href="https://github.com/ezaspy/elrond/issues">
    <img src="https://img.shields.io/github/issues/markdown-templates/markdown-snippets.svg" alt="Issues">
    </a>
    <a href="https://github.com/ezaspy/elrond/network/members">
    <img src="https://img.shields.io/github/forks/markdown-templates/markdown-snippets.svg" alt="Forks">
    <a href="https://github.com/ezaspy/elrond/stargazers">
    <img src="https://img.shields.io/github/stars/markdown-templates/markdown-snippets.svg" alt="Stars">
    </a>
    <a href="https://www.python.org">
    <img src="https://img.shields.io/badge/language-python-yellow" alt="Python">
    </a>
    <img src="https://img.shields.io/badge/subject-DFIR-red" alt="Subject">
    <img src="https://img.shields.io/github/last-commit/ezaspy/elrond" alt="Last Commit">
    </a>
    <br><br>
  </p>
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Prerequisites](#prerequisites)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)


<br><br>
<!-- ABOUT THE PROJECT -->
## About The Project

elrond has been created to help fellow digitial forensicators with the identification, collection, processing, analysis and outputting of forensic artefacts from a Windows, macOS or Linux E01 or VMDK disk images as well as raw memory images and previously collected artefacts which can all be outputted into Splunk or Elastic. I have spent many times repeating the same processes by mounting, collecting and processing (mainly Windows) forensic artefacts and then attempting to correlate them together as well as with other data sources and artefacts. Thus, as mentioned above elrond has been built to consolidate those seperate processes into one single script helping to accerlate and automate these otherwise repetitive, tedious and often occasionally-run commands. As elrond outputs the artefact information as either CSV or JSON, they can be processed by many commonly-used log file analysis tools. As elrond does have the capability to stand up a dedicated Splunk or Elastic instance, the artefacts are automatically assigned and aligned with the MITRE ATT&CK Framework in the form of dashboards.
elrond also provides features includng image and file hashing, metadata extraction, file recovery and carving, IOC extraction, keyword searching and timelining.
<br><br><br>

<!-- Prerequisites -->
## Prerequisites

There are several software package required for using elrond but almost all of them are contained within the SANS SIFT Worksation virtual machine OVA. You can download the SIFT OVA where I have included all of the software which might be used by elrond (volatility3, apfs-fuse etc.).
Alternatviely, if you prefer to install the packages yourself...

* [SANS SIFT Workstation](https://digital-forensics.sans.org/community/downloads) (18.04)
* [apfs-fuse](https://github.com/ezaspy/apfs-fuse) - macOS disk analysis
* [Volatility3](https://github.com/volatilityfoundation/volatility3/) - optional
  * [Python 3.5.3+](https://www.python.org/downloads/release/python-353/) - required if installing volatility3
* [dwarfdump](https://manpages.ubuntu.com/manpages/trusty/man1/dwarfdump.1.html) - creating own memory profiles for volatility2.6
* [exiftool](https://exiftool.org) - obtain metadata information from image files (.jpg, .png etc.)
<br><br>

### Condensed Version
`./make_SIFT-elrond.sh`<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br>
`sudo make`<br><br>

### Long Version
#### Installing python3.7
`sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt-get update && sudo apt-get install python3.7`
#### Configuring python3.7 (optional)
`sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 1`
#### Installing Volatility3
`git clone https://github.com/volatilityfoundation/volatility3 && sudo mv volatility3/ /usr/lib/python3.7/`
#### Configuring Volatility3
`sudo chmod -R 755 /usr/lib/python3.7/volatility3/ && sudo chown -R root:root /usr/lib/python3.7/volatility3/`
#### Installing dwarfdump
`sudo apt-get install -y dwarfdump`
#### Installing exilftool
`sudo apt install libimage-exiftool-perl`
#### Installing apfs-fuse
`sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui && cd /usr/local/bin && sudo git clone https://github.com/ezaspy/apfs-fuse.git && cd apfs-fuse && sudo git submodule init && sudo git submodule update && sudo mkdir build && cd build && sudo cmake .. && sudo ccmake .`<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br>
`sudo make`
<br><br><br>


<!-- USAGE EXAMPLES -->
## Usage
`python3 elrond.py [-h] [-AaCcDFHIiMoPpQqRrSsTtUVvZ] <case_id> <directory> [<output_directory>] [-K] [<keyword_file>]`
<br><br>
#### Example [Previously collected disk artefacts] (Automatically Process, Analysis and index (collected) artefacts in Splunk)
`python3 elrond.py -aqvVPAS case_name /images`
#### Example [Disk( & Memory) Image(s)] (Automatically Collect, Process, Analysis and index all default in Splunk)
`python3 elrond.py -aqvVMCPAS case_name /images`
#### Example [Disk Image(s)] (Automatically, Collect, Process and conduct keyword searching)
`python3 elrond.py -aqvVCPS case_name /images -K keywords.txt`
<br><br>
### Support
Please note that if you are using the -C flag (i.e. your artefacts have already been collected via another means). Please ensure your folder structure is as follows: `<path_to_hostname(s)>`/folder/`<hostname(s)>/<artefacts(s)>`
<br>
See the [support](https://github.com/ezaspy/elrond/issues) for a list of commands and additional third-party tools to help with preparing images or data for elrond.
<br><br><br>


<!-- ROADMAP -->
## Roadmap

* volatility3 compatibility
* Index into Elastic
* Live mode

<br>See the [open issues](https://github.com/ezaspy/elrond/issues) for a list of proposed features (and known issues).
<br>
See the [changes](https://github.com/ezaspy/elrond/blob/main/CHANGES.txt) for a list of previous changes to elrond.
<br><br><br>


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

Distributed under the MIT License. See [LICENSE](https://github.com/ezaspy/elrond/master/LICENSE.txt) for more information.
<br><br><br>


<!-- CONTACT -->
## Contact

ezaspy - ezaspython@gmail.com

Project Link: [https://github.com/ezaspy/elrond](https://github.com/ezaspy/elrond)

Other Projects: [https://github.com/ezaspy/](https://github.com/ezaspy/)
<br><br><br>


<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Joff Thyor](https://www.blackhillsinfosec.com/team/joff-thyer/)<br>
* [SANS](https://www.sans.org)

* Tooling
  * [joachimmetz](https://github.com/joachimmetz)
  * [Harlan Carvey](https://github.com/hcarvey)
  * [williballenthin](https://github.com/williballenthin)
  * [dkovar](https://github.com/dkovar)
  * [Richard Penman](https://github.com/richardpenman)
  * [The Volatility Foundation](https://github.com/volatilityfoundation)
  * [AVML](https://github.com/microsoft/avml)
  * [Jonathon Poling](https://ponderthebits.com/2017/02/osx-mac-memory-acquisition-and-analysis-using-osxpmem-and-volatility/)
  * [@binaryz0ne](https://www.binary-zone.com/2019/06/20/acquiring-linux-memory-using-avml-and-using-it-with-volatility/)
* Documentation
  * [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
  * [hatchful](https://hatchful.shopify.com)
  * [Image Shields](https://shields.io)
* Theme &amp; Artwork
  * [J.R.R. Tolkien](https://en.wikipedia.org/wiki/J._R._R._Tolkien)
  * [Peter Jackson](https://twitter.com/ReaPeterJackson)
  * [ASCII Art Generator](https://www.ascii-art-generator.org)
  * [ASCII World](http://www.asciiworld.com/-Lord-of-the-Rings-.html)
  * [SIFT-elrond Desktop background](https://www.hdwallpaper.nu/wp-content/uploads/2015/04/rings_the_lord_of_the_rings_one_ring_hd_wallpaper.jpg)


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[elrond-screenshot]: images/screenshot.png
