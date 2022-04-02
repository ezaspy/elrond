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
    <a href="https://www.python.org">
      <img src="https://img.shields.io/badge/language-python-blue" alt="Python">
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

elrond has been created to help fellow digitial forensicators with the identification, collection, processing, analysis and outputting of forensic artefacts from a Windows E01 or VMDK, macOS DMG/E01 or VMDK, Linux dd or VMDK disk images as well as raw memory images and previously collected artefacts which can all be outputted into Splunk. I have spent many an incident repeating the same processes by mounting, collecting (mainly Windows) forensic artefacts and then attempting to correlate them together with other data sources and artefacts. Thus, as mentioned above elrond has been built to consolidate those seperate processes into one single script helping to accerlate and automate these otherwise repetitive, tedious and often occasionally-referenced commands. As elrond outputs the artefact information as either CSV or JSON, they can be processed by many commonly-used log file analysis tools, consequently, elrond does have the capability to stand up a dedicated Splunk instance, whereby the artefacts are automatically assigned and aligned with the MITRE ATT&CK® Framework.
elrond also provides additional features such as image and file hashing, metadata extraction, file recovery and carving, IOC extraction, keyword searching and timelining.
<br><br><br>

<!-- Prerequisites -->
## Prerequisites

There are several software package required for using elrond but almost all of them are contained within the SANS SIFT Worksation virtual machine OVA. However, for the software which is not included, I have provided a script ([elrond_env.sh](https://github.com/ezaspy/elrond/elrond_env.sh)) which installs and configures the additional software which might be required during running elrond (volatility3, apfs-fuse etc.).<br>
* [SANS SIFT Workstation](https://digital-forensics.sans.org/community/downloads) (20.04)
* See the [software file](https://github.com/ezaspy/elrond/SOFTWARE.md) to install and configure the additional software for both SIFT 20.04 and 18.04.
  * Please note the elrond also only supports x64 memory images.<br><br>

Alternatviely, if you prefer to install the packages yourself...<br>
* [volatility3](https://github.com/volatilityfoundation/volatility3/) - (optional)
* [dwarfdump](https://manpages.ubuntu.com/manpages/trusty/man1/dwarfdump.1.html) - processing Linux memory images in volatility3
* [apfs-fuse](https://github.com/ezaspy/apfs-fuse) - macOS disk analysis
<br><br>

<!-- USAGE EXAMPLES -->
## Usage
`python3 elrond.py [-h] [-AaCcDFHIiMoPpQqRrSsTtUVvZ] <case_id> <directory> [<output_directory>] [-K] [<keyword_file>]`<br>
### Recommended examples<br>
* With previously collected artefacts

Automatically (attain )Metadata, Collect, Process, Analysis and index artefacts in Splunk<br>
`python3 elrond.py -aqvVPAS case_name /images`
* Without previously collected artefacts

Automatically (attain )Metadata, Collect, Process, Analysis and index artefacts in Splunk<br>
`python3 elrond.py -aqvVPAS case_name /images`<br><br>
### Additional examples
Automatically Process, Analysis and index artefacts in Splunk (previously collected disk artefacts)<br>
`python3 elrond.py -aqvVPAS case_name /images`

Automatically, super-quietly Collect, Process, Analysis and index all artefacts (including memory) in Splunk<br>
`python3 elrond.py -aqQvVMCPAS case_name /images`

Automatically, super-quietly Collect, Process and conduct Keyword Searching (with no printing)<br>
`python3 elrond.py -aqQCPS case_name /images -K keywords.txt`
<br><br>
### Support
Please note that if you are using the -C flag (i.e. your artefacts have already been collected via another means). Please ensure your folder structure is as follows: `<path_to_hostname(s)>`/folder/`<hostname(s)>/<artefacts(s)>`<br><br>
See the [support file](https://github.com/ezaspy/elrond/SUPPORT.md) for a list of commands and additional third-party tools to help with preparing images or data for elrond.<br><br><br>


<!-- ROADMAP -->
## Roadmap

* ELK/Elastic 'module'
* Live 'module'

<br>See the [open issues](https://github.com/ezaspy/elrond/issues) for a list of proposed features (and known issues).<br><br><br>


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

ezaspy - ezaspython (at) gmail (dot) com

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
  * [mnrkbys](https://github.com/mnrkbys/macosac)
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
