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

- [About](#about)
  - [Related Projects](#related-projects)
- [Configuration](#configuration)
  - [SIFT-elrond (recommended)](#sift-elrond-(recommended))
  - [Self-build](#configure)
  - [Updating](#updating)
- [Usage](#usage)
- [Artefacts](#artefacts)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Notices](#notices)
- [Acknowledgements](#acknowledgements)

<br><br>

<!-- ABOUT -->

## About

elrond has been created to help fellow digitial forensicators with the identification, extraction, collection, processing, analysis and outputting of forensic artefacts from (up to 20 paritions for) Windows E01 or VMDK, macOS DMG/E01 or VMDK, Linux dd or VMDK disk images as well as raw memory images and previously collected artefacts which can all be outputted into Splunk. I have spent many an incident repeating the same processes by mounting, collecting (mainly Windows) forensic artefacts and then attempting to correlate them together with other data sources and artefacts. Thus, as mentioned above elrond has been built to consolidate those seperate processes into one single script helping to accerlate and automate these otherwise repetitive, tedious and often occasionally-referenced commands. As elrond outputs the artefact information as either CSV or JSON, they can be processed by many commonly-used log file analysis tools, consequently, elrond does have the capability to stand up a local [Splunk](https://www.splunk.com/) (with acompanying [app](https://splunkbase.splunk.com/app/6606/)) or [elastic](https://www.elastic.co/) instance, whereby the artefacts are automatically assigned and aligned with the [MITRE ATT&CK® Framework](https://attack.mitre.org/). In addition, elrond can also populate a local [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) instance providing a visual representation of potential attack techniques leveraged as part of said incident.<br>
Additional features include image and file hashing, metadata extraction, file recovery and carving, AV scanning, IOC extraction, keyword searching and timelining.
<br>

It is important to note that elrond utilises many existing tools which have been built by other developers. elrond does do custom structuring of the outputted data but the conversion of the data is done by the other aforementioned toolsets. This is perhaps easier to explain with a [meme](https://github.com/ezaspy/elrond/blob/main/elrond/images/elrond_meme.jpeg).

<!--### Wild West Hackin' Fest 2023

I presented elrond, at [Wild West Hackin' Fest 2023](https://wildwesthackinfest.com) as part of the Toolshed Talks. The full talk can be found on the [WWHF website]() and on [YouTube](). -->
<!-- [![Watch the video](https://img.youtube.com/vi/nTQUwghvy5Q/default.jpg)](https://youtu.be/nTQUwghvy5Q)

<p align="center">
  <a href="http://www.youtube.com/watch?feature=player_embedded&v=nTQUwghvy5Q" target="_blank">
  <img src="http://img.youtube.com/vi/nTQUwghvy5Q/mqdefault.jpg" alt="Watch the video" width="240" height="180" border="10" />
  </a>
</p>

<br> -->

### Related Projects

elrond is responsible for the analysis-side of digital forensic, but what about acquisition? An acompanying script called [gandalf](https://github.com/ezaspy/gandalf) can be deployed (locally or remotely) on either Windows (using [PowerShell](https://learn.microsoft.com/en-us/powershell/)), Linux, or macOS (using [Python](https://www.python.org) or [bash]()) hosts to acquire forensic artefacts. 
<br><br><br>

<!-- PREREQUISITES -->

## Configuration

### Initial Configuration