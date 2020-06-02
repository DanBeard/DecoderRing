# SBOM Decoder Ring

**One Decoder ring to translate them all**

###About
The end goal of the decoder ring project is to be able to easily and automatically translate between all SBOM formats, keeping as much nuance and precision as possible between formats

Currently supported input formats:
* SPDX 2.1
* CSV

Currently supported output formats:
* SPDX 2.1
* SWID (with modifications)
* CSV

See formats.md for a table with mappings between the different formats
##Requirements
* Python 3.6+

    pip install -r requirements.txt

##TODO
* Increase SPDX and SWID precision
* Add XycloneDX
 
 
 ####Usage
 ./decode.py --infile <infile location> --format <one of spdx,csv>
 
 The script will create an output folder that contains the translated SBOMs
 
