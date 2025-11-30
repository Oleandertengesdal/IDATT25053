# Picture Geolocation Challenge - Solution Guide

## Challenge Description
Find where a picture was taken, posted by someone named "Lasse something" who lives in Norway.

**Answer Format:** `///word.word.word` (what3words format)

## Investigation Steps

### 1. Image Metadata Analysis
First, check if the image contains EXIF data with GPS coordinates:

```bash
# Install exiftool if not already installed
# brew install exiftool (macOS)

# Extract metadata
exiftool where_is_this.jpg
```

Look for:
- GPS Latitude/Longitude
- Camera make/model
- Date taken
- Any embedded location data

### 2. Visual Analysis
Examine the image for identifying features:
- Architecture style (Norwegian?)
- Landscape/terrain
- Street signs, house numbers
- Visible landmarks
- Vegetation (helps determine region)
- Power lines, infrastructure style
- License plates if any vehicles visible

### 3. Reverse Image Search
Try multiple reverse image search engines:
- Google Images: https://images.google.com (click camera icon)
- TinEye: https://tineye.com
- Yandex: https://yandex.com/images (often better for location-based searches)

### 4. Social Media Investigation
Search for "Lasse" + Norway + any visible clues:
- Facebook, Instagram, Twitter
- Look for public posts about houses/property
- Check location tags

### 5. what3words Conversion
Once you have coordinates or a location:
1. Go to https://what3words.com
2. Enter the coordinates or drop a pin on the map
3. Get the three-word address in format: `///word.word.word`

## Tools to Use

```bash
# Check image metadata
exiftool where_is_this.jpg

# If image has GPS coordinates, convert to what3words
# Use the what3words website or API

# Look for strings/text in image
strings where_is_this.jpg | grep -i "gps\|location\|lat\|lon"
```

## Common Norwegian Location Indicators
- Red/white houses (traditional Norwegian style)
- Fjords, mountains in background
- Specific architecture
- Norwegian road signs
- Terrain features

## Notes
- The challenge mentions "nearest point of interest that Google has assigned a name to"
- Don't need exact house coordinates, just the general area
- Format must be: `///word.word.word` (three words separated by periods)

## Next Steps
1. Run the metadata extraction
2. Open the image and look for visual clues
3. Try reverse image search
4. Search for "Lasse" if you find any additional identifying information
5. Convert final location to what3words format
