#!/usr/bin/env python3
"""
OSINT Geolocation Challenge - Image Analysis Tool

This script helps analyze the image for location clues.
Since we need to find where "Lasse something" in Norway posted this picture,
we should use multiple OSINT techniques.
"""

import subprocess
import sys
from pathlib import Path

def check_image_properties():
    """Check basic image properties."""
    print("="*70)
    print("IMAGE ANALYSIS - where_is_this.jpg")
    print("="*70)
    print()
    
    img_path = Path("where_is_this.jpg")
    if not img_path.exists():
        print("❌ Image file not found!")
        return
    
    print(f"✓ File found: {img_path}")
    print(f"  Size: {img_path.stat().st_size:,} bytes")
    print()

def extract_metadata():
    """Extract and display metadata."""
    print("="*70)
    print("METADATA ANALYSIS")
    print("="*70)
    print()
    
    try:
        result = subprocess.run(
            ['exiftool', 'where_is_this.jpg'],
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except FileNotFoundError:
        print("⚠ exiftool not found. Install with: brew install exiftool")
        print()

def check_for_steganography():
    """Check for hidden data in the image."""
    print("="*70)
    print("STEGANOGRAPHY CHECK")
    print("="*70)
    print()
    
    print("Checking for hidden strings...")
    try:
        result = subprocess.run(
            ['strings', 'where_is_this.jpg'],
            capture_output=True,
            text=True
        )
        
        lines = result.stdout.split('\n')
        interesting = [l for l in lines if len(l) > 10 and any(
            word in l.lower() for word in ['http', 'www', 'lat', 'lon', 'gps', 'norway', 'lasse', 'location']
        )]
        
        if interesting:
            print("Found interesting strings:")
            for line in interesting[:20]:
                print(f"  {line}")
        else:
            print("No obvious hidden strings found.")
        print()
    except Exception as e:
        print(f"Error: {e}")

def investigation_guide():
    """Print investigation guide."""
    print("="*70)
    print("OSINT INVESTIGATION GUIDE")
    print("="*70)
    print()
    print("Since the image has no GPS metadata, you need to use visual analysis:")
    print()
    print("1. VISUAL CLUES TO LOOK FOR:")
    print("   - House style (Norwegian architecture?)")
    print("   - Landscape features (mountains, water, terrain)")
    print("   - Vegetation type")
    print("   - Street signs or house numbers")
    print("   - Power lines, infrastructure")
    print("   - Visible text on buildings/signs")
    print("   - Vehicle license plates")
    print("   - Weather/lighting (can indicate region)")
    print()
    print("2. REVERSE IMAGE SEARCH:")
    print("   - Google Images: https://images.google.com")
    print("   - Yandex Images: https://yandex.com/images")
    print("   - TinEye: https://tineye.com")
    print("   Upload the image and see if it matches anything")
    print()
    print("3. SOCIAL MEDIA SEARCH:")
    print("   - Search for 'Lasse' + Norway + house/property")
    print("   - Check Instagram location tags")
    print("   - Facebook public posts")
    print("   - Look for real estate listings")
    print()
    print("4. NORWEGIAN GEOLOCATION TIPS:")
    print("   - Red houses are common in Norway")
    print("   - Look for fjords, mountains in background")
    print("   - Norwegian road signs have specific colors")
    print("   - Check for .no domain websites in any text")
    print()
    print("5. CONVERT TO WHAT3WORDS:")
    print("   Once you find the location:")
    print("   - Go to: https://what3words.com")
    print("   - Enter coordinates or drop a pin")
    print("   - Get the ///word.word.word address")
    print()
    print("="*70)

def provide_tools():
    """Provide useful tools and commands."""
    print()
    print("="*70)
    print("USEFUL TOOLS & COMMANDS")
    print("="*70)
    print()
    print("Open image:")
    print("  open where_is_this.jpg")
    print()
    print("Check all strings in image:")
    print("  strings where_is_this.jpg | less")
    print()
    print("Search for specific patterns:")
    print("  strings where_is_this.jpg | grep -i 'pattern'")
    print()
    print("Python reverse image search libraries:")
    print("  pip install reverse-image-search")
    print()
    print("Manual reverse search URLs:")
    print("  https://images.google.com (click camera icon)")
    print("  https://yandex.com/images/search")
    print("  https://tineye.com")
    print()
    print("="*70)

def main():
    """Main function."""
    print()
    check_image_properties()
    extract_metadata()
    check_for_steganography()
    investigation_guide()
    provide_tools()
    
    print()
    print("="*70)
    print("NEXT STEPS")
    print("="*70)
    print()
    print("1. Open the image: open where_is_this.jpg")
    print("2. Note down visual clues")
    print("3. Try reverse image search")
    print("4. Search for 'Lasse' + any clues you find")
    print("5. Convert location to what3words format")
    print()
    print("Remember: Format must be ///word.word.word")
    print("="*70)
    print()

if __name__ == "__main__":
    main()
