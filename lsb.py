#!/usr/bin/env python3

import sys
import struct
from itertools import zip_longest
from os import path
from pathlib import Path
import random
import math
import hashlib

import numpy
import matplotlib.pyplot as plt
from PIL import Image
from crypt import AESCipher


# Decompose a binary file into an array of bits
def decompose(data):
    v = []

    # Pack file len in 4 bytes
    fSize = len(data)
    bytes = [b for b in struct.pack("i", fSize)]

    bytes += [b for b in data]

    for b in bytes:
        for i in range(7, -1, -1):
            v.append((b >> i) & 0x1)

    return v


# Assemble an array of bits into a binary file
def assemble(v):
    byteArray = bitLstToByteArray(v)

    payload_size = struct.unpack("i", byteArray[:4])[0]

    return byteArray[4: payload_size + 4]


# Set the i-th bit of v to x
def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n


# Returns the i-th bit of n.
def getBit(i, n):
    return int((n & (1 << i)) > 0)


def bitLstToByteArray(bitLst):
    byteArray = bytearray()

    for i in range(len(bitLst) // 8):
        byte = 0

        for j in range(8):
            if i*8 + j < len(bitLst):
                byte = (byte << 1) + bitLst[i*8 + j]

        byteArray.append(byte)

    return byteArray


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


# Efficiently pops a random item from a list, altering list order.
def rndPop(lst):
    if lst:
        rndPos = random.randrange(len(lst))
        rndElem = lst[rndPos]
        lst[rndPos] = lst[-1]
        del lst[-1]

        return rndElem
    else:
        return None


# Embed payload file into LSB bits of an image
def embed(imgFile, payload, password):
    # Process source image
    img = Image.open(imgFile)
    (width, height) = img.size
    conv = img.convert("RGBA").getdata()
    print("[*] Input image size: %dx%d pixels." % (width, height))
    max_size = width * height * 3.0 / 8 / 1024  # max payload size
    print("[*] Usable payload size: %.2f KB." % max_size)

    f = open(payload, "rb")
    data = f.read()
    f.close()
    print("[+] Payload size: %.3f KB " % (len(data) / 1024.0))

    # Encrypt
    cipher = AESCipher(password)
    data_enc = cipher.encrypt(data)

    # Process data from payload file
    v = decompose(data_enc)

    # Add until multiple of 3
    while len(v) % 3:
        v.append(0)

    payload_size = len(v) / 8 / 1024.0
    print("[+] Encrypted payload size: %.3f KB " % payload_size)
    if payload_size > max_size - 4:
        print("[-] Cannot embed. File too large")
        sys.exit()

    # Create output image
    steg_img = Image.new('RGBA', (width, height))
    data_img = steg_img.getdata()

    idx = 0

    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            if idx < len(v):
                r = set_bit(r, 0, v[idx])
                g = set_bit(g, 0, v[idx + 1])
                b = set_bit(b, 0, v[idx + 2])
            data_img.putpixel((w, h), (r, g, b, a))
            idx = idx + 3

    steg_img.save(imgFile + "-stego.png", "PNG")

    print("[+] %s embedded successfully!" % payload)


def embedRandom(imgFilePath, payloadFilePath, passwd, bitSelectionLimit):
    with Image.open(imgFilePath) as img:
        (width, height) = img.size
        imgData = img.convert("RGBA").getdata()

    print("[*] Input image size: {}x{} pixels.".format(width, height))

    maxPayloadSize = width * height * 3 / 8 / 1024
    print("[*] Usable payload size: {:.4f}KB.".format(maxPayloadSize))

    with open(payloadFilePath, "rb") as payloadFile:
        payloadData = payloadFile.read()

    print("[*] Payload size: {:.4f}KB ".format(len(payloadData) / 1024))

    # Encrypt payload data.
    payloadDataEnc = AESCipher(passwd).encrypt(payloadData)
    print("[*] Encrypted payload size: {:.4f}KB.".format(len(payloadDataEnc)/1024))

    # Payload data encrypted to list of bit triples.
    payloadDataEncBitTriples = list(grouper(decompose(payloadDataEnc), 3, 0))

    payloadSize = len(payloadDataEncBitTriples) * 3 / 8 / 1024

    if payloadSize > maxPayloadSize - 4:
        print("[!] Cannot embed. Payload file too large.")
        return

    # Create output stego-image.
    stegoImg = Image.new("RGBA", (width, height))
    stegoImgData = stegoImg.getdata()

    # Copy the original img bytes.
    for h in range(height):
        for w in range(width):
            stegoImgData.putpixel((w, h), imgData.getpixel((w, h)))

    freePixels = [(w, h) for h in range(height) for w in range(width)]
    random.seed(hashlib.sha256(passwd.encode()).digest(), 2)

    for bitTriple in payloadDataEncBitTriples:
        pixel = rndPop(freePixels)
        r, g, b, a = stegoImgData.getpixel(pixel)

        r = set_bit(r, random.randrange(bitSelectionLimit+1), bitTriple[0])
        g = set_bit(g, random.randrange(bitSelectionLimit+1), bitTriple[1])
        b = set_bit(b, random.randrange(bitSelectionLimit+1), bitTriple[2])

        stegoImgData.putpixel(pixel, (r, g, b, a))

    stegoImgFilePath = Path(imgFilePath)
    stegoImg.save(path.join(stegoImgFilePath.parent, stegoImgFilePath.stem + "-stego.png"), "PNG")

    print("[*] Payload file embedded successfully!")


# Extract data embedded into LSB of the input file
def extract(in_file, out_file, password):
    # Process source image
    img = Image.open(in_file)
    (width, height) = img.size
    conv = img.convert("RGBA").getdata()
    print("[+] Image size: %dx%d pixels." % (width, height))

    # Extract LSBs
    v = []
    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            v.append(r & 1)
            v.append(g & 1)
            v.append(b & 1)

    data_out = assemble(v)

    # Decrypt
    cipher = AESCipher(password)
    data_dec = cipher.decrypt(data_out)

    # Write decrypted data
    out_f = open(out_file, "wb")
    out_f.write(data_dec)
    out_f.close()

    print("[+] Written extracted data to %s." % out_file)


def getHiddenBits(stegoImgData, pixel, bitSelectionLimit):
    r, g, b, _ = stegoImgData.getpixel(pixel)

    return (getBit(random.randrange(bitSelectionLimit+1), r),
            getBit(random.randrange(bitSelectionLimit+1), g),
            getBit(random.randrange(bitSelectionLimit+1), b))


def extractRandom(stegoImgFilePath, outputFilePath, passwd, bitSelectionLimit):
    # Process stego img file.
    with Image.open(stegoImgFilePath) as stegoImg:
        (width, height) = stegoImg.size
        stegoImgData = stegoImg.convert("RGBA").getdata()

    print("[*] Stego image size: {}x{} pixels.".format(width, height))

    notCheckedPixels = [(w, h) for h in range(height) for w in range(width)]
    payloadDataEncBits = []
    random.seed(hashlib.sha256(passwd.encode()).digest(), 2)

    # Retrieve payload size.
    for _ in range(11):
        payloadDataEncBits.extend(getHiddenBits(stegoImgData, rndPop(notCheckedPixels), bitSelectionLimit))

    payloadSize = struct.unpack("i", bitLstToByteArray(payloadDataEncBits[:32]))[0]
    print("[*] Encrypted payload size: {:.4f}KB.".format(payloadSize/1024))

    for _ in range(int(math.ceil((payloadSize*8-1) / 3))):
        payloadDataEncBits.extend(getHiddenBits(stegoImgData, rndPop(notCheckedPixels), bitSelectionLimit))

    payloadDataEncBytes = assemble(payloadDataEncBits)

    # Decrypt payload data.
    payloadDataBytes = AESCipher(passwd).decrypt(payloadDataEncBytes)
    print("[*] Payload size: {:.4f}KB ".format(len(payloadDataBytes) / 1024))

    # Write decrypted data.
    with open(outputFilePath, "wb") as outputFile:
        outputFile.write(payloadDataBytes)

    print("[*] Data extracted to {}.".format(outputFilePath))


# Statistical analysis of an image to detect LSB steganography
def analyse(in_file):
    """
    - Split the image into blocks.
    - Compute the average value of the LSBs for each block.
    - The plot of the averages should be around 0.5 for zones that contain
      hidden encrypted messages (random data).
    """
    BS = 100  # Block size
    img = Image.open(in_file)
    (width, height) = img.size
    print("[+] Image size: %dx%d pixels." % (width, height))
    conv = img.convert("RGBA").getdata()

    # Extract LSBs
    vr = []  # Red LSBs
    vg = []  # Green LSBs
    vb = []  # LSBs
    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            vr.append(r & 1)
            vg.append(g & 1)
            vb.append(b & 1)

    # Average colours' LSB per each block
    avgR = []
    avgG = []
    avgB = []
    for i in range(0, len(vr), BS):
        avgR.append(numpy.mean(vr[i:i + BS]))
        avgG.append(numpy.mean(vg[i:i + BS]))
        avgB.append(numpy.mean(vb[i:i + BS]))

    # Nice plot
    numBlocks = len(avgR)
    blocks = [i for i in range(0, numBlocks)]
    plt.axis([0, len(avgR), 0, 1])
    plt.ylabel('Average LSB per block')
    plt.xlabel('Block number')

    # plt.plot(blocks, avgR, 'r.')
    # plt.plot(blocks, avgG, 'g')
    plt.plot(blocks, avgB, 'bo')

    plt.show()


def printUsage(progName):
    print("LSB steganograhy. Hide files within least significant bits of images.\n")
    print("Usage:")
    print("  {} hide <img_file> <payload_file> <password>".format(progName))
    print("  {} hideRandom <imgFile> <payloadFile> <password> <bitSelectionLimit>".format(progName))
    print("  {} extract <stego_file> <out_file> <password>".format(progName))
    print("  {} extractRandom <stegoFile> <outputFile> <password> <bitSelectionLimit>".format(progName))
    print("  {} analyse <stego_file>\n".format(progName))
    print("  <bitSelectionLimit>: the program will randomly use one bit of each byte to store the payload info,"
          " but only up to the <bitSelectionLimit> bit. Possible values are: 0, 1, ... , 7.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        printUsage(sys.argv[0])
        sys.exit()

    if sys.argv[1] == "hide":
        embed(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "hideRandom":
        embedRandom(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    elif sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "extractRandom":
        extractRandom(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    elif sys.argv[1] == "analyse":
        analyse(sys.argv[2])
    else:
        print("[!] Invalid operation specified.")