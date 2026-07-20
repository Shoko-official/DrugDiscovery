import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

export const EXPECTED_PNGS = Object.freeze({
  "32x32.png": 32,
  "64x64.png": 64,
  "128x128.png": 128,
  "128x128@2x.png": 256,
  "icon.png": 512,
  "StoreLogo.png": 50,
  "Square30x30Logo.png": 30,
  "Square44x44Logo.png": 44,
  "Square71x71Logo.png": 71,
  "Square89x89Logo.png": 89,
  "Square107x107Logo.png": 107,
  "Square142x142Logo.png": 142,
  "Square150x150Logo.png": 150,
  "Square284x284Logo.png": 284,
  "Square310x310Logo.png": 310,
});
export const EXPECTED_ICO_SIZES = Object.freeze([16, 24, 32, 48, 64, 256]);
export const EXPECTED_ICNS_TYPES = Object.freeze([
  "is32",
  "s8mk",
  "ic11",
  "il32",
  "l8mk",
  "ic12",
  "ic07",
  "ic13",
  "ic08",
  "ic14",
  "ic09",
  "ic10",
]);

const PNG_SIGNATURE = Buffer.from("89504e470d0a1a0a", "hex");
const ALLOWED_PNG_CHUNKS = new Set(["IDAT", "IEND", "IHDR"]);
const ICNS_PNG_SIZES = Object.freeze({
  ic07: 128,
  ic08: 256,
  ic09: 512,
  ic10: 1024,
  ic11: 32,
  ic12: 64,
  ic13: 256,
  ic14: 512,
});
const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

export function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function paethPredictor(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const leftDistance = Math.abs(estimate - left);
  const upDistance = Math.abs(estimate - up);
  const upLeftDistance = Math.abs(estimate - upLeft);
  if (leftDistance <= upDistance && leftDistance <= upLeftDistance) {
    return left;
  }
  return upDistance <= upLeftDistance ? up : upLeft;
}

function decodeScanlines(compressed, header) {
  const bytesPerPixel = 4;
  const rowLength = header.width * bytesPerPixel;
  const expectedLength = header.height * (rowLength + 1);
  let raw;
  try {
    raw = inflateSync(compressed, { maxOutputLength: expectedLength });
  } catch {
    throw new Error("Invalid PNG image data.");
  }
  if (raw.length !== expectedLength) {
    throw new Error("Invalid PNG image data.");
  }

  const pixels = Buffer.alloc(header.width * header.height * bytesPerPixel);
  let source = 0;
  for (let row = 0; row < header.height; row += 1) {
    const filter = raw[source];
    source += 1;
    if (filter > 4) {
      throw new Error("Invalid PNG image data.");
    }
    const rowStart = row * rowLength;
    for (let column = 0; column < rowLength; column += 1) {
      const current = raw[source];
      source += 1;
      const destination = rowStart + column;
      const left = column >= bytesPerPixel ? pixels[destination - bytesPerPixel] : 0;
      const up = row > 0 ? pixels[destination - rowLength] : 0;
      const upLeft =
        row > 0 && column >= bytesPerPixel
          ? pixels[destination - rowLength - bytesPerPixel]
          : 0;
      let predictor = 0;
      if (filter === 1) {
        predictor = left;
      } else if (filter === 2) {
        predictor = up;
      } else if (filter === 3) {
        predictor = Math.floor((left + up) / 2);
      } else if (filter === 4) {
        predictor = paethPredictor(left, up, upLeft);
      }
      pixels[destination] = (current + predictor) & 0xff;
    }
  }
  return pixels;
}

function decodePng(buffer) {
  if (buffer.length < PNG_SIGNATURE.length || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error("Invalid PNG signature.");
  }

  let offset = 8;
  let header;
  const imageData = [];
  let hasEnd = false;
  while (offset < buffer.length) {
    if (offset + 12 > buffer.length) {
      throw new Error("Invalid PNG chunk bounds.");
    }
    const length = buffer.readUInt32BE(offset);
    const typeStart = offset + 4;
    const dataStart = typeStart + 4;
    const checksumStart = dataStart + length;
    const nextOffset = checksumStart + 4;
    if (nextOffset > buffer.length) {
      throw new Error("Invalid PNG chunk bounds.");
    }

    const typeBytes = buffer.subarray(typeStart, dataStart);
    const type = typeBytes.toString("ascii");
    if (!ALLOWED_PNG_CHUNKS.has(type)) {
      throw new Error("Unexpected PNG chunk.");
    }
    const data = buffer.subarray(dataStart, checksumStart);
    const expectedChecksum = buffer.readUInt32BE(checksumStart);
    if (crc32(Buffer.concat([typeBytes, data])) !== expectedChecksum) {
      throw new Error("Invalid PNG checksum.");
    }

    if (type === "IHDR") {
      if (offset !== 8 || length !== 13 || header) {
        throw new Error("Invalid PNG header.");
      }
      header = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        bitDepth: data[8],
        colorType: data[9],
      };
      if (
        header.width === 0 ||
        header.height === 0 ||
        header.width > 4096 ||
        header.height > 4096 ||
        data[10] !== 0 ||
        data[11] !== 0 ||
        data[12] !== 0
      ) {
        throw new Error("Invalid PNG header.");
      }
    } else if (type === "IDAT") {
      imageData.push(data);
    } else if (type === "IEND") {
      if (length !== 0 || nextOffset !== buffer.length) {
        throw new Error("Invalid PNG end chunk.");
      }
      hasEnd = true;
    }
    offset = nextOffset;
  }

  if (!header || imageData.length === 0 || !hasEnd) {
    throw new Error("Incomplete PNG structure.");
  }
  if (header.bitDepth !== 8 || header.colorType !== 6) {
    throw new Error("PNG must use 8-bit RGBA color.");
  }
  const pixels = decodeScanlines(Buffer.concat(imageData), header);
  let visible = false;
  for (let offset = 3; offset < pixels.length; offset += 4) {
    if (pixels[offset] > 0) {
      visible = true;
      break;
    }
  }
  if (!visible) {
    throw new Error("PNG image has no visible pixels.");
  }
  return {
    header,
    pixels,
  };
}

export function parsePng(buffer) {
  return decodePng(buffer).header;
}

function hasTransparentBorder({ header, pixels }) {
  const alphaAt = (x, y) => pixels[(y * header.width + x) * 4 + 3];
  for (let x = 0; x < header.width; x += 1) {
    if (alphaAt(x, 0) !== 0 || alphaAt(x, header.height - 1) !== 0) {
      return false;
    }
  }
  for (let y = 0; y < header.height; y += 1) {
    if (alphaAt(0, y) !== 0 || alphaAt(header.width - 1, y) !== 0) {
      return false;
    }
  }
  return true;
}

export function parseIco(buffer) {
  if (
    buffer.length < 6 ||
    buffer.readUInt16LE(0) !== 0 ||
    buffer.readUInt16LE(2) !== 1
  ) {
    throw new Error("Invalid ICO header.");
  }
  const count = buffer.readUInt16LE(4);
  if (count !== EXPECTED_ICO_SIZES.length || buffer.length < 6 + count * 16) {
    throw new Error("Unexpected ICO layers.");
  }

  const sizes = [];
  const ranges = [];
  for (let index = 0; index < count; index += 1) {
    const entry = 6 + index * 16;
    const width = buffer[entry] || 256;
    const height = buffer[entry + 1] || 256;
    const planes = buffer.readUInt16LE(entry + 4);
    const bitDepth = buffer.readUInt16LE(entry + 6);
    const length = buffer.readUInt32LE(entry + 8);
    const offset = buffer.readUInt32LE(entry + 12);
    if (
      width !== height ||
      (planes !== 0 && planes !== 1) ||
      bitDepth !== 32 ||
      length === 0 ||
      offset < 6 + count * 16 ||
      offset + length > buffer.length
    ) {
      throw new Error("Invalid ICO layer.");
    }
    const icon = decodePng(buffer.subarray(offset, offset + length));
    if (icon.header.width !== width || icon.header.height !== height) {
      throw new Error("Invalid ICO layer.");
    }
    ranges.push({ start: offset, end: offset + length });
    sizes.push(width);
  }
  ranges.sort((left, right) => left.start - right.start);
  let expectedOffset = 6 + count * 16;
  for (const range of ranges) {
    if (range.start !== expectedOffset) {
      throw new Error("Unexpected ICO payload layout.");
    }
    expectedOffset = range.end;
  }
  if (expectedOffset !== buffer.length) {
    throw new Error("Unexpected ICO payload layout.");
  }
  sizes.sort((left, right) => left - right);
  if (!sizes.every((size, index) => size === EXPECTED_ICO_SIZES[index])) {
    throw new Error("Unexpected ICO layers.");
  }
  return sizes;
}

export function parseIcns(buffer) {
  if (
    buffer.length < 8 ||
    buffer.toString("ascii", 0, 4) !== "icns" ||
    buffer.readUInt32BE(4) !== buffer.length
  ) {
    throw new Error("Invalid ICNS header.");
  }

  const chunks = new Map();
  let offset = 8;
  while (offset < buffer.length) {
    if (offset + 8 > buffer.length) {
      throw new Error("Invalid ICNS chunk bounds.");
    }
    const type = buffer.toString("ascii", offset, offset + 4);
    const length = buffer.readUInt32BE(offset + 4);
    if (length < 8 || offset + length > buffer.length) {
      throw new Error("Invalid ICNS chunk bounds.");
    }
    if (chunks.has(type)) {
      throw new Error("Duplicate ICNS chunk.");
    }
    chunks.set(type, buffer.subarray(offset + 8, offset + length));
    offset += length;
  }

  if (!EXPECTED_ICNS_TYPES.every((type) => chunks.has(type))) {
    throw new Error("Missing ICNS chunks.");
  }
  if (
    chunks.size !== EXPECTED_ICNS_TYPES.length ||
    [...chunks.keys()].some((type) => !EXPECTED_ICNS_TYPES.includes(type))
  ) {
    throw new Error("Unexpected ICNS chunks.");
  }

  for (const [type, size] of Object.entries(ICNS_PNG_SIZES)) {
    const icon = decodePng(chunks.get(type));
    if (icon.header.width !== size || icon.header.height !== size) {
      throw new Error("Invalid ICNS icon dimensions.");
    }
  }
  validateIcnsLegacyRle(chunks.get("is32"), 16);
  validateIcnsLegacyRle(chunks.get("il32"), 32);
  if (chunks.get("s8mk").length !== 16 * 16 || chunks.get("l8mk").length !== 32 * 32) {
    throw new Error("Invalid ICNS alpha mask.");
  }
  return [...EXPECTED_ICNS_TYPES];
}

function validateIcnsLegacyRle(data, size) {
  let offset = 0;
  const pixelsPerChannel = size * size;
  for (let channel = 0; channel < 3; channel += 1) {
    let decoded = 0;
    while (decoded < pixelsPerChannel) {
      if (offset >= data.length) {
        throw new Error("Invalid ICNS legacy icon data.");
      }
      const control = data[offset];
      offset += 1;
      if (control < 128) {
        const count = control + 1;
        if (offset + count > data.length || decoded + count > pixelsPerChannel) {
          throw new Error("Invalid ICNS legacy icon data.");
        }
        offset += count;
        decoded += count;
      } else {
        const count = control - 125;
        if (offset >= data.length || decoded + count > pixelsPerChannel) {
          throw new Error("Invalid ICNS legacy icon data.");
        }
        offset += 1;
        decoded += count;
      }
    }
  }
  if (offset !== data.length) {
    throw new Error("Invalid ICNS legacy icon data.");
  }
}

export function validateIconDirectory(iconDirectory) {
  const masterPath = resolve(iconDirectory, "..", "app-icon.png");
  if (!existsSync(masterPath)) {
    throw new Error("Missing Tauri icon source.");
  }
  const master = decodePng(readFileSync(masterPath));
  if (
    master.header.width !== master.header.height ||
    master.header.width < 512 ||
    !hasTransparentBorder(master)
  ) {
    throw new Error("Invalid Tauri icon source.");
  }

  for (const [filename, size] of Object.entries(EXPECTED_PNGS)) {
    const path = resolve(iconDirectory, filename);
    if (!existsSync(path)) {
      throw new Error(`Missing Tauri icon: ${filename}.`);
    }
    const icon = decodePng(readFileSync(path));
    if (
      icon.header.width !== size ||
      icon.header.height !== size ||
      !hasTransparentBorder(icon)
    ) {
      throw new Error(`Unexpected Tauri icon dimensions: ${filename}.`);
    }
  }

  const icoPath = resolve(iconDirectory, "icon.ico");
  const icnsPath = resolve(iconDirectory, "icon.icns");
  if (!existsSync(icoPath) || !existsSync(icnsPath)) {
    throw new Error("Missing Tauri container icons.");
  }
  parseIco(readFileSync(icoPath));
  parseIcns(readFileSync(icnsPath));
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();

if (isMain) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    validateIconDirectory(
      resolve(repositoryRoot, "apps", "desktop", "src-tauri", "icons"),
    );
    console.log("Tauri icon set valid.");
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Tauri icon validation failed.");
    process.exitCode = 1;
  }
}
