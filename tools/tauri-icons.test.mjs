import assert from "node:assert/strict";
import test from "node:test";
import { deflateSync } from "node:zlib";

import {
  EXPECTED_ICNS_TYPES,
  EXPECTED_ICO_SIZES,
  EXPECTED_PNGS,
  crc32,
  parseIcns,
  parseIco,
  parsePng,
} from "./validate-tauri-icons.mjs";

function chunk(type, data = Buffer.alloc(0)) {
  const name = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])), 0);
  return Buffer.concat([length, name, data, checksum]);
}

function png(width, height, compressedData) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  const rowLength = 1 + width * 4;
  const scanlines = Buffer.alloc(height * rowLength);
  if (width > 2 && height > 2) {
    const pixel = rowLength + 1 + 4;
    scanlines[pixel] = 22;
    scanlines[pixel + 1] = 139;
    scanlines[pixel + 2] = 103;
    scanlines[pixel + 3] = 255;
  }
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    chunk("IHDR", header),
    chunk("IDAT", compressedData ?? deflateSync(scanlines)),
    chunk("IEND"),
  ]);
}

function ico(sizes = EXPECTED_ICO_SIZES) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(sizes.length, 4);
  const directory = Buffer.alloc(sizes.length * 16);
  const payloads = [];
  let offset = header.length + directory.length;

  sizes.forEach((size, index) => {
    const entry = index * 16;
    directory[entry] = size === 256 ? 0 : size;
    directory[entry + 1] = size === 256 ? 0 : size;
    directory.writeUInt16LE(0, entry + 4);
    directory.writeUInt16LE(32, entry + 6);
    const payload = png(size, size);
    directory.writeUInt32LE(payload.length, entry + 8);
    directory.writeUInt32LE(offset, entry + 12);
    payloads.push(payload);
    offset += payload.length;
  });

  return Buffer.concat([header, directory, ...payloads]);
}

function legacyRle(size) {
  const values = [];
  for (let channel = 0; channel < 3; channel += 1) {
    let remaining = size * size;
    while (remaining > 0) {
      const count = Math.min(130, remaining);
      values.push(count + 125, channel * 64);
      remaining -= count;
    }
  }
  return Buffer.from(values);
}

function icns(types = EXPECTED_ICNS_TYPES) {
  const pngSizes = {
    ic07: 128,
    ic08: 256,
    ic09: 512,
    ic10: 1024,
    ic11: 32,
    ic12: 64,
    ic13: 256,
    ic14: 512,
  };
  const chunks = types.map((type) => {
    let payload;
    if (pngSizes[type]) {
      payload = png(pngSizes[type], pngSizes[type]);
    } else if (type === "is32") {
      payload = legacyRle(16);
    } else if (type === "il32") {
      payload = legacyRle(32);
    } else if (type === "s8mk") {
      payload = Buffer.alloc(16 * 16, 255);
    } else if (type === "l8mk") {
      payload = Buffer.alloc(32 * 32, 255);
    } else {
      payload = Buffer.alloc(0);
    }
    const value = Buffer.alloc(8 + payload.length);
    value.write(type, 0, 4, "ascii");
    value.writeUInt32BE(value.length, 4);
    payload.copy(value, 8);
    return value;
  });
  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(8);
  header.write("icns", 0, 4, "ascii");
  header.writeUInt32BE(header.length + body.length, 4);
  return Buffer.concat([header, body]);
}

test("declares the complete desktop PNG icon set", () => {
  assert.deepEqual(EXPECTED_PNGS, {
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
});

test("validates RGBA PNG structure, dimensions, and checksums", () => {
  assert.deepEqual(parsePng(png(128, 128)), {
    width: 128,
    height: 128,
    bitDepth: 8,
    colorType: 6,
  });

  const invalid = png(128, 128);
  invalid[invalid.length - 1] ^= 0xff;
  assert.throws(() => parsePng(invalid), { message: "Invalid PNG checksum." });
  assert.throws(() => parsePng(png(128, 128, Buffer.from([0]))), {
    message: "Invalid PNG image data.",
  });
  const withUnknownChunk = png(128, 128);
  const iend = withUnknownChunk.subarray(withUnknownChunk.length - 12);
  const privateChunk = chunk("raNd", Buffer.from("private"));
  assert.throws(
    () =>
      parsePng(
        Buffer.concat([
          withUnknownChunk.subarray(0, withUnknownChunk.length - 12),
          privateChunk,
          iend,
        ]),
      ),
    { message: "Unexpected PNG chunk." },
  );
});

test("validates the exact ICO layer sizes and bounds", () => {
  assert.deepEqual(parseIco(ico()), EXPECTED_ICO_SIZES);
  assert.throws(() => parseIco(ico([16, 32, 256])), {
    message: "Unexpected ICO layers.",
  });
  const invalid = ico();
  invalid[invalid.readUInt32LE(18)] = 0;
  assert.throws(() => parseIco(invalid), { message: "Invalid PNG signature." });
  assert.throws(() => parseIco(Buffer.concat([ico(), Buffer.from([0])])), {
    message: "Unexpected ICO payload layout.",
  });
});

test("validates required ICNS chunks and declared length", () => {
  assert.deepEqual(parseIcns(icns()), EXPECTED_ICNS_TYPES);
  assert.throws(() => parseIcns(icns(["ic07"])), {
    message: "Missing ICNS chunks.",
  });
  assert.throws(() => parseIcns(icns([...EXPECTED_ICNS_TYPES, "raNd"])), {
    message: "Unexpected ICNS chunks.",
  });
});
