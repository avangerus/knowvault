// Card U-3: the smallest PNG reader/writer the screen comparison needs.
//
// The walkthrough compares the browser's own PNG screenshots pixel by pixel.
// Node ships zlib, so the only missing piece is the PNG container itself:
// decode the chunks, undo the scanline filters and expose RGBA bytes; encode
// RGBA bytes back into a PNG for the difference picture. No image library is
// installed, and the product never depends on this file.
//
// Supported, because it is exactly what Chromium's page.screenshot() emits:
// 8-bit channels, no interlacing, colour types 0 (grey), 2 (RGB), 3 (indexed),
// 4 (grey+alpha) and 6 (RGBA). Anything else is rejected loudly: a screenshot
// the comparison cannot read must fail, not silently pass.

import zlib from "node:zlib";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[n] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let value = 0xffffffff;
  for (let index = 0; index < bytes.length; index += 1) {
    value = CRC_TABLE[(value ^ bytes[index]) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

const CHANNELS_BY_COLOR_TYPE = new Map([
  [0, 1],
  [2, 3],
  [3, 1],
  [4, 2],
  [6, 4],
]);

// decodePng returns { width, height, data } with one RGBA byte per channel,
// four bytes per pixel, row-major from the top-left corner.
export function decodePng(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error("not a PNG file");
  }
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  let palette = null;
  const idat = [];
  let sawHeader = false;
  let sawEnd = false;
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString("latin1", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) {
      throw new Error(`truncated PNG chunk ${type}`);
    }
    const data = buffer.subarray(dataStart, dataEnd);
    if (type === "IHDR") {
      if (length !== 13) throw new Error("malformed PNG header");
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      if (data[10] !== 0) throw new Error(`unsupported PNG compression ${data[10]}`);
      if (data[11] !== 0) throw new Error(`unsupported PNG filter method ${data[11]}`);
      interlace = data[12];
      sawHeader = true;
    } else if (type === "PLTE") {
      palette = data;
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      sawEnd = true;
      break;
    }
    offset = dataEnd + 4;
  }
  if (!sawHeader) throw new Error("PNG without a header chunk");
  if (!sawEnd) throw new Error("PNG without an end chunk");
  if (width <= 0 || height <= 0) throw new Error("PNG with an empty canvas");
  if (bitDepth !== 8) throw new Error(`unsupported PNG bit depth ${bitDepth}`);
  if (interlace !== 0) throw new Error("interlaced PNG is not supported");
  const channels = CHANNELS_BY_COLOR_TYPE.get(colorType);
  if (channels === undefined) throw new Error(`unsupported PNG colour type ${colorType}`);
  if (colorType === 3 && palette === null) throw new Error("indexed PNG without a palette");

  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const expected = height * (stride + 1);
  if (raw.length < expected) {
    throw new Error(`PNG pixel data is ${raw.length} bytes, want ${expected}`);
  }

  const data = new Uint8Array(width * height * 4);
  const line = new Uint8Array(stride);
  const previous = new Uint8Array(stride);
  let position = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = raw[position];
    position += 1;
    for (let x = 0; x < stride; x += 1) {
      const value = raw[position + x];
      const a = x >= channels ? line[x - channels] : 0;
      const b = previous[x];
      const c = x >= channels ? previous[x - channels] : 0;
      let restored;
      switch (filter) {
        case 0:
          restored = value;
          break;
        case 1:
          restored = value + a;
          break;
        case 2:
          restored = value + b;
          break;
        case 3:
          restored = value + ((a + b) >> 1);
          break;
        case 4:
          restored = value + paeth(a, b, c);
          break;
        default:
          throw new Error(`unsupported PNG scanline filter ${filter}`);
      }
      line[x] = restored & 0xff;
    }
    position += stride;
    for (let x = 0; x < width; x += 1) {
      const pixel = (y * width + x) * 4;
      if (colorType === 6) {
        data[pixel] = line[x * 4];
        data[pixel + 1] = line[x * 4 + 1];
        data[pixel + 2] = line[x * 4 + 2];
        data[pixel + 3] = line[x * 4 + 3];
      } else if (colorType === 2) {
        data[pixel] = line[x * 3];
        data[pixel + 1] = line[x * 3 + 1];
        data[pixel + 2] = line[x * 3 + 2];
        data[pixel + 3] = 255;
      } else if (colorType === 0) {
        const grey = line[x];
        data[pixel] = grey;
        data[pixel + 1] = grey;
        data[pixel + 2] = grey;
        data[pixel + 3] = 255;
      } else if (colorType === 4) {
        const grey = line[x * 2];
        data[pixel] = grey;
        data[pixel + 1] = grey;
        data[pixel + 2] = grey;
        data[pixel + 3] = line[x * 2 + 1];
      } else {
        const index = line[x] * 3;
        data[pixel] = palette[index];
        data[pixel + 1] = palette[index + 1];
        data[pixel + 2] = palette[index + 2];
        data[pixel + 3] = 255;
      }
    }
    previous.set(line);
  }
  return { width, height, data, colorType };
}

function chunk(type, data) {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(data.length, 0);
  header.write(type, 4, "latin1");
  const body = Buffer.concat([header.subarray(4), data]);
  const footer = Buffer.alloc(4);
  footer.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([header, data, footer]);
}

// encodePng writes RGBA bytes (four per pixel, row-major) as a colour-type 6
// PNG with filter 0 on every scanline. The difference picture uses it.
export function encodePng({ width, height, data }) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new Error("encodePng needs positive integer width and height");
  }
  if (data.length < width * height * 4) {
    throw new Error("encodePng pixel data is shorter than width*height*4");
  }
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (stride + 1);
    raw[rowStart] = 0;
    for (let index = 0; index < stride; index += 1) {
      raw[rowStart + 1 + index] = data[y * stride + index];
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  header[10] = 0;
  header[11] = 0;
  header[12] = 0;
  return Buffer.concat([
    PNG_SIGNATURE,
    chunk("IHDR", header),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
