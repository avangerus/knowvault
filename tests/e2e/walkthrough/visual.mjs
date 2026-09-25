// Card U-3: compare a fresh screenshot with the approved reference picture of
// the same step.
//
// The comparison is deliberately literal: decode both PNGs, compare pixel by
// pixel with a small per-channel tolerance so anti-aliasing and the browser's
// own re-encoding do not count as a change, and report the share of the screen
// that differs. When that share is above the stated threshold the caller also
// gets a difference picture: the actual screen faded to a dark grey with every
// differing pixel painted red, so a person sees what moved without opening two
// images side by side.
//
// Everything here is pure computation over byte arrays; nothing touches
// product code or the network.

import { decodePng, encodePng } from "./png.mjs";

// DEFAULT_PIXEL_TOLERANCE is the per-channel difference (0..255) below which
// two pixels count as the same. It absorbs text anti-aliasing, which differs by
// a few counts between two renders of identical markup.
export const DEFAULT_PIXEL_TOLERANCE = 16;

// DEFAULT_DIFFERENCE_THRESHOLD is the share of the screen's pixels that may
// differ before a step is failed, when the caller does not state another one.
// It is measured, not guessed: five full runs of unchanged code differed only
// where the clock is rendered, at most 0.0194% of a 1440x900 screen; see
// README.
export const DEFAULT_DIFFERENCE_THRESHOLD = 0.0005;

// pixelsDiffer is the one comparison rule: a pixel differs when any red, green
// or blue channel is further than the tolerance from the reference. Alpha is
// ignored because screenshots are opaque.
function pixelsDiffer(reference, actual, index, tolerance) {
  return (
    Math.abs(reference[index] - actual[index]) > tolerance ||
    Math.abs(reference[index + 1] - actual[index + 1]) > tolerance ||
    Math.abs(reference[index + 2] - actual[index + 2]) > tolerance
  );
}

// highlightedBase dims the actual screen so red difference pixels stand out.
function highlightedBase(actual) {
  const data = new Uint8Array(actual.data.length);
  for (let index = 0; index < actual.data.length; index += 4) {
    data[index] = Math.round(actual.data[index] * 0.28) + 24;
    data[index + 1] = Math.round(actual.data[index + 1] * 0.28) + 24;
    data[index + 2] = Math.round(actual.data[index + 2] * 0.28) + 24;
    data[index + 3] = 255;
  }
  return data;
}

function border(data, width, height, thickness, colour) {
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      if (x >= thickness && x < width - thickness && y >= thickness && y < height - thickness) continue;
      const index = (y * width + x) * 4;
      data[index] = colour[0];
      data[index + 1] = colour[1];
      data[index + 2] = colour[2];
      data[index + 3] = 255;
    }
  }
}

// comparePngs returns the measured difference between an approved reference and
// a fresh screenshot of the same step.
//
//   size_mismatch      the two pictures have different dimensions
//   total_pixels       width * height of the compared canvas
//   different_pixels   pixels beyond the tolerance
//   difference_ratio   different_pixels / total_pixels
//   difference_box     the rectangle that contains every differing pixel
//   beyond_threshold   difference_ratio > threshold
//   diff               PNG bytes highlighting the difference, or null
export function comparePngs(referenceBytes, actualBytes, options = {}) {
  const pixelTolerance = options.pixelTolerance ?? DEFAULT_PIXEL_TOLERANCE;
  const threshold = options.threshold ?? DEFAULT_DIFFERENCE_THRESHOLD;
  if (!(pixelTolerance >= 0)) throw new Error(`pixelTolerance=${pixelTolerance}, want a number >= 0`);
  if (!(threshold >= 0)) throw new Error(`threshold=${threshold}, want a number >= 0`);

  const reference = decodePng(referenceBytes);
  const actual = decodePng(actualBytes);
  const base = {
    pixel_tolerance: pixelTolerance,
    threshold,
    reference_width: reference.width,
    reference_height: reference.height,
    actual_width: actual.width,
    actual_height: actual.height,
  };

  if (reference.width !== actual.width || reference.height !== actual.height) {
    const data = highlightedBase(actual);
    border(data, actual.width, actual.height, 6, [255, 0, 0]);
    const total = actual.width * actual.height;
    return {
      ...base,
      size_mismatch: true,
      width: actual.width,
      height: actual.height,
      total_pixels: total,
      different_pixels: total,
      difference_ratio: 1,
      difference_box: { x: 0, y: 0, right: actual.width - 1, bottom: actual.height - 1 },
      beyond_threshold: true,
      diff: encodePng({ width: actual.width, height: actual.height, data }),
    };
  }

  const width = actual.width;
  const height = actual.height;
  let different = 0;
  let minX = width;
  let minY = height;
  let maxX = -1;
  let maxY = -1;
  const data = highlightedBase(actual);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const index = (y * width + x) * 4;
      if (!pixelsDiffer(reference.data, actual.data, index, pixelTolerance)) continue;
      different += 1;
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
      data[index] = 255;
      data[index + 1] = 40;
      data[index + 2] = 40;
      data[index + 3] = 255;
    }
  }
  const total = width * height;
  const ratio = total === 0 ? 0 : different / total;
  const beyond = ratio > threshold;
  return {
    ...base,
    size_mismatch: false,
    width,
    height,
    total_pixels: total,
    different_pixels: different,
    difference_ratio: ratio,
    difference_box: maxX < 0 ? null : { x: minX, y: minY, right: maxX, bottom: maxY },
    beyond_threshold: beyond,
    diff: beyond ? encodePng({ width, height, data }) : null,
  };
}
